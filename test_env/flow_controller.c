#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "flow_controller.h"
#ifdef NN_BACKEND
#include "nn_controller.h"
#endif

const char *const flow_counter_names[FLOW_COUNTER_COUNT] = {
	"tracked", "created", "replaced", "unknown", "skip_truncated",
	"skip_vlan", "skip_ipv6", "skip_non_ipv4", "skip_fragment",
	"skip_non_tcp", "skip_malformed", "skip_nonlinear", "capacity_failure",
	"resolve_failure", "observation_loss", "gc_expired", "gc_delete_failure",
	"id_exhausted",
};
const char *const flow_state_names[FLOW_REPLACED + 1] = {
	"open", "half_closed", "closing", "closed", "reset", "replaced",
};
#define U64(value) ((uint64_t)(value))
enum map_slot { COUNTS, INDEX, STATS, SERIAL, CONFIG, TRACKING, OBSERVATIONS };
static const char *const map_names[FLOW_MAP_COUNT] = {
	"hook_counts", "flow_index", "flow_stats", "flow_serial", "flow_config",
	"tracking", "observations",
};
static const enum bpf_map_type map_types[FLOW_MAP_COUNT] = {
	BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_RINGBUF,
};
static const __u32 map_keys[FLOW_MAP_COUNT] = {
	4, sizeof(struct flow_key), 8, 4, 4, 4, 0,
};
static const __u32 map_values[FLOW_MAP_COUNT] = {
	8, 8, sizeof(struct flow_value), 8, sizeof(struct flow_config), 8, 0,
};
static const __u32 map_entries[FLOW_MAP_COUNT] = {
	2, FLOW_INDEX_CAPACITY, FLOW_CAPACITY, 1, 1, FLOW_COUNTER_COUNT, FLOW_RING_BYTES,
};

_Static_assert(sizeof(struct flow_key) == 20, "flow key ABI");
_Static_assert(sizeof(struct flow_value) == 208, "flow value ABI");
_Static_assert(sizeof(struct flow_config) == 24, "flow config ABI");
_Static_assert(sizeof(struct flow_observation) == 168, "flow observation ABI");

static __u64 monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (__u64)now.tv_sec * 1000000000ULL + (__u64)now.tv_nsec;
}

void flow_controller_init(struct flow_controller *flow)
{
	for (int i = 0; i < FLOW_MAP_COUNT; i++)
		flow->map_fds[i] = -1;
	flow->gc_fd = -1;
	flow->idle_ms = FLOW_DEFAULT_IDLE_MS;
	flow->closed_ms = FLOW_DEFAULT_CLOSED_MS;
	flow->gc_ms = FLOW_DEFAULT_GC_MS;
}

static int parse_positive(const char *text, __u64 *value)
{
	char *end;
	unsigned long long result;

	if (!text[0] || text[0] == '-' || text[0] == '+')
		return -EINVAL;
	errno = 0;
	result = strtoull(text, &end, 10);
	/* A day is ample for this private validation lab, and bounds ns overflow. */
	if (errno || *end || !result || result > 86400000ULL)
		return -EINVAL;
	*value = result;
	return 0;
}

int flow_arguments(struct flow_controller *flow, int argc, char **argv)
{
	for (int i = 4; i < argc; i++) {
		__u64 *target;

		if (!strcmp(argv[i], "--capture")) {
			if (flow->capture)
				return -EINVAL;
			flow->capture = true;
			continue;
		}
		if (!strcmp(argv[i], "--idle-ms"))
			target = &flow->idle_ms;
		else if (!strcmp(argv[i], "--closed-ms"))
			target = &flow->closed_ms;
		else if (!strcmp(argv[i], "--gc-ms"))
			target = &flow->gc_ms;
		else
			return -EINVAL;
		if (++i >= argc || parse_positive(argv[i], target))
			return -EINVAL;
	}
	return 0;
}

int flow_validate_object(struct bpf_object *object)
{
	struct bpf_program *gc = bpf_object__find_program_by_name(object, "flow_gc");

	if (!gc || bpf_program__type(gc) != BPF_PROG_TYPE_SCHED_CLS)
		return -EINVAL;
	for (int i = 0; i < FLOW_MAP_COUNT; i++) {
		struct bpf_map *map = bpf_object__find_map_by_name(object, map_names[i]);

		if (!map || bpf_map__type(map) != map_types[i] ||
		    bpf_map__key_size(map) != map_keys[i] ||
		    bpf_map__value_size(map) != map_values[i] ||
		    bpf_map__max_entries(map) != map_entries[i] || bpf_map__pin_path(map))
			return -EINVAL;
	}
	return 0;
}

int flow_collect_ids(struct flow_controller *flow, struct bpf_object *object)
{
	struct bpf_program *gc = bpf_object__find_program_by_name(object, "flow_gc");
	struct bpf_prog_info program = {};
	__u32 size = sizeof(program);

	flow->gc_fd = gc ? bpf_program__fd(gc) : -1;
	if (flow->gc_fd >= 0) {
		if (bpf_prog_get_info_by_fd(flow->gc_fd, &program, &size))
			return -errno;
		flow->gc_id = program.id;
	}
	for (int i = 0; i < FLOW_MAP_COUNT; i++) {
		struct bpf_map *map = bpf_object__find_map_by_name(object, map_names[i]);
		struct bpf_map_info info = {};

		flow->map_fds[i] = map ? bpf_map__fd(map) : -1;
		if (flow->map_fds[i] < 0)
			continue;
		size = sizeof(info);
		if (bpf_map_get_info_by_fd(flow->map_fds[i], &info, &size))
			return -errno;
		flow->map_ids[i] = info.id;
	}
	return 0;
}

static int consume_observation(void *context, void *data, size_t size)
{
	struct flow_controller *flow = context;
	const struct flow_observation *record = data;

	if (size != sizeof(*record) || record->header_length > FLOW_HEADER_CAPACITY ||
	    record->kind > 1 || (record->kind == 1 &&
	    (record->skip_reason < FLOW_C_SKIP_TRUNCATED || record->skip_reason > FLOW_C_SKIP_NONLINEAR)))
		return -EPROTO;
	if (flow->pending_count == FLOW_DIAGNOSTIC_CAPACITY) {
		flow->diagnostic_buffer_loss++;
		return 0;
	}
	flow->pending[flow->pending_count++] = *record;
	return 0;
}

int flow_prepare(struct flow_controller *flow, struct bpf_object *object)
{
	struct flow_config config = {
		.abi_version = FLOW_ABI_VERSION,
		.idle_ns = flow->idle_ms * 1000000ULL,
		.closed_ns = flow->closed_ms * 1000000ULL,
	};
	__u32 zero = 0;
	int result = flow_collect_ids(flow, object);

	if (result)
		return result;
	if (!flow->gc_id)
		return -EIO;
	for (int i = 0; i < FLOW_MAP_COUNT; i++)
		if (!flow->map_ids[i])
			return -EIO;
	/* Capture stays disabled until the unattached role selftest is cleared. */
	if (bpf_map_update_elem(flow->map_fds[CONFIG], &zero, &config, BPF_ANY))
		return -errno;
	flow->snapshot_values = calloc(FLOW_CAPACITY, sizeof(*flow->snapshot_values));
	if (!flow->snapshot_values)
		return -ENOMEM;
	if (flow->capture) {
		flow->pending = calloc(FLOW_DIAGNOSTIC_CAPACITY, sizeof(*flow->pending));
		if (!flow->pending)
			return -ENOMEM;
		flow->ring = ring_buffer__new(flow->map_fds[OBSERVATIONS],
					     consume_observation, flow, NULL);
		if (!flow->ring)
			return errno ? -errno : -ENOMEM;
	}
	return 0;
}

static int clear_hash(int fd, size_t key_size)
{
	unsigned char key[sizeof(struct flow_key)];

	if (key_size > sizeof(key))
		return -EINVAL;
	/* Called only before either TC program is attached. */
	while (!bpf_map_get_next_key(fd, NULL, key))
		if (bpf_map_delete_elem(fd, key))
			return -errno;
	return errno == ENOENT ? 0 : -errno;
}

int flow_after_selftest(struct flow_controller *flow, int cpu_count, __u64 *cpu_values)
{
	struct flow_config config = {
		.abi_version = FLOW_ABI_VERSION,
		.capture_enabled = flow->capture,
		.idle_ns = flow->idle_ms * 1000000ULL,
		.closed_ns = flow->closed_ms * 1000000ULL,
	};
	__u64 serial = 0;
	__u32 key = 0;
	int result;

	memset(cpu_values, 0, (size_t)cpu_count * sizeof(*cpu_values));
	result = clear_hash(flow->map_fds[INDEX], sizeof(struct flow_key));
	if (!result)
		result = clear_hash(flow->map_fds[STATS], sizeof(__u64));
	for (key = 0; !result && key < FLOW_COUNTER_COUNT; key++)
		if (bpf_map_update_elem(flow->map_fds[TRACKING], &key, cpu_values, BPF_ANY))
			result = -errno;
	key = 0;
	if (!result && bpf_map_update_elem(flow->map_fds[SERIAL], &key, &serial, BPF_ANY))
		result = -errno;
	if (!result && bpf_map_update_elem(flow->map_fds[CONFIG], &key, &config, BPF_ANY))
		result = -errno;
	return result;
}

static int compare_ids(const void *a, const void *b)
{
	const __u64 x = *(const __u64 *)a, y = *(const __u64 *)b;

	return x > y ? 1 : x < y ? -1 : 0;
}

/* Concurrent hash traversal is deliberately bounded, then de-duplicated. A
 * snapshot locks each generation independently; it is not a global barrier.
 */
static int collect_keys(int fd, __u64 keys[FLOW_CAPACITY], size_t *count)
{
	__u64 cursor, next;
	bool have_cursor = false;
	size_t used = 0, unique = 0;

	for (size_t step = 0; step < FLOW_CAPACITY * 2U && used < FLOW_CAPACITY; step++) {
		if (bpf_map_get_next_key(fd, have_cursor ? &cursor : NULL, &next)) {
			if (errno != ENOENT)
				return -errno;
			break;
		}
		keys[used++] = next;
		cursor = next;
		have_cursor = true;
	}
	qsort(keys, used, sizeof(*keys), compare_ids);
	for (size_t i = 0; i < used; i++)
		if (!i || keys[i] != keys[i - 1])
			keys[unique++] = keys[i];
	*count = unique;
	return 0;
}

int flow_tick(struct flow_controller *flow)
{
	__u64 now = monotonic_ns();
	size_t count;
	int result;

	if (!now)
		return -errno;
	if (flow->ring) {
		result = ring_buffer__consume(flow->ring);
		if (result < 0)
			return result;
	}
	if (now - flow->last_gc_ns < flow->gc_ms * 1000000ULL)
		return 0;
	flow->last_gc_ns = now;
	result = collect_keys(flow->map_fds[STATS], flow->keys, &count);
	if (result)
		return result;
	for (size_t i = 0; i < count; i++) {
		/* skb test-run requires at least an Ethernet-sized frame on 5.15. */
		unsigned char request[64] = {};
		struct bpf_test_run_opts options = {
			.sz = sizeof(options), .data_in = request,
			.data_size_in = sizeof(request), .repeat = 1,
		};

		memcpy(request, &flow->keys[i], sizeof(flow->keys[i]));
		result = bpf_prog_test_run_opts(flow->gc_fd, &options);
		if (result)
			return result;
		if (options.retval)
			return -EPROTO;
	}
#ifdef NN_BACKEND
	return nn_prune_rx(flow->map_fds[STATS]);
#else
	return 0;
#endif
}

static void print_address(__u32 address)
{
	printf("\"%u.%u.%u.%u\"", address >> 24, (address >> 16) & 255,
	       (address >> 8) & 255, address & 255);
}

static void print_direction(const struct flow_direction *d)
{
	printf("{\"packets\":%" PRIu64 ",\"ipv4_bytes\":%" PRIu64
	       ",\"tcp_segment_bytes\":%" PRIu64 ",\"tcp_header_bytes\":%" PRIu64
	       ",\"first_ns\":%" PRIu64 ",\"last_ns\":%" PRIu64
	       ",\"max_iat_ns\":%" PRIu64 ",\"min_segment_bytes\":%u,"
	       "\"max_segment_bytes\":%u}", U64(d->packets), U64(d->ipv4_bytes),
	       U64(d->tcp_segment_bytes), U64(d->tcp_header_bytes), U64(d->first_ns),
	       U64(d->last_ns), U64(d->max_iat_ns), d->min_segment_bytes,
	       d->max_segment_bytes);
}

static void print_flow(__u64 id, const struct flow_value *value)
{
	const struct flow_key *key = &value->key;
	const char *initiator = value->initiator == 1 ? "a" :
		value->initiator == 2 ? "b" : "unknown";
	const char *state = value->state <= FLOW_REPLACED ?
		flow_state_names[value->state] : "invalid";

	printf("{\"id\":%" PRIu64 ",\"key\":{\"a_addr\":", U64(id));
	print_address(key->a_addr);
	printf(",\"a_port\":%u,\"b_addr\":", key->a_port);
	print_address(key->b_addr);
	printf(",\"b_port\":%u,\"ifindex\":%u,\"protocol\":%u},"
	       "\"initiator\":\"%s\",\"state\":\"%s\",\"first_ns\":%" PRIu64
	       ",\"last_ns\":%" PRIu64 ",\"closed_ns\":%" PRIu64
	       ",\"ordinal\":%" PRIu64 ",\"a_to_b\":", key->b_port, key->ifindex,
	       key->protocol, initiator, state, U64(value->first_ns),
	       U64(value->last_ns), U64(value->closed_ns), U64(value->ordinal));
	print_direction(&value->directions[0]);
	printf(",\"b_to_a\":");
	print_direction(&value->directions[1]);
	printf("}");
}

static int read_flows(int fd, __u64 keys[FLOW_CAPACITY],
		      struct flow_value values[FLOW_CAPACITY], size_t *count)
{
	size_t candidates, used = 0;
	int result = collect_keys(fd, keys, &candidates);

	if (result)
		return result;
	for (size_t i = 0; i < candidates; i++) {
		if (bpf_map_lookup_elem_flags(fd, &keys[i], &values[used], BPF_F_LOCK)) {
			if (errno == ENOENT)
				continue;
			return -errno;
		}
		if (values[used].tombstone || !values[used].ordinal)
			continue;
		keys[used++] = keys[i];
	}
	*count = used;
	return 0;
}

static void print_flows(const __u64 *keys, const struct flow_value *values, size_t count)
{
	printf(",\"flows\":[");
	for (size_t i = 0; i < count; i++) {
		if (i)
			putchar(',');
		print_flow(keys[i], &values[i]);
	}
	putchar(']');
}

/* Caller supplies FLOW_CAPACITY keys and limit+1 values. The last value is
 * reusable lookup scratch once retained rows reach the explicit display cap.
 * Enumeration is bounded, not an atomic membership snapshot across GC. */
int flow_bounded_snapshot(int fd, __u64 *keys, struct flow_value *values,
			  size_t limit, size_t *total)
{
	size_t candidates, used = 0;
	int result = collect_keys(fd, keys, &candidates);
	if (result) return result;
	for (size_t i = 0; i < candidates; i++) {
		size_t row = used < limit ? used : limit;
		if (bpf_map_lookup_elem_flags(fd, &keys[i], &values[row], BPF_F_LOCK)) {
			if (errno == ENOENT) continue;
			return -errno;
		}
		if (values[row].tombstone || !values[row].ordinal) continue;
		if (used < limit) keys[used] = keys[i];
		used++;
	}
	*total = used;
	return 0;
}

void flow_print_rows(const __u64 *keys, const struct flow_value *values, size_t count)
{
	print_flows(keys, values, count);
}

int flow_prepare_snapshot(struct flow_controller *flow, int cpu_count, __u64 *cpu_values)
{
	int result;

	flow->snapshot_start_ns = monotonic_ns();
	if (!flow->snapshot_start_ns)
		return -errno;
	if (flow->ring) {
		result = ring_buffer__consume(flow->ring);
		if (result < 0)
			return result;
	}
	for (__u32 key = 0; key < FLOW_COUNTER_COUNT; key++) {
		flow->counter_values[key] = 0;
		if (bpf_map_lookup_elem(flow->map_fds[TRACKING], &key, cpu_values))
			return -errno;
		for (int cpu = 0; cpu < cpu_count; cpu++)
			flow->counter_values[key] += cpu_values[cpu];
	}
	result = read_flows(flow->map_fds[STATS], flow->keys,
			    flow->snapshot_values, &flow->snapshot_count);
	if (result)
		return result;
	flow->snapshot_end_ns = monotonic_ns();
	return flow->snapshot_end_ns ? 0 : -errno;
}

void flow_print_snapshot(struct flow_controller *flow)
{
	printf(",\"snapshot_ns\":%" PRIu64, U64(flow->snapshot_start_ns));
	print_flows(flow->keys, flow->snapshot_values, flow->snapshot_count);
	bool first = true;
	printf(",\"observations\":[");
	for (size_t i = 0; i < flow->pending_count; i++) {
		const struct flow_observation *record = &flow->pending[i];
		if (record->kind)
			continue;

		if (!first)
			putchar(',');
		first = false;
		printf("{\"flow_id\":%" PRIu64 ",\"ordinal\":%" PRIu64
		       ",\"timestamp_ns\":%" PRIu64 ",\"ifindex\":%u,"
		       "\"direction\":%u,\"hook\":%u,\"header_hex\":\"",
		       U64(record->flow_id), U64(record->ordinal), U64(record->timestamp_ns),
		       record->ifindex, record->direction, record->hook);
		for (unsigned int byte = 0; byte < record->header_length; byte++)
			printf("%02x", record->headers[byte]);
		printf("\"}");
	}
	printf("],\"skipped_observations\":[");
	first = true;
	for (size_t i = 0; i < flow->pending_count; i++) {
		const struct flow_observation *record = &flow->pending[i];
		if (!record->kind)
			continue;
		if (!first)
			putchar(',');
		first = false;
		printf("{\"timestamp_ns\":%" PRIu64 ",\"ifindex\":%u,\"hook\":%u,"
		       "\"reason\":\"%s\",\"header_hex\":\"", U64(record->timestamp_ns),
		       record->ifindex, record->hook, flow_counter_names[record->skip_reason]);
		for (unsigned int byte = 0; byte < record->header_length; byte++)
			printf("%02x", record->headers[byte]);
		printf("\"}");
	}
	flow->pending_count = 0;
	printf("],\"counters\":{");
	for (int i = 0; i < FLOW_COUNTER_COUNT; i++)
		printf("%s\"%s\":%" PRIu64, i ? "," : "", flow_counter_names[i],
		       U64(flow->counter_values[i]));
	printf(",\"diagnostic_buffer_loss\":%" PRIu64 "},\"snapshot_end_ns\":%" PRIu64,
	       U64(flow->diagnostic_buffer_loss), U64(flow->snapshot_end_ns));
}

void flow_print_ids(const struct flow_controller *flow)
{
	printf(",\"gc\":%u", flow->gc_id);
#ifdef NN_BACKEND
	nn_print_program_ids();
#endif
	printf("},\"map_ids\":{");
	for (int i = 0; i < FLOW_MAP_COUNT; i++)
		printf("%s\"%s\":%u", i ? "," : "", map_names[i], flow->map_ids[i]);
#ifdef NN_BACKEND
	nn_print_map_ids();
#endif
	putchar('}');
}

void flow_print_ready(const struct flow_controller *flow)
{
#ifdef NN_BACKEND
	printf(",\"flow_abi_version\":%d,"
#else
	printf(",\"backend\":\"flows\",\"flow_abi_version\":%d,"
	       "\"feature_schema\":\"" FLOW_FEATURE_SCHEMA "\","
#endif
	       "\"clock\":\"monotonic-lock-observed-clamped\","
	       "\"snapshot_scope\":\"per-generation-locked-not-global\","
	       "\"config\":{\"idle_ms\":%" PRIu64 ",\"closed_ms\":%" PRIu64
	       ",\"gc_ms\":%" PRIu64 ",\"capture_enabled\":%s,\"capacity\":%d,"
	       "\"index_capacity\":%d,\"diagnostic_capacity\":%d}",
	       FLOW_ABI_VERSION, U64(flow->idle_ms),
	       U64(flow->closed_ms), U64(flow->gc_ms), flow->capture ? "true" : "false",
	       FLOW_CAPACITY, FLOW_INDEX_CAPACITY, FLOW_DIAGNOSTIC_CAPACITY);
}

void flow_controller_close(struct flow_controller *flow)
{
	ring_buffer__free(flow->ring);
	free(flow->pending);
	free(flow->snapshot_values);
}

/* A typed numeric map ID is not ownership evidence. Inspect only a map held
 * by the supplied live controller in the same already-validated lab netns.
 * fdinfo is the kernel's map-ID proof; no path-based bpffs/global pins exist.
 */
static int check_map_owner(const char *owner_pid, __u32 id,
			   const struct stat *namespace_identity)
{
	struct stat identity;
	struct dirent *entry;
	char path[128], *end;
	unsigned long pid;
	DIR *directory;
	int result = -ENOENT;

	if (!owner_pid[0] || owner_pid[0] == '-' || owner_pid[0] == '+')
		return -EINVAL;
	errno = 0;
	pid = strtoul(owner_pid, &end, 10);
	if (errno || *end || !pid || pid > INT_MAX)
		return -EINVAL;
	snprintf(path, sizeof(path), "/proc/%lu/ns/net", pid);
	if (stat(path, &identity))
		return -errno;
	if (identity.st_dev != namespace_identity->st_dev ||
	    identity.st_ino != namespace_identity->st_ino)
		return -EPERM;
	snprintf(path, sizeof(path), "/proc/%lu/fdinfo", pid);
	directory = opendir(path);
	if (!directory)
		return -errno;
	while ((entry = readdir(directory))) {
		FILE *stream;
		char line[256];
		unsigned int found;

		if (entry->d_name[0] == '.')
			continue;
		/* proc fdinfo entries are decimal descriptor numbers. */
		strtoul(entry->d_name, &end, 10);
		if (*end)
			continue;
		snprintf(path, sizeof(path), "/proc/%lu/fdinfo/%.*s", pid, 20, entry->d_name);
		stream = fopen(path, "re");
		if (!stream)
			continue; /* A descriptor may close during traversal. */
		while (fgets(line, sizeof(line), stream)) {
			if (sscanf(line, "map_id: %u", &found) == 1 && found == id) {
				result = 0;
				break;
			}
		}
		fclose(stream);
		if (!result)
			break;
	}
	closedir(directory);
	return result;
}

int flow_inspect(const char *map_id, const char *owner_pid,
		 const struct stat *namespace_identity)
{
	struct bpf_get_fd_by_id_opts options = {
		.sz = sizeof(options), .open_flags = BPF_F_RDONLY,
	};
	struct bpf_map_info info = {};
	__u64 *keys;
	struct flow_value *values;
	size_t count = 0;
	__u64 start = monotonic_ns(), finish;
	__u32 size = sizeof(info);
	char *end;
	unsigned long id;
	int fd, result;

	if (!map_id[0] || map_id[0] == '-' || map_id[0] == '+')
		return -EINVAL;
	errno = 0;
	id = strtoul(map_id, &end, 10);
	if (errno || *end || !id || id > UINT32_MAX)
		return -EINVAL;
	result = check_map_owner(owner_pid, (__u32)id, namespace_identity);
	if (result)
		return result;
	fd = bpf_map_get_fd_by_id_opts((__u32)id, &options);
	if (fd < 0)
		return -errno;
	result = bpf_map_get_info_by_fd(fd, &info, &size) ? -errno : 0;
	if (!result && (info.type != BPF_MAP_TYPE_HASH || info.key_size != 8 ||
	    info.value_size != sizeof(struct flow_value) || info.max_entries != FLOW_CAPACITY ||
	    strcmp(info.name, "flow_stats")))
		result = -EINVAL;
	keys = result ? NULL : calloc(FLOW_CAPACITY, sizeof(*keys));
	values = result ? NULL : calloc(FLOW_CAPACITY, sizeof(*values));
	if (!result && (!keys || !values))
		result = -ENOMEM;
	if (!result)
		result = read_flows(fd, keys, values, &count);
	finish = monotonic_ns();
	if (!result) {
		printf("{\"schema_version\":1,\"event\":\"inspection\",\"flow_abi_version\":%d,"
		       "\"map_id\":%lu,\"snapshot_ns\":%" PRIu64,
		       FLOW_ABI_VERSION, id, U64(start));
		print_flows(keys, values, count);
		printf(",\"snapshot_end_ns\":%" PRIu64 "}\n", U64(finish));
	}
	free(keys);
	free(values);
	close(fd);
	return result;
}
