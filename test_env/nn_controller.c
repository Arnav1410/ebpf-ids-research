#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "nn_controller.h"
#include "nn_context.h"
#include "private_scope.h"
#include "nn_json.h"
#define U64(x) ((uint64_t)(x))
enum { RX, JOBS, PARAMS, SLOTS, CONTROL, TAILS, RESULTS, TRACES, ZERO, TZERO, COUNTS, EVENTS, EVENT_SEQ };
static const char *const maps[NN_MAP_COUNT] = {
	"nn_rx", "nn_jobs", "nn_params", "nn_slots", "nn_control", "nn_tails",
	"nn_results", "nn_traces", "nn_zero", "nn_tzero", "nn_counts", "nn_events", "nn_event_seq" };
static const enum bpf_map_type types[NN_MAP_COUNT] = {
	BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_ARRAY };
static const __u32 keys[NN_MAP_COUNT] = { 8,16,4,4,4,4,16,16,4,4,4,0,4 };
static const __u32 sizes[NN_MAP_COUNT] = { 56,432,5216,40,16,4,152,544,432,544,8,0,8 };
static const __u32 entries[NN_MAP_COUNT] = {
	NN_CAPACITY,NN_CAPACITY,2,2,1,6,NN_CAPACITY,NN_CAPACITY,1,1,NN_COUNTER_COUNT,
	NN_EVENT_RING_BYTES,1 };
static const char *const programs[NN_PROGRAM_COUNT] = {
	"nn_normalize", "nn_linear0", "nn_relu0", "nn_linear1", "nn_relu1", "nn_output", "nn_vector" };
static const __u32 map_flags[NN_MAP_COUNT] = {
	0,0,BPF_F_RDONLY_PROG,0,0,0,0,BPF_F_NO_PREALLOC,
	BPF_F_RDONLY_PROG,BPF_F_RDONLY_PROG,0,0,0 };
static const char *const roles[NN_PROGRAM_COUNT] = {
	"normalize", "linear0", "relu0", "linear1", "relu1", "output", "vector" };
static const char *const counter_names[NN_COUNTER_COUNT] = {
	"trigger","complete","unready","job_full","tail_missing","bad_params",
	"trace_full","result_full","rx_full","missing_job","bad_stage",
	"event_emitted","event_dropped","event_missing_counts" };
static int fds[NN_MAP_COUNT];
static __u32 ids[NN_MAP_COUNT], prog_ids[NN_PROGRAM_COUNT];
static int prog_fds[NN_PROGRAM_COUNT];
static bool installed[6], trace_enabled;
static const char *params_path, *identity_text;
static __u32 event_ring_bytes = NN_EVENT_RING_BYTES;
static struct nn_slot loaded_slot;
static struct nn_result *snapshot_results;
static struct nn_trace *snapshot_traces;
static bool *snapshot_has_trace;
static size_t snapshot_count;
static __u64 snapshot_counts[NN_COUNTER_COUNT];
_Static_assert(sizeof(struct nn_params) == 5216, "parameter ABI");
_Static_assert(sizeof(struct nn_result) == 152, "result ABI");
_Static_assert(sizeof(struct nn_job) == 432, "job ABI");
_Static_assert(sizeof(struct nn_trace) == 544, "trace ABI");
_Static_assert(sizeof(struct nn_event) == NN_EVENT_BYTES, "event ABI");
int nn_arguments(struct flow_controller *flow, int argc, char **argv)
{
	int n = 4;
	for (int i = 4; i < argc; i++) {
		if (!strcmp(argv[i], "--params") || !strcmp(argv[i], "--model-id")) {
			bool model = !strcmp(argv[i], "--model-id");
			if (++i == argc) return -EINVAL;
			if (model) { if (identity_text) return -EINVAL; identity_text = argv[i]; }
			else { if (params_path) return -EINVAL; params_path = argv[i]; }
		} else if (!strcmp(argv[i], "--trace")) {
			if (trace_enabled) return -EINVAL;
			trace_enabled = true;
		} else if (!strcmp(argv[i], "--event-ring-bytes")) {
			char *end;
			unsigned long bytes;
			if (++i == argc || !argv[i][0] ||
			    strspn(argv[i], "0123456789") != strlen(argv[i])) return -EINVAL;
			errno = 0;
			bytes = strtoul(argv[i], &end, 10);
			if (errno || *end || bytes < NN_EVENT_RING_MIN_BYTES ||
			    bytes > NN_EVENT_RING_BYTES || (bytes & (bytes - 1)) ||
			    bytes % (unsigned long)sysconf(_SC_PAGESIZE)) return -EINVAL;
			event_ring_bytes = bytes;
		} else argv[n++] = argv[i];
	}
	if (!params_path || !identity_text || strlen(identity_text) != 64) return -EINVAL;
	for (int i = 0; i < 32; i++) {
		unsigned int byte;
		char text[3] = {identity_text[i * 2], identity_text[i * 2 + 1], 0};
		if (strspn(text, "0123456789abcdef") != 2 || sscanf(text, "%x", &byte) != 1)
			return -EINVAL;
		loaded_slot.identity[i] = byte;
	}
	return flow_arguments(flow, n, argv);
}
int nn_validate_object(struct bpf_object *obj)
{
	for (int i = 0; i < NN_MAP_COUNT; i++) {
		struct bpf_map *map = bpf_object__find_map_by_name(obj, maps[i]);
		if (!map || bpf_map__type(map) != types[i] || bpf_map__key_size(map) != keys[i] ||
		    bpf_map__value_size(map) != sizes[i] || bpf_map__max_entries(map) != entries[i] ||
		    bpf_map__map_flags(map) != map_flags[i] || bpf_map__pin_path(map)) return -EINVAL;
	}
	for (int i = 0; i < NN_PROGRAM_COUNT; i++) {
		struct bpf_program *p = bpf_object__find_program_by_name(obj, programs[i]);
		if (!p || bpf_program__type(p) != BPF_PROG_TYPE_SCHED_CLS) return -EINVAL;
	}
	{
		struct bpf_map *ring = bpf_object__find_map_by_name(obj, "nn_events");
		int result = bpf_map__set_max_entries(ring, event_ring_bytes);
		if (result) return result;
	}
	return 0;
}
static int read_regular(const char *path, void *data, size_t size)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW), result = 0;
	size_t done = 0;
	if (fd < 0) return -errno;
	if (fstat(fd, &st)) { result = -errno; goto out; }
	if (!S_ISREG(st.st_mode) || st.st_size != (off_t)size) { result = -EINVAL; goto out; }
	while (done < size) {
		ssize_t n = read(fd, (char *)data + done, size - done);
		if (n < 0 && errno == EINTR) continue;
		if (n <= 0) { result = n ? -errno : -EIO; goto out; }
		done += (size_t)n;
	}
out:
	close(fd);
	return result;
}
int nn_collect_ids(struct bpf_object *obj)
{
	for (int i = 0; i < NN_MAP_COUNT; i++) {
		struct bpf_map *map = bpf_object__find_map_by_name(obj, maps[i]);
		struct bpf_map_info info = {};
		__u32 size = sizeof(info);
		fds[i] = bpf_map__fd(map);
		if (fds[i] < 0) continue;
		if (bpf_map_get_info_by_fd(fds[i], &info, &size)) return -errno;
		ids[i] = info.id;
	}
	for (int i = 0; i < NN_PROGRAM_COUNT; i++) {
		struct bpf_program *p = bpf_object__find_program_by_name(obj, programs[i]);
		struct bpf_prog_info info = {};
		__u32 size = sizeof(info);
		prog_fds[i] = bpf_program__fd(p);
		if (prog_fds[i] < 0) continue;
		if (bpf_prog_get_info_by_fd(prog_fds[i], &info, &size)) return -errno;
		prog_ids[i] = info.id;
	}
	return 0;
}
int nn_prepare(struct bpf_object *obj)
{
	struct nn_params params;
	struct nn_control control = {};
	__u32 zero = 0;
	int result = nn_collect_ids(obj);
	if (result) return result;
	result = read_regular(params_path, &params, sizeof(params));
	if (result) return result;
	for (int i = 0; i < 6; i++) if (!params.scale[i]) return -EINVAL;
	if (bpf_map_update_elem(fds[PARAMS], &zero, &params, BPF_ANY)) return -errno;
	if (bpf_map_freeze(fds[PARAMS]) || bpf_map_freeze(fds[ZERO]) ||
	    bpf_map_freeze(fds[TZERO])) return -errno;
	loaded_slot.ready = 1;
	if (bpf_map_update_elem(fds[SLOTS], &zero, &loaded_slot, BPF_ANY) ||
	    bpf_map_update_elem(fds[CONTROL], &zero, &control, BPF_ANY)) return -errno;
	for (__u32 i = 0; i < 6; i++) {
		__u32 old;
		if (!bpf_map_lookup_elem(fds[TAILS], &i, &old)) return -ESTALE;
		if (errno != ENOENT) return -errno;
		if (bpf_map_update_elem(fds[TAILS], &i, &prog_fds[i], BPF_ANY)) return -errno;
		installed[i] = true;
	}
	snapshot_results = calloc(NN_CAPACITY, sizeof(*snapshot_results));
	if (trace_enabled)
		snapshot_traces = calloc(NN_CAPACITY, sizeof(*snapshot_traces));
	snapshot_has_trace = calloc(NN_CAPACITY, sizeof(*snapshot_has_trace));
	return snapshot_results && (!trace_enabled || snapshot_traces) && snapshot_has_trace ? 0 : -ENOMEM;
}
static int clear_map(int fd)
{
	struct nn_key key;
	while (!bpf_map_get_next_key(fd, NULL, &key))
		if (bpf_map_delete_elem(fd, &key)) return -errno;
	return errno == ENOENT ? 0 : -errno;
}
int nn_after_selftest(void)
{
	const int slots[] = { RX, JOBS, RESULTS, TRACES };
	struct nn_control control = {.trace = trace_enabled};
	__u32 zero = 0;
	int cpus = libbpf_num_possible_cpus(), result = 0;
	__u64 *values;
	if (cpus <= 0) return -EINVAL;
	values = calloc((size_t)cpus, sizeof(*values));
	if (!values) return -ENOMEM;
	for (size_t i = 0; !result && i < sizeof(slots)/sizeof(slots[0]); i++) result = clear_map(fds[slots[i]]);
	for (__u32 i = 0; !result && i < NN_COUNTER_COUNT; i++)
		if (bpf_map_update_elem(fds[COUNTS], &i, values, BPF_ANY)) result = -errno;
	if (!result && bpf_map_update_elem(fds[CONTROL], &zero, &control, BPF_ANY)) result = -errno;
	free(values);
	return result;
}
/* Called only after the controller has stopped GC and detached both primaries. */
int nn_clear_tails(void)
{
	int result = 0;
	for (__u32 i = 0; i < 6; i++) {
		__u32 id;
		if (!installed[i]) continue;
		if (bpf_map_lookup_elem(fds[TAILS], &i, &id)) {
			if (errno == ENOENT) { installed[i] = false; continue; }
			result = -errno; continue;
		}
		if (id != prog_ids[i]) { result = -ESTALE; continue; }
		if (bpf_map_delete_elem(fds[TAILS], &i)) result = -errno;
		else installed[i] = false;
	}
	free(snapshot_results); free(snapshot_traces); free(snapshot_has_trace);
	return result;
}
void nn_print_program_ids(void)
{
	for (int i = 0; i < NN_PROGRAM_COUNT; i++) printf(",\"%s\":%u", roles[i], prog_ids[i]);
}
void nn_print_map_ids(void)
{
	for (int i = 0; i < NN_MAP_COUNT; i++) printf(",\"%s\":%u", maps[i], ids[i]);
}
void nn_print_ready(void)
{
	printf(",\"backend\":\"inference\",\"nn_abi_version\":%d,\"feature_schema\":\"%s\","
	       "\"model_schema\":\"%s\",\"model_id\":\"%s\","
	       "\"quantization\":16,\"trace_enabled\":%s,"
	       "\"event_ring_bytes\":%u,\"event_schema_version\":%d,\"event_size\":%d",
	       NN_ABI_VERSION, NN_FEATURE_SCHEMA, NN_MODEL_SCHEMA, identity_text,
	       trace_enabled ? "true" : "false", event_ring_bytes,
	       NN_EVENT_SCHEMA_VERSION, NN_EVENT_BYTES);
}
static void print_ints(const __s32 *v, size_t n)
{
	putchar('[');
	for (size_t i = 0; i < n; i++) printf("%s%d", i ? "," : "", v[i]);
	putchar(']');
}
static void print_record(const struct nn_result *r, const struct nn_trace *t)
{
	putchar('{');
	nn_json_result(r);
	if (t) {
		printf(",\"stages\":{\"normalized\":"); print_ints(t->normalized, 6);
		printf(",\"input_linear\":"); print_ints(t->linear0, 32);
		printf(",\"input_relu\":"); print_ints(t->relu0, 32);
		printf(",\"hidden_linear\":"); print_ints(t->linear1, 32);
		printf(",\"hidden_relu\":"); print_ints(t->relu1, 32);
		printf(",\"output\":"); print_ints(t->output, 2); putchar('}');
	}
	/* caller appends native test-run evidence, then closes object */
}
int nn_prepare_snapshot(int cpus, __u64 *values)
{
	struct nn_key cursor, next;
	bool have = false;
	int result = 0;
	snapshot_count = 0;
	if (cpus <= 0) return -EINVAL;
	for (__u32 i = 0; i < NN_COUNTER_COUNT; i++) {
		snapshot_counts[i] = 0;
		if (bpf_map_lookup_elem(fds[COUNTS], &i, values)) return -errno;
		for (int c = 0; c < cpus; c++) snapshot_counts[i] += values[c];
	}
	for (size_t step = 0; step < NN_CAPACITY * 2U && snapshot_count < NN_CAPACITY; step++) {
		if (bpf_map_get_next_key(fds[RESULTS], have ? &cursor : NULL, &next)) {
			if (errno != ENOENT) result = -errno;
			break;
		}
		cursor = next; have = true;
		/* Flow ID zero belongs exclusively to native vector consumers. */
		if (!next.flow_id) continue;
		if (bpf_map_lookup_elem(fds[RESULTS], &next, &snapshot_results[snapshot_count])) {
			if (errno == ENOENT) continue;
			result = -errno; break;
		}
		snapshot_has_trace[snapshot_count] = false;
		if (trace_enabled) {
			int got = bpf_map_lookup_elem(fds[TRACES], &next, &snapshot_traces[snapshot_count]);
			if (got && errno != ENOENT) { result = -errno; break; }
			snapshot_has_trace[snapshot_count] = !got;
		}
		snapshot_count++;
	}
	return result;
}
void nn_print_snapshot(void)
{
	printf(",\"inference_results\":[");
	for (size_t i = 0; i < snapshot_count; i++) {
		if (i) putchar(',');
		print_record(&snapshot_results[i], snapshot_has_trace[i] ? &snapshot_traces[i] : NULL);
		putchar('}');
	}
	printf("],\"inference_counters\":{");
	for (int i = 0; i < NN_COUNTER_COUNT; i++)
		printf("%s\"%s\":%" PRIu64, i ? "," : "", counter_names[i], U64(snapshot_counts[i]));
	putchar('}');
}

static int parse_id(const char *text, __u32 *id)
{
	char *end;
	unsigned long n;
	if (!text[0] || strspn(text, "0123456789") != strlen(text)) return -EINVAL;
	errno = 0; n = strtoul(text, &end, 10);
	if (errno || *end || !n || n > UINT32_MAX) return -EINVAL;
	*id = n; return 0;
}
static __u64 now_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
	return (__u64)t.tv_sec * 1000000000ULL + (__u64)t.tv_nsec;
}
int nn_vectors(int argc, char **argv, const struct stat *ns)
{
	enum { VRESULT, VTRACE, VCONTROL, VSLOTS, VTAILS, VMAPS };
	const char *owner = NULL, *input = NULL;
	const char *options[VMAPS] = { "--results", "--traces", "--control", "--slots", "--tails" };
	const int expected[VMAPS] = { RESULTS, TRACES, CONTROL, SLOTS, TAILS };
	__u32 mapids[VMAPS] = {}, entryid, active = 0, tailid = 0, missing = 0;
	int mapfds[VMAPS] = {-1,-1,-1,-1,-1}, entryfd = -1, tailfd = -1, result = 0;
	int jobfd = -1;
	bool unready = false, have_missing = false, mutated = false;
	struct nn_slot saved_slot = {}, changed_slot = {};
	struct nn_control control;
	struct stat st;
	struct nn_result *records = NULL;
	struct nn_trace *traces = NULL;
	bool *have_trace = NULL, *restored = NULL;
	__u32 *retvals = NULL;
	__s64 *features = NULL;
	size_t count = 0, completed = 0, issued = 0;
	const struct nn_context_abi context = nn_kernel_context_abi();
	struct __sk_buff *after = NULL;
	__u64 started = now_ns(), elapsed;
	if (argc < 4 || parse_id(argv[1], &entryid)) return -EINVAL;
	for (int i = 4; i < argc; i++) {
		const char *opt = argv[i];
		if (!strcmp(opt, "--unready")) { if (unready) return -EINVAL; unready = true; continue; }
		if (++i == argc) return -EINVAL;
		if (!strcmp(opt, "--owner-pid")) { if (owner) return -EINVAL; owner = argv[i]; }
		else if (!strcmp(opt, "--input")) { if (input) return -EINVAL; input = argv[i]; }
		else if (!strcmp(opt, "--missing-slot")) {
			if (have_missing || strlen(argv[i]) != 1 || argv[i][0] < '0' || argv[i][0] > '5') return -EINVAL;
			missing = argv[i][0] - '0'; have_missing = true;
		} else {
			int j;
			for (j = 0; j < VMAPS; j++) if (!strcmp(opt, options[j])) break;
			if (j == VMAPS || mapids[j] || parse_id(argv[i], &mapids[j])) return -EINVAL;
		}
	}
	if (!owner || !input || (unready && have_missing)) return -EINVAL;
	result = private_owned_id(owner, ns, entryid, true);
	if (result) goto out;
	entryfd = bpf_prog_get_fd_by_id(entryid);
	if (entryfd < 0) { result = -errno; goto out; }
	{
		struct bpf_prog_info info = {};
		__u32 size = sizeof(info);
		if (bpf_prog_get_info_by_fd(entryfd, &info, &size)) { result = -errno; goto out; }
		if (info.type != BPF_PROG_TYPE_SCHED_CLS || strcmp((char *)info.name, "nn_vector")) { result = -EPERM; goto out; }
	}
	for (int i = 0; i < VMAPS; i++) {
		struct bpf_map_info info = {};
		__u32 size = sizeof(info);
		if (!mapids[i]) { result = -EINVAL; goto out; }
		result = private_owned_id(owner, ns, mapids[i], false);
		if (result) goto out;
		mapfds[i] = bpf_map_get_fd_by_id(mapids[i]);
		if (mapfds[i] < 0) { result = -errno; goto out; }
		if (bpf_map_get_info_by_fd(mapfds[i], &info, &size)) { result = -errno; goto out; }
		int e = expected[i];
		if (info.type != (__u32)types[e] || info.key_size != keys[e] ||
		    info.value_size != sizes[e] || info.max_entries != entries[e] ||
		    info.map_flags != map_flags[e] || strcmp((char *)info.name, maps[e])) { result = -EPERM; goto out; }
	}
	/* Prove actual entry-program bindings, not merely a bag of owner-held IDs. */
	{
		struct bpf_prog_info info = {};
		__u32 size = sizeof(info), bound[32];
		info.nr_map_ids = 32; info.map_ids = (__u64)(uintptr_t)bound;
		if (bpf_prog_get_info_by_fd(entryfd, &info, &size)) { result = -errno; goto out; }
		if (info.nr_map_ids > 32) { result = -E2BIG; goto out; }
		for (int i = 0; i < VMAPS; i++) {
			bool found = false;
			for (__u32 j = 0; j < info.nr_map_ids; j++) if (bound[j] == mapids[i]) found = true;
			if (!found) { result = -EPERM; goto out; }
		}
		for (__u32 i = 0; i < info.nr_map_ids; i++) {
			struct bpf_map_info map = {};
			__u32 map_size = sizeof(map);
			int fd = bpf_map_get_fd_by_id(bound[i]);
			if (fd < 0) { result = -errno; goto out; }
			if (bpf_map_get_info_by_fd(fd, &map, &map_size)) {
				result = -errno; close(fd); goto out;
			}
			if (!strcmp((char *)map.name, "nn_jobs")) {
				result = private_owned_id(owner, ns, bound[i], false);
				if (result || jobfd >= 0 || map.type != BPF_MAP_TYPE_HASH ||
				    map.key_size != 16 || map.value_size != sizeof(struct nn_job) ||
				    map.max_entries != NN_CAPACITY) {
					if (!result) result = -EPERM;
					close(fd); goto out;
				}
				jobfd = fd;
			} else close(fd);
		}
		if (jobfd < 0) { result = -EPERM; goto out; }
	}
	/* Installed UAPI headers can predate the running kernel's appended fields. */
	if (context.cb_offset != __builtin_offsetof(struct __sk_buff, cb) ||
	    context.size < context.cb_offset + sizeof(((struct __sk_buff *)0)->cb)) {
		result = -EPROTO; goto out;
	}
	after = calloc(1, context.size);
	if (!after) { result = -ENOMEM; goto out; }
	if (lstat(input, &st)) { result = -errno; goto out; }
	if (!S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size % 48 || st.st_size > 48 * 16384) { result = -EINVAL; goto out; }
	count = (size_t)st.st_size / 48;
	features = malloc((size_t)st.st_size); records = calloc(count, sizeof(*records));
	traces = calloc(count, sizeof(*traces)); have_trace = calloc(count, sizeof(*have_trace));
	restored = calloc(count, sizeof(*restored)); retvals = calloc(count, sizeof(*retvals));
	if (!features || !records || !traces || !have_trace || !restored || !retvals) { result = -ENOMEM; goto out; }
	result = read_regular(input, features, (size_t)st.st_size);
	if (result) goto out;
	{
		__u32 zero = 0;
		if (bpf_map_lookup_elem(mapfds[VCONTROL], &zero, &control)) { result = -errno; goto out; }
		active = control.active;
		if (active > 1 || bpf_map_lookup_elem(mapfds[VSLOTS], &active, &saved_slot)) { result = -EINVAL; goto out; }
		if (unready) {
			changed_slot = saved_slot; changed_slot.ready = 0;
			if (bpf_map_update_elem(mapfds[VSLOTS], &active, &changed_slot, BPF_ANY)) { result = -errno; goto out; }
			mutated = true;
		}
		if (have_missing) {
			if (bpf_map_lookup_elem(mapfds[VTAILS], &missing, &tailid)) { result = -errno; goto out; }
			result = private_owned_id(owner, ns, tailid, true);
			if (result) goto out;
			tailfd = bpf_prog_get_fd_by_id(tailid);
			if (tailfd < 0) { result = -errno; goto out; }
			{
				struct bpf_prog_info info = {};
				__u32 size = sizeof(info);
				if (bpf_prog_get_info_by_fd(tailfd, &info, &size)) { result = -errno; goto out; }
				if (info.type != BPF_PROG_TYPE_SCHED_CLS ||
				    strcmp((char *)info.name, programs[missing])) { result = -ESTALE; goto out; }
			}
			if (bpf_map_delete_elem(mapfds[VTAILS], &missing)) { result = -errno; goto out; }
			mutated = true;
		}
	}
	for (size_t i = 0; i < count; i++) {
		struct nn_vector_input request = {
			.key = { 0, started + i },
		};
		struct __sk_buff before = {};
		unsigned char packet_out[128];
		struct bpf_test_run_opts opts = {
			.sz = sizeof(opts), .data_in = &request, .data_size_in = sizeof(request),
			.data_out = packet_out, .data_size_out = sizeof(packet_out),
			.ctx_in = &before, .ctx_size_in = sizeof(before),
			.ctx_out = after, .ctx_size_out = context.size, .repeat = 1,
		};
		memcpy(request.features, features + i * 6, 48);
		for (int c = 0; c < 5; c++) before.cb[c] = 0x9a000000U + (__u32)c;
		struct nn_result existing;
		if (!bpf_map_lookup_elem(mapfds[VRESULT], &request.key, &existing) || errno != ENOENT) { result = -EEXIST; break; }
		struct nn_trace existing_trace;
		if (!bpf_map_lookup_elem(mapfds[VTRACE], &request.key, &existing_trace) || errno != ENOENT) { result = -EEXIST; break; }
		issued = i + 1;
		result = bpf_prog_test_run_opts(entryfd, &opts);
		if (result) { result = result < 0 ? result : -errno; break; }
		retvals[i] = opts.retval;
		restored[i] = opts.ctx_size_out == context.size && !memcmp(before.cb, after->cb, sizeof(before.cb));
		struct nn_job remaining;
		if (!bpf_map_lookup_elem(jobfd, &request.key, &remaining) || errno != ENOENT) {
			result = -EUCLEAN; break;
		}
		if (bpf_map_lookup_elem(mapfds[VRESULT], &request.key, &records[i])) { result = -errno; break; }
		have_trace[i] = !bpf_map_lookup_elem(mapfds[VTRACE], &request.key, &traces[i]);
		if (!have_trace[i] && errno != ENOENT) { result = -errno; break; }
		/* Consume only the unique key generated by this utility invocation. */
		if (bpf_map_delete_elem(mapfds[VRESULT], &request.key)) { result = -errno; break; }
		if (have_trace[i] && bpf_map_delete_elem(mapfds[VTRACE], &request.key)) { result = -errno; break; }
		completed++;
	}
out:
	for (size_t i = 0; i < issued; i++) {
		struct nn_key key = { 0, started + i };
		if (bpf_map_delete_elem(mapfds[VRESULT], &key) && errno != ENOENT) result = -errno;
		if (bpf_map_delete_elem(mapfds[VTRACE], &key) && errno != ENOENT) result = -errno;
		if (bpf_map_delete_elem(jobfd, &key) && errno != ENOENT) result = -errno;
	}
	if (mutated && unready) {
		struct nn_slot current;
		if (bpf_map_lookup_elem(mapfds[VSLOTS], &active, &current)) result = -errno;
		else if (memcmp(&current, &changed_slot, sizeof(current))) result = -ESTALE;
		else if (bpf_map_update_elem(mapfds[VSLOTS], &active, &saved_slot, BPF_ANY)) result = -errno;
	}
	if (mutated && have_missing) {
		__u32 current;
		if (!bpf_map_lookup_elem(mapfds[VTAILS], &missing, &current)) result = -ESTALE;
		else if (errno != ENOENT) result = -errno;
		else if (bpf_map_update_elem(mapfds[VTAILS], &missing, &tailfd, BPF_ANY)) result = -errno;
	}
	elapsed = now_ns() - started;
	if (!result && completed == count) {
		printf("{\"schema_version\":1,\"vectors\":[");
		for (size_t i = 0; i < count; i++) {
			if (i) putchar(',');
			print_record(&records[i], have_trace[i] ? &traces[i] : NULL);
			printf(",\"retval\":%u,\"cb_restored\":%s}", retvals[i], restored[i] ? "true" : "false");
		}
		printf("],\"count\":%zu,\"elapsed_ns\":%" PRIu64 ",\"owned_keys_removed\":true,\"slots_restored\":true,"
		       "\"kernel_context_bytes\":%u,\"userspace_context_bytes\":%zu}\n",
		       count, U64(elapsed), context.size, sizeof(struct __sk_buff));
	}
	for (int i = 0; i < VMAPS; i++) if (mapfds[i] >= 0) close(mapfds[i]);
	if (entryfd >= 0) close(entryfd);
	if (tailfd >= 0) close(tailfd);
	if (jobfd >= 0) close(jobfd);
	free(features); free(records); free(traces); free(have_trace); free(restored); free(retvals);
	free(after);
	return result;
}

/* An ID cannot become live again after Flow deletion. Also collect RX creation
 * racing tombstoning between the Flow and RX pre-lock lookups. */
int nn_prune_rx(int stats_fd)
{
	__u64 cursor = 0, next;
	bool have = false;
	for (size_t step = 0; step < NN_CAPACITY * 2U; step++) {
		struct flow_value value;
		if (bpf_map_get_next_key(fds[RX], have ? &cursor : NULL, &next))
			return errno == ENOENT ? 0 : -errno;
		cursor = next; have = true;
		if (!bpf_map_lookup_elem_flags(stats_fd, &next, &value, BPF_F_LOCK)) continue;
		if (errno != ENOENT) return -errno;
		if (bpf_map_delete_elem(fds[RX], &next) && errno != ENOENT) return -errno;
	}
	return 0;
}
