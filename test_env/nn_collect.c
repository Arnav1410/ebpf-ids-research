#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <linux/nsfs.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "private_scope.h"
#include "flow_controller.h"
#include "nn_json.h"
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__ || !defined(__x86_64__)
#error nn event ABI requires little-endian x64
#endif
#define U64(x) ((uint64_t)(x))
#define FLOW_LIMIT 32U
_Static_assert(sizeof(struct nn_event) == NN_EVENT_BYTES, "event ABI");
_Static_assert(sizeof(struct nn_result) == 152, "result ABI");
enum { RING, COUNTERS, SEQUENCE, SLOTS, CONTROL, HOOKS, FLOWS, MAP_COUNT };
static const char *const names[MAP_COUNT] = {
	"nn_events", "nn_counts", "nn_event_seq", "nn_slots", "nn_control", "hook_counts", "flow_stats" };
static const char *const source_names[MAP_COUNT] = {
	"ring_map_id", "counters_map_id", "sequence_map_id", "slots_map_id", "control_map_id", "hook_counts_map_id", "flow_stats_map_id" };
static const enum bpf_map_type types[MAP_COUNT] = {
	BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_HASH };
static const __u32 keys[MAP_COUNT] = {0,4,4,4,4,4,8};
static const __u32 sizes[MAP_COUNT] = {0,8,8,40,16,8,208};
static const __u32 entries[MAP_COUNT] = {0,NN_COUNTER_COUNT,1,2,1,2,FLOW_CAPACITY};
static const char *const counter_names[NN_COUNTER_COUNT] = {
	"trigger","complete","unready","job_full","tail_missing","bad_params",
	"trace_full","result_full","rx_full","missing_job","bad_stage",
	"event_emitted","event_dropped","event_missing_counts" };
struct reader {
	struct private_scope scope;
	int namespace_fd, lock_fd, fds[MAP_COUNT], cpus;
	__u32 ids[MAP_COUNT], owner_pid, ring_bytes;
	const char *owner, *model_id;
	__u8 identity[32];
	struct ring_buffer *ring;
	__u64 *cpu_values;
	__u64 flow_keys[FLOW_CAPACITY];
	struct flow_value flow_values[FLOW_LIMIT + 1];
	__u64 decode_errors;
	unsigned int errors;
};
static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static void json_string(const char *text)
{
	const unsigned char *p = (const unsigned char *)text;
	putchar('"');
	for (; *p; p++) {
		if (*p == '"' || *p == '\\') printf("\\%c", *p);
		else if (*p < 0x20 || *p >= 0x7f) printf("\\u%04x", *p);
		else putchar(*p);
	}
	putchar('"');
}
static void prefix(const struct reader *r, const char *event)
{
	printf("{\"schema_version\":1,\"event\":\"%s\",\"mode\":\"live\",\"clock\":\"monotonic\","
	       "\"source\":{\"owner_pid\":%u", event, r->owner_pid);
	for (int i = 0; i < MAP_COUNT; i++) printf(",\"%s\":%u", source_names[i], r->ids[i]);
	printf(",\"model_id\":"); json_string(r->model_id ? r->model_id : "");
	putchar('}');
}
static void error_event(struct reader *r, const char *stage, int code)
{
	if (code < 0) code = -code;
	if (!code) code = EIO;
	r->errors++;
	fprintf(stderr, "%s: %s\n", stage, strerror(code));
	prefix(r, "error");
	printf(",\"stage\":"); json_string(stage);
	printf(",\"errno\":%d,\"message\":", code); json_string(strerror(code));
	printf("}\n");
}
static int parse_id(const char *s, __u32 *id)
{
	char *end;
	unsigned long n;
	if (!s[0] || strspn(s, "0123456789") != strlen(s)) return -EINVAL;
	errno = 0; n = strtoul(s, &end, 10);
	if (errno || *end || !n || n > UINT32_MAX) return -EINVAL;
	*id = n;
	return 0;
}
static int arguments(struct reader *r, int argc, char **argv)
{
	if (argc < 4 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE) ||
	    parse_id(argv[1], &r->ids[RING])) return -EINVAL;
	for (int i = 4; i < argc; i += 2) {
		int slot = -1;
		if (i + 1 == argc) return -EINVAL;
		if (!strcmp(argv[i], "--owner-pid")) {
			if (r->owner || parse_id(argv[i+1], &r->owner_pid) || r->owner_pid > INT_MAX) return -EINVAL;
			r->owner = argv[i+1]; continue;
		}
		if (!strcmp(argv[i], "--model-id")) {
			if (r->model_id) return -EINVAL;
			r->model_id = argv[i+1]; continue;
		}
		if (!strcmp(argv[i], "--counters")) slot = COUNTERS;
		else if (!strcmp(argv[i], "--sequence")) slot = SEQUENCE;
		else if (!strcmp(argv[i], "--slots")) slot = SLOTS;
		else if (!strcmp(argv[i], "--control")) slot = CONTROL;
		else if (!strcmp(argv[i], "--hook-counts")) slot = HOOKS;
		else if (!strcmp(argv[i], "--flow-stats")) slot = FLOWS;
		if (slot < 0 || r->ids[slot] || parse_id(argv[i+1], &r->ids[slot])) return -EINVAL;
	}
	if (!r->owner || !r->model_id || strlen(r->model_id) != 64 ||
	    strspn(r->model_id, "0123456789abcdef") != 64) return -EINVAL;
	for (int i = 0; i < MAP_COUNT; i++) if (!r->ids[i]) return -EINVAL;
	for (int i = 0; i < 32; i++) {
		unsigned int byte;
		char text[3] = {r->model_id[2*i], r->model_id[2*i+1], 0};
		if (sscanf(text, "%x", &byte) != 1) return -EINVAL;
		r->identity[i] = byte;
	}
	return 0;
}
static int owned_maps(struct reader *r, bool open_maps)
{
	for (int i = 0; i < MAP_COUNT; i++) {
		struct bpf_get_fd_by_id_opts opts = {
			.sz = sizeof(opts), .open_flags = i == RING ? 0 : BPF_F_RDONLY,
		};
		struct bpf_map_info info = {};
		__u32 bytes = sizeof(info);
		int result = private_owned_id(r->owner, &r->scope.namespace_identity, r->ids[i], false);
		if (result) return result;
		if (!open_maps) continue;
		/* Ring consumer-page mmap needs a writable FD. All metadata FDs are
		 * read-only; the reader never performs a BPF map update/delete. */
		r->fds[i] = bpf_map_get_fd_by_id_opts(r->ids[i], &opts);
		if (r->fds[i] < 0) return -errno;
		if (bpf_map_get_info_by_fd(r->fds[i], &info, &bytes)) return -errno;
		if (strcmp(info.name, names[i]) || info.type != types[i] || info.id != r->ids[i] ||
		    info.key_size != keys[i] || info.value_size != sizes[i] || info.map_flags ||
		    (i != RING && info.max_entries != entries[i])) return -EINVAL;
		if (i == RING) {
			if (info.max_entries < NN_EVENT_RING_MIN_BYTES || info.max_entries > NN_EVENT_RING_BYTES ||
			    (info.max_entries & (info.max_entries - 1)) ||
			    info.max_entries % (unsigned long)sysconf(_SC_PAGESIZE)) return -EINVAL;
			r->ring_bytes = info.max_entries;
		}
	}
	return 0;
}
static int model_binding(struct reader *r)
{
	struct nn_control before, after;
	struct nn_slot slot;
	__u32 zero = 0;
	if (bpf_map_lookup_elem(r->fds[CONTROL], &zero, &before)) return -errno;
	if (before.active > 1) return -EINVAL;
	if (bpf_map_lookup_elem(r->fds[SLOTS], &before.active, &slot) ||
	    bpf_map_lookup_elem(r->fds[CONTROL], &zero, &after)) return -errno;
	if (memcmp(&before, &after, sizeof(before)) || slot.ready != 1 || slot.reserved ||
	    memcmp(slot.identity, r->identity, sizeof(slot.identity))) return -ESTALE;
	return 0;
}
static int single_reader(struct reader *r)
{
	struct sockaddr_un address = {.sun_family = AF_UNIX};
	int length;
	r->lock_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (r->lock_fd < 0) return -errno;
	/* Abstract socket lifetime is exactly this FD's lifetime, within the
	 * validated private netns. No pathname, symlink, stale PID file or unlink. */
	length = snprintf(address.sun_path + 1, sizeof(address.sun_path) - 1,
			  "nn-collect:%u:%u", r->owner_pid, r->ids[RING]);
	if (length < 0 || (size_t)length >= sizeof(address.sun_path) - 1) return -EOVERFLOW;
	if (bind(r->lock_fd, (struct sockaddr *)&address,
		 offsetof(struct sockaddr_un, sun_path) + 1 + length)) return -errno;
	return 0;
}
static int decode(void *context, void *data, size_t size)
{
	struct reader *r = context;
	const struct nn_event *e = data;
	const struct nn_result *v;
	static const char *const directions[2] = {"a_to_b", "b_to_a"};
	static const char *const counts[4] = {"packets", "ipv4_bytes", "tcp_segment_bytes", "tcp_header_bytes"};
	if (size != sizeof(*e) || e->version != NN_EVENT_SCHEMA_VERSION || e->size != sizeof(*e) ||
	    e->endian != NN_EVENT_ENDIAN) goto invalid;
	v = &e->result;
	if (!e->sequence || !v->key.flow_id || !v->key.trigger_ordinal ||
	    v->status > NN_BAD_STAGE || v->slot > 1 || v->trigger_flags > 255 || !(v->trigger_flags & 5) ||
	    v->tuple.ifindex != (__u32)r->scope.ifindex || v->tuple.protocol != 6 ||
	    e->counts_valid > 1 ||
	    (!v->status && (memcmp(v->identity, r->identity, 32) || v->stage_bitmap != 63 || v->label > 1)) ||
	    (e->counts_valid && (e->counts_ordinal < v->key.trigger_ordinal ||
	     e->counts_timestamp_ns < v->timestamp_ns || e->flow_state > FLOW_REPLACED))) goto invalid;
	prefix(r, "classification");
	printf(",\"event_schema_version\":%d,\"sequence\":%" PRIu64 ",", NN_EVENT_SCHEMA_VERSION, U64(e->sequence));
	nn_json_result(v);
	printf(",\"reason\":\"%s\",\"counts_ordinal\":%" PRIu64 ",\"counts_timestamp_ns\":%" PRIu64
	       ",\"flow_state\":%u,\"counts_valid\":%s,\"direction_counts\":{",
	       (v->trigger_flags & 5) == 5 ? "fin_rst" : (v->trigger_flags & 4) ? "rst" : "fin",
	       U64(e->counts_ordinal), U64(e->counts_timestamp_ns), e->flow_state,
	       e->counts_valid ? "true" : "false");
	for (int d = 0; d < 2; d++) {
		printf("%s\"%s\":{", d ? "," : "", directions[d]);
		for (int c = 0; c < 4; c++) printf("%s\"%s\":%" PRIu64, c ? "," : "", counts[c], U64(e->direction_counts[d][c]));
		putchar('}');
	}
	printf("}}\n");
	return ferror(stdout) ? -EPIPE : 0;
invalid:
	r->decode_errors++;
	error_event(r, "event decode", EPROTO);
	return ferror(stdout) ? -EPIPE : 0;
}
static int sum_counter(struct reader *r, int fd, __u32 key, __u64 *sum)
{
	*sum = 0;
	if (bpf_map_lookup_elem(fd, &key, r->cpu_values)) return -errno;
	for (int c = 0; c < r->cpus; c++) *sum += r->cpu_values[c];
	return 0;
}
static int counters(struct reader *r, const char *event)
{
	__u64 counts[NN_COUNTER_COUNT], hooks[2], sequence;
	__u32 zero = 0;
	size_t total;
	uint64_t start = now_ns();
	int result;
	for (__u32 i = 0; i < NN_COUNTER_COUNT; i++) {
		result = sum_counter(r, r->fds[COUNTERS], i, &counts[i]);
		if (result) return result;
	}
	for (__u32 i = 0; i < 2; i++) {
		result = sum_counter(r, r->fds[HOOKS], i, &hooks[i]);
		if (result) return result;
	}
	if (bpf_map_lookup_elem(r->fds[SEQUENCE], &zero, &sequence)) return -errno;
	result = flow_bounded_snapshot(r->fds[FLOWS], r->flow_keys, r->flow_values, FLOW_LIMIT, &total);
	if (result) return result;
	prefix(r, event);
	printf(",\"timestamp_ns\":%" PRIu64 ",\"snapshot_ns\":%" PRIu64 ",\"snapshot_end_ns\":%" PRIu64
	       ",\"sequence\":%" PRIu64 ",\"reader_decode_errors\":%" PRIu64 ",\"inference_counters\":{",
	       now_ns(), start, now_ns(), U64(sequence), U64(r->decode_errors));
	for (int i = 0; i < NN_COUNTER_COUNT; i++) printf("%s\"%s\":%" PRIu64, i ? "," : "", counter_names[i], U64(counts[i]));
	printf("},\"hook_counts\":{\"ingress\":%" PRIu64 ",\"egress\":%" PRIu64
	       "},\"flow_limit\":%u,\"flows_total\":%zu,\"flows_truncated\":%s",
	       U64(hooks[0]), U64(hooks[1]), FLOW_LIMIT, total, total > FLOW_LIMIT ? "true" : "false");
	flow_print_rows(r->flow_keys, r->flow_values, total < FLOW_LIMIT ? total : FLOW_LIMIT);
	if (!strcmp(event, "stopped")) printf(",\"errors\":%u", r->errors);
	printf("}\n");
	return ferror(stdout) ? -EPIPE : 0;
}
int main(int argc, char **argv)
{
	struct reader r = {.namespace_fd = -1, .lock_fd = -1};
	sigset_t signals;
	struct timespec no_wait = {};
	uint64_t last_snapshot = 0;
	bool ready = false;
	int result, received;
	for (int i = 0; i < MAP_COUNT; i++) r.fds[i] = -1;
	setvbuf(stdout, NULL, _IOLBF, 0);
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT); sigaddset(&signals, SIGTERM); sigaddset(&signals, SIGUSR1);
	result = pthread_sigmask(SIG_BLOCK, &signals, NULL);
	if (result) { error_event(&r, "signal mask", result); goto out; }
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) { error_event(&r, "stdout signal handling", errno); goto out; }
	result = arguments(&r, argc, argv);
	if (result) { error_event(&r, "usage: nn-collect RING_ID veth-idss /run/netns/ids_server --owner-pid PID --model-id SHA --counters ID --sequence ID --slots ID --control ID --hook-counts ID --flow-stats ID", result); goto out; }
	r.namespace_fd = open(LAB_NAMESPACE, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (r.namespace_fd < 0) { error_event(&r, "namespace open", errno); goto out; }
	if (fstat(r.namespace_fd, &r.scope.namespace_identity)) { error_event(&r, "namespace identity", errno); goto out; }
	result = ioctl(r.namespace_fd, NS_GET_NSTYPE);
	if (result != CLONE_NEWNET) { error_event(&r, "namespace type", result < 0 ? errno : EPERM); goto out; }
	result = private_check_scope(&r.scope, true);
	if (result) { error_event(&r, "private scope", result); goto out; }
	result = owned_maps(&r, true);
	if (result) { error_event(&r, "FD-proven map ownership", result); goto out; }
	result = model_binding(&r);
	if (result) { error_event(&r, "active ready model binding", result); goto out; }
	result = single_reader(&r);
	if (result) { error_event(&r, "single reader lock", result); goto out; }
	r.cpus = libbpf_num_possible_cpus();
	if (r.cpus <= 0) { error_event(&r, "possible CPUs", EINVAL); goto out; }
	r.cpu_values = calloc((size_t)r.cpus, sizeof(*r.cpu_values));
	if (!r.cpu_values) { error_event(&r, "counter storage", ENOMEM); goto out; }
	r.ring = ring_buffer__new(r.fds[RING], decode, &r, NULL);
	if (!r.ring) { error_event(&r, "ring consumer", errno); goto out; }
	/* Revalidate after acquiring all resources, before advertising readiness. */
	result = private_check_scope(&r.scope, false);
	if (!result) result = owned_maps(&r, false);
	if (!result) result = model_binding(&r);
	if (result) { error_event(&r, "ready source binding", result); goto out; }
	prefix(&r, "ready");
	printf(",\"nn_abi_version\":%d,\"event_schema_version\":%d,\"event_size\":%d,\"event_ring_bytes\":%u,"
	       "\"feature_schema\":\"%s\",\"model_schema\":\"%s\",\"quantization\":16,\"ifindex\":%d}\n",
	       NN_ABI_VERSION, NN_EVENT_SCHEMA_VERSION, NN_EVENT_BYTES, r.ring_bytes, NN_FEATURE_SCHEMA, NN_MODEL_SCHEMA, r.scope.ifindex);
	ready = true;
	for (;;) {
		/* Signals remain blocked (including inherited masks): finite polling
		 * plus sigtimedwait, not an EINTR-dependent shutdown handler. */
		received = sigtimedwait(&signals, NULL, &no_wait);
		if (received == SIGINT || received == SIGTERM) break;
		if (received < 0 && errno != EAGAIN && errno != EINTR) { error_event(&r, "signal wait", errno); break; }
		if (received == SIGUSR1 || now_ns() - last_snapshot >= 1000000000ULL) {
			result = private_check_scope(&r.scope, false);
			if (!result) result = owned_maps(&r, false);
			if (!result) result = model_binding(&r);
			if (!result) result = counters(&r, "source_counters");
			if (result) { error_event(&r, "source counters/binding", result); break; }
			last_snapshot = now_ns();
		}
		result = ring_buffer__poll(r.ring, 100);
		if (result < 0 && result != -EINTR) { error_event(&r, "ring poll", result); break; }
		if (ferror(stdout)) { error_event(&r, "stdout", EPIPE); break; }
	}
	if (ready) {
		result = counters(&r, "stopped");
		if (result) error_event(&r, "final source counters", result);
	}
out:
	ring_buffer__free(r.ring);
	for (int i = 0; i < MAP_COUNT; i++) if (r.fds[i] >= 0) close(r.fds[i]);
	if (r.lock_fd >= 0) close(r.lock_fd);
	if (r.namespace_fd >= 0) close(r.namespace_fd);
	free(r.cpu_values);
	return r.errors || ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
}
