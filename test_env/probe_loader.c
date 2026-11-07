#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <linux/nsfs.h>
#include <linux/rtnetlink.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#ifdef FLOW_BACKEND
#include "flow_controller.h"
#endif
#ifdef NN_BACKEND
#include "nn_controller.h"
#endif
#include "private_scope.h"

#define FILTER_HANDLE 1
#define FILTER_PRIORITY 49152
#define MAX_ERRORS 32

struct loader {
	struct bpf_object *object;
	struct bpf_program *programs[2];
	int program_fds[2];
	int map_fd;
	__u32 program_ids[2];
	__u32 map_id;
	bool attached[2];
	bool qdisc_created;
	int ifindex;
	int peer_ifindex;
	unsigned char mac[6];
	int namespace_fd;
	struct stat namespace_identity;
	int cpu_count;
	__u64 *cpu_values;
	uint64_t stats_sequence;
	unsigned int error_count;
	char errors[MAX_ERRORS][256];
#ifdef FLOW_BACKEND
	struct flow_controller flow;
#endif
};

static const char *const directions[2] = { "ingress", "egress" };
#ifdef FLOW_BACKEND
static const char *const program_names[2] = { "flow_ingress", "flow_egress" };
#else
static const char *const program_names[2] = { "probe_ingress", "probe_egress" };
#endif
static const enum bpf_tc_attach_point attach_points[2] = {
	BPF_TC_INGRESS, BPF_TC_EGRESS,
};

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
	(void)level;
	return vfprintf(stderr, format, args);
}

static void json_string(const char *text)
{
	const unsigned char *p = (const unsigned char *)text;

	putchar('"');
	for (; *p; p++) {
		if (*p == '"' || *p == '\\')
			printf("\\%c", *p);
		else if (*p < 0x20 || *p >= 0x7f)
			printf("\\u%04x", *p);
		else
			putchar(*p);
	}
	putchar('"');
}

static void error_event(struct loader *state, const char *stage, int code)
{
	char message[256];

	if (code < 0)
		code = -code;
	if (!code)
		code = EIO;
	snprintf(message, sizeof(message), "%s: %s", stage, strerror(code));
	if (state->error_count < MAX_ERRORS)
		snprintf(state->errors[state->error_count], sizeof(state->errors[0]), "%s", message);
	state->error_count++;
	fprintf(stderr, "%s\n", message);
	printf("{\"schema_version\":1,\"event\":\"error\",\"stage\":");
	json_string(stage);
	printf(",\"errno\":%d,\"message\":", code);
	json_string(message);
	printf("}\n");
	fflush(stdout);
}


static int check_scope(struct loader *state, bool capture)
{
	struct private_scope scope = {
		.ifindex = state->ifindex, .peer_ifindex = state->peer_ifindex,
		.namespace_identity = state->namespace_identity,
	};
	int result;
	memcpy(scope.mac, state->mac, sizeof(scope.mac));
	result = private_check_scope(&scope, capture);
	if (!result && capture) {
		state->ifindex = scope.ifindex;
		state->peer_ifindex = scope.peer_ifindex;
		memcpy(state->mac, scope.mac, sizeof(state->mac));
	}
	return result;
}

static int snapshot(struct loader *state, uint64_t counts[2])
{
	__u32 key;
	int cpu;

	for (key = 0; key < 2; key++) {
		counts[key] = 0;
		if (bpf_map_lookup_elem(state->map_fd, &key, state->cpu_values))
			return -errno;
		for (cpu = 0; cpu < state->cpu_count; cpu++)
			counts[key] += state->cpu_values[cpu];
	}
	return 0;
}

static int selftest(struct loader *state)
{
	/* Ethernet + IPv4 + TCP SYN, including valid IP/TCP checksums and padding. */
	static const unsigned char packet[60] = {
		0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00,
		0x45, 0, 0, 0x28, 0, 1, 0x40, 0, 0x40, 0x06, 0xb6, 0x43,
		0x21, 0x21, 0x21, 0x49, 0x21, 0x21, 0x21, 0x01,
		0x30, 0x39, 0x1f, 0x90, 0, 0, 0, 1, 0, 0, 0, 0,
		0x50, 0x02, 0xff, 0xff, 0xdb, 0x8c, 0, 0,
	};
	uint64_t counts[2];
	int result, direction;

	result = snapshot(state, counts);
	if (result)
		return result;
	if (counts[0] || counts[1])
		return -EUCLEAN;
	for (direction = 0; direction < 2; direction++) {
		struct bpf_test_run_opts options = {
			.sz = sizeof(options),
			.data_in = packet,
			.data_size_in = sizeof(packet),
			.repeat = 1,
		};

		result = bpf_prog_test_run_opts(state->program_fds[direction], &options);
		if (result)
			return result;
		if (options.retval != 0) /* TC_ACT_OK */
			return -EPROTO;
		result = snapshot(state, counts);
		if (result)
			return result;
		if (counts[0] != 1 || counts[1] != (uint64_t)direction)
			return -EUCLEAN;
	}
	return 0;
}

static void collect_ids(struct loader *state)
{
	struct bpf_map_info map = {};
	__u32 size;
	int direction;

	if (state->map_fd >= 0) {
		size = sizeof(map);
		if (bpf_map_get_info_by_fd(state->map_fd, &map, &size))
			error_event(state, "map identity", errno);
		else
			state->map_id = map.id;
	}
	for (direction = 0; direction < 2; direction++) {
		struct bpf_prog_info program = {};

		if (state->program_fds[direction] < 0)
			continue;
		size = sizeof(program);
		if (bpf_prog_get_info_by_fd(state->program_fds[direction], &program, &size))
			error_event(state, program_names[direction], errno);
		else
			state->program_ids[direction] = program.id;
	}
#ifdef FLOW_BACKEND
	{
		int result = flow_collect_ids(&state->flow, state->object);
		if (result)
			error_event(state, "flow object identity", result);
	}
#endif
#ifdef NN_BACKEND
	{
		int result = nn_collect_ids(state->object);
		if (result)
			error_event(state, "inference object identity", result);
	}
#endif
}

static int load_object(struct loader *state, const char *path)
{
	struct bpf_program *program;
	struct bpf_map *map, *counts;
	int direction, result, programs = 0, maps = 0;

	state->object = bpf_object__open_file(path, NULL);
	result = (int)libbpf_get_error(state->object);
	if (result) {
		state->object = NULL;
		return result;
	}
	bpf_object__for_each_program(program, state->object)
		programs++;
	bpf_object__for_each_map(map, state->object)
		maps++;
#ifdef NN_BACKEND
	if (programs != 3 + NN_PROGRAM_COUNT || maps != FLOW_MAP_COUNT + NN_MAP_COUNT ||
	    flow_validate_object(state->object) || nn_validate_object(state->object))
		return -EINVAL;
#elif defined(FLOW_BACKEND)
	if (programs != 3 || maps != FLOW_MAP_COUNT || flow_validate_object(state->object))
		return -EINVAL;
#else
	if (programs != 2 || maps != 1)
		return -EINVAL;
#endif
	counts = bpf_object__find_map_by_name(state->object, "hook_counts");
	if (!counts || bpf_map__type(counts) != BPF_MAP_TYPE_PERCPU_ARRAY ||
	    bpf_map__max_entries(counts) != 2 || bpf_map__key_size(counts) != sizeof(__u32) ||
	    bpf_map__value_size(counts) != sizeof(__u64) || bpf_map__pin_path(counts))
		return -EINVAL;
	for (direction = 0; direction < 2; direction++) {
		state->programs[direction] = bpf_object__find_program_by_name(
			state->object, program_names[direction]);
		if (!state->programs[direction] ||
		    bpf_program__type(state->programs[direction]) != BPF_PROG_TYPE_SCHED_CLS)
			return -EINVAL;
	}
	result = bpf_object__load(state->object);
	state->map_fd = bpf_map__fd(counts);
	for (direction = 0; direction < 2; direction++)
		state->program_fds[direction] = bpf_program__fd(state->programs[direction]);
	collect_ids(state);
	if (result)
		return result;
	if (state->error_count || !state->map_id || !state->program_ids[0] ||
	    !state->program_ids[1])
		return -EIO;
#ifdef FLOW_BACKEND
	result = flow_prepare(&state->flow, state->object);
	if (result)
		return result;
#ifdef NN_BACKEND
	return nn_prepare(state->object);
#endif
#endif
	return 0;
}

static void print_ids(const struct loader *state)
{
	printf("\"program_ids\":{\"ingress\":%u,\"egress\":%u",
	       state->program_ids[0], state->program_ids[1]);
#ifdef FLOW_BACKEND
	flow_print_ids(&state->flow);
#else
	printf("},\"map_ids\":{\"hook_counts\":%u}", state->map_id);
#endif
}

static bool detach_filters(struct loader *state)
{
	bool complete = true;
	int direction;

	for (direction = 0; direction < 2; direction++) {
		struct bpf_tc_hook hook = {
			.sz = sizeof(hook),
			.ifindex = state->ifindex,
			.attach_point = attach_points[direction],
		};
		struct bpf_tc_opts query = {
			.sz = sizeof(query),
			.handle = FILTER_HANDLE,
			.priority = FILTER_PRIORITY,
		};
		/* Query outputs must NOT be reused as libbpf detach inputs. */
		struct bpf_tc_opts detach = {
			.sz = sizeof(detach),
			.handle = FILTER_HANDLE,
			.priority = FILTER_PRIORITY,
		};
		int result;

		if (!state->attached[direction])
			continue;
		result = check_scope(state, false);
		if (result) {
			error_event(state, "detach scope identity", result);
			complete = false;
			continue;
		}
		result = bpf_tc_query(&hook, &query);
		if (result == -ENOENT) {
			state->attached[direction] = false;
			continue;
		}
		if (result || query.prog_id != state->program_ids[direction]) {
			error_event(state, directions[direction], result ? result : -ESTALE);
			complete = false;
			continue;
		}
		result = bpf_tc_detach(&hook, &detach);
		if (result) {
			error_event(state, "filter detach", result);
			complete = false;
		} else {
			state->attached[direction] = false;
		}
	}
	return complete;
}

int main(int argc, char **argv)
{
	struct loader state = {
		.program_fds = { -1, -1 }, .map_fd = -1, .namespace_fd = -1,
	};
	struct bpf_tc_hook hook = { .sz = sizeof(hook) };
	sigset_t signals;
	bool detached;
	int result, direction;
	unsigned int error;

#ifdef FLOW_BACKEND
	flow_controller_init(&state.flow);
#endif
	libbpf_set_print(libbpf_log);
	setvbuf(stdout, NULL, _IOLBF, 0);
	/* Block before loading/attaching so early stop/stat requests cannot be lost. */
	sigemptyset(&signals);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, SIGUSR1);
	result = pthread_sigmask(SIG_BLOCK, &signals, NULL);
	if (result) {
		error_event(&state, "signal mask", result);
		goto cleanup;
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		error_event(&state, "stdout signal handling", errno);
		goto cleanup;
	}
#ifdef FLOW_INSPECT
	if (argc != 6 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE) ||
	    strcmp(argv[4], "--owner-pid")) {
		error_event(&state, "usage: flow-inspect MAP_ID veth-idss /run/netns/ids_server "
			    "--owner-pid LOADER_PID", EINVAL);
		goto cleanup;
	}
#elif defined(NN_VECTORS)
	if (argc < 4 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE)) {
		error_event(&state, "usage: nn-vectors ENTRY_ID veth-idss /run/netns/ids_server "
			    "--owner-pid PID --results ID --traces ID --control ID --slots ID "
			    "--tails ID --input FILE [--unready | --missing-slot N]", EINVAL);
		goto cleanup;
	}
#elif defined(NN_BACKEND)
	if (argc < 4 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE) ||
	    nn_arguments(&state.flow, argc, argv)) {
		error_event(&state, "usage: nn-loader OBJECT veth-idss /run/netns/ids_server "
			    "--params FILE --model-id SHA256 [--trace] [Flow options]", EINVAL);
		goto cleanup;
	}
#elif defined(FLOW_BACKEND)
	if (argc < 4 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE) ||
	    flow_arguments(&state.flow, argc, argv)) {
		error_event(&state, "usage: flow-loader OBJECT veth-idss /run/netns/ids_server "
			    "[--capture] [--idle-ms N] [--closed-ms N] [--gc-ms N]", EINVAL);
		goto cleanup;
	}
#else
	if (argc != 4 || strcmp(argv[2], LAB_INTERFACE) || strcmp(argv[3], LAB_NAMESPACE)) {
		error_event(&state, "usage: probe-loader OBJECT veth-idss /run/netns/ids_server", EINVAL);
		goto cleanup;
	}
#endif
	state.namespace_fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (state.namespace_fd < 0) {
		error_event(&state, "namespace open", errno);
		goto cleanup;
	}
	if (fstat(state.namespace_fd, &state.namespace_identity)) {
		error_event(&state, "namespace identity", errno);
		goto cleanup;
	}
	result = ioctl(state.namespace_fd, NS_GET_NSTYPE);
	if (result != CLONE_NEWNET) {
		error_event(&state, "namespace type", result < 0 ? errno : EPERM);
		goto cleanup;
	}
	result = check_scope(&state, true);
	if (result) {
		error_event(&state, "initial scope", result);
		goto cleanup;
	}
#ifdef FLOW_INSPECT
	result = flow_inspect(argv[1], argv[5], &state.namespace_identity);
	if (result)
		error_event(&state, "read-only flow inspection", result);
	goto cleanup;
#endif
#ifdef NN_VECTORS
	result = nn_vectors(argc, argv, &state.namespace_identity);
	if (result)
		error_event(&state, "owned vector test-run", result);
	goto cleanup;
#endif
	state.cpu_count = libbpf_num_possible_cpus();
	if (state.cpu_count <= 0) {
		error_event(&state, "possible CPUs", state.cpu_count);
		goto cleanup;
	}
	state.cpu_values = calloc((size_t)state.cpu_count, sizeof(*state.cpu_values));
	if (!state.cpu_values) {
		error_event(&state, "counter buffer", ENOMEM);
		goto cleanup;
	}
	result = load_object(&state, argv[1]);
	if (result) {
		error_event(&state, "object load", result);
		goto cleanup;
	}
	result = selftest(&state);
	if (result) {
		error_event(&state, "counter direction selftest", result);
		goto cleanup;
	}
#ifdef FLOW_BACKEND
	result = flow_after_selftest(&state.flow, state.cpu_count, state.cpu_values);
	if (result) {
		error_event(&state, "clear unattached flow selftest state", result);
		goto cleanup;
	}
#endif
#ifdef NN_BACKEND
	result = nn_after_selftest();
	if (result) {
		error_event(&state, "clear unattached inference selftest state", result);
		goto cleanup;
	}
#endif
	result = check_scope(&state, false);
	if (result) {
		error_event(&state, "attach scope", result);
		goto cleanup;
	}
	hook.ifindex = state.ifindex;
	hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
	/* libbpf uses NLM_F_CREATE|NLM_F_EXCL: a foreign clsact is an error. */
	result = bpf_tc_hook_create(&hook);
	if (result) {
		error_event(&state, "exclusive clsact create", result);
		goto cleanup;
	}
	state.qdisc_created = true;
	for (direction = 0; direction < 2; direction++) {
		struct bpf_tc_opts options = {
			.sz = sizeof(options),
			.prog_fd = state.program_fds[direction],
			.handle = FILTER_HANDLE,
			.priority = FILTER_PRIORITY,
		};

		result = check_scope(&state, false);
		if (result) {
			error_event(&state, "filter attach scope", result);
			goto cleanup;
		}
		hook.attach_point = attach_points[direction];
		/* No BPF_TC_F_REPLACE: never overwrite an existing filter. */
		result = bpf_tc_attach(&hook, &options);
		if (result) {
			/* An acknowledged attach can fail while parsing its echo. Query
			 * the exact slot so partial success is still cleaned up by ID. */
			struct bpf_tc_opts query = {
				.sz = sizeof(query), .handle = FILTER_HANDLE,
				.priority = FILTER_PRIORITY,
			};

			if (!bpf_tc_query(&hook, &query) &&
			    query.prog_id == state.program_ids[direction])
				state.attached[direction] = true;
			error_event(&state, directions[direction], result);
			goto cleanup;
		}
		state.attached[direction] = true;
		if (options.prog_id != state.program_ids[direction]) {
			error_event(&state, "attached program identity", ESTALE);
			goto cleanup;
		}
	}
	printf("{\"schema_version\":1,\"event\":\"ready\",\"ifindex\":%d,"
	       "\"qdisc_created\":true,", state.ifindex);
	print_ids(&state);
#ifdef FLOW_BACKEND
	flow_print_ready(&state.flow);
#endif
#ifdef NN_BACKEND
	nn_print_ready();
#endif
	printf(",\"filter\":{\"handle\":%d,\"priority\":%d},"
	       "\"counter_selftest\":{\"pass\":true,\"after_ingress\":[1,0],"
	       "\"after_egress\":[1,1]}}\n", FILTER_HANDLE, FILTER_PRIORITY);
	fflush(stdout);
	if (ferror(stdout)) {
		error_event(&state, "ready output", EPIPE);
		goto cleanup;
	}
	for (;;) {
		uint64_t counts[2];
		int received;

#ifdef FLOW_BACKEND
		{
			struct timespec timeout = { .tv_nsec = 20000000 };
			result = flow_tick(&state.flow);
			if (result) {
				error_event(&state, "flow observation drain or GC", result);
				break;
			}
			received = sigtimedwait(&signals, NULL, &timeout);
			if (received < 0 && (errno == EAGAIN || errno == EINTR))
				continue;
			result = received < 0 ? errno : 0;
		}
#else
		result = sigwait(&signals, &received);
#endif
		if (result) {
			error_event(&state, "signal wait", result);
			break;
		}
		if (received == SIGINT || received == SIGTERM)
			break;
		if (received != SIGUSR1)
			continue;
		result = snapshot(&state, counts);
		if (result) {
			error_event(&state, "counter snapshot", result);
			break;
		}
#ifdef FLOW_BACKEND
		result = flow_prepare_snapshot(&state.flow, state.cpu_count, state.cpu_values);
#ifdef NN_BACKEND
		if (!result)
			result = nn_prepare_snapshot(state.cpu_count, state.cpu_values);
#endif
		if (result) {
			error_event(&state, "flow snapshot", result);
			break;
		}
#endif
		printf("{\"schema_version\":1,\"event\":\"stats\",\"seq\":%" PRIu64
		       ",\"ingress\":%" PRIu64 ",\"egress\":%" PRIu64,
		       ++state.stats_sequence, counts[0], counts[1]);
#ifdef FLOW_BACKEND
		flow_print_snapshot(&state.flow);
#endif
#ifdef NN_BACKEND
		nn_print_snapshot();
#endif
		printf("}\n");
		fflush(stdout);
		if (ferror(stdout)) {
			error_event(&state, "stats output", EPIPE);
			break;
		}
	}
cleanup:
	detached = detach_filters(&state);
#ifdef NN_BACKEND
	if (detached) {
		result = nn_clear_tails();
		if (result)
			error_event(&state, "clear owned expected tail-call references", result);
	}
#endif
	/* qdisc lifetime belongs to the adapter after empty-filter identity checks. */
#ifdef FLOW_BACKEND
	flow_controller_close(&state.flow);
#endif
	bpf_object__close(state.object);
	free(state.cpu_values);
	if (state.namespace_fd >= 0)
		close(state.namespace_fd);
	printf("{\"schema_version\":1,\"event\":\"stopped\",\"qdisc_created\":%s,"
	       "\"filters_detached\":%s,", state.qdisc_created ? "true" : "false",
	       detached ? "true" : "false");
	print_ids(&state);
	printf(",\"errors\":[");
	for (error = 0; error < state.error_count && error < MAX_ERRORS; error++) {
		if (error)
			putchar(',');
		json_string(state.errors[error]);
	}
	printf("]}\n");
	fflush(stdout);
	return state.error_count || !detached || ferror(stdout) ? EXIT_FAILURE : EXIT_SUCCESS;
}
