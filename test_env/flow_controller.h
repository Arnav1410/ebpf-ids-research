#ifndef TEST_ENV_FLOW_CONTROLLER_H
#define TEST_ENV_FLOW_CONTROLLER_H
#include <stdbool.h>
#include <stddef.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include "flow.h"

#define FLOW_MAP_COUNT 7
#define FLOW_DIAGNOSTIC_CAPACITY 16384
struct stat;
struct bpf_object;
struct ring_buffer;
struct flow_controller {
	int map_fds[FLOW_MAP_COUNT];
	__u32 map_ids[FLOW_MAP_COUNT];
	int gc_fd;
	__u32 gc_id;
	__u64 idle_ms;
	__u64 closed_ms;
	__u64 gc_ms;
	__u64 last_gc_ns;
	bool capture;
	struct ring_buffer *ring;
	struct flow_observation *pending;
	size_t pending_count;
	__u64 diagnostic_buffer_loss;
	__u64 keys[FLOW_CAPACITY];
	struct flow_value *snapshot_values;
	size_t snapshot_count;
	__u64 counter_values[FLOW_COUNTER_COUNT];
	__u64 snapshot_start_ns;
	__u64 snapshot_end_ns;
};

void flow_controller_init(struct flow_controller *flow);
int flow_arguments(struct flow_controller *flow, int argc, char **argv);
int flow_validate_object(struct bpf_object *object);
int flow_collect_ids(struct flow_controller *flow, struct bpf_object *object);
int flow_prepare(struct flow_controller *flow, struct bpf_object *object);
int flow_after_selftest(struct flow_controller *flow, int cpu_count, __u64 *cpu_values);
int flow_tick(struct flow_controller *flow);
int flow_prepare_snapshot(struct flow_controller *flow, int cpu_count, __u64 *cpu_values);
void flow_print_snapshot(struct flow_controller *flow);
void flow_print_ids(const struct flow_controller *flow);
void flow_print_ready(const struct flow_controller *flow);
void flow_controller_close(struct flow_controller *flow);
int flow_inspect(const char *map_id, const char *owner_pid, const struct stat *namespace_identity);
int flow_bounded_snapshot(int fd, __u64 *keys, struct flow_value *values,
			  size_t limit, size_t *total);
void flow_print_rows(const __u64 *, const struct flow_value *, size_t count);
#endif
