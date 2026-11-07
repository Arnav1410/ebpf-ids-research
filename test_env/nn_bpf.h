#ifndef TEST_ENV_NN_BPF_H
#define TEST_ENV_NN_BPF_H
#include "nn.h"
#include "../src/mlp.bpf.h"
struct nn_seed {
	struct nn_key key;
	__u64 timestamp_ns;
	__s64 features[6];
	struct flow_key tuple;
	__u32 trigger_flags;
};
#define NN_MAP(name, kind, cap, keytype, valuetype) struct { \
	__uint(type, kind); __uint(max_entries, cap); \
	__type(key, keytype); __type(value, valuetype); } name SEC(".maps")
#define NN_RO_ARRAY(name, cap, valuetype) struct { \
	__uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, cap); \
	__uint(map_flags, BPF_F_RDONLY_PROG); \
	__type(key, __u32); __type(value, valuetype); } name SEC(".maps")
NN_MAP(nn_rx, BPF_MAP_TYPE_HASH, NN_CAPACITY, __u64, struct nn_rx);
NN_MAP(nn_jobs, BPF_MAP_TYPE_HASH, NN_CAPACITY, struct nn_key, struct nn_job);
NN_RO_ARRAY(nn_params, 2, struct nn_params);
NN_MAP(nn_slots, BPF_MAP_TYPE_ARRAY, 2, __u32, struct nn_slot);
NN_MAP(nn_control, BPF_MAP_TYPE_ARRAY, 1, __u32, struct nn_control);
NN_MAP(nn_tails, BPF_MAP_TYPE_PROG_ARRAY, 6, __u32, __u32);
NN_MAP(nn_results, BPF_MAP_TYPE_HASH, NN_CAPACITY, struct nn_key, struct nn_result);
NN_MAP(nn_counts, BPF_MAP_TYPE_PERCPU_ARRAY, NN_COUNTER_COUNT, __u32, __u64);
NN_RO_ARRAY(nn_zero, 1, struct nn_job);
NN_RO_ARRAY(nn_tzero, 1, struct nn_trace);
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, NN_CAPACITY);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct nn_key);
	__type(value, struct nn_trace);
} nn_traces SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, NN_EVENT_RING_BYTES);
} nn_events SEC(".maps");
NN_MAP(nn_event_seq, BPF_MAP_TYPE_ARRAY, 1, __u32, __u64);
_Static_assert(sizeof(struct nn_event) == NN_EVENT_BYTES, "event ABI");
_Static_assert(sizeof(struct nn_seed) == 96, "seed ABI");
#undef NN_MAP
#undef NN_RO_ARRAY
static __always_inline void nn_count(__u32 reason)
{
	__u64 *n = bpf_map_lookup_elem(&nn_counts, &reason);
	if (n) (*n)++;
}
static __always_inline int nn_eligible(const struct parsed_packet *p, __u32 hook)
{
	return !hook && (p->direction ? p->key.b_addr : p->key.a_addr) == 555819337;
}
static __noinline struct nn_rx *nn_get_rx(__u64 id)
{
	struct nn_rx *rx = bpf_map_lookup_elem(&nn_rx, &id);
	if (!rx) {
		struct nn_rx zero = {};
		bpf_map_update_elem(&nn_rx, &id, &zero, BPF_NOEXIST);
		rx = bpf_map_lookup_elem(&nn_rx, &id);
		if (!rx) nn_count(NN_C_RX_FULL);
	}
	return rx;
}
/* Pure inline hook: caller holds the existing Flow lock, and has clamped time.
 * No map/helper/subprogram operation is permitted in this function. */
static __always_inline void nn_rx_update(struct nn_rx *rx,
	const struct parsed_packet *p, __u64 now, __s64 features[6])
{
	if (!rx->features[5]) {
		rx->features[0] = p->segment_length;
		rx->features[2] = p->segment_length;
		rx->features[3] = p->direction ? p->key.a_port : p->key.b_port;
	} else {
		__u64 gap = now - rx->last_ns;
		if (gap > (__u64)rx->features[1]) rx->features[1] = gap;
		if (p->segment_length > rx->features[0]) rx->features[0] = p->segment_length;
		if (p->segment_length < rx->features[2]) rx->features[2] = p->segment_length;
	}
	rx->last_ns = now;
	rx->features[4] += p->tcp_header_length;
	rx->features[5]++;
	if (p->flags & 5)
		__builtin_memcpy(features, rx->features, 48);
}
/* cb is stable __sk_buff UAPI. Avoid vmlinux CO-RE's relocated array base,
 * which clang-12 materializes as a forbidden modified context pointer. */
static __always_inline __u32 nn_cb_get(struct __sk_buff *skb, __u32 index)
{
	barrier_var(skb);
	return ((__u32 *)((__u8 *)skb + __builtin_offsetof(struct __sk_buff, cb)))[index];
}
static __always_inline void nn_cb_set(struct __sk_buff *skb, __u32 index, __u32 value)
{
	barrier_var(skb);
	((__u32 *)((__u8 *)skb + __builtin_offsetof(struct __sk_buff, cb)))[index] = value;
}
static __always_inline void nn_restore(struct __sk_buff *skb, const struct nn_job *job)
{
#pragma unroll
	for (int i = 0; i < 5; i++) nn_cb_set(skb, i, job->saved_cb[i]);
}
/* A looked-up Flow generation stays RCU-alive through this BPF invocation.
 * GC can tombstone/delete it concurrently; the lock chooses a coherent prefix,
 * never a recycled generation (IDs are unique). Helpers stay outside the lock. */
static __always_inline void nn_publish(const struct nn_result *result)
{
	__u32 zero = 0;
	__u64 *serial;
	__u64 sequence;
	struct nn_event *event;
	struct flow_value *value;
	if (!result->key.flow_id) return;
	serial = bpf_map_lookup_elem(&nn_event_seq, &zero);
	if (!serial) { nn_count(NN_C_EVENT_DROPPED); return; }
	sequence = __sync_fetch_and_add(serial, 1) + 1;
	event = bpf_ringbuf_reserve(&nn_events, sizeof(*event), 0);
	if (!event) { nn_count(NN_C_EVENT_DROPPED); return; }
	__builtin_memset(event, 0, sizeof(*event));
	event->version = NN_EVENT_SCHEMA_VERSION;
	event->size = sizeof(*event);
	event->endian = NN_EVENT_ENDIAN;
	event->sequence = sequence;
	event->result = *result;
	value = bpf_map_lookup_elem(&flow_stats, &result->key.flow_id);
	if (value) {
		bpf_spin_lock(&value->lock);
		if (!value->tombstone) {
			event->counts_ordinal = value->ordinal;
			event->counts_timestamp_ns = value->last_ns;
			event->flow_state = value->state;
#pragma unroll
			for (int d = 0; d < 2; d++) {
				event->direction_counts[d][0] = value->directions[d].packets;
				event->direction_counts[d][1] = value->directions[d].ipv4_bytes;
				event->direction_counts[d][2] = value->directions[d].tcp_segment_bytes;
				event->direction_counts[d][3] = value->directions[d].tcp_header_bytes;
			}
			event->counts_valid = 1;
		}
		bpf_spin_unlock(&value->lock);
	}
	if (!event->counts_valid) nn_count(NN_C_EVENT_MISSING_COUNTS);
	bpf_ringbuf_submit(event, 0);
	nn_count(NN_C_EVENT_EMITTED);
}
static __always_inline int nn_finish(struct __sk_buff *skb, struct nn_job *job, __u32 status)
{
	struct nn_key key = job->result.key;
	job->result.status = status;
	if (status) job->result.label = 0;
	if (bpf_map_update_elem(&nn_results, &key, &job->result, BPF_NOEXIST)) {
		nn_count(NN_C_RESULT_FULL);
		if (job->trace & 2)
			bpf_map_delete_elem(&nn_traces, &key);
	}
	if (!status) nn_count(NN_C_COMPLETE);
	nn_publish(&job->result);
	nn_restore(skb, job);
	if (bpf_map_delete_elem(&nn_jobs, &key))
		nn_count(NN_C_MISSING_JOB);
	return 0;
}
static __always_inline struct nn_job *nn_current(struct __sk_buff *skb)
{
	struct nn_key key = {
		.flow_id = ((__u64)nn_cb_get(skb, 1) << 32) | nn_cb_get(skb, 0),
		.trigger_ordinal = ((__u64)nn_cb_get(skb, 3) << 32) | nn_cb_get(skb, 2),
	};
	struct nn_job *job = bpf_map_lookup_elem(&nn_jobs, &key);
	if (!job) nn_count(NN_C_MISSING_JOB);
	return job;
}
static __always_inline int nn_next(struct __sk_buff *skb, struct nn_job *job, __u32 next)
{
	bpf_tail_call(skb, &nn_tails, next);
	nn_count(NN_C_TAIL_MISSING);
	return nn_finish(skb, job, NN_TAIL_MISSING);
}
/* Tail-call from the entry frame, not below the tracker's 256-byte frame. */
static __always_inline int nn_start(struct __sk_buff *skb, const struct nn_seed *seed, int vector)
{
	__u32 zero = 0, active;
	const struct nn_control *control = bpf_map_lookup_elem(&nn_control, &zero);
	const struct nn_job *initial = bpf_map_lookup_elem(&nn_zero, &zero);
	struct nn_job *job;
	struct nn_slot *slot;
	nn_count(NN_C_TRIGGER);
	if (!control || !initial) { nn_count(NN_C_JOB_FULL); return 0; }
	active = control->active;
	if (bpf_map_update_elem(&nn_jobs, &seed->key, initial, BPF_NOEXIST)) {
		nn_count(NN_C_JOB_FULL); return 0;
	}
	job = bpf_map_lookup_elem(&nn_jobs, &seed->key);
	if (!job) { nn_count(NN_C_MISSING_JOB); return 0; }
	job->result.key = seed->key;
	job->result.timestamp_ns = seed->timestamp_ns;
	__builtin_memcpy(job->result.features, seed->features, 48);
	job->result.tuple = seed->tuple;
	job->result.trigger_flags = seed->trigger_flags;
	job->result.slot = active;
	job->trace = vector || control->trace;
#pragma unroll
	for (int i = 0; i < 5; i++) job->saved_cb[i] = nn_cb_get(skb, i);
	nn_cb_set(skb, 0, seed->key.flow_id);
	nn_cb_set(skb, 1, seed->key.flow_id >> 32);
	nn_cb_set(skb, 2, seed->key.trigger_ordinal);
	nn_cb_set(skb, 3, seed->key.trigger_ordinal >> 32);
	slot = bpf_map_lookup_elem(&nn_slots, &active);
	if (slot)
		__builtin_memcpy(job->result.identity, slot->identity, 32);
	if (active > 1 || !slot || !slot->ready) {
		nn_count(NN_C_UNREADY); return nn_finish(skb, job, NN_UNREADY);
	}
	if (job->trace) {
		const struct nn_trace *empty = bpf_map_lookup_elem(&nn_tzero, &zero);
		if (!empty || bpf_map_update_elem(&nn_traces, &seed->key, empty, BPF_NOEXIST)) {
			nn_count(NN_C_TRACE_FULL); return nn_finish(skb, job, NN_TRACE_FULL);
		}
		job->trace |= 2;
	}
	return nn_next(skb, job, 0);
}
static __always_inline struct nn_trace *nn_trace_for(struct nn_job *job)
{
	if (!(job->trace & 2)) return NULL;
	return bpf_map_lookup_elem(&nn_traces, &job->result.key);
}
static __always_inline int nn_stage_valid(struct nn_job *job, __u32 expected)
{
	if (job->result.stage_bitmap == expected) return 1;
	nn_count(NN_C_BAD_STAGE); return 0;
}
SEC("tc") int nn_normalize(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_params *params;
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 0)) return nn_finish(skb, job, NN_BAD_STAGE);
	params = bpf_map_lookup_elem(&nn_params, &job->result.slot);
	if (!params) { nn_count(NN_C_BAD_PARAMS); return nn_finish(skb, job, NN_BAD_PARAMS); }
#pragma unroll
	for (int i = 0; i < 6; i++)
		if (!params->scale[i]) { nn_count(NN_C_BAD_PARAMS); return nn_finish(skb, job, NN_BAD_PARAMS); }
	standard_scaler(job->result.features, job->hidden[0], params->mean, params->scale, 6);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->normalized, job->hidden[0], 24);
	job->result.stage_bitmap = 1;
	return nn_next(skb, job, 1);
}
SEC("tc") int nn_linear0(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_params *params;
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 1)) return nn_finish(skb, job, NN_BAD_STAGE);
	params = bpf_map_lookup_elem(&nn_params, &job->result.slot);
	if (!params) { nn_count(NN_C_BAD_PARAMS); return nn_finish(skb, job, NN_BAD_PARAMS); }
	linear_layer(params->weights0, job->hidden[0], job->hidden[1], 32, 6);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->linear0, job->hidden[1], 128);
	job->result.stage_bitmap = 3;
	return nn_next(skb, job, 2);
}
SEC("tc") int nn_relu0(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 3)) return nn_finish(skb, job, NN_BAD_STAGE);
	relu(job->hidden[1], 32);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->relu0, job->hidden[1], 128);
	job->result.stage_bitmap = 7;
	return nn_next(skb, job, 3);
}
SEC("tc") int nn_linear1(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_params *params;
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 7)) return nn_finish(skb, job, NN_BAD_STAGE);
	params = bpf_map_lookup_elem(&nn_params, &job->result.slot);
	if (!params) { nn_count(NN_C_BAD_PARAMS); return nn_finish(skb, job, NN_BAD_PARAMS); }
	linear_layer(params->weights1, job->hidden[1], job->hidden[0], 32, 32);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->linear1, job->hidden[0], 128);
	job->result.stage_bitmap = 15;
	return nn_next(skb, job, 4);
}
SEC("tc") int nn_relu1(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 15)) return nn_finish(skb, job, NN_BAD_STAGE);
	relu(job->hidden[0], 32);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->relu1, job->hidden[0], 128);
	job->result.stage_bitmap = 31;
	return nn_next(skb, job, 5);
}
SEC("tc") int nn_output(struct __sk_buff *skb)
{
	struct nn_job *job = nn_current(skb);
	struct nn_params *params;
	struct nn_trace *trace;
	if (!job) return 0;
	if (!nn_stage_valid(job, 31)) return nn_finish(skb, job, NN_BAD_STAGE);
	params = bpf_map_lookup_elem(&nn_params, &job->result.slot);
	if (!params) { nn_count(NN_C_BAD_PARAMS); return nn_finish(skb, job, NN_BAD_PARAMS); }
	linear_layer(params->weights2, job->hidden[0], job->result.logits, 2, 32);
	trace = nn_trace_for(job);
	if (trace) __builtin_memcpy(trace->output, job->result.logits, 8);
	job->result.stage_bitmap = 63;
	job->result.label = job->result.logits[0] > job->result.logits[1] ? 0 : 1;
	return nn_finish(skb, job, NN_OK);
}
SEC("tc") int nn_vector(struct __sk_buff *skb)
{
	const __u8 *data = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	struct nn_seed seed = {};
	if (data + sizeof(struct nn_vector_input) > end) return 0;
	__builtin_memcpy(&seed.key, data, 16);
	if (seed.key.flow_id || !seed.key.trigger_ordinal) return 0;
	__builtin_memcpy(seed.features, data + 16, 48);
	seed.timestamp_ns = bpf_ktime_get_ns();
	return nn_start(skb, &seed, 1);
}
#endif
