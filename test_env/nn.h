#ifndef TEST_ENV_NN_H
#define TEST_ENV_NN_H
#include "flow.h"
#define NN_ABI_VERSION 2
#define NN_FEATURE_SCHEMA "original-rx-six-v1"
#define NN_MODEL_SCHEMA "mlp-6-32-32-2-no-bias-q16-v1"
#define NN_CAPACITY 8192
#define NN_STAGE_COUNT 6
#define NN_MAP_COUNT 13
#define NN_EVENT_SCHEMA_VERSION 1
#define NN_EVENT_ENDIAN 0x01020304U
#define NN_EVENT_BYTES 256
#define NN_EVENT_RING_BYTES (1U << 20)
#define NN_EVENT_RING_MIN_BYTES 4096U
#define NN_PROGRAM_COUNT 7
#define NN_PARAM_BYTES 5216
struct nn_key { __u64 flow_id, trigger_ordinal; };
struct nn_params {
	__s32 weights0[192], weights1[1024], weights2[64];
	__s64 mean[6], scale[6];
};
struct nn_slot { __u32 ready, reserved; __u8 identity[32]; };
struct nn_control { __u32 active, trace; __u64 vector_serial; };
struct nn_rx { __s64 features[6]; __u64 last_ns; };
/* Public publication contains no skb control words or internal scratch. */
struct nn_result {
	struct nn_key key;
	__u64 timestamp_ns;
	__s64 features[6];
	__u8 identity[32];
	struct flow_key tuple;
	__u32 stage_bitmap, status, label;
	__s32 logits[2];
	__u32 slot, trigger_flags;
};
/* Fixed little-endian/x64 wire ABI. Counts may describe a later coherent
 * generation prefix than the frozen classification trigger. No skb.cb. */
struct nn_event {
	__u16 version, size;
	__u32 endian;
	__u64 sequence;
	struct nn_result result;
	__u64 counts_ordinal, counts_timestamp_ns;
	__u64 direction_counts[2][4];
	__u32 flow_state, counts_valid;
};
struct nn_trace {
	__s32 normalized[6], linear0[32], relu0[32], linear1[32], relu1[32], output[2];
};
struct nn_job {
	struct nn_result result;
	__u32 saved_cb[5];
	__u32 trace;
	__s32 hidden[2][32];
};
/* Vector binary: native little-endian key16 + six signed64 features (64 bytes).
 * Flow ID zero is reserved for vectors: real Flow IDs start at one.
 */
struct nn_vector_input { struct nn_key key; __s64 features[6]; };
enum nn_status { NN_OK, NN_UNREADY, NN_JOB_FULL, NN_TAIL_MISSING, NN_BAD_PARAMS,
	NN_TRACE_FULL, NN_BAD_STAGE };
enum nn_counter { NN_C_TRIGGER, NN_C_COMPLETE, NN_C_UNREADY, NN_C_JOB_FULL,
	NN_C_TAIL_MISSING, NN_C_BAD_PARAMS, NN_C_TRACE_FULL, NN_C_RESULT_FULL,
	NN_C_RX_FULL, NN_C_MISSING_JOB, NN_C_BAD_STAGE,
	NN_C_EVENT_EMITTED, NN_C_EVENT_DROPPED, NN_C_EVENT_MISSING_COUNTS,
	NN_COUNTER_COUNT };
#endif
