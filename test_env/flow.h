#ifndef TEST_ENV_FLOW_H
#define TEST_ENV_FLOW_H

/* Version 1: host-endian scalar map ABI; IPv4 addresses are numeric host order.
 * BPF includes vmlinux.h first; userspace includes linux/types.h first.
 * Private object/map identity supplies the network namespace, never a tuple guess.
 */
#define FLOW_ABI_VERSION 1
#define FLOW_FEATURE_SCHEMA "stage04-rx-v1"
#define FLOW_CAPACITY 8192
#define FLOW_INDEX_CAPACITY 16384
#define FLOW_HEADER_CAPACITY 134
#define FLOW_RING_BYTES (1U << 20)
#define FLOW_RESOLVE_ATTEMPTS 4
#define FLOW_DEFAULT_IDLE_MS 120000
#define FLOW_DEFAULT_CLOSED_MS 2000
#define FLOW_DEFAULT_GC_MS 250

struct flow_key {
	__u32 a_addr;
	__u32 b_addr;
	__u32 ifindex;
	__u16 a_port;
	__u16 b_port;
	__u8 protocol;
	__u8 reserved[3];
};

struct flow_direction {
	__u64 packets;
	__u64 ipv4_bytes;
	__u64 tcp_segment_bytes;
	__u64 tcp_header_bytes;
	__u64 first_ns;
	__u64 last_ns;
	__u64 max_iat_ns;
	__u32 min_segment_bytes;
	__u32 max_segment_bytes;
};

enum flow_state {
	FLOW_OPEN,
	FLOW_HALF_CLOSED,
	FLOW_CLOSING,
	FLOW_CLOSED,
	FLOW_RESET,
	FLOW_REPLACED,
};

/* No helper calls while lock is held. Snapshot with BPF_F_LOCK. Published
 * generations are never reset: only unpublished CAS losers can be discarded.
 */
struct flow_value {
	struct bpf_spin_lock lock;
	__u32 tombstone;
	struct flow_key key;
	__u32 state;
	__u64 first_ns;
	__u64 last_ns;
	__u64 closed_ns;
	__u64 ordinal;
	struct flow_direction directions[2];
	__u32 initial_seq;
	__u32 fin_end[2];
	__u8 initiator; /* 0 unknown, 1 canonical A, 2 canonical B */
	__u8 fin_seen;  /* direction bitmask */
	__u8 fin_acked; /* direction bitmask: that direction's FIN was ACKed */
	__u8 reserved;
};

struct flow_config {
	__u32 abi_version;
	__u32 capture_enabled;
	__u64 idle_ns;
	__u64 closed_ns;
};

/* The timestamp is bpf_ktime_get_ns sampled before the flow lock, clamped to
 * last_ns while holding that lock: monotonic lock-observed time, not wire time.
 * Accepted records contain Ethernet/IPv4/TCP headers; skipped records contain
 * only Ethernet (plus the fixed IPv6 header for that reason), never payload.
 * ring delivery order is not ordinal order on multiple CPUs.
 */
struct flow_observation {
	__u64 flow_id;
	__u64 ordinal;
	__u64 timestamp_ns;
	__u32 ifindex;
	__u16 header_length;
	__u8 direction;
	__u8 hook;
	__u8 headers[FLOW_HEADER_CAPACITY];
	__u8 kind; /* 0 accepted TCP, 1 counted parser skip */
	__u8 skip_reason;
};

enum flow_counter {
	FLOW_C_TRACKED,
	FLOW_C_CREATED,
	FLOW_C_REPLACED,
	FLOW_C_UNKNOWN,
	FLOW_C_SKIP_TRUNCATED,
	FLOW_C_SKIP_VLAN,
	FLOW_C_SKIP_IPV6,
	FLOW_C_SKIP_NON_IPV4,
	FLOW_C_SKIP_FRAGMENT,
	FLOW_C_SKIP_NON_TCP,
	FLOW_C_SKIP_MALFORMED,
	FLOW_C_SKIP_NONLINEAR,
	FLOW_C_CAPACITY_FAILURE,
	FLOW_C_RESOLVE_FAILURE,
	FLOW_C_OBSERVATION_LOSS,
	FLOW_C_GC_EXPIRED,
	FLOW_C_GC_DELETE_FAILURE,
	FLOW_C_ID_EXHAUSTED,
	FLOW_COUNTER_COUNT,
};

#ifndef __BPF__
extern const char *const flow_counter_names[FLOW_COUNTER_COUNT];
extern const char *const flow_state_names[FLOW_REPLACED + 1];
#endif
#endif
