#ifndef TC_IDS_ABI_H
#define TC_IDS_ABI_H
#define TC_ACT_OK 0
struct ids_tc_stats {
    u64 packets, bytes, matched, rejected;
    u64 stages[6];
    u64 predictions, tail_failures;
    u64 flow_full, workspace_busy, duplicate_triggers, inference_failures;
    u64 timestamp_reorders, result_failures;
};
#ifndef TC_MINIMAL
/* Directional IPv4 key retained for Phase 1. No egress/canonical key yet. */
struct flow { int saddr, sport, daddr, dport; };
#define TC_FLOW_CAPACITY 8192
#define TC_IDLE 0
#define TC_RUNNING 1
#define TC_DONE 2
/* Lock is top-level, BTF-described, and initialized only by a zeroed insertion.
 * No tensors live here. All related fields are read/written under this lock.
 */
struct tc_flow {
    struct bpf_spin_lock lock;
    u32 state;
    u64 packets, bytes, min_length, max_length, header_length;
    u64 first_ns, last_ns, max_duration, sequence;
    u64 completed_ns, failures, duplicates, timestamp_reorders;
    u32 tcp_flags, reserved;
};
/* Immutable hash-map value: published once by map_update, never edited in place. */
struct tc_result {
    struct flow key;
    s64 features[6];
    s32 tensors[6][32];
    u64 completed_ns, stage_mask;
    s32 label, model_slot;
    u64 sequence;
    u32 cpu, reserved;
};
/* One owner per CPU across the full non-sleepable tail-call chain. The busy
 * guard detects nested/reentrant use; it is not a claim of universal safety.
 */
struct tc_workspace {
    u32 busy, next_stage;
    s32 hidden1[32], hidden2[32];
    struct tc_result record;
};
#endif
#endif
