#ifndef TC_IDS_ABI_H
#define TC_IDS_ABI_H
#define TC_ACT_OK 0
struct ids_tc_stats {
    u64 packets, bytes, matched, rejected;
    u64 stages[6];
    u64 predictions, tail_failures;
};
#ifndef TC_MINIMAL
/* One latest completed record per CPU: demo telemetry, not a lossless log. */
struct tc_result {
    struct flow key;
    s64 features[6];
    s32 tensors[6][32];
    u64 completed_ns, stage_mask;
    s32 label, model_slot;
};
#endif
#endif
