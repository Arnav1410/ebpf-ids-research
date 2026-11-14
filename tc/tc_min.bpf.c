// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#define TC_MINIMAL
#include "abi.h"
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ids_tc_stats);
} stats SEC(".maps");
SEC("tc")
int tc_minimal(struct __sk_buff *skb)
{
    u32 zero = 0;
    struct ids_tc_stats *s = bpf_map_lookup_elem(&stats, &zero);
    if (s) {
        __sync_fetch_and_add(&s->packets, 1);
        __sync_fetch_and_add(&s->bytes, skb->len);
    }
    return TC_ACT_OK;
}

/* Phase 2's first stage: observe server responses without flow tracking or NN
 * changes. Both hooks share this object's private stats map. */
SEC("tc")
int tc_minimal_egress(struct __sk_buff *skb)
{
    u32 zero = 0;
    struct ids_tc_stats *s = bpf_map_lookup_elem(&stats, &zero);
    if (s) {
        __sync_fetch_and_add(&s->egress_packets, 1);
        __sync_fetch_and_add(&s->egress_bytes, skb->len);
    }
    return TC_ACT_OK;
}
char __license[] SEC("license") = "GPL";
