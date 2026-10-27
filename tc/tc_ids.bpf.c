// SPDX-License-Identifier: GPL-2.0
/* Separate TC ingress port. Original XDP source/parameters remain untouched. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/params.bpf.h"
#include "../src/common.h"
#include "../src/handler.bpf.h"
#include "../src/mlp.bpf.h"
#include "abi.h"

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 6);
    __type(key, u32);
    __type(value, u32);
} progs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ids_tc_stats);
} stats SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tc_result);
} results SEC(".maps");

static __always_inline struct ids_tc_stats *tc_counters(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&stats, &zero);
}

/* skb reads handle non-linear buffers. No payload linearization or modification.
 * Untagged Ethernet IPv4/TCP only; fragments and malformed headers pass unscored.
 * The feature length stays IP total length minus IP header length (TCP included). */
static __always_inline int tc_parse(struct __sk_buff *skb, struct flow *f,
                                   struct tcphdr *tcp, u64 *segment_length)
{
    struct ethhdr eth;
    struct iphdr ip;
    if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) || eth.h_proto != bpf_htons(0x0800)) return -1;
    if (bpf_skb_load_bytes(skb, sizeof(eth), &ip, sizeof(ip))) return -1;
    u32 ihl = ip.ihl * 4;
    u32 total = bpf_ntohs(ip.tot_len);
    if (ip.version != 4 || ihl < 20 || ihl > 60 || ip.protocol != IPPROTO_TCP
        || (bpf_ntohs(ip.frag_off) & 0x3fff) || total < ihl + 20
        || skb->len < sizeof(eth) || total > skb->len - sizeof(eth)) return -1;
    if (bpf_skb_load_bytes(skb, sizeof(eth) + ihl, tcp, sizeof(*tcp))) return -1;
    u32 header = tcp->doff * 4;
    if (header < 20 || header > 60 || total < ihl + header) return -1;
    f->saddr = ip.saddr; f->daddr = ip.daddr;
    f->sport = tcp->source; f->dport = tcp->dest;
    *segment_length = total - ihl;
    return 0;
}

static __always_inline struct flow_attribute *tc_attribute(struct __sk_buff *skb, struct flow *f)
{
    struct tcphdr tcp;
    u64 length;
    if (tc_parse(skb, f, &tcp, &length)) return NULL;
    return bpf_map_lookup_elem(&flow_map, f);
}

static __always_inline struct tc_result *tc_record(struct flow *f)
{
    u32 zero = 0;
    struct tc_result *r = bpf_map_lookup_elem(&results, &zero);
    if (!r || r->key.saddr != f->saddr || r->key.daddr != f->daddr
        || r->key.sport != f->sport || r->key.dport != f->dport) return NULL;
    return r;
}

static __always_inline void tc_capture(struct flow *f, struct flow_attribute *a, int stage)
{
    struct tc_result *r = tc_record(f);
    struct ids_tc_stats *s = tc_counters();
    if (s) __sync_fetch_and_add(&s->stages[stage], 1);
    if (!r) return;
    s32 *tensor = (stage == 0 || stage == 3 || stage == 4) ? a->hidden2 : a->hidden1;
    int count = stage == 0 ? 6 : (stage == 5 ? 2 : 32);
    #pragma clang loop unroll(full)
    for (int j = 0; j < 32; ++j)
        if (j < count) r->tensors[stage][j] = tensor[j];
    r->stage_mask |= 1U << stage;
    if (stage == 5) {
        r->label = a->hidden1[0] > a->hidden1[1] ? 0 : 1;
        r->completed_ns = bpf_ktime_get_ns();
        if (s) __sync_fetch_and_add(&s->predictions, 1);
    }
}

static __always_inline int tc_next(struct __sk_buff *skb, u32 index)
{
    bpf_tail_call(skb, &progs, index);
    struct ids_tc_stats *s = tc_counters();
    if (s) __sync_fetch_and_add(&s->tail_failures, 1);
    return TC_ACT_OK;
}

SEC("tc")
int tc_entry(struct __sk_buff *skb)
{
    struct ids_tc_stats *s = tc_counters();
    if (s) { __sync_fetch_and_add(&s->packets, 1); __sync_fetch_and_add(&s->bytes, skb->len); }
    struct flow f = {};
    struct tcphdr tcp;
    u64 length;
    if (tc_parse(skb, &f, &tcp, &length)) {
        if (s) __sync_fetch_and_add(&s->rejected, 1);
        return TC_ACT_OK;
    }
    if (bpf_ntohl(f.saddr) != 555819337) return TC_ACT_OK; /* Original 33.33.33.73 gate. */
    if (s) __sync_fetch_and_add(&s->matched, 1);
    update_flow_attribute(&f, &tcp, length);
    if (!(tcp.fin || tcp.rst)) return TC_ACT_OK;
    struct flow_attribute *a = bpf_map_lookup_elem(&flow_map, &f);
    u32 zero = 0;
    s32 *index = bpf_map_lookup_elem(&nn_idx, &zero);
    struct tc_result *r = bpf_map_lookup_elem(&results, &zero);
    if (!a || !index || !r) return TC_ACT_OK;
    a->nn_idx = *index;
    r->key = f; r->stage_mask = 0; r->completed_ns = 0; r->model_slot = *index;
    r->features[0] = a->max_packet_length; r->features[1] = a->max_duration;
    r->features[2] = a->min_packet_length; r->features[3] = a->dst_port;
    r->features[4] = a->header_length; r->features[5] = a->num_packet;
    return tc_next(skb, 0);
}

SEC("tc")
int tc_preprocessing(struct __sk_buff *skb)
{
    struct flow f = {};
    struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &a->nn_idx);
    if (!net) return TC_ACT_OK;
    s64 x[6] = {a->max_packet_length, a->max_duration, a->min_packet_length,
                a->dst_port, a->header_length, a->num_packet};
    standard_scaler(x, a->hidden2, net->mean, net->scale, 6);
    tc_capture(&f, a, 0);
    return tc_next(skb, 1);
}
SEC("tc")
int tc_input_linear(struct __sk_buff *skb)
{
    struct flow f = {}; struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &a->nn_idx);
    if (!net) return TC_ACT_OK;
    linear_layer(net->layer_0_weight, a->hidden2, a->hidden1, 32, 6);
    tc_capture(&f, a, 1); return tc_next(skb, 2);
}
SEC("tc")
int tc_input_relu(struct __sk_buff *skb)
{
    struct flow f = {}; struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    relu(a->hidden1, 32); tc_capture(&f, a, 2); return tc_next(skb, 3);
}
SEC("tc")
int tc_hidden_linear(struct __sk_buff *skb)
{
    struct flow f = {}; struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &a->nn_idx);
    if (!net) return TC_ACT_OK;
    linear_layer(net->layer_1_weight, a->hidden1, a->hidden2, 32, 32);
    tc_capture(&f, a, 3); return tc_next(skb, 4);
}
SEC("tc")
int tc_hidden_relu(struct __sk_buff *skb)
{
    struct flow f = {}; struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    relu(a->hidden2, 32); tc_capture(&f, a, 4); return tc_next(skb, 5);
}
SEC("tc")
int tc_output_linear(struct __sk_buff *skb)
{
    struct flow f = {}; struct flow_attribute *a = tc_attribute(skb, &f);
    if (!a) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &a->nn_idx);
    if (!net) return TC_ACT_OK;
    linear_layer(net->layer_2_weight, a->hidden2, a->hidden1, 2, 32);
    tc_capture(&f, a, 5);
    return TC_ACT_OK;
}
char __license[] SEC("license") = "GPL";
