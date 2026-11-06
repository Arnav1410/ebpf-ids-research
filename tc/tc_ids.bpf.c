// SPDX-License-Identifier: GPL-2.0
/* Separate TC monitor. Only the original ingress leg supplies MLP features. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/params.bpf.h"
#include "../src/mlp.bpf.h"
#include "abi.h"
#include "flow_key.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TC_FLOW_CAPACITY);
    __type(key, struct tc_key);
    __type(value, struct tc_flow);
} flow_map SEC(".maps");
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, TC_FLOW_CAPACITY);
    __type(key, struct tc_key);
    __type(value, struct tc_result);
} results SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tc_workspace);
} workspace SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tc_config);
} tc_configuration SEC(".maps");

static __always_inline struct ids_tc_stats *tc_counters(void)
{
    u32 zero = 0;
    return bpf_map_lookup_elem(&stats, &zero);
}

static __always_inline int tc_allowed(const struct flow *input,int egress)
{
    u32 zero=0;
    struct tc_config *cfg=bpf_map_lookup_elem(&tc_configuration,&zero);
    return cfg && (!cfg->client_filter || cfg->client_ipv4==(u32)(egress?input->daddr:input->saddr));
}

static __always_inline struct tc_flow *tc_find_flow(const struct tc_key *key)
{
    struct tc_flow *f=bpf_map_lookup_elem(&flow_map,key);
    if(!f){
        struct tc_flow initial={};
        initial.min_length=0x3fffffffffffffffULL;
        bpf_map_update_elem(&flow_map,key,&initial,BPF_NOEXIST);
        /* Always relookup: another CPU can win insertion of this same key. */
        f=bpf_map_lookup_elem(&flow_map,key);
    }
    return f;
}

/* Fully inlined arithmetic only; no helpers or BPF subprogram calls under lock.
 * Monitoring timestamps track sample extrema; they are NOT MLP IAT inputs. */
static __always_inline void tc_monitor_locked(struct tc_flow *f,u32 hook,u32 direction,
                                            u64 now,u32 bytes,u32 flags)
{
    struct tc_direction_stats *d=&f->hooks[hook];
    d->packets++;d->bytes+=bytes;d->tcp_flags|=flags;
    if(d->packets==1 || now<d->first_ns)d->first_ns=now;
    if(now>=d->last_ns)d->last_ns=now;else d->timestamp_reorders++;
    f->endpoint_packets[direction]++;f->endpoint_bytes[direction]+=bytes;
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

/* No map lookup or other helper is performed inside any locked region. */
static __always_inline void tc_release(struct tc_workspace *w)
{
    __sync_lock_test_and_set(&w->busy, 0);
}

static __always_inline int tc_finish(struct tc_workspace *w, int success)
{
    struct ids_tc_stats *s = tc_counters();
    struct tc_flow *f = bpf_map_lookup_elem(&flow_map, &w->record.key);
    u64 completed = success ? bpf_ktime_get_ns() : 0;
    if (success) {
        w->record.completed_ns = completed;
        if (bpf_map_update_elem(&results, &w->record.key, &w->record, BPF_ANY)) {
            success = 0;
            if (s) __sync_fetch_and_add(&s->result_failures, 1);
        }
    }
    if (f) {
        bpf_spin_lock(&f->lock);
        if (f->state == TC_RUNNING && f->sequence == w->record.sequence) {
            f->state = success ? TC_DONE : TC_IDLE;
            if (success) f->completed_ns = completed;
            else f->failures++;
        }
        bpf_spin_unlock(&f->lock);
    }
    if (s) {
        if (success) __sync_fetch_and_add(&s->predictions, 1);
        else __sync_fetch_and_add(&s->inference_failures, 1);
    }
    tc_release(w);
    return TC_ACT_OK;
}

static __always_inline struct tc_workspace *tc_stage(u32 expected)
{
    u32 zero = 0;
    struct tc_workspace *w = bpf_map_lookup_elem(&workspace, &zero);
    if (!w || !w->busy) return NULL;
    if (w->next_stage != expected) {
        tc_finish(w, 0);
        return NULL;
    }
    return w;
}

static __always_inline void tc_capture(struct tc_workspace *w, int stage)
{
    struct ids_tc_stats *s = tc_counters();
    if (s) __sync_fetch_and_add(&s->stages[stage], 1);
    s32 *tensor = (stage == 0 || stage == 3 || stage == 4) ? w->hidden2 : w->hidden1;
    int count = stage == 0 ? 6 : (stage == 5 ? 2 : 32);
    #pragma clang loop unroll(full)
    for (int j = 0; j < 32; ++j)
        if (j < count) w->record.tensors[stage][j] = tensor[j];
    w->record.stage_mask |= 1U << stage;
}

static __always_inline int tc_next(struct __sk_buff *skb, struct tc_workspace *w, u32 index)
{
    w->next_stage = index;
    bpf_tail_call(skb, &progs, index);
    struct ids_tc_stats *s = tc_counters();
    if (s) __sync_fetch_and_add(&s->tail_failures, 1);
    return tc_finish(w, 0);
}

SEC("tc")
int tc_entry(struct __sk_buff *skb)
{
    struct ids_tc_stats *s = tc_counters();
    /* Keep the pointer non-null on every continuation path. Compound optional
     * stats guards after the lock can lose verifier refinement when clang
     * lowers the trigger booleans. Key zero is valid in this fixed-size array;
     * the defensive null path still passes the packet without inference.
     */
    if (!s) return TC_ACT_OK;
    __sync_fetch_and_add(&s->packets, 1);
    __sync_fetch_and_add(&s->bytes, skb->len);
    struct flow input = {};
    struct tc_key key = {};
    struct tcphdr tcp;
    u64 length;
    if (tc_parse(skb, &input, &tcp, &length)) {
        if (s) __sync_fetch_and_add(&s->rejected, 1);
        return TC_ACT_OK;
    }
    if (!tc_allowed(&input,0)) return TC_ACT_OK;
    u32 direction=tc_key_build(&input,&key);
    if (s) __sync_fetch_and_add(&s->matched, 1);
    /* Helpers and context loads precede the spin lock. */
    u64 now = bpf_ktime_get_ns();
    u32 zero = 0, cpu = bpf_get_smp_processor_id();
    u32 flags = (tcp.syn ? 2 : 0) | (tcp.fin ? 1 : 0) | (tcp.rst ? 4 : 0);
    u32 header = tcp.doff * 4;
    u32 destination_port = bpf_ntohs((unsigned short)input.dport);
    s32 *idx = bpf_map_lookup_elem(&nn_idx, &zero);
    s32 slot = idx ? *idx : -1;
    struct tc_workspace *w = bpf_map_lookup_elem(&workspace, &zero);
    if (!w) {
        if (s) __sync_fetch_and_add(&s->workspace_busy, 1);
        return TC_ACT_OK;
    }
    struct tc_flow *f = tc_find_flow(&key);
    if (!f) { __sync_fetch_and_add(&s->flow_full, 1); return TC_ACT_OK; }
    int closing = tcp.fin || tcp.rst;
    int owned = closing && __sync_val_compare_and_swap(&w->busy, 0, 1) == 0;
    int start = 0, duplicate = 0, reordered = 0, input_matches=0;
    u32 skb_bytes=skb->len;
    bpf_spin_lock(&f->lock);
    tc_monitor_locked(f,0,direction,now,skb_bytes,flags);
    if(!f->input_initialized){f->input=input;f->input_direction=direction;f->input_initialized=1;}
    input_matches=f->input_direction==direction;
    if(input_matches){
    f->packets++; f->bytes += length; f->header_length += header;
    if (length < f->min_length) f->min_length = length;
    if (length > f->max_length) f->max_length = length;
    if (f->packets == 1) { f->first_ns = now; f->last_ns = now; f->input=input; }
    if (now >= f->last_ns) {
        u64 elapsed = now - f->last_ns;
        if (elapsed > f->max_duration) f->max_duration = elapsed;
        f->last_ns = now;
    } else {
        /* Cross-CPU samples can arrive at the lock out of timestamp order.
         * Clamp the late interval to zero, never unsigned-underflow the IAT. */
        f->timestamp_reorders++; reordered = 1;
    }
    f->tcp_flags |= flags;
    if (closing) {
        if (f->state != TC_IDLE) { f->duplicates++; duplicate = 1; }
        else if (owned) {
            f->state = TC_RUNNING; f->sequence++;
            w->record.key = key;
            w->record.input = f->input;
            w->record.input_direction = f->input_direction;
            w->record.sequence = f->sequence;
            w->record.features[0] = f->max_length;
            w->record.features[1] = f->max_duration;
            w->record.features[2] = f->min_length;
            w->record.features[3] = destination_port;
            w->record.features[4] = f->header_length;
            w->record.features[5] = f->packets;
            start = 1;
        }
    }
    }
    bpf_spin_unlock(&f->lock);
    if(!input_matches)__sync_fetch_and_add(&s->ingress_other_direction,1);
    if (s && reordered) __sync_fetch_and_add(&s->timestamp_reorders, 1);
    if (s && duplicate) __sync_fetch_and_add(&s->duplicate_triggers, 1);
    if (s && closing && input_matches && !owned && !duplicate) __sync_fetch_and_add(&s->workspace_busy, 1);
    if (!start) { if (owned) tc_release(w); return TC_ACT_OK; }
    w->record.stage_mask = 0; w->record.completed_ns = 0;
    w->record.model_slot = slot; w->record.cpu = cpu;
    return tc_next(skb, w, 0);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
    struct ids_tc_stats *s=tc_counters();
    if(!s)return TC_ACT_OK;
    __sync_fetch_and_add(&s->egress_packets,1);
    __sync_fetch_and_add(&s->egress_bytes,skb->len);
    struct flow input={};struct tc_key key={};struct tcphdr tcp;u64 length;
    if(tc_parse(skb,&input,&tcp,&length)){
        __sync_fetch_and_add(&s->egress_rejected,1);return TC_ACT_OK;
    }
    if(!tc_allowed(&input,1))return TC_ACT_OK;
    __sync_fetch_and_add(&s->egress_matched,1);
    u32 direction=tc_key_build(&input,&key),bytes=skb->len;
    u32 flags=(tcp.syn?2:0)|(tcp.fin?1:0)|(tcp.rst?4:0);
    u64 now=bpf_ktime_get_ns();
    struct tc_flow *f=tc_find_flow(&key);
    if(!f){__sync_fetch_and_add(&s->flow_full,1);return TC_ACT_OK;}
    bpf_spin_lock(&f->lock);
    tc_monitor_locked(f,1,direction,now,bytes,flags);
    bpf_spin_unlock(&f->lock);
    return TC_ACT_OK;
}

SEC("tc")
int tc_preprocessing(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(0);
    if (!w) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &w->record.model_slot);
    if (!net) return tc_finish(w, 0);
    standard_scaler(w->record.features, w->hidden2, net->mean, net->scale, 6);
    tc_capture(w, 0); return tc_next(skb, w, 1);
}
SEC("tc")
int tc_input_linear(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(1);
    if (!w) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &w->record.model_slot);
    if (!net) return tc_finish(w, 0);
    linear_layer(net->layer_0_weight, w->hidden2, w->hidden1, 32, 6);
    tc_capture(w, 1); return tc_next(skb, w, 2);
}
SEC("tc")
int tc_input_relu(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(2);
    if (!w) return TC_ACT_OK;
    relu(w->hidden1, 32); tc_capture(w, 2); return tc_next(skb, w, 3);
}
SEC("tc")
int tc_hidden_linear(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(3);
    if (!w) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &w->record.model_slot);
    if (!net) return tc_finish(w, 0);
    linear_layer(net->layer_1_weight, w->hidden1, w->hidden2, 32, 32);
    tc_capture(w, 3); return tc_next(skb, w, 4);
}
SEC("tc")
int tc_hidden_relu(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(4);
    if (!w) return TC_ACT_OK;
    relu(w->hidden2, 32); tc_capture(w, 4); return tc_next(skb, w, 5);
}
SEC("tc")
int tc_output_linear(struct __sk_buff *skb)
{
    struct tc_workspace *w = tc_stage(5);
    if (!w) return TC_ACT_OK;
    struct Net *net = bpf_map_lookup_elem(&nn_parameters, &w->record.model_slot);
    if (!net) return tc_finish(w, 0);
    linear_layer(net->layer_2_weight, w->hidden2, w->hidden1, 2, 32);
    tc_capture(w, 5);
    w->record.label = w->hidden1[0] > w->hidden1[1] ? 0 : 1;
    return tc_finish(w, 1);
}
char __license[] SEC("license") = "GPL";
