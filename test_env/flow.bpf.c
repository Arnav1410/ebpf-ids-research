#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#define __BPF__ 1
#include "flow.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} hook_counts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, FLOW_INDEX_CAPACITY);
	__type(key, struct flow_key);
	__type(value, __u64);
} flow_index SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FLOW_CAPACITY);
	__type(key, __u64);
	__type(value, struct flow_value);
} flow_stats SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} flow_serial SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct flow_config);
} flow_config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, FLOW_COUNTER_COUNT);
	__type(key, __u32);
	__type(value, __u64);
} tracking SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, FLOW_RING_BYTES);
} observations SEC(".maps");

struct parsed_packet {
	struct flow_key key;
	__u32 seq;
	__u32 ack;
	__u16 ip_length;
	__u16 segment_length;
	__u16 tcp_header_length;
	__u16 header_length;
	__u8 flags;
	__u8 direction;
};

#ifdef NN_BACKEND
#include "nn_bpf.h"
#endif

static __always_inline void count(__u32 reason)
{
	__u64 *value = bpf_map_lookup_elem(&tracking, &reason);

	if (value)
		(*value)++;
}

/* Parse bytewise: no alignment assumptions, fixed IPv4/TCP header bug, or
 * data outside the skb's linear region. VLAN metadata is unsupported too.
 */
static __always_inline int parse(struct __sk_buff *skb, struct parsed_packet *p)
{
	const __u8 *data = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	const __u8 *ip, *tcp;
	__u32 source, dest, ihl, doff;
	__u16 sport, dport, ether, fragment, total;

	/* Payload may live in skb fragments; only headers need direct access. */
	if (skb->vlan_present)
		return FLOW_C_SKIP_VLAN;
	if (data + 14 > end)
		return skb->len < 14 ? FLOW_C_SKIP_TRUNCATED : FLOW_C_SKIP_NONLINEAR;
	ether = ((__u16)data[12] << 8) | data[13];
	if (ether == 0x8100 || ether == 0x88a8 || ether == 0x9100)
		return FLOW_C_SKIP_VLAN;
	if (ether == 0x86dd)
		return FLOW_C_SKIP_IPV6;
	if (ether != 0x0800)
		return FLOW_C_SKIP_NON_IPV4;
	ip = data + 14;
	if (ip + 20 > end)
		return skb->len < 34 ? FLOW_C_SKIP_TRUNCATED : FLOW_C_SKIP_NONLINEAR;
	ihl = (ip[0] & 15) * 4;
	if ((ip[0] >> 4) != 4 || ihl < 20)
		return FLOW_C_SKIP_MALFORMED;
	total = ((__u16)ip[2] << 8) | ip[3];
	if (total < ihl)
		return FLOW_C_SKIP_MALFORMED;
	if (skb->len < 14 || total > skb->len - 14)
		return FLOW_C_SKIP_TRUNCATED;
	fragment = ((__u16)ip[6] << 8) | ip[7];
	if (fragment & 0x3fff)
		return FLOW_C_SKIP_FRAGMENT;
	if (ip[9] != 6)
		return FLOW_C_SKIP_NON_TCP;
	if (total < ihl + 20)
		return FLOW_C_SKIP_MALFORMED;
	tcp = ip + ihl;
	if (tcp + 20 > end)
		return FLOW_C_SKIP_NONLINEAR;
	doff = (tcp[12] >> 4) * 4;
	if (doff < 20 || doff > total - ihl)
		return FLOW_C_SKIP_MALFORMED;
	if (tcp + doff > end)
		return FLOW_C_SKIP_NONLINEAR;
	source = ((__u32)ip[12] << 24) | ((__u32)ip[13] << 16) |
		 ((__u32)ip[14] << 8) | ip[15];
	dest = ((__u32)ip[16] << 24) | ((__u32)ip[17] << 16) |
	       ((__u32)ip[18] << 8) | ip[19];
	sport = ((__u16)tcp[0] << 8) | tcp[1];
	dport = ((__u16)tcp[2] << 8) | tcp[3];
	p->direction = source < dest || (source == dest && sport <= dport) ? 0 : 1;
	p->key.a_addr = p->direction ? dest : source;
	p->key.b_addr = p->direction ? source : dest;
	p->key.a_port = p->direction ? dport : sport;
	p->key.b_port = p->direction ? sport : dport;
	p->key.ifindex = skb->ifindex;
	p->key.protocol = 6;
	p->seq = ((__u32)tcp[4] << 24) | ((__u32)tcp[5] << 16) |
		 ((__u32)tcp[6] << 8) | tcp[7];
	p->ack = ((__u32)tcp[8] << 24) | ((__u32)tcp[9] << 16) |
		 ((__u32)tcp[10] << 8) | tcp[11];
	p->flags = tcp[13];
	p->ip_length = total;
	p->segment_length = total - ihl;
	p->tcp_header_length = doff;
	p->header_length = 14 + ihl + doff;
	return -1;
}

/* Only a failed publication CAS permits immediate candidate deletion. An LRU
 * index entry can be evicted while an RCU value pointer exists; a successful
 * CAS is therefore re-resolved by the caller, never assumed to be reachable.
 * Such a displaced candidate remains an ordinary ID-owned generation for GC.
 * Aligned DW loads are single-copy reads on this x64 VM. Volatile keeps them
 * explicit without C11 atomic-load IR unsupported by clang-12's BPF backend;
 * every publication/serial write still uses an atomic compare-and-swap.
 */
static __noinline int publish(const struct parsed_packet *p, __u64 *index,
			     __u64 expected)
{
	struct flow_value initial = {};
	__u32 zero = 0;
	__u64 *serial = bpf_map_lookup_elem(&flow_serial, &zero);
	__u64 id = 0, previous;
	int result;

	if (!serial)
		return -1;
#pragma unroll
	for (int attempt = 0; attempt < 16; attempt++) {
		previous = *(volatile __u64 *)serial;
		if (previous == ~0ULL) {
			count(FLOW_C_ID_EXHAUSTED);
			return -1;
		}
		if (__sync_val_compare_and_swap(serial, previous, previous + 1) == previous) {
			id = previous + 1;
			break;
		}
	}
	if (!id) {
		count(FLOW_C_RESOLVE_FAILURE);
		return -1;
	}
	initial.key = p->key;
	initial.last_ns = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&flow_stats, &id, &initial, BPF_NOEXIST)) {
		count(FLOW_C_CAPACITY_FAILURE);
		return -1;
	}
	if (index)
		result = __sync_val_compare_and_swap(index, expected, id) == expected ? 0 : -1;
	else
		result = bpf_map_update_elem(&flow_index, &p->key, &id, BPF_NOEXIST);
	if (result) {
		/* The ID was never visible through this canonical entry. */
		bpf_map_delete_elem(&flow_stats, &id);
		return 0;
	}
	count(FLOW_C_CREATED);
	return 0;
}

static __always_inline int new_epoch(const struct flow_value *v,
				    const struct parsed_packet *p)
{
	if ((p->flags & 0x12) != 0x02)
		return 0;
	if (!v->ordinal)
		return 0;
	return !v->initiator || v->state >= FLOW_CLOSED ||
		(v->initiator == p->direction + 1 && v->initial_seq != p->seq);
}

/* All compound state changes occur under one generation's spinlock. */
static __always_inline void update(struct flow_value *v,
				   const struct parsed_packet *p, __u64 now)
{
	__u32 direction = p->direction & 1;
	struct flow_direction *d = &v->directions[direction];
	__u32 peer = direction ^ 1;
	__u64 gap;

	if (now < v->last_ns)
		now = v->last_ns;
	if (!v->ordinal)
		v->first_ns = now;
	v->last_ns = now;
	v->ordinal++;
	if (!d->packets) {
		d->first_ns = now;
		d->min_segment_bytes = p->segment_length;
	} else {
		gap = now - d->last_ns;
		if (gap > d->max_iat_ns)
			d->max_iat_ns = gap;
		if (p->segment_length < d->min_segment_bytes)
			d->min_segment_bytes = p->segment_length;
	}
	d->last_ns = now;
	d->packets++;
	d->ipv4_bytes += p->ip_length;
	d->tcp_segment_bytes += p->segment_length;
	d->tcp_header_bytes += p->tcp_header_length;
	if (p->segment_length > d->max_segment_bytes)
		d->max_segment_bytes = p->segment_length;
	if (!v->initiator && (p->flags & 0x12) == 0x02) {
		v->initiator = direction + 1;
		v->initial_seq = p->seq;
	}
	if (p->flags & 0x01) {
		if (!(v->fin_seen & (1U << direction)))
			v->fin_end[direction] = p->seq + p->segment_length -
				p->tcp_header_length + !!(p->flags & 0x02) + 1;
		v->fin_seen |= 1U << direction;
	}
	if ((p->flags & 0x10) && (v->fin_seen & (1U << peer)) &&
	    (__s32)(p->ack - v->fin_end[peer]) >= 0)
		v->fin_acked |= 1U << peer;
	if (p->flags & 0x04) {
		v->state = FLOW_RESET;
		if (!v->closed_ns)
			v->closed_ns = now;
	} else if (v->state < FLOW_CLOSED) {
		if (v->fin_seen == 3 && v->fin_acked == 3) {
			v->state = FLOW_CLOSED;
			v->closed_ns = now;
		} else if (v->fin_seen == 3) {
			v->state = FLOW_CLOSING;
		} else if (v->fin_seen) {
			v->state = FLOW_HALF_CLOSED;
		}
	}
}

static __always_inline void observe(struct __sk_buff *skb,
		const struct parsed_packet *p, __u64 id, __u64 ordinal,
		__u64 timestamp, __u32 hook)
{
	__u32 zero = 0;
	const struct flow_config *config = bpf_map_lookup_elem(&flow_config, &zero);
	const __u8 *data = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	struct flow_observation *record;

	if (!config || !config->capture_enabled)
		return;
	record = bpf_ringbuf_reserve(&observations, sizeof(*record), 0);
	if (!record) {
		count(FLOW_C_OBSERVATION_LOSS);
		return;
	}
	__builtin_memset(record, 0, sizeof(*record));
	record->flow_id = id;
	record->ordinal = ordinal;
	record->timestamp_ns = timestamp;
	record->ifindex = p->key.ifindex;
	record->direction = p->direction;
	record->hook = hook;
	record->header_length = p->header_length;
#pragma unroll
	for (int i = 0; i < FLOW_HEADER_CAPACITY; i++) {
		if (i < p->header_length && data + i + 1 <= end)
			record->headers[i] = data[i];
	}
	bpf_ringbuf_submit(record, 0);
}

/* Diagnostic only: identify fixture skips independently of automatic traffic. */
static __always_inline void observe_skip(struct __sk_buff *skb, __u32 reason, __u32 hook)
{
	__u32 zero = 0;
	const struct flow_config *config = bpf_map_lookup_elem(&flow_config, &zero);
	const __u8 *data = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	struct flow_observation *record;
	__u32 limit = reason == FLOW_C_SKIP_IPV6 ? 54 : 14;

	if (!config || !config->capture_enabled)
		return;
	record = bpf_ringbuf_reserve(&observations, sizeof(*record), 0);
	if (!record) {
		count(FLOW_C_OBSERVATION_LOSS);
		return;
	}
	__builtin_memset(record, 0, sizeof(*record));
	record->timestamp_ns = bpf_ktime_get_ns();
	record->ifindex = skb->ifindex;
	record->hook = hook;
	record->kind = 1;
	record->skip_reason = reason;
#pragma unroll
	for (__u32 i = 0; i < 54; i++) {
		if (i < limit && data + i + 1 <= end) {
			record->headers[i] = data[i];
			record->header_length = i + 1;
		}
	}
	bpf_ringbuf_submit(record, 0);
}

static __always_inline int track(struct __sk_buff *skb, __u32 hook)
{
	struct parsed_packet packet = {};
	__u64 *hook_count = bpf_map_lookup_elem(&hook_counts, &hook);
	__u64 now, id, ordinal, timestamp;
	__u32 unknown;
	int reason;
#ifdef NN_BACKEND
	struct nn_seed seed;
	int eligible, trigger;
#endif

	if (hook_count)
		(*hook_count)++;
	reason = parse(skb, &packet);
	if (reason >= 0) {
		count(reason);
		observe_skip(skb, reason, hook);
		return 0;
	}
#ifdef NN_BACKEND
	eligible = nn_eligible(&packet, hook);
	trigger = eligible && (packet.flags & 5);
#endif
	now = bpf_ktime_get_ns();
#pragma unroll
	for (int attempt = 0; attempt < FLOW_RESOLVE_ATTEMPTS; attempt++) {
		__u64 *index = bpf_map_lookup_elem(&flow_index, &packet.key);
		struct flow_value *value;
		int replace = 0;
#ifdef NN_BACKEND
		struct nn_rx *rx = NULL;
#endif

		if (!index) {
			if (publish(&packet, NULL, 0))
				return 0;
			continue;
		}
		id = *(volatile __u64 *)index;
		value = bpf_map_lookup_elem(&flow_stats, &id);
		if (!value) {
			if (publish(&packet, index, id))
				return 0;
			continue;
		}
#ifdef NN_BACKEND
		if (eligible)
			rx = nn_get_rx(id);
#endif
		bpf_spin_lock(&value->lock);
		if (value->tombstone || value->state == FLOW_REPLACED) {
			replace = 1;
		} else if (new_epoch(value, &packet)) {
			value->state = FLOW_REPLACED;
			if (!value->closed_ns)
				value->closed_ns = now < value->last_ns ? value->last_ns : now;
			replace = 2;
		} else {
			update(value, &packet, now);
			ordinal = value->ordinal;
			timestamp = value->last_ns;
			unknown = !value->initiator;
#ifdef NN_BACKEND
			if (rx)
				nn_rx_update(rx, &packet, timestamp, seed.features);
#endif
		}
		bpf_spin_unlock(&value->lock);
		if (replace) {
			if (replace == 2)
				count(FLOW_C_REPLACED);
			if (publish(&packet, index, id))
				return 0;
			continue;
		}
		count(FLOW_C_TRACKED);
		if (unknown)
			count(FLOW_C_UNKNOWN);
		observe(skb, &packet, id, ordinal, timestamp, hook);
#ifdef NN_BACKEND
		if (trigger && rx) {
			seed.key.flow_id = id;
			seed.key.trigger_ordinal = ordinal;
			seed.timestamp_ns = timestamp;
			seed.tuple = packet.key;
			seed.trigger_flags = packet.flags;
			return nn_start(skb, &seed, 0);
		}
#endif
		return 0;
	}
	count(FLOW_C_RESOLVE_FAILURE);
	return 0;
}

SEC("tc")
int flow_ingress(struct __sk_buff *skb)
{
	return track(skb, 0);
}

SEC("tc")
int flow_egress(struct __sk_buff *skb)
{
	return track(skb, 1);
}

/* Dedicated test-run-only GC program; the controller passes one unique ID as
 * eight input bytes. Never attach this program. No canonical-key deletion.
 */
SEC("tc")
int flow_gc(struct __sk_buff *skb)
{
	const __u8 *data = (const void *)(long)skb->data;
	const __u8 *end = (const void *)(long)skb->data_end;
	struct flow_value *value;
	struct flow_config *config;
	__u64 id, now, age, ttl;
	__u32 zero = 0;
	int expired = 0;

	if (data + sizeof(id) > end)
		return 0;
	__builtin_memcpy(&id, data, sizeof(id));
	config = bpf_map_lookup_elem(&flow_config, &zero);
	if (!config || config->abi_version != FLOW_ABI_VERSION)
		return 0;
	value = bpf_map_lookup_elem(&flow_stats, &id);
	if (!value)
		return 0;
	now = bpf_ktime_get_ns();
	/* Config helpers and reads precede the lock; no helper runs inside it. */
	ttl = config->idle_ns;
	age = config->closed_ns;
	bpf_spin_lock(&value->lock);
	if (value->state >= FLOW_CLOSED) {
		ttl = age;
		age = value->closed_ns;
	} else {
		age = value->last_ns;
	}
	if (value->tombstone || (now >= age && now - age >= ttl)) {
		value->tombstone = 1;
		expired = 1;
	}
	bpf_spin_unlock(&value->lock);
	if (expired) {
		if (bpf_map_delete_elem(&flow_stats, &id))
			count(FLOW_C_GC_DELETE_FAILURE);
		else {
			count(FLOW_C_GC_EXPIRED);
#ifdef NN_BACKEND
			bpf_map_delete_elem(&nn_rx, &id);
#endif
		}
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
