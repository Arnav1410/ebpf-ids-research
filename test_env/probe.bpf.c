#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} hook_counts SEC(".maps");

SEC("tc")
int probe_ingress(struct __sk_buff *skb)
{
	__u32 key = 0;
	__u64 *count = bpf_map_lookup_elem(&hook_counts, &key);

	(void)skb;
	if (count)
		(*count)++;
	return 0; /* TC_ACT_OK: the probe never changes packet disposition. */
}

SEC("tc")
int probe_egress(struct __sk_buff *skb)
{
	__u32 key = 1;
	__u64 *count = bpf_map_lookup_elem(&hook_counts, &key);

	(void)skb;
	if (count)
		(*count)++;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
