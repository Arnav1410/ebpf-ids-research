#ifndef VALIDATION_BPF_HELPERS_H
#define VALIDATION_BPF_HELPERS_H
#define SEC(name)
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
void *validation_lookup(void *, const void *);
long validation_update(void *, const void *, const void *, unsigned long long);
unsigned long long validation_clock(void);
void validation_tail_call(struct xdp_md *, void *, unsigned int);
void validation_printk(const char *, ...);
#define bpf_map_lookup_elem validation_lookup
#define bpf_map_update_elem validation_update
#define bpf_ktime_get_ns validation_clock
#define bpf_tail_call validation_tail_call
#define bpf_printk validation_printk
#endif
