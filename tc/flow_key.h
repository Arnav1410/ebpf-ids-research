#ifndef TC_FLOW_KEY_H
#define TC_FLOW_KEY_H
/* Shared by BPF, controller fixtures and host tests. Explicit conversions keep
 * canonical ordering independent of the machine's byte order. */
static inline __attribute__((always_inline)) u32 tc_host_addr(u32 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap32(value);
#else
    return value;
#endif
}
static inline __attribute__((always_inline)) unsigned tc_host_port(u32 value)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap16((unsigned short)value);
#else
    return (unsigned short)value;
#endif
}
/* Returns packet direction: 0 means endpoint A -> B; 1 means B -> A.
 * This is independent of the TC hook and of the chosen MLP input leg. */
static inline __attribute__((always_inline)) u32 tc_key_build(const struct flow *p,
                                                             struct tc_key *k)
{
    u32 source=tc_host_addr(p->saddr), destination=tc_host_addr(p->daddr);
    int first=source<destination || (source==destination && tc_host_port(p->sport)<=tc_host_port(p->dport));
    k->a_addr=first?(u32)p->saddr:(u32)p->daddr;
    k->a_port=first?(u32)p->sport:(u32)p->dport;
    k->b_addr=first?(u32)p->daddr:(u32)p->saddr;
    k->b_port=first?(u32)p->dport:(u32)p->sport;
    k->protocol=6;
    return first?0:1;
}
#endif
