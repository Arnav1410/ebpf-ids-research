/* Offline validation only. Actual feature helpers under established host mocks.
 * No socket, BPF syscall or inference is executed. Source-IP filtering is outside
 * this per-connection feature probe and direction is supplied by the cohort.
 */
#ifdef PROBE_TC
#include "../../tc/tests/native.c"
void probe_reset(void)
{
    host_reset();
    host_filter(0, 0);
    host_missing_slot(0); /* Keep the NN out of the feature-validation gate. */
}
int probe_packet(const unsigned char *data, unsigned len, uint64_t ns)
{
    return host_packet(data, len, ns);
}
int probe_features(int64_t out[6])
{
    struct tc_flow *f = validation_lookup(&flow_map, &last_key);
    if (!f) return -1;
    out[0] = f->max_length; out[1] = f->max_duration; out[2] = f->min_length;
    out[3] = __builtin_bswap16((uint16_t)f->input.dport);
    out[4] = f->header_length; out[5] = f->packets;
    return counters.predictions ? -2 : 0;
}
#else
#include "../../validation/native.c"
void probe_reset(void) { native_reset(); }
int probe_packet(const unsigned char *data, unsigned len, uint64_t ns)
{
    struct xdp_md ctx = {(uintptr_t)data, (uintptr_t)data + len};
    struct flow f = {};
    if (flow_tuple(&ctx, &f)) return -1;
    const struct iphdr *ip = (const void *)(data + sizeof(struct ethhdr));
    struct tcphdr *tcp = (void *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    timestamp = ns;
    update_flow_attribute(&f, tcp, ntohs(ip->tot_len) - ip->ihl * 4);
    return 0;
}
int probe_features(int64_t out[6])
{
    int64_t all[8];
    if (native_flow(0, all)) return -1;
    memcpy(out, all, 6 * sizeof(*out));
    return predictions ? -2 : 0;
}
#endif
