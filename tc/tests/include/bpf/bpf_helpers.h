#include "../../../../validation/include/bpf/bpf_helpers.h"
int tc_test_load(void *, unsigned int, void *, unsigned int);
#define bpf_skb_load_bytes tc_test_load
/* Host helper dispatch returns; a successful real tail call never returns. */
#undef bpf_tail_call
#define bpf_tail_call(ctx, map, slot) do { validation_tail_call((struct xdp_md *)(ctx), map, slot); return 0; } while (0)
