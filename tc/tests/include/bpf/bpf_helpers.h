#include "../../../../validation/include/bpf/bpf_helpers.h"
int tc_test_load(void *, unsigned int, void *, unsigned int);
#define bpf_skb_load_bytes tc_test_load
void tc_test_lock(struct bpf_spin_lock *);
void tc_test_unlock(struct bpf_spin_lock *);
int tc_test_tail(void *, unsigned int);
#define bpf_spin_lock(lock) tc_test_lock(lock)
#define bpf_spin_unlock(lock) tc_test_unlock(lock)
#define bpf_get_smp_processor_id() 0
/* Host helper dispatch returns; a successful real tail call never returns. */
#undef bpf_tail_call
#define bpf_tail_call(ctx, map, slot) do { if (tc_test_tail(ctx, slot)) return 0; } while (0)
