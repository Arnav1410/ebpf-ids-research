/* Separate translation unit: generated kernel types must not collide with
 * libc/UAPI types in the native controller. The UAPI prefix stays stable while
 * a newer kernel can append output fields to __sk_buff. */
#define BPF_NO_PRESERVE_ACCESS_INDEX
#include <vmlinux.h>
#include "nn_context.h"

struct nn_context_abi nn_kernel_context_abi(void)
{
	return (struct nn_context_abi) {
		.size = sizeof(struct __sk_buff),
		.cb_offset = __builtin_offsetof(struct __sk_buff, cb),
	};
}
