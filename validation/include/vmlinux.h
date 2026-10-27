/* Host-only ABI for compiling the unchanged detector in an offline harness.
 * This is deliberately NOT a replacement kernel/vmlinux header. */
#ifndef VALIDATION_VMLINUX_H
#define VALIDATION_VMLINUX_H
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
typedef uint64_t u64;
typedef uint32_t u32;
typedef int64_t s64;
typedef int32_t s32;
struct xdp_md { uintptr_t data, data_end; };
#define XDP_PASS 2
#define BPF_MAP_TYPE_HASH 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PROG_ARRAY 3
#define BPF_NOEXIST 1
#define LIBBPF_PIN_BY_NAME 1
#endif
