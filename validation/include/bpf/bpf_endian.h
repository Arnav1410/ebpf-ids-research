#ifndef VALIDATION_BPF_ENDIAN_H
#define VALIDATION_BPF_ENDIAN_H
#include <arpa/inet.h>
#define bpf_htons htons
#define bpf_ntohs ntohs
#define bpf_ntohl ntohl
#endif
