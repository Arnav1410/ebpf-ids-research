#ifndef LS_PARAMS_BPF_H
#define LS_PARAMS_BPF_H
#include "arithmetic.h"
/* Distinct experimental layout. Original Q16 struct/header is untouched. */
struct Net {
    int32_t layer_0_weight[192],layer_1_weight[1024],layer_2_weight[64];
    int64_t mean[6],scale[6];
    struct ls_metadata calibration;
};
#ifndef LS_HOST
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __type(key,int32_t);
    __type(value,struct Net);
    __uint(max_entries,2);
} nn_parameters SEC(".maps");
struct {
    __uint(type,BPF_MAP_TYPE_ARRAY);
    __type(key,int32_t);
    __type(value,int32_t);
    __uint(max_entries,1);
} nn_idx SEC(".maps");
#endif
#endif
