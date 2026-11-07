#ifndef LS_ARITHMETIC_H
#define LS_ARITHMETIC_H
/* Shared host/BPF arithmetic. Caller provides stdint types (or vmlinux.h).
 * No floating point, negative signed shifts, wrap or saturating predictions. */
#define LS_OK 0
#define LS_CONFIG 1
#define LS_RANGE 2
#define LS_OVERFLOW 3
#define LS_PARAMETERS 4
#define LS_I64_MAX ((int64_t)0x7fffffffffffffffLL)
#define LS_I64_MIN (-LS_I64_MAX-1)
#define LS_I32_MAX 2147483647
#define LS_I32_MIN (-2147483647-1)
#define LS_U64_MAX (~(uint64_t)0)
#define LS_INLINE static inline __attribute__((always_inline))

struct ls_metadata {
    uint32_t magic, version, q_normalized, q_weight[3], q_output[3], reserved;
    uint64_t delta_limit[6];
};
struct ls_diagnostic_counters { uint64_t errors[4]; };

LS_INLINE int ls_valid(const struct ls_metadata *m)
{
    if(m->magic!=0x4c535031 || m->version!=1 || m->reserved || m->q_normalized>24)return LS_CONFIG;
    uint32_t q=m->q_normalized;
    #pragma clang loop unroll(full)
    for(int i=0;i<3;++i){
        if(m->q_weight[i]!=16 || m->q_output[i]>30 || m->q_output[i]>q+16
           || q+16-m->q_output[i]>62)return LS_CONFIG;
        q=m->q_output[i];
    }
    #pragma clang loop unroll(full)
    for(int j=0;j<6;++j)
        if(!m->delta_limit[j] || m->delta_limit[j]>(uint64_t)LS_I64_MAX)return LS_CONFIG;
    return LS_OK;
}

LS_INLINE int ls_signed32(uint64_t magnitude,int negative,int32_t *out)
{
    if(negative){
        if(magnitude>2147483648ULL)return LS_OVERFLOW;
        *out=magnitude==2147483648ULL?LS_I32_MIN:-(int32_t)magnitude;
    }else{
        if(magnitude>(uint64_t)LS_I32_MAX)return LS_OVERFLOW;
        *out=(int32_t)magnitude;
    }
    return LS_OK;
}

LS_INLINE int ls_round_shift(int64_t value,uint32_t bits,int32_t *out)
{
    if(bits>62)return LS_CONFIG;
    uint64_t magnitude=value<0?(uint64_t)0-(uint64_t)value:(uint64_t)value;
    if(bits){
        uint64_t quotient=magnitude>>bits;
        uint64_t remainder=magnitude&(((uint64_t)1<<bits)-1);
        uint64_t half=(uint64_t)1<<(bits-1);
        if(remainder>half || (remainder==half && (quotient&1)))quotient++;
        magnitude=quotient;
    }
    return ls_signed32(magnitude,value<0,out);
}

LS_INLINE int ls_add(int64_t a,int64_t b,int64_t *out)
{
    if((b>0 && a>LS_I64_MAX-b) || (b<0 && a<LS_I64_MIN-b))return LS_OVERFLOW;
    *out=a+b;return LS_OK;
}

LS_INLINE int ls_normalize(const int64_t *x,int32_t *y,const int64_t *mean,
                           const int64_t *scale,const struct ls_metadata *m)
{
    if(ls_valid(m))return LS_CONFIG;
    uint32_t q=m->q_normalized;
    #pragma clang loop unroll(full)
    for(int j=0;j<6;++j){
        if(scale[j]<=0)return LS_CONFIG;
        int negative=x[j]<mean[j];
        uint64_t magnitude=negative?(uint64_t)mean[j]-(uint64_t)x[j]:(uint64_t)x[j]-(uint64_t)mean[j];
        if(magnitude>m->delta_limit[j])return LS_RANGE;
        uint64_t divisor=(uint64_t)scale[j],whole=magnitude/divisor,remainder=magnitude%divisor;
        if(whole>(LS_U64_MAX>>q) || remainder>(LS_U64_MAX>>q))return LS_OVERFLOW;
        uint64_t fraction=remainder<<q,base=whole<<q,quotient=fraction/divisor;
        if(base>LS_U64_MAX-quotient)return LS_OVERFLOW;
        base+=quotient;remainder=fraction%divisor;
        if(remainder>divisor-remainder || (remainder==divisor-remainder && (base&1))){
            if(base==LS_U64_MAX)return LS_OVERFLOW;
            base++;
        }
        int error=ls_signed32(base,negative,&y[j]);if(error)return error;
    }
    return LS_OK;
}

LS_INLINE int ls_linear(const int32_t *weights,const int32_t *x,int32_t *y,
                        int rows,int columns,uint32_t shift)
{
    if(rows<1 || rows>32 || columns<1 || columns>32 || shift>62)return LS_CONFIG;
    /* BPF call sites have constant dimensions. Generic host primitive exports
     * also accept dynamic toy dimensions, for which forced unrolling is invalid. */
    #ifdef __bpf__
    #pragma clang loop unroll(full)
    #endif
    for(int i=0;i<rows;++i){
        int64_t total=0;
        for(int j=0;j<columns;++j){
            int64_t product=(int64_t)weights[i*columns+j]*(int64_t)x[j];
            if(ls_add(total,product,&total))return LS_OVERFLOW;
        }
        int error=ls_round_shift(total,shift,&y[i]);if(error)return error;
    }
    return LS_OK;
}
#endif
