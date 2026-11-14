/* Host-only exports of the SAME integer header used by experimental BPF. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#define LS_HOST
#include "params.bpf.h"
#include "calibrated.h"
#include "../src/mlp_params.bpf.h"
static struct Net model;
void ls_native_reset(void)
{
    memset(&model,0,sizeof(model));
    memcpy(model.layer_0_weight,layer_0_weight,sizeof(layer_0_weight));
    memcpy(model.layer_1_weight,layer_1_weight,sizeof(layer_1_weight));
    memcpy(model.layer_2_weight,layer_2_weight,sizeof(layer_2_weight));
    memcpy(model.mean,mean,sizeof(mean));memcpy(model.scale,scale,sizeof(scale));
    model.calibration=ls_calibrated_metadata;
}
int ls_native_shift(int64_t value,uint32_t bits,int32_t *out){return ls_round_shift(value,bits,out);}
int ls_native_add(int64_t a,int64_t b,int64_t *out){return ls_add(a,b,out);}
int ls_native_normalize(int64_t *raw,int64_t *mu,int64_t *scale,uint32_t q,uint64_t *limits,int32_t *out)
{
    struct ls_metadata m=ls_calibrated_metadata;m.q_normalized=q;
    /* This primitive test keeps valid scale transitions when q is small. */
    if(q<=24){m.q_output[0]=q;m.q_output[1]=q;m.q_output[2]=q;}
    memcpy(m.delta_limit,limits,6*sizeof(*limits));return ls_normalize(raw,out,mu,scale,&m);
}
int ls_native_linear(int32_t *w,int32_t *x,int32_t *out,int rows,int columns,uint32_t bits)
{return ls_linear(w,x,out,rows,columns,bits);}
unsigned ls_native_packed(unsigned char *out){memcpy(out,&model,sizeof(model));return sizeof(model);}
void ls_native_invalid_metadata(int kind)
{
    model.calibration=ls_calibrated_metadata;
    if(kind==1)model.calibration.q_normalized=64;
    if(kind==2)model.calibration.magic=0;
    if(kind==3)model.calibration.q_weight[1]=15;
    if(kind==4)model.calibration.q_output[2]=63;
}
int ls_native_mlp(int64_t *raw,int32_t *out,int32_t *label)
{
    int error=ls_normalize(raw,out,model.mean,model.scale,&model.calibration);if(error)return error;
    int32_t *weights[]={model.layer_0_weight,model.layer_1_weight,model.layer_2_weight};
    const int rows[]={32,32,2},columns[]={6,32,32},input_offset[]={0,64,128},output_offset[]={32,96,160};
    uint32_t q=model.calibration.q_normalized;
    for(int layer=0;layer<3;++layer){
        uint32_t next=model.calibration.q_output[layer];
        error=ls_linear(weights[layer],out+input_offset[layer],out+output_offset[layer],rows[layer],columns[layer],q+16-next);
        if(error)return error;
        if(layer<2)for(int j=0;j<32;++j){int32_t value=out[output_offset[layer]+j];out[output_offset[layer]+32+j]=value>0?value:0;}
        q=next;
    }
    *label=out[160]>out[161]?0:1;return LS_OK;
}

/* Standalone UBSan driver: all stdin records are fixed int64[6] rows. */
int main(void)
{
    ls_native_reset();int64_t raw[6],sum;int32_t out[192],label,rounded;unsigned records=0;
    assert(ls_add(LS_I64_MAX,1,&sum)==LS_OVERFLOW);
    assert(ls_add(LS_I64_MIN,-1,&sum)==LS_OVERFLOW);
    assert(!ls_round_shift(LS_I64_MIN,32,&rounded)&&rounded==LS_I32_MIN);
    assert(ls_round_shift(LS_I64_MAX,32,&rounded)==LS_OVERFLOW);
    int32_t weights[]={LS_I32_MIN,LS_I32_MIN},input[]={LS_I32_MIN,LS_I32_MIN};
    assert(ls_linear(weights,input,&rounded,1,2,32)==LS_OVERFLOW);
    size_t count;
    while((count=fread(raw,sizeof(*raw),6,stdin))==6){
        assert(!ls_native_mlp(raw,out,&label));records++;
    }
    assert(!count&&!ferror(stdin));printf("UBSan: %u supported network fixtures; boundary guards passed\n",records);
    return 0;
}
