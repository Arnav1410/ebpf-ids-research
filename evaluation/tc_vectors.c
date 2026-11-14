/* Validation only: compile the actual TC source and its existing host mocks.
 * Precomputed features bypass packet parsing; this is NOT kernel execution. */
#include "../tc/tests/native.c"
int vector_infer(const int64_t raw[6],int32_t tensors[192],int32_t *label)
{
    host_reset();
    struct flow input={.saddr=__builtin_bswap32(555819337),.daddr=__builtin_bswap32(555819265),
        .sport=__builtin_bswap16(48000),.dport=__builtin_bswap16(5001)};
    tc_key_build(&input,&last_key);
    struct tc_flow state={.state=TC_RUNNING,.sequence=1,.input=input,.input_initialized=1,.input_direction=1};
    if(validation_update(&flow_map,&last_key,&state,BPF_NOEXIST))return 1;
    work.busy=1;work.next_stage=0;work.record.key=last_key;work.record.input=input;
    work.record.sequence=1;work.record.model_slot=0;memcpy(work.record.features,raw,48);
    struct __sk_buff skb={};tc_preprocessing(&skb);
    struct tc_result *r=validation_lookup(&results,&last_key);
    if(!r||r->stage_mask!=63||counters.predictions!=1||work.busy)return 2;
    memcpy(tensors,r->tensors,sizeof(r->tensors));*label=r->label;return 0;
}
