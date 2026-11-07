/* Validation only: private test-runs reject bad inputs without attaching. */
static int kernel_numerical_checks(struct bpf_object *obj)
{
    int cpus=libbpf_num_possible_cpus();KC(cpus>0,"numerical CPUs");
    struct tc_workspace *values=calloc(cpus,sizeof(*values));KC(values,"numerical workspace allocation");
    int work=bpf_object__find_map_fd_by_name(obj,"workspace"),flows=bpf_object__find_map_fd_by_name(obj,"flow_map");
    int results_fd=bpf_object__find_map_fd_by_name(obj,"results");u32 zero=0;
    for(int test=0;test<8;++test){
        unsigned port=49010+test;struct tc_key key=kc_key(port);
        struct tc_flow state={.state=TC_RUNNING,.sequence=1,.input=kc_tuple(port),.input_initialized=1,.input_direction=1};
        KC(!bpf_map_update_elem(flows,&key,&state,BPF_NOEXIST),"numerical fixture flow");
        for(int cpu=0;cpu<cpus;++cpu){
            values[cpu]=(struct tc_workspace){};values[cpu].busy=1;
            values[cpu].next_stage=test==7?1:0;values[cpu].record.key=key;
            values[cpu].record.input=kc_tuple(port);values[cpu].record.sequence=1;
            values[cpu].record.model_slot=test==6?2:0;
            for(int j=0;j<6;++j)values[cpu].record.features[j]=mean[j];
            if(test<6)values[cpu].record.features[test]+=(s64)ls_calibrated_metadata.delta_limit[test]+1;
            if(test==7)for(int j=0;j<6;++j)values[cpu].hidden2[j]=layer_0_weight[j]>=0?LS_I32_MAX:LS_I32_MIN;
        }
        KC(!bpf_map_update_elem(work,&zero,values,BPF_ANY),"seed invalid numerical fixture");
        const char *name=test==7?"tc_input_linear":"tc_preprocessing";
        int fd=bpf_program__fd(bpf_object__find_program_by_name(obj,name));
        KC(!kc_packet(fd,port,0x11,0),"invalid numerical input still passes packet");
        KC(!kc_flow(flows,port,TC_IDLE,1,1),"invalid inference state unwinds");
        struct tc_result result;
        KC(bpf_map_lookup_elem(results_fd,&key,&result)&&errno==ENOENT,"invalid inference must not publish prediction");
        KC(!bpf_map_lookup_elem(work,&zero,values),"numerical workspace readback");
        int released=0;for(int cpu=0;cpu<cpus;++cpu)released+=values[cpu].busy==0;
        KC(released==1,"failed inference releases executing CPU ownership");
        memset(values,0,cpus*sizeof(*values));
        KC(!bpf_map_update_elem(work,&zero,values,BPF_ANY),"reset validation-only workspace seeds");
    }
    free(values);
    kc_pass("six_out_of_domain_features_rejected");kc_pass("missing_parameter_rejected");kc_pass("unsafe_linear_narrow_rejected");
    return snapshot(obj,0);
}
