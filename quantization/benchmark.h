/* Host controller only. Timed execution is in the original kernel programs.
 * Private, unattached maps are reseeded BETWEEN repeat=1 calls, never timed. */
static int bench_delete(int fd,const struct tc_key *key)
{
    if(!bpf_map_delete_elem(fd,key) || errno==ENOENT)return 0;
    return die("benchmark private-key removal");
}

static int bench_measure(struct bpf_object *obj,int cpu,int entry,int warm,int samples,const s64 raw[6])
{
    cpu_set_t allowed,set;CPU_ZERO(&set);
    KC(!sched_getaffinity(0,sizeof(allowed),&allowed)&&cpu>=0&&cpu<CPU_SETSIZE&&CPU_ISSET(cpu,&allowed),"benchmark CPU allowed");
    CPU_SET(cpu,&set);KC(!sched_setaffinity(0,sizeof(set),&set),"pin benchmark process only");
    int cpus=libbpf_num_possible_cpus();KC(cpus>cpu,"benchmark per-CPU index");
    struct tc_workspace *values=calloc(cpus,sizeof(*values));u32 *times=calloc(samples,sizeof(*times));
    if(!values||!times){free(values);free(times);return die("benchmark allocation");}
    int rc=1,zero=0;
    int ws=bpf_object__find_map_fd_by_name(obj,"workspace"),flows=bpf_object__find_map_fd_by_name(obj,"flow_map");
    int results_fd=bpf_object__find_map_fd_by_name(obj,"results"),stats=bpf_object__find_map_fd_by_name(obj,"stats");
    struct ids_tc_stats before={},after={};struct tc_result first={},last={};
    struct tc_key key=kc_key(49500);
    if(bpf_map_lookup_elem(stats,&zero,&before)){die("benchmark initial counters");goto done;}
    int fd=bpf_program__fd(bpf_object__find_program_by_name(obj,entry?"tc_entry":"tc_preprocessing"));
    for(int iteration=0;iteration<warm+samples;++iteration){
        if(exiting){fprintf(stderr,"Benchmark interrupted\n");goto done;}
        memset(values,0,cpus*sizeof(*values));
        struct tc_flow state={.state=entry?TC_IDLE:TC_RUNNING,.sequence=entry?0:1,
            .min_length=0x3fffffffffffffffULL,.input=kc_tuple(49500),.input_initialized=1,.input_direction=1};
        if(!entry){
            values[cpu].busy=1;values[cpu].record.key=key;
            values[cpu].record.input=kc_tuple(49500);values[cpu].record.sequence=1;
            values[cpu].record.cpu=cpu;values[cpu].record.input_direction=1;
            memcpy(values[cpu].record.features,raw,sizeof(values[cpu].record.features));
        }
        if(bench_delete(flows,&key)||bench_delete(results_fd,&key)
           || bpf_map_update_elem(flows,&key,&state,BPF_NOEXIST)
           || bpf_map_update_elem(ws,&zero,values,BPF_ANY)){die("benchmark quiescent state seed");goto done;}
        unsigned char packet[54]={},out[128];
        packet[12]=8;packet[14]=0x45;packet[17]=40;packet[22]=64;packet[23]=6;
        packet[26]=33;packet[27]=33;packet[28]=33;packet[29]=73;
        packet[30]=33;packet[31]=33;packet[32]=33;packet[33]=1;
        packet[34]=49500>>8;packet[35]=49500&255;packet[36]=5001>>8;packet[37]=5001&255;
        packet[46]=0x50;packet[47]=0x11;
        LIBBPF_OPTS(bpf_test_run_opts,opts,.data_in=packet,.data_out=out,
                    .data_size_in=sizeof(packet),.data_size_out=sizeof(out),.repeat=1);
        if(sched_getcpu()!=cpu || bpf_prog_test_run_opts(fd,&opts) || opts.retval!=TC_ACT_OK){die("benchmark kernel invocation");goto done;}
        if(bpf_map_lookup_elem(results_fd,&key,&last) || last.stage_mask!=63 || last.sequence!=1
           || last.cpu!=(u32)cpu || last.model_slot!=0 || memcmp(&last.key,&key,sizeof(key))
           || memcmp(last.features,raw,sizeof(last.features))){fprintf(stderr,"Benchmark skipped/corrupted inference\n");goto done;}
        if(!iteration)first=last;
        else if(first.label!=last.label || memcmp(first.tensors,last.tensors,sizeof(first.tensors))){fprintf(stderr,"Benchmark tensors changed on identical input\n");goto done;}
        if(bpf_map_lookup_elem(ws,&zero,values) || values[cpu].busy){fprintf(stderr,"Benchmark workspace ownership leak\n");goto done;}
        if(bpf_map_lookup_elem_flags(flows,&key,&state,BPF_F_LOCK) || state.state!=TC_DONE || state.failures){fprintf(stderr,"Benchmark incomplete flow state\n");goto done;}
        if(iteration>=warm)times[iteration-warm]=opts.duration;
    }
    if(bpf_map_lookup_elem(stats,&zero,&after)){die("benchmark final counters");goto done;}
    u64 calls=warm+samples;
    if(after.predictions-before.predictions!=calls || after.tail_failures!=before.tail_failures
       || after.inference_failures!=before.inference_failures || after.workspace_busy!=before.workspace_busy
       || after.result_failures!=before.result_failures || after.flow_full!=before.flow_full){fprintf(stderr,"Benchmark inference accounting failed\n");goto done;}
    for(int i=0;i<6;++i)if(after.stages[i]-before.stages[i]!=calls){fprintf(stderr,"Benchmark tail stage skipped\n");goto done;}
    if(entry && (after.packets-before.packets!=calls || after.matched-before.matched!=calls)){fprintf(stderr,"Benchmark entry path skipped\n");goto done;}
    printf("{\"event\":\"benchmark_block\",\"mode\":\"%s\",\"cpu\":%d,\"kind\":\"%s\","
           "\"warmup\":%d,\"samples\":%d,\"kernel_repeat\":1,\"prediction_delta\":%llu,\"stage_deltas\":[",
           INFERENCE_MODE,cpu,entry?"entry":"mlp",warm,samples,(unsigned long long)calls);
    for(int i=0;i<6;++i)printf("%s%llu",i?",":"",(unsigned long long)(after.stages[i]-before.stages[i]));
    printf("],\"duration_ns\":[");for(int i=0;i<samples;++i)printf("%s%u",i?",":"",times[i]);
    printf("],\"record\":");print_record(&last);printf("}\n");
    rc=0;
done:
    free(values);free(times);return rc;
}

static int bench_serve(struct bpf_object *obj)
{
    cpu_set_t allowed;KC(!sched_getaffinity(0,sizeof(allowed),&allowed),"benchmark affinity");
    printf("{\"event\":\"benchmark_ready\",\"mode\":\"%s\",\"allowed_cpus\":[",INFERENCE_MODE);
    int n=0;for(int cpu=0;cpu<CPU_SETSIZE;++cpu)if(CPU_ISSET(cpu,&allowed))printf("%s%d",n++?",":"",cpu);
    printf("],\"network_attachments\":false}\n");
    char line[512];
    while(!exiting && fgets(line,sizeof(line),stdin)){
        if(!strcmp(line,"stop\n"))return 0;
        char *save=NULL,*token=strtok_r(line," \t\r\n",&save);
        if(!token || strcmp(token,"measure")){fprintf(stderr,"Expected benchmark measure/stop\n");return 1;}
        s64 fields[10];
        for(int i=0;i<10;++i){
            token=strtok_r(NULL," \t\r\n",&save);char *end=NULL;errno=0;
            if(!token){fprintf(stderr,"Incomplete benchmark command\n");return 1;}
            fields[i]=strtoll(token,&end,10);
            if(errno || !end || *end){fprintf(stderr,"Invalid benchmark integer\n");return 1;}
        }
        if(strtok_r(NULL," \t\r\n",&save) || fields[0]<0 || fields[0]>=CPU_SETSIZE
           || fields[1]<0 || fields[1]>1 || fields[2]<0 || fields[2]>128 || fields[3]<1 || fields[3]>256){
            fprintf(stderr,"Benchmark bounds exceeded\n");return 1;
        }
        if(bench_measure(obj,fields[0],fields[1],fields[2],fields[3],&fields[4]))return 1;
    }
    return exiting?1:0;
}
