/* Private kernel test-runs, separate evidence from attached packet tests. */
static int kc_reverse_packet(int fd,unsigned port,unsigned char flags,int malformed)
{
    unsigned char p[54]={},out[128];
    p[12]=8;p[14]=0x45;p[17]=40;p[22]=64;p[23]=6;
    p[26]=33;p[27]=33;p[28]=33;p[29]=1;p[30]=33;p[31]=33;p[32]=33;p[33]=73;
    p[34]=5001>>8;p[35]=5001&255;p[36]=port>>8;p[37]=port;p[46]=0x50;p[47]=flags;
    if(malformed==1)p[14]=0x44;
    if(malformed==2)p[20]=0x20;
    if(malformed==3)p[46]=0x40;
    LIBBPF_OPTS(bpf_test_run_opts,o,.data_in=p,.data_out=out,
                .data_size_in=sizeof(p),.data_size_out=sizeof(out),.repeat=1);
    KC(!bpf_prog_test_run_opts(fd,&o)&&o.retval==TC_ACT_OK,"egress test-run passes");
    return 0;
}

struct kb_worker {int fd,cpu,port,calls,reverse,error;atomic_int *start;};
static void *kb_work(void *arg)
{
    struct kb_worker *w=arg;cpu_set_t set;CPU_ZERO(&set);CPU_SET(w->cpu,&set);
    if(pthread_setaffinity_np(pthread_self(),sizeof(set),&set))w->error=1;
    int start;while(!(start=atomic_load(w->start)))sched_yield();
    if(start<0||w->error)return NULL;
    if(sched_getcpu()!=w->cpu){w->error=1;return NULL;}
    for(int i=0;i<w->calls;++i){
        int flags=i==w->calls-1?(w->reverse?4:0x11):0x10;
        if(w->reverse?kc_reverse_packet(w->fd,w->port,flags,0):kc_packet(w->fd,w->port,flags,0)){
            w->error=1;break;
        }
    }
    return NULL;
}

static int kb_parallel(int ingress,int egress,int flows,int distinct)
{
    cpu_set_t allowed;KC(!sched_getaffinity(0,sizeof(allowed),&allowed),"bidirectional affinity");
    int cpus[CPU_SETSIZE],nc=0;
    for(int i=0;i<CPU_SETSIZE;++i)if(CPU_ISSET(i,&allowed))cpus[nc++]=i;
    KC(nc>=2,"bidirectional SMP requires two CPUs");
    int n=distinct?20:4,calls=distinct?65:257,created=0,failed=0;
    struct kb_worker w[20];pthread_t threads[20];atomic_int start=0;
    for(int i=0;i<n;++i){
        w[i]=(struct kb_worker){.fd=i%2?egress:ingress,.cpu=cpus[i%nc],
            .port=distinct?47100+i/2:47000,.calls=calls,.reverse=i%2,.start=&start};
        if(pthread_create(&threads[i],NULL,kb_work,&w[i])){failed=1;break;}created++;
    }
    atomic_store(&start,failed?-1:1);
    for(int i=0;i<created;++i){pthread_join(threads[i],NULL);failed|=w[i].error;}
    KC(!failed&&created==n,"bidirectional worker completion");
    for(int i=0;i<(distinct?10:1);++i){
        struct tc_key key=kc_key(distinct?47100+i:47000);struct tc_flow f={};
        KC(!bpf_map_lookup_elem_flags(flows,&key,&f,BPF_F_LOCK),"bidirectional locked read");
        u64 packets=distinct?calls:2*calls;
        KC(f.hooks[0].packets==packets&&f.hooks[1].packets==packets,"shared canonical key, separate hooks");
        KC(f.hooks[0].bytes==54*packets&&f.hooks[1].bytes==54*packets,"directional skb bytes");
        KC(f.endpoint_packets[0]==packets&&f.endpoint_packets[1]==packets,"endpoint/hook direction");
        KC(f.packets==packets&&f.bytes==20*packets&&f.header_length==20*packets,"egress excluded from features");
        KC(f.state==TC_DONE&&f.sequence==1&&!f.failures&&f.duplicates==(u64)(distinct?0:1),"isolated single inference");
    }
    printf("{\"event\":\"kernel_case\",\"name\":\"%s\",\"workers\":%d,\"calls_per_worker\":%d,\"assertions\":\"PASS\",\"cpu_affinities\":[",
           distinct?"bidirectional_distinct_flows":"bidirectional_same_flow",n,calls);
    for(int i=0;i<n;++i)printf("%s%d",i?",":"",w[i].cpu);
    printf("],\"interleaving\":\"CPU-pinned opportunity; exact overlap not forced\"}\n");
    return 0;
}

static int kernel_bidirectional_checks(struct bpf_object *obj)
{
    int ingress=bpf_program__fd(bpf_object__find_program_by_name(obj,"tc_entry"));
    int egress=bpf_program__fd(bpf_object__find_program_by_name(obj,"tc_egress"));
    int flows=bpf_object__find_map_fd_by_name(obj,"flow_map"),ws=bpf_object__find_map_fd_by_name(obj,"workspace");
    int result_fd=bpf_object__find_map_fd_by_name(obj,"results");
    KC(!kc_fixed(obj,flows,ws),"fixed vectors unchanged");
    KC(!kb_parallel(ingress,egress,flows,0)&&!kb_parallel(ingress,egress,flows,1),"bidirectional parallel cases");
    KC(!kc_workspaces(ws,0),"bidirectional workspace release");
    unsigned port=48000;struct tc_key key=kc_key(port);struct tc_flow f={};
    KC(!kc_reverse_packet(egress,port,1,0)&&!kc_reverse_packet(egress,port,4,0),"egress first FIN/RST");
    KC(!bpf_map_lookup_elem_flags(flows,&key,&f,BPF_F_LOCK),"egress-only shared flow");
    KC(!f.input_initialized&&!f.packets&&!f.sequence&&f.state==TC_IDLE&&f.hooks[1].packets==2,"egress cannot trigger or define MLP leg");
    KC(!kc_packet(ingress,port,2,0)&&!kc_packet(ingress,port,0x11,0),"ingress after egress inference");
    struct tc_result before,after;
    KC(!bpf_map_lookup_elem(result_fd,&key,&before),"shared flow prediction");
    KC(!kc_reverse_packet(egress,port,0x11,0),"post-inference egress FIN passes");
    KC(!bpf_map_lookup_elem(result_fd,&key,&after)&&!memcmp(&before,&after,sizeof(before)),"egress does not mutate inference");
    kc_pass("egress_first_and_duplicate_result_immutable");
    for(int i=1;i<=3;++i)KC(!kc_reverse_packet(egress,48100+i,4,i),"malformed egress passes");
    kc_pass("malformed_egress_pass_unscored");
    int filled=0;struct tc_flow empty={};
    for(int i=0;i<TC_FLOW_CAPACITY;++i){
        struct tc_key fake={.a_addr=1,.b_addr=2,.a_port=i,.b_port=3,.protocol=6};
        if(bpf_map_update_elem(flows,&fake,&empty,BPF_NOEXIST)){KC(errno==E2BIG||errno==ENOSPC,"egress capacity error");break;}
        filled++;
    }
    KC(filled>0&&filled<TC_FLOW_CAPACITY,"egress capacity reached");
    KC(!kc_reverse_packet(egress,49000,4,0),"full egress map passes packet");key=kc_key(49000);
    KC(bpf_map_lookup_elem_flags(flows,&key,&f,BPF_F_LOCK)&&errno==ENOENT,"full egress flow not inserted");
    for(int i=0;i<filled;++i){struct tc_key fake={.a_addr=1,.b_addr=2,.a_port=i,.b_port=3,.protocol=6};KC(!bpf_map_delete_elem(flows,&fake),"capacity fixture removal");}
    kc_pass("egress_flow_capacity_pass");
    KC(!kc_workspaces(ws,0),"final bidirectional workspace release");
    return snapshot(obj,0);
}
