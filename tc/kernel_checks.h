/* Actual private SCHED_CLS test-runs; no attachments. The entry program invokes
 * populated tail slots. Affinity uses pthreads, not unsupported skb test flags. */
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#define KC(expr, msg) do { if (!(expr)) { fprintf(stderr,"Kernel case failed: %s errno=%d\n",msg,errno); return 1; } } while(0)
static struct flow kc_tuple(unsigned port)
{
    return (struct flow){.saddr=(int)htonl(555819337),.daddr=(int)htonl(555819265),
        .sport=htons(port),.dport=htons(5001)};
}
static struct tc_key kc_key(unsigned port)
{
    struct flow tuple=kc_tuple(port);struct tc_key key={};tc_key_build(&tuple,&key);return key;
}
static int kc_packet(int fd, unsigned port, unsigned char flags, int malformed)
{
    unsigned char p[54]={}, out[128];
    p[12]=8;p[14]=0x45;p[17]=40;p[22]=64;p[23]=6;
    p[26]=33;p[27]=33;p[28]=33;p[29]=73;p[30]=33;p[31]=33;p[32]=33;p[33]=1;
    p[34]=port>>8;p[35]=port;p[36]=5001>>8;p[37]=5001&255;p[46]=0x50;p[47]=flags;
    if(malformed==1)p[14]=0x44;
    if(malformed==2)p[20]=0x20;
    if(malformed==3)p[46]=0x40;
    LIBBPF_OPTS(bpf_test_run_opts,o,.data_in=p,.data_out=out,
        .data_size_in=sizeof(p),.data_size_out=sizeof(out),.repeat=1);
    int rc=bpf_prog_test_run_opts(fd,&o);
    if(rc||o.retval!=TC_ACT_OK){fprintf(stderr,"TC test-run rc=%d action=%u errno=%d\n",rc,o.retval,errno);return 1;}
    return 0;
}
struct kc_worker {int fd,cpu,port,calls,error;atomic_int *start;};
static void *kc_work(void *arg)
{
    struct kc_worker *w=arg;cpu_set_t set;CPU_ZERO(&set);CPU_SET(w->cpu,&set);
    if(pthread_setaffinity_np(pthread_self(),sizeof(set),&set))w->error=1;
    int start;while(!(start=atomic_load(w->start)))sched_yield();
    if(start<0||w->error)return NULL;
    if(sched_getcpu()!=w->cpu){w->error=1;return NULL;}
    for(int i=0;i<w->calls;++i)if(kc_packet(w->fd,w->port,i==w->calls-1?0x11:0x10,0)){w->error=1;break;}
    return NULL;
}
static int kc_flow(int fd,unsigned port,u32 state,u64 sequence,u64 failures)
{
    struct tc_key k=kc_key(port);struct tc_flow f={};
    KC(!bpf_map_lookup_elem_flags(fd,&k,&f,BPF_F_LOCK),"locked flow readback");
    KC(f.state==state&&f.sequence==sequence&&f.failures==failures,"flow state machine");return 0;
}
static int kc_parallel(int fd,int distinct,int flow_fd)
{
    cpu_set_t allowed;KC(!sched_getaffinity(0,sizeof(allowed),&allowed),"CPU affinity");
    int cpus[CPU_SETSIZE],nc=0;
    for(int i=0;i<CPU_SETSIZE;++i)if(CPU_ISSET(i,&allowed))cpus[nc++]=i;
    KC(nc>=2,"SMP test requires two allowed CPUs");
    int n=distinct?10:4,calls=distinct?65:257,created=0,failed=0;
    struct kc_worker w[10];pthread_t t[10];atomic_int start=0;
    for(int i=0;i<n;++i){
        w[i]=(struct kc_worker){.fd=fd,.cpu=cpus[i%nc],.port=distinct?42000+i:41000,.calls=calls,.start=&start};
        if(pthread_create(&t[i],NULL,kc_work,&w[i])){failed=1;break;}created++;
    }
    atomic_store(&start,failed?-1:1);
    for(int i=0;i<created;++i){pthread_join(t[i],NULL);failed|=w[i].error;}
    KC(!failed&&created==n,"workers");
    for(int i=0;i<(distinct?n:1);++i){
        struct tc_key k=kc_key(distinct?42000+i:41000);struct tc_flow f={};
        KC(!bpf_map_lookup_elem_flags(flow_fd,&k,&f,BPF_F_LOCK),"parallel readback");
        KC(f.packets==(u64)(distinct?calls:n*calls)&&f.bytes==f.packets*20,"lost updates");
        KC(f.state==TC_DONE&&f.sequence==1&&!f.failures&&f.duplicates==(u64)(distinct?0:n-1),"duplicate/running inference");
    }
    printf("{\"event\":\"kernel_case\",\"name\":\"%s\",\"workers\":%d,\"calls_per_worker\":%d,\"cpu_affinities\":[",
           distinct?"distinct_flows":"same_flow",n,calls);
    for(int i=0;i<n;++i)printf("%s%d",i?",":"",w[i].cpu);
    printf("],\"assertions\":\"PASS\",\"interleaving\":\"opportunity, not forced scheduling\"}\n");return 0;
}
static int kc_workspaces(int fd,int inject)
{
    int n=libbpf_num_possible_cpus();KC(n>0,"possible CPUs");
    struct tc_workspace *v=calloc(n,sizeof(*v));KC(v,"workspace allocation");u32 zero=0;
    if(inject){for(int i=0;i<n;++i){v[i].busy=1;v[i].record.features[0]=1337;}}
    int err=inject?bpf_map_update_elem(fd,&zero,v,BPF_ANY):bpf_map_lookup_elem(fd,&zero,v);
    int busy=0;for(int i=0;i<n;++i)busy|=v[i].busy;free(v);
    KC(!err&&(inject||!busy),"workspace owner release");return 0;
}
static void kc_pass(const char *name){printf("{\"event\":\"kernel_case\",\"name\":\"%s\",\"assertions\":\"PASS\"}\n",name);}
static int kc_capacity(int fd,int entry,int flows,int result_mode)
{
    struct tc_flow f={};struct tc_result r={};int filled=0;
    for(int i=0;i<TC_FLOW_CAPACITY;++i){
        struct tc_key k={.a_addr=1,.b_addr=2,.a_port=i,.b_port=3,.protocol=6};
        if(bpf_map_update_elem(fd,&k,result_mode?(void *)&r:(void *)&f,BPF_NOEXIST)){
            KC(errno==E2BIG||errno==ENOSPC,"full hash error");break;
        }filled++;
    }
    KC(filled>0&&filled<TC_FLOW_CAPACITY,"hash reached capacity");
    unsigned port=result_mode?45001:45000;KC(!kc_packet(entry,port,0x11,0),"full-map packet passes");
    if(result_mode){KC(!kc_flow(flows,port,TC_IDLE,1,1),"publication failure recovered");}
    else{struct tc_key k=kc_key(port);KC(bpf_map_lookup_elem_flags(flows,&k,&f,BPF_F_LOCK)&&errno==ENOENT,"full flow map");}
    for(int i=0;i<filled;++i){struct tc_key k={.a_addr=1,.b_addr=2,.a_port=i,.b_port=3,.protocol=6};KC(!bpf_map_delete_elem(fd,&k),"fixture removal");}
    if(result_mode)KC(!kc_packet(entry,port,0x11,0)&&!kc_flow(flows,port,TC_DONE,2,1),"publication retry");
    kc_pass(result_mode?"result_capacity_retry":"flow_capacity_pass");return 0;
}
static int kc_fixed(struct bpf_object *obj,int flows,int ws)
{
    int fd=bpf_program__fd(bpf_object__find_program_by_name(obj,"tc_preprocessing"));
    int cpus=libbpf_num_possible_cpus();KC(cpus>0,"fixed fixture CPU count");
    struct tc_workspace *v=calloc(cpus,sizeof(*v));KC(v,"fixed fixture allocation");
    for(int fixture=0;fixture<3;++fixture){
        struct tc_key key=kc_key(46000+fixture);struct flow input=kc_tuple(46000+fixture);
        struct tc_flow state={.state=TC_RUNNING,.sequence=1,.input=input,.input_initialized=1,.input_direction=1};
        if(bpf_map_update_elem(flows,&key,&state,BPF_NOEXIST)){free(v);KC(0,"fixed fixture flow");}
        for(int cpu=0;cpu<cpus;++cpu){
            v[cpu].busy=1;v[cpu].next_stage=0;v[cpu].record.key=key;
            v[cpu].record.input=input;v[cpu].record.input_direction=1;
            v[cpu].record.sequence=1;v[cpu].record.cpu=cpu;
            for(int j=0;j<6;++j)v[cpu].record.features[j]=mean[j]+(fixture==1?scale[j]:fixture==2?-scale[j]:0);
        }
        u32 zero=0;int err=bpf_map_update_elem(ws,&zero,v,BPF_ANY);
        if(!err)err=kc_packet(fd,46000+fixture,0x11,0);
        memset(v,0,cpus*sizeof(*v));int reset=bpf_map_update_elem(ws,&zero,v,BPF_ANY);
        if(err||reset){free(v);KC(0,"fixed fixture kernel run");}
        if(kc_flow(flows,46000+fixture,TC_DONE,1,0)){free(v);return 1;}
    }
    free(v);kc_pass("fixed_mean_above_below_full_chain");return 0;
}
static int kernel_checks(struct bpf_object *obj)
{
    int entry=bpf_program__fd(bpf_object__find_program_by_name(obj,"tc_entry"));
    int flows=bpf_object__find_map_fd_by_name(obj,"flow_map"),results_fd=bpf_object__find_map_fd_by_name(obj,"results");
    int progs_fd=bpf_object__find_map_fd_by_name(obj,"progs"),ws=bpf_object__find_map_fd_by_name(obj,"workspace");
    int idx=bpf_object__find_map_fd_by_name(obj,"nn_idx");
    KC(!kc_fixed(obj,flows,ws),"fixed deterministic full-chain vectors");
    KC(!kc_parallel(entry,0,flows)&&!kc_parallel(entry,1,flows),"parallel kernel cases");
    KC(!kc_workspaces(ws,0),"parallel workspace release");
    for(u32 i=0;i<6;++i){
        unsigned port=43000+i;KC(!bpf_map_delete_elem(progs_fd,&i),"remove private tail target");
        KC(!kc_packet(entry,port,0x11,0)&&!kc_flow(flows,port,TC_IDLE,1,1)&&!kc_workspaces(ws,0),"tail failure recovery");
        int fd=bpf_program__fd(bpf_object__find_program_by_name(obj,stages[i]));
        KC(!bpf_map_update_elem(progs_fd,&i,&fd,BPF_ANY),"restore target");
        KC(!kc_packet(entry,port,0x11,0)&&!kc_flow(flows,port,TC_DONE,2,1),"tail retry");
    }kc_pass("all_missing_tail_slots_retry");
    u32 zero=0;int bad=2,good=0;
    KC(!bpf_map_update_elem(idx,&zero,&bad,BPF_ANY),"missing model selection");
    KC(!kc_packet(entry,43010,4,0)&&!kc_flow(flows,43010,TC_IDLE,1,1),"missing model recovery");
    KC(!bpf_map_update_elem(idx,&zero,&good,BPF_ANY),"restore model");
    KC(!kc_packet(entry,43010,4,0)&&!kc_flow(flows,43010,TC_DONE,2,1),"model retry");kc_pass("missing_model_retry");
    struct tc_key k=kc_key(41000);struct tc_result before,after;
    KC(!bpf_map_lookup_elem(results_fd,&k,&before),"duplicate result baseline");
    for(int i=0;i<5;++i)KC(!kc_packet(entry,41000,4,0),"duplicate RST passes");
    KC(!bpf_map_lookup_elem(results_fd,&k,&after)&&!memcmp(&before,&after,sizeof(before)),"duplicate result immutable");
    kc_pass("duplicate_result_immutable");
    for(int i=1;i<=3;++i)KC(!kc_packet(entry,44000+i,0x11,i),"malformed packet passes");
    kc_pass("malformed_pass_unscored");
    KC(!kc_capacity(flows,entry,flows,0)&&!kc_capacity(results_fd,entry,flows,1),"capacity cases");
    KC(!kc_workspaces(ws,1),"inject busy owners");
    KC(!kc_packet(entry,45002,4,0)&&!kc_flow(flows,45002,TC_IDLE,0,0),"busy guard state");
    int n=libbpf_num_possible_cpus();struct tc_workspace *v=calloc(n,sizeof(*v));KC(v,"guard readback");
    int err=bpf_map_lookup_elem(ws,&zero,v),unchanged=1;
    for(int i=0;i<n;++i)if(v[i].busy!=1||v[i].record.features[0]!=1337)unchanged=0;
    memset(v,0,n*sizeof(*v));int reset=bpf_map_update_elem(ws,&zero,v,BPF_ANY);free(v);
    KC(!err&&!reset&&unchanged,"injected owner not overwritten");
    KC(!kc_packet(entry,45002,4,0)&&!kc_flow(flows,45002,TC_DONE,1,0),"busy guard retry");
    kc_pass("injected_reentrancy_guard");KC(!kc_workspaces(ws,0),"final workspace release");
    return snapshot(obj,0);
}
