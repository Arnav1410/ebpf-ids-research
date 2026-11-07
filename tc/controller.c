// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "id_scan.h"
typedef int64_t s64;
typedef int32_t s32;
typedef uint64_t u64;
typedef uint32_t u32;
#define __uint(n, v) int (*n)[v]
#define __type(n, v) v *n
#define SEC(n)
#define LIBBPF_PIN_BY_NAME 1
#ifdef IDS_LAYER_SPECIFIC
#include "../quantization/params.bpf.h"
#include "../quantization/calibrated.h"
#define INFERENCE_MODE "layer_specific"
#else
#include "../src/params.bpf.h"
#define INFERENCE_MODE "static_q16"
#endif
#undef PARAMS_BPF_H
#include "../src/mlp_params.bpf.h"
#include "abi.h"
#include "flow_key.h"
_Static_assert(sizeof(struct tc_workspace) % 8 == 0, "per-CPU value stride must be aligned");

static const char *stages[] = {"tc_preprocessing", "tc_input_linear", "tc_input_relu",
    "tc_hidden_linear", "tc_hidden_relu", "tc_output_linear"};
static const int sizes[] = {6, 32, 32, 32, 32, 2};
static volatile sig_atomic_t exiting;
static void stop(int sig) { (void)sig; exiting = 1; }
static int die(const char *op)
{
    fprintf(stderr, "%s: %s (errno=%d)\n", op, strerror(errno), errno);
    return 1;
}

static void print_key(const struct tc_key *key)
{
    char a[INET_ADDRSTRLEN],b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&key->a_addr,a,sizeof(a));inet_ntop(AF_INET,&key->b_addr,b,sizeof(b));
    printf("{\"a_ip\":\"%s\",\"a_port\":%u,\"b_ip\":\"%s\",\"b_port\":%u,\"protocol\":%u}",
           a,tc_host_port(key->a_port),b,tc_host_port(key->b_port),key->protocol);
}

static void print_record(const struct tc_result *r)
{
    printf("{\"key\":");print_key(&r->key);
    printf(",\"mlp_input_direction\":%u,\"cpu\":%u,\"completed_ns\":%llu,\"mask\":%llu,\"label\":%d,"
           "\"model_slot\":%d,\"source_port\":%u,\"sequence\":%llu,\"features\":[",
           r->input_direction,r->cpu, (unsigned long long)r->completed_ns, (unsigned long long)r->stage_mask,
           r->label, r->model_slot, ntohs((uint16_t)r->input.sport), (unsigned long long)r->sequence);
    for (int j = 0; j < 6; ++j) printf("%s%lld", j ? "," : "", (long long)r->features[j]);
    printf("],\"tensors\":[");
    for (int stage = 0; stage < 6; ++stage) {
        printf("%s[", stage ? "," : "");
        for (int j = 0; j < sizes[stage]; ++j) printf("%s%d", j ? "," : "", r->tensors[stage][j]);
        printf("]");
    }
    printf("]}");
}

static int snapshot(struct bpf_object *obj, int minimal)
{
    uint32_t zero = 0;
    struct ids_tc_stats s;
    if (bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj, "stats"), &zero, &s)) return die("stats lookup");
    printf("{\"event\":\"snapshot\",\"inference_mode\":\"%s\",\"packets\":%llu,\"bytes\":%llu,\"matched\":%llu,"
           "\"rejected\":%llu,\"predictions\":%llu,\"tail_failures\":%llu,\"stages\":[",
           INFERENCE_MODE,(unsigned long long)s.packets, (unsigned long long)s.bytes, (unsigned long long)s.matched,
           (unsigned long long)s.rejected, (unsigned long long)s.predictions, (unsigned long long)s.tail_failures);
    for (int i = 0; i < 6; ++i) printf("%s%llu", i ? "," : "", (unsigned long long)s.stages[i]);
    printf("],\"flow_full\":%llu,\"workspace_busy\":%llu,\"duplicate_triggers\":%llu,"
           "\"inference_failures\":%llu,\"timestamp_reorders\":%llu,\"result_failures\":%llu,"
           "\"egress_packets\":%llu,\"egress_bytes\":%llu,\"egress_matched\":%llu,"
           "\"egress_rejected\":%llu,\"ingress_other_direction\":%llu,\"results\":[",
           (unsigned long long)s.flow_full, (unsigned long long)s.workspace_busy,
           (unsigned long long)s.duplicate_triggers, (unsigned long long)s.inference_failures,
           (unsigned long long)s.timestamp_reorders, (unsigned long long)s.result_failures,
           (unsigned long long)s.egress_packets, (unsigned long long)s.egress_bytes,
           (unsigned long long)s.egress_matched,(unsigned long long)s.egress_rejected,
           (unsigned long long)s.ingress_other_direction);
    if (!minimal) {
        int fd = bpf_object__find_map_fd_by_name(obj, "results"), count = 0;
        struct tc_key key, next, *previous = NULL;
        while (!bpf_map_get_next_key(fd, previous, &next)) {
            struct tc_result r;
            if (bpf_map_lookup_elem(fd, &next, &r)) return die("result lookup");
            if (count++) printf(",");
            print_record(&r);
            key = next; previous = &key;
            if (count > TC_FLOW_CAPACITY) return die("result iteration limit");
        }
        if (errno != ENOENT) return die("result key iteration");
    }
    printf("],\"flows\":[");
    if (!minimal) {
        int fd = bpf_object__find_map_fd_by_name(obj, "flow_map"), count = 0;
        struct tc_key key, next, *previous = NULL;
        while (!bpf_map_get_next_key(fd, previous, &next)) {
            struct tc_flow f = {};
            if (bpf_map_lookup_elem_flags(fd, &next, &f, BPF_F_LOCK)) return die("locked flow lookup");
            printf("%s{\"source_port\":%u,\"packets\":%llu,\"bytes\":%llu,\"state\":%u,"
                   "\"sequence\":%llu,\"duplicates\":%llu,\"failures\":%llu,\"timestamp_reorders\":%llu,",
                   count++ ? "," : "", ntohs((uint16_t)f.input.sport), (unsigned long long)f.packets,
                   (unsigned long long)f.bytes, f.state, (unsigned long long)f.sequence,
                   (unsigned long long)f.duplicates, (unsigned long long)f.failures,
                   (unsigned long long)f.timestamp_reorders);
            printf("\"key\":");print_key(&next);
            printf(",\"input_initialized\":%s,\"mlp_input_direction\":%u,\"hooks\":{",f.input_initialized?"true":"false",f.input_direction);
            for(int h=0;h<2;++h){
                const struct tc_direction_stats *d=&f.hooks[h];
                printf("%s\"%s\":{\"packets\":%llu,\"bytes\":%llu,\"first_ns\":%llu,\"last_ns\":%llu,"
                       "\"timestamp_reorders\":%llu,\"tcp_flags\":%u}",h?",":"",h?"egress":"ingress",
                       (unsigned long long)d->packets,(unsigned long long)d->bytes,
                       (unsigned long long)d->first_ns,(unsigned long long)d->last_ns,
                       (unsigned long long)d->timestamp_reorders,d->tcp_flags);
            }
            printf("},\"endpoint_packets\":[%llu,%llu],\"endpoint_bytes\":[%llu,%llu]}",
                   (unsigned long long)f.endpoint_packets[0],(unsigned long long)f.endpoint_packets[1],
                   (unsigned long long)f.endpoint_bytes[0],(unsigned long long)f.endpoint_bytes[1]);
            key = next; previous = &key;
            if (count > TC_FLOW_CAPACITY) return die("flow iteration limit");
        }
        if (errno != ENOENT) return die("flow key iteration");
    }
    printf("]");
    #ifdef IDS_LAYER_SPECIFIC
    if(!minimal){
        u64 diagnostics[4]={};
        if(bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj,"ls_diagnostics"),&zero,diagnostics))return die("numerical diagnostics");
        printf(",\"numerical_diagnostics\":{\"configuration\":%llu,\"range\":%llu,\"overflow\":%llu,\"parameters\":%llu}",
               (unsigned long long)diagnostics[0],(unsigned long long)diagnostics[1],
               (unsigned long long)diagnostics[2],(unsigned long long)diagnostics[3]);
    }
    #endif
    printf("}\n"); fflush(stdout);
    return 0;
}

#include "kernel_checks.h"
#include "bidirectional_checks.h"
#include "../quantization/benchmark.h"
#ifdef IDS_LAYER_SPECIFIC
#include "../quantization/kernel_checks.h"
#endif

#include "deploy_guard.h"

static int detach_owned(struct bpf_tc_hook *hook, u32 program_id, const char *direction,u32 handle,u32 priority)
{
    LIBBPF_OPTS(bpf_tc_opts, q, .handle=handle, .priority=priority);
    if (bpf_tc_query(hook,&q) || q.prog_id!=program_id) {
        fprintf(stderr,"Owned TC %s filter changed: refusing unknown detach\n",direction);
        return 1;
    }
    LIBBPF_OPTS(bpf_tc_opts, d, .handle=handle, .priority=priority);
    if (bpf_tc_detach(hook,&d)) return die("detach owned TC filter");
    /* Exact post-detach GETTFILTER may return EINVAL after a chain disappears.
     * Successful empty dumps of BOTH directions remain mandatory in the runner. */
    printf("{\"event\":\"detach_acknowledged\",\"program_id\":%u,\"direction\":\"%s\","
           "\"absence_verification\":\"pending_filter_dumps\"}\n",program_id,direction);
    return 0;
}

int main(int argc, char **argv)
{
    if(argc==8 && !strcmp(argv[1],"--detach-owned")){
        u32 index,handle,priority,in,out;
        if(geteuid() || parse_deployment_u32(argv[3],&index,UINT32_MAX)
           ||parse_deployment_u32(argv[4],&handle,UINT32_MAX)||parse_deployment_u32(argv[5],&priority,65535)
           ||(strcmp(argv[6],"0")&&parse_deployment_u32(argv[6],&in,UINT32_MAX))
           ||(strcmp(argv[7],"0")&&parse_deployment_u32(argv[7],&out,UINT32_MAX))
           ||if_nametoindex(argv[2])!=index){fprintf(stderr,"Invalid owned-detach identity\n");return 2;}
        if(!strcmp(argv[6],"0"))in=0;
        if(!strcmp(argv[7],"0"))out=0;
        LIBBPF_OPTS(bpf_tc_hook,h,.ifindex=index,.attach_point=BPF_TC_INGRESS);
        int status=in?detach_owned(&h,in,"ingress",handle,priority):0;
        h.attach_point=BPF_TC_EGRESS;
        if(out&&detach_owned(&h,out,"egress",handle,priority))status=1;
        return status;
    }
    if (argc == 3 && !strcmp(argv[1], "--list-ids")) {
        int rc;
        if (!strcmp(argv[2], "prog")) rc = tc_scan_ids(stdout, bpf_prog_get_next_id);
        else if (!strcmp(argv[2], "map")) rc = tc_scan_ids(stdout, bpf_map_get_next_id);
        else { fprintf(stderr, "Expected prog or map\n"); return 2; }
        if (rc) fprintf(stderr, "ID registry scan failed: %s (%d)\n", strerror(-rc), rc);
        return rc ? 1 : 0;
    }
    int inspect = argc == 4 && !strcmp(argv[1], "--inspect");
    int kernel_test = argc == 4 && !strcmp(argv[1], "--kernel-tests");
    int bidirectional_test=argc==4 && !strcmp(argv[1],"--bidirectional-tests");
    int numerical_test=argc==4 && !strcmp(argv[1],"--numerical-tests");
    int benchmark=argc==4 && !strcmp(argv[1],"--benchmark-kernel");
    kernel_test|=bidirectional_test|numerical_test|benchmark;
    #ifndef IDS_LAYER_SPECIFIC
    if(numerical_test){fprintf(stderr,"Numerical rejection suite requires layer_specific controller\n");return 2;}
    #endif
    int deployment=argc>=5 && !strcmp(argv[1],"--deploy");
    int serve=deployment || (argc>=5 && !strcmp(argv[1],"--serve"));
    int run=argc>=6 && !strcmp(argv[1],"--run");
    if (!inspect && !kernel_test && !run && !serve) {
        fprintf(stderr, "Usage: controller --inspect OBJECT LOGDIR | --run OBJECT tcids-s0 NETNS_INODE LOGDIR [--egress-counter|--bidirectional] [--client-ip IP|any] | --serve OBJECT INTERFACE LOGDIR [--bidirectional] [--client-ip IP|any] | --kernel-tests OBJECT LOGDIR | --bidirectional-tests OBJECT LOGDIR | --list-ids prog|map\n"); return 2;
    }
    int egress_counter=0,bidirectional=deployment;
    u32 attach_handle=deployment?0x4e4e:1,attach_priority=deployment?49152:1;
    struct tc_config configuration={};
    if(kernel_test){configuration.client_filter=1;configuration.client_ipv4=htonl(555819337);}
    for(int i=serve?5:6;(run||serve)&&i<argc;++i){
        if(!strcmp(argv[i],"--egress-counter"))egress_counter=1;
        else if(!strcmp(argv[i],"--bidirectional"))bidirectional=1;
        else if(!strcmp(argv[i],"--client-ip") && i+1<argc){
            const char *address=argv[++i];
            configuration.client_filter=strcmp(address,"any")!=0;
            if(configuration.client_filter && inet_pton(AF_INET,address,&configuration.client_ipv4)!=1){fprintf(stderr,"Invalid client IPv4 address\n");return 2;}
        }else if(deployment && i+1<argc && !strcmp(argv[i],"--handle")){
            if(parse_deployment_u32(argv[++i],&attach_handle,UINT32_MAX))return 2;
        }else if(deployment && i+1<argc && !strcmp(argv[i],"--priority")){
            if(parse_deployment_u32(argv[++i],&attach_priority,65535))return 2;
        }else{fprintf(stderr,"Unknown or incomplete option: %s\n",argv[i]);return 2;}
    }
    const char *logdir = argv[(inspect || kernel_test) ? 3 : serve?4:5];
    if (kernel_test && geteuid()) { fprintf(stderr,"Kernel tests require approved root invocation\n"); return 2; }
    if (!inspect && !kernel_test) {
        struct stat ns;
        if (geteuid() || (!serve && (strcmp(argv[3], "tcids-s0") || stat("/proc/self/ns/net", &ns)
            || ns.st_ino != strtoull(argv[4], NULL, 10)))) {
            fprintf(stderr, "Refusing: require root, tcids-s0 and the runner-owned namespace inode\n"); return 2;
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stop); signal(SIGTERM, stop);
    int rc = 0, attached = 0, egress_attached = 0, loaded = 0;
    uint32_t entry_id = 0, egress_id = 0, program_ids[16] = {}, map_ids[16] = {};
    int np = 0, nm = 0;
    char *logs[16] = {};
    struct bpf_object *obj = bpf_object__open_file(argv[2], NULL);
    if (!obj || libbpf_get_error(obj)) return die("open TC object");
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj)
        if (bpf_map__set_pin_path(map, NULL)) { rc = die("disable pins"); goto out; }
    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        if (np >= 16 || bpf_program__type(p) != BPF_PROG_TYPE_SCHED_CLS) { rc = die("non-TC program"); goto out; }
        logs[np] = calloc(1, 4 * 1024 * 1024);
        if (!logs[np] || bpf_program__set_log_buf(p, logs[np], 4 * 1024 * 1024)
            || bpf_program__set_log_level(p, 1)) { rc = die("verifier logging"); goto out; }
        ++np;
    }
    int minimal = bpf_object__find_program_by_name(obj, "tc_minimal") != NULL;
    if (np != (minimal ? 2 : 8)) { rc = die("unexpected program count"); goto out; }
    map=bpf_object__find_map_by_name(obj,"stats");
    if (!map || bpf_map__type(map)!=BPF_MAP_TYPE_ARRAY || bpf_map__max_entries(map)!=1
        || bpf_map__key_size(map)!=sizeof(u32) || bpf_map__value_size(map)!=sizeof(struct ids_tc_stats)) {
        fprintf(stderr,"Counter map ABI mismatch\n"); rc=1; goto out;
    }
    if ((egress_counter && (!minimal || bidirectional)) || (bidirectional && minimal)) {
        fprintf(stderr,"Egress counter requires minimal object; bidirectional requires full object\n"); rc=1; goto out;
    }
    if (!minimal) {
        map=bpf_object__find_map_by_name(obj,"nn_parameters");
        if(!map || bpf_map__value_size(map)!=sizeof(struct Net) || bpf_map__key_size(map)!=4 || bpf_map__max_entries(map)!=2){
            fprintf(stderr,"Model/mode ABI mismatch: expected %zu parameter bytes for %s\n",sizeof(struct Net),INFERENCE_MODE);rc=1;goto out;
        }
        const char *names[]={"flow_map","workspace","results"};
        const enum bpf_map_type types[]={BPF_MAP_TYPE_HASH,BPF_MAP_TYPE_PERCPU_ARRAY,BPF_MAP_TYPE_HASH};
        const size_t values[]={sizeof(struct tc_flow),sizeof(struct tc_workspace),sizeof(struct tc_result)};
        for (int i=0;i<3;++i) {
            map=bpf_object__find_map_by_name(obj,names[i]);
            if (!map || bpf_map__type(map)!=types[i] || bpf_map__value_size(map)!=values[i]
                || bpf_map__key_size(map)!=(i==1?sizeof(u32):sizeof(struct tc_key))) {
                fprintf(stderr,"TC state ABI mismatch: %s\n",names[i]); rc=1; goto out;
            }
        }
        printf("{\"event\":\"state_abi\",\"flow_bytes\":%zu,\"workspace_bytes\":%zu,\"result_bytes\":%zu}\n",
               sizeof(struct tc_flow),sizeof(struct tc_workspace),sizeof(struct tc_result));
    }
    printf("{\"event\":\"schema\",\"minimal\":%s,\"program_type\":3,\"programs\":%d,\"pins_disabled\":true}\n",
           minimal ? "true" : "false", np);
    /* LIBBPF_OPTS clears padding too: libbpf validates trailing bytes. Ordinary
     * designated initializers can leave those bytes unspecified at -O2. */
    LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point=BPF_TC_INGRESS);
    LIBBPF_OPTS(bpf_tc_hook, egress_hook, .attach_point=BPF_TC_EGRESS);
    if (inspect) goto out;
    if (!kernel_test) {
        hook.ifindex = if_nametoindex(argv[3]);
        if (!hook.ifindex) { rc = die("test interface missing"); goto out; }
        if(deployment && deployment_empty_hooks(hook.ifindex)){rc=1;goto out;}
    }
    if (bpf_object__load(obj)) { rc = die("TC load/verifier"); goto out; }
    loaded = 1;
    int pi = 0;
    bpf_object__for_each_program(p, obj) {
        struct bpf_prog_info info = {}; uint32_t len = sizeof(info);
        if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len)) { rc = die("program metadata"); goto out; }
        if (info.type != BPF_PROG_TYPE_SCHED_CLS) { rc = die("wrong loaded type"); goto out; }
        program_ids[pi++] = info.id;
        if(benchmark)printf("{\"event\":\"program_resources\",\"name\":\"%s\",\"id\":%u,\"bytecode_bytes\":%u,\"jit_bytes\":%u}\n",
                            bpf_program__name(p),info.id,info.xlated_prog_len,info.jited_prog_len);
    }
    bpf_object__for_each_map(map, obj) {
        struct bpf_map_info info = {}; uint32_t len = sizeof(info);
        if (nm >= 16 || bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &len)) { rc = die("map metadata"); goto out; }
        map_ids[nm++] = info.id;
        printf("{\"event\":\"map\",\"name\":\"%s\",\"id\":%u,\"key_bytes\":%u,\"value_bytes\":%u}\n",
               bpf_map__name(map),info.id,info.key_size,info.value_size);
    }
    printf("{\"event\":\"loaded\",\"program_ids\":[");
    for (int i=0;i<np;++i) printf("%s%u",i?",":"",program_ids[i]);
    printf("],\"map_ids\":[");
    for (int i=0;i<nm;++i) printf("%s%u",i?",":"",map_ids[i]);
    printf("]}\n");
    if (!minimal) {
        u32 configuration_zero=0;
        int cfg=bpf_object__find_map_fd_by_name(obj,"tc_configuration");
        if(bpf_map_update_elem(cfg,&configuration_zero,&configuration,BPF_ANY) || bpf_map_freeze(cfg)){rc=die("configure private client filter");goto out;}
        char client[INET_ADDRSTRLEN];inet_ntop(AF_INET,&configuration.client_ipv4,client,sizeof(client));
        printf("{\"event\":\"configuration\",\"client_filter\":%s,\"client_ipv4\":\"%s\",\"mlp_input\":\"first eligible ingress leg only\"}\n",
               configuration.client_filter?"true":"false",client);
        struct Net net = {}, actual;
        memcpy(net.layer_0_weight, layer_0_weight, sizeof(layer_0_weight));
        memcpy(net.layer_1_weight, layer_1_weight, sizeof(layer_1_weight));
        memcpy(net.layer_2_weight, layer_2_weight, sizeof(layer_2_weight));
        memcpy(net.mean, mean, sizeof(mean)); memcpy(net.scale, scale, sizeof(scale));
        #ifdef IDS_LAYER_SPECIFIC
        net.calibration=ls_calibrated_metadata;
        if(ls_valid(&net.calibration)){fprintf(stderr,"Invalid calibrated scales\n");rc=1;goto out;}
        printf("{\"event\":\"inference_mode\",\"mode\":\"layer_specific\",\"q_normalized\":%u,"
               "\"q_weights\":[%u,%u,%u],\"q_outputs\":[%u,%u,%u],\"parameter_sha256\":\"%s\"}\n",
               net.calibration.q_normalized,net.calibration.q_weight[0],net.calibration.q_weight[1],net.calibration.q_weight[2],
               net.calibration.q_output[0],net.calibration.q_output[1],net.calibration.q_output[2],LS_PARAMETER_SHA256);
        #else
        printf("{\"event\":\"inference_mode\",\"mode\":\"static_q16\",\"tensor_exponents\":[16,16,16,16,16,16]}\n");
        #endif
        int params = bpf_object__find_map_fd_by_name(obj, "nn_parameters");
        int index_fd = bpf_object__find_map_fd_by_name(obj, "nn_idx");
        int progs_fd = bpf_object__find_map_fd_by_name(obj, "progs");
        for (int slot = 0; slot < 2; ++slot)
            if (bpf_map_update_elem(params, &slot, &net, BPF_ANY)
                || bpf_map_lookup_elem(params, &slot, &actual) || memcmp(&net, &actual, sizeof(net))) {
                rc = die("model write/readback"); goto out;
            }
        if (bpf_map_freeze(params)) { rc = die("freeze private static model"); goto out; }
        int zero = 0;
        if (bpf_map_update_elem(index_fd, &zero, &zero, BPF_ANY)) { rc = die("select model"); goto out; }
        for (uint32_t i = 0; i < 6; ++i) {
            p = bpf_object__find_program_by_name(obj, stages[i]);
            if (!p) { rc = die("stage missing"); goto out; }
            int fd = bpf_program__fd(p);
            uint32_t id;
            struct bpf_prog_info info = {}; uint32_t len = sizeof(info);
            if (bpf_prog_get_info_by_fd(fd, &info, &len) || bpf_map_update_elem(progs_fd, &i, &fd, BPF_ANY)
                || bpf_map_lookup_elem(progs_fd, &i, &id) || id != info.id || info.type != BPF_PROG_TYPE_SCHED_CLS) {
                rc = die("TC tail-call verification"); goto out;
            }
            printf("{\"event\":\"tail_slot\",\"slot\":%u,\"program_id\":%u,\"type\":3}\n", i, id);
        }
        printf("{\"event\":\"model\",\"bytes_per_slot\":%zu,\"slots_verified\":2,\"active\":0}\n", sizeof(net));
    }
    if (kernel_test) {
        if (minimal) { fprintf(stderr,"Kernel suite requires the full TC object\n"); rc=1; }
        else if(benchmark)rc=bench_serve(obj);
        #ifdef IDS_LAYER_SPECIFIC
        else if(numerical_test)rc=kernel_numerical_checks(obj);
        #endif
        else rc=bidirectional_test?kernel_bidirectional_checks(obj):kernel_checks(obj);
        goto out;
    }
    p = bpf_object__find_program_by_name(obj, minimal ? "tc_minimal" : "tc_entry");
    if(deployment && deployment_empty_hooks(hook.ifindex)){rc=1;goto out;}
    int create_status=bpf_tc_hook_create(&hook);
    if(create_status && !(deployment && create_status==-EEXIST)) { rc = die("create private clsact (existing qdisc refused)"); goto out; }
    printf("{\"event\":\"%s\",\"ifindex\":%d}\n",create_status?"qdisc_reused":"qdisc_created",hook.ifindex);
    LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd=bpf_program__fd(p), .handle=attach_handle, .priority=attach_priority);
    if (bpf_tc_attach(&hook, &opts)) { rc = die("TC ingress attach"); goto out; }
    attached = 1; entry_id = opts.prog_id;
    LIBBPF_OPTS(bpf_tc_opts, query, .handle=attach_handle, .priority=attach_priority);
    if (bpf_tc_query(&hook, &query) || query.prog_id != entry_id) { rc = die("TC attachment query"); goto out; }
    if (egress_counter || bidirectional) {
        egress_hook.ifindex=hook.ifindex;
        p=bpf_object__find_program_by_name(obj,egress_counter?"tc_minimal_egress":"tc_egress");
        if (!p) { fprintf(stderr,"Egress counter program missing\n"); rc=1; goto out; }
        LIBBPF_OPTS(bpf_tc_opts, eo, .prog_fd=bpf_program__fd(p), .handle=attach_handle, .priority=attach_priority);
        if (bpf_tc_attach(&egress_hook,&eo)) { rc=die("TC egress attach"); goto out; }
        egress_attached=1; egress_id=eo.prog_id;
        LIBBPF_OPTS(bpf_tc_opts, eq, .handle=attach_handle, .priority=attach_priority);
        if (bpf_tc_query(&egress_hook,&eq) || eq.prog_id!=egress_id) { rc=die("TC egress attachment query"); goto out; }
    }
    if(deployment && (deployment_filter_count(hook.ifindex,0)!=1 || deployment_filter_count(hook.ifindex,1)!=1)){
        fprintf(stderr,"Classifier state changed during deployment; rolling back owned filters\n");rc=1;goto out;
    }
    printf("{\"event\":\"ready\",\"ifindex\":%d,\"program_id\":%u,\"handle\":%u,\"priority\":%u,\"program_ids\":[", hook.ifindex, entry_id,attach_handle,attach_priority);
    for (int i = 0; i < np; ++i) printf("%s%u", i ? "," : "", program_ids[i]);
    printf("],\"map_ids\":[");
    for (int i = 0; i < nm; ++i) printf("%s%u", i ? "," : "", map_ids[i]);
    printf("]");
    if (egress_attached) printf(",\"egress_program_id\":%u",egress_id);
    printf("}\n");
    while (!exiting) {
        struct pollfd fds = {.fd = STDIN_FILENO, .events = POLLIN};
        int n = poll(&fds, 1, 500);
        if (n < 0) { if (errno == EINTR) continue; rc = die("poll"); break; }
        if (!n) continue;
        char line[64];
        if (!fgets(line, sizeof(line), stdin) || !strcmp(line, "stop\n")) break;
        if (!strcmp(line, "snapshot\n")) { if (snapshot(obj, minimal)) { rc = 1; break; } }
        else { errno = EINVAL; rc = die("unknown control command"); break; }
    }
out:
    if (egress_attached && detach_owned(&egress_hook,egress_id,"egress",attach_handle,attach_priority)) rc=1;
    if (attached && detach_owned(&hook,entry_id,"ingress",attach_handle,attach_priority)) rc=1;
    int i = 0;
    bpf_object__for_each_program(p, obj) {
        char path[4096]; snprintf(path, sizeof(path), "%s/verifier-%s.log", logdir, bpf_program__name(p));
        FILE *f = fopen(path, "wx");
        if (!f) rc = die("save verifier log");
        else { if (logs[i]) fputs(logs[i], f); fclose(f); }
        ++i;
    }
    bpf_object__close(obj);
    for (i = 0; i < np; ++i) free(logs[i]);
    if (loaded) printf("{\"event\":\"closed\",\"qdisc_cleanup\":\"runner-owned interface only\"}\n");
    return rc;
}
