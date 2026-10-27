// SPDX-License-Identifier: GPL-2.0
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
#define __uint(n, v) int (*n)[v]
#define __type(n, v) v *n
#define SEC(n)
#define LIBBPF_PIN_BY_NAME 1
#include "../src/common.h"
#include "../src/params.bpf.h"
#undef PARAMS_BPF_H
#include "../src/mlp_params.bpf.h"
#include "abi.h"

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

static int snapshot(struct bpf_object *obj, int minimal)
{
    uint32_t zero = 0;
    struct ids_tc_stats s;
    if (bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj, "stats"), &zero, &s)) return die("stats lookup");
    printf("{\"event\":\"snapshot\",\"packets\":%llu,\"bytes\":%llu,\"matched\":%llu,"
           "\"rejected\":%llu,\"predictions\":%llu,\"tail_failures\":%llu,\"stages\":[",
           (unsigned long long)s.packets, (unsigned long long)s.bytes, (unsigned long long)s.matched,
           (unsigned long long)s.rejected, (unsigned long long)s.predictions, (unsigned long long)s.tail_failures);
    for (int i = 0; i < 6; ++i) printf("%s%llu", i ? "," : "", (unsigned long long)s.stages[i]);
    printf("],\"results\":[");
    if (!minimal) {
        int cpus = libbpf_num_possible_cpus();
        if (cpus <= 0) return die("CPU count");
        struct tc_result *r = calloc(cpus, sizeof(*r));
        if (!r) return die("result allocation");
        if (bpf_map_lookup_elem(bpf_object__find_map_fd_by_name(obj, "results"), &zero, r)) {
            free(r); return die("result lookup");
        }
        int count = 0;
        for (int cpu = 0; cpu < cpus; ++cpu) {
            if (!r[cpu].completed_ns) continue;
            printf("%s{\"cpu\":%d,\"completed_ns\":%llu,\"mask\":%llu,\"label\":%d,"
                   "\"model_slot\":%d,\"source_port\":%u,\"features\":[", count++ ? "," : "", cpu,
                   (unsigned long long)r[cpu].completed_ns, (unsigned long long)r[cpu].stage_mask,
                   r[cpu].label, r[cpu].model_slot, ntohs((uint16_t)r[cpu].key.sport));
            for (int j = 0; j < 6; ++j) printf("%s%lld", j ? "," : "", (long long)r[cpu].features[j]);
            printf("],\"tensors\":[");
            for (int stage = 0; stage < 6; ++stage) {
                printf("%s[", stage ? "," : "");
                for (int j = 0; j < sizes[stage]; ++j) printf("%s%d", j ? "," : "", r[cpu].tensors[stage][j]);
                printf("]");
            }
            printf("]}");
        }
        free(r);
    }
    printf("]}\n"); fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 3 && !strcmp(argv[1], "--list-ids")) {
        int rc;
        if (!strcmp(argv[2], "prog")) rc = tc_scan_ids(stdout, bpf_prog_get_next_id);
        else if (!strcmp(argv[2], "map")) rc = tc_scan_ids(stdout, bpf_map_get_next_id);
        else { fprintf(stderr, "Expected prog or map\n"); return 2; }
        if (rc) fprintf(stderr, "ID registry scan failed: %s (%d)\n", strerror(-rc), rc);
        return rc ? 1 : 0;
    }
    int inspect = argc == 4 && !strcmp(argv[1], "--inspect");
    if (!inspect && (argc != 6 || strcmp(argv[1], "--run"))) {
        fprintf(stderr, "Usage: controller --inspect OBJECT LOGDIR | --run OBJECT tcids-s0 NETNS_INODE LOGDIR | --list-ids prog|map\n"); return 2;
    }
    const char *logdir = argv[inspect ? 3 : 5];
    if (!inspect) {
        struct stat ns;
        if (geteuid() || strcmp(argv[3], "tcids-s0") || stat("/proc/self/ns/net", &ns)
            || ns.st_ino != strtoull(argv[4], NULL, 10)) {
            fprintf(stderr, "Refusing: require root, tcids-s0 and the runner-owned namespace inode\n"); return 2;
        }
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGINT, stop); signal(SIGTERM, stop);
    int rc = 0, attached = 0, loaded = 0;
    uint32_t entry_id = 0, program_ids[16] = {}, map_ids[16] = {};
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
    if (np != (minimal ? 1 : 7)) { rc = die("unexpected program count"); goto out; }
    printf("{\"event\":\"schema\",\"minimal\":%s,\"program_type\":3,\"programs\":%d,\"pins_disabled\":true}\n",
           minimal ? "true" : "false", np);
    struct bpf_tc_hook hook = {.sz = sizeof(hook), .attach_point = BPF_TC_INGRESS};
    if (inspect) goto out;
    hook.ifindex = if_nametoindex(argv[3]);
    if (!hook.ifindex) { rc = die("test interface missing"); goto out; }
    if (bpf_object__load(obj)) { rc = die("TC load/verifier"); goto out; }
    loaded = 1;
    int pi = 0;
    bpf_object__for_each_program(p, obj) {
        struct bpf_prog_info info = {}; uint32_t len = sizeof(info);
        if (bpf_prog_get_info_by_fd(bpf_program__fd(p), &info, &len)) { rc = die("program metadata"); goto out; }
        if (info.type != BPF_PROG_TYPE_SCHED_CLS) { rc = die("wrong loaded type"); goto out; }
        program_ids[pi++] = info.id;
    }
    bpf_object__for_each_map(map, obj) {
        struct bpf_map_info info = {}; uint32_t len = sizeof(info);
        if (nm >= 16 || bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &len)) { rc = die("map metadata"); goto out; }
        map_ids[nm++] = info.id;
    }
    if (!minimal) {
        struct Net net = {}, actual;
        memcpy(net.layer_0_weight, layer_0_weight, sizeof(layer_0_weight));
        memcpy(net.layer_1_weight, layer_1_weight, sizeof(layer_1_weight));
        memcpy(net.layer_2_weight, layer_2_weight, sizeof(layer_2_weight));
        memcpy(net.mean, mean, sizeof(mean)); memcpy(net.scale, scale, sizeof(scale));
        int params = bpf_object__find_map_fd_by_name(obj, "nn_parameters");
        int index_fd = bpf_object__find_map_fd_by_name(obj, "nn_idx");
        int progs_fd = bpf_object__find_map_fd_by_name(obj, "progs");
        for (int slot = 0; slot < 2; ++slot)
            if (bpf_map_update_elem(params, &slot, &net, BPF_ANY)
                || bpf_map_lookup_elem(params, &slot, &actual) || memcmp(&net, &actual, sizeof(net))) {
                rc = die("model write/readback"); goto out;
            }
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
    p = bpf_object__find_program_by_name(obj, minimal ? "tc_minimal" : "tc_entry");
    if (bpf_tc_hook_create(&hook)) { rc = die("create private clsact (existing qdisc refused)"); goto out; }
    struct bpf_tc_opts opts = {.sz = sizeof(opts), .prog_fd = bpf_program__fd(p), .handle = 1, .priority = 1};
    if (bpf_tc_attach(&hook, &opts)) { rc = die("TC ingress attach"); goto out; }
    attached = 1; entry_id = opts.prog_id;
    struct bpf_tc_opts query = {.sz = sizeof(query), .handle = 1, .priority = 1};
    if (bpf_tc_query(&hook, &query) || query.prog_id != entry_id) { rc = die("TC attachment query"); goto out; }
    printf("{\"event\":\"ready\",\"ifindex\":%d,\"program_id\":%u,\"handle\":1,\"priority\":1,\"program_ids\":[", hook.ifindex, entry_id);
    for (int i = 0; i < np; ++i) printf("%s%u", i ? "," : "", program_ids[i]);
    printf("],\"map_ids\":[");
    for (int i = 0; i < nm; ++i) printf("%s%u", i ? "," : "", map_ids[i]);
    printf("]}\n");
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
    if (attached) {
        struct bpf_tc_opts q = {.sz = sizeof(q), .handle = 1, .priority = 1};
        if (bpf_tc_query(&hook, &q) || q.prog_id != entry_id) {
            fprintf(stderr, "Owned TC filter changed: refusing to detach an unknown program\n"); rc = 1;
        } else {
            struct bpf_tc_opts d = {.sz = sizeof(d), .handle = 1, .priority = 1};
            if (bpf_tc_detach(&hook, &d)) rc = die("detach owned filter");
            else {
                /* An exact GETTFILTER can return EINVAL when deleting the last
                 * filter also removes its chain. Do not interpret query errors
                 * as absence: the runner must dump BOTH directions successfully
                 * and verify empty results before removing our clsact.
                 */
                printf("{\"event\":\"detach_acknowledged\",\"program_id\":%u,"
                       "\"absence_verification\":\"pending_filter_dumps\"}\n", entry_id);
            }
        }
    }
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
