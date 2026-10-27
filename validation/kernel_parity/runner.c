/* Private original-object BPF_PROG_TEST_RUN driver. No interface attachment,
 * map pinning, network configuration, trace consumption, or live-frame mode.
 * --inspect opens ELF/BTF only; --execute explicitly loads/executes BPF. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

typedef int64_t s64;
typedef int32_t s32;
typedef uint64_t u64;
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define SEC(name)
#define LIBBPF_PIN_BY_NAME 1
#include "../../src/common.h"
#include "../../src/params.bpf.h"

static const char *names[] = {"xdp_preprocessing", "xdp_input_linear", "xdp_input_relu",
                             "xdp_hidden_linear", "xdp_hidden_relu", "xdp_output_linear", "xdp_prog"};
static const int sizes[] = {6, 32, 32, 32, 32, 2};
static FILE *events;
static int flow_fd, prog_fds[7];
static uint32_t prog_ids[7], map_ids[5];
static int loaded, failed;

static int error(const char *operation)
{
    int code = errno;
    fprintf(stderr, "%s: errno=%d (%s)\n", operation, code, strerror(code));
    if (events) {
        fprintf(events, "{\"event\":\"error\",\"operation\":\"%s\",\"errno\":%d}\n", operation, code);
        fflush(events);
    }
    failed = 1;
    return -1;
}

static int read_exact(FILE *f, void *value, size_t size)
{
    if (fread(value, 1, size, f) != size) { errno = EINVAL; return error("input truncated"); }
    return 0;
}

static int packet_read(FILE *f, unsigned char *packet, uint32_t *length)
{
    if (read_exact(f, length, 4)) return -1;
    if (*length < 54 || *length > 512) { errno = EINVAL; return error("packet size"); }
    return read_exact(f, packet, *length);
}

static void packet_key(const unsigned char *packet, struct flow *key)
{
    uint16_t port;
    memset(key, 0, sizeof(*key));
    memcpy(&key->saddr, packet + 26, 4);
    memcpy(&key->daddr, packet + 30, 4);
    memcpy(&port, packet + 34, 2); key->sport = port;
    memcpy(&port, packet + 36, 2); key->dport = port;
}

static void vector(const int32_t *values, int size)
{
    fputc('[', events);
    for (int i = 0; i < size; ++i) fprintf(events, "%s%d", i ? "," : "", values[i]);
    fputc(']', events);
}

static void features(const struct flow_attribute *a)
{
    fprintf(events, "[%lld,%lld,%lld,%lld,%lld,%lld]", (long long)a->max_packet_length,
            (long long)a->max_duration, (long long)a->min_packet_length,
            (long long)a->dst_port, (long long)a->header_length, (long long)a->num_packet);
}

static int invoke(int stage, const unsigned char *packet, uint32_t length,
                  const char *kind, unsigned int index)
{
    unsigned char output[2048];
    struct bpf_test_run_opts opts = {.sz = sizeof(opts), .data_in = packet,
        .data_size_in = length, .data_out = output, .data_size_out = sizeof(output),
        .repeat = 1, .flags = 0};
    if (bpf_prog_test_run_opts(prog_fds[stage], &opts)) return error("BPF_PROG_TEST_RUN");
    fprintf(events, "{\"event\":\"test_run\",\"kind\":\"%s\",\"index\":%u,"
            "\"stage\":\"%s\",\"program_id\":%u,\"retval\":%u,\"repeat\":1,"
            "\"flags\":0,\"duration_ns\":%u}\n", kind, index, names[stage],
            prog_ids[stage], opts.retval, opts.duration);
    fflush(events);
    if (opts.retval != XDP_PASS) { errno = EPROTO; return error("unexpected XDP retval"); }
    return 0;
}

static int stages(const unsigned char *packet, uint32_t length, const struct flow *key,
                  const char *kind, unsigned int index, int32_t snapshots[6][32])
{
    struct flow_attribute attr;
    for (int stage = 0; stage < 6; ++stage) {
        if (invoke(stage, packet, length, kind, index)) return -1;
        if (bpf_map_lookup_elem(flow_fd, key, &attr)) return error("read stage flow");
        const int32_t *tensor = stage == 0 || stage == 3 || stage == 4 ? attr.hidden2 : attr.hidden1;
        memcpy(snapshots[stage], tensor, sizes[stage] * sizeof(int32_t));
    }
    return 0;
}

static void tensors(int32_t snapshots[6][32])
{
    fputc('[', events);
    for (int stage = 0; stage < 6; ++stage) {
        if (stage) fputc(',', events);
        vector(snapshots[stage], sizes[stage]);
    }
    fputc(']', events);
}

static int empty_tail_calls(int fd)
{
    for (uint32_t i = 0; i < 6; ++i) {
        uint32_t value;
        if (bpf_map_lookup_elem(fd, &i, &value) == 0 || errno != ENOENT) {
            errno = EPROTO; return error("tail-call slot unexpectedly populated");
        }
    }
    return 0;
}

static int cleanup_ids(void)
{
    /* No pins/links exist. Allow deferred kernel object release a short grace. */
    for (int attempt = 0; attempt < 100; ++attempt) {
        int remaining = 0;
        for (int i = 0; i < 7; ++i) {
            int fd = bpf_prog_get_fd_by_id(prog_ids[i]);
            if (fd >= 0) { close(fd); ++remaining; }
            else if (errno != ENOENT) return error("inspect released program ID");
        }
        for (int i = 0; i < 5; ++i) {
            int fd = bpf_map_get_fd_by_id(map_ids[i]);
            if (fd >= 0) { close(fd); ++remaining; }
            else if (errno != ENOENT) return error("inspect released map ID");
        }
        if (!remaining) {
            fprintf(events, "{\"event\":\"cleanup\",\"private_program_ids_absent\":true,"
                    "\"private_map_ids_absent\":true,\"attachments_created\":0,\"pins_created\":0}\n");
            return 0;
        }
        usleep(10000);
    }
    errno = EBUSY;
    return error("private BPF IDs remain after close");
}

int main(int argc, char **argv)
{
    if (argc != 6 || (strcmp(argv[1], "--inspect") && strcmp(argv[1], "--execute"))) {
        fprintf(stderr, "Usage: runner --inspect|--execute OBJECT INPUT EVENTS LOG_DIRECTORY\n"); return 2;
    }
    int execute = !strcmp(argv[1], "--execute");
    if (execute && geteuid() != 0) { fprintf(stderr, "--execute requires an explicitly approved root invocation\n"); return 2; }
    events = fopen(argv[4], "wx");
    if (!events) { perror("events file"); return 2; }
    FILE *input = NULL;
    struct bpf_object *object = NULL;
    char *logs[8] = {};
    const size_t log_size = 4 * 1024 * 1024;
    for (int i = 0; i < 8; ++i) {
        logs[i] = calloc(1, log_size);
        if (!logs[i]) { error("allocate verifier logs"); goto out; }
    }
    struct bpf_object_open_opts open_opts = {.sz = sizeof(open_opts),
        .kernel_log_buf = logs[7], .kernel_log_size = log_size, .kernel_log_level = 1};
    object = bpf_object__open_file(argv[2], &open_opts);
    if (!object || libbpf_get_error(object)) { object = NULL; error("open BPF ELF"); goto out; }
    struct bpf_map *map;
    int map_count = 0, program_count = 0;
    bpf_object__for_each_map(map, object) {
        /* Disables both automatic pinned-map reuse and automatic pin creation. */
        if (bpf_map__set_pin_path(map, NULL) || bpf_map__pin_path(map)) {
            errno = EPROTO; error("disable map pinning"); goto out;
        }
        ++map_count;
    }
    struct bpf_program *program;
    bpf_object__for_each_program(program, object) ++program_count;
    if (map_count != 5 || program_count != 7) { errno = EPROTO; error("object counts"); goto out; }
    const char *map_names[] = {"flow_map", "nn_parameters", "nn_idx", "progs"};
    const int value_sizes[] = {sizeof(struct flow_attribute), sizeof(struct Net), 4, 4};
    const int key_sizes[] = {sizeof(struct flow), 4, 4, 4};
    const enum bpf_map_type types[] = {BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY};
    for (int i = 0; i < 4; ++i) {
        map = bpf_object__find_map_by_name(object, map_names[i]);
        if (!map || bpf_map__value_size(map) != (unsigned)value_sizes[i]
            || bpf_map__key_size(map) != (unsigned)key_sizes[i] || bpf_map__type(map) != types[i]) {
            errno = EPROTO; error("original map ABI mismatch"); goto out;
        }
    }
    for (int i = 0; i < 7; ++i) {
        program = bpf_object__find_program_by_name(object, names[i]);
        if (!program || bpf_program__type(program) != BPF_PROG_TYPE_XDP) {
            errno = EPROTO; error("original XDP program missing"); goto out;
        }
        if (bpf_program__set_log_buf(program, logs[i], log_size)
            || bpf_program__set_log_level(program, 1)) { error("set verifier logging"); goto out; }
    }
    fprintf(events, "{\"event\":\"schema\",\"program_count\":7,\"map_count\":5,"
            "\"flow_key_bytes\":%zu,\"flow_value_bytes\":%zu,\"model_bytes\":%zu,"
            "\"all_pin_paths_disabled\":true,\"kernel_execution\":false}\n",
            sizeof(struct flow), sizeof(struct flow_attribute), sizeof(struct Net));
    fflush(events);
    if (!execute) goto out;
    if (bpf_object__load(object)) { error("BPF object load / verifier"); goto out; }
    loaded = 1;
    fprintf(events, "{\"event\":\"loaded\",\"programs\":[");
    for (int i = 0; i < 7; ++i) {
        program = bpf_object__find_program_by_name(object, names[i]);
        prog_fds[i] = bpf_program__fd(program);
        struct bpf_prog_info info = {}; uint32_t length = sizeof(info);
        if (bpf_prog_get_info_by_fd(prog_fds[i], &info, &length)) { error("program info"); goto out; }
        prog_ids[i] = info.id;
        fprintf(events, "%s{\"name\":\"%s\",\"id\":%u,\"type\":%u,"
                "\"jited_prog_len\":%u,\"xlated_prog_len\":%u}", i ? "," : "", names[i],
                info.id, info.type, info.jited_prog_len, info.xlated_prog_len);
    }
    fprintf(events, "],\"maps\":[");
    int mi = 0;
    bpf_object__for_each_map(map, object) {
        struct bpf_map_info info = {}; uint32_t length = sizeof(info);
        if (bpf_map_get_info_by_fd(bpf_map__fd(map), &info, &length)) { error("map info"); goto out; }
        map_ids[mi++] = info.id;
        fprintf(events, "%s{\"name\":\"%s\",\"id\":%u}", mi > 1 ? "," : "", bpf_map__name(map), info.id);
    }
    fprintf(events, "]}\n"); fflush(events);
    input = fopen(argv[3], "rb");
    if (!input) { error("open fixture input"); goto out; }
    char magic[8]; uint32_t fixture_count, packet_count;
    struct Net model;
    if (read_exact(input, magic, 8) || memcmp(magic, "NNKPAR1\0", 8)
        || read_exact(input, &fixture_count, 4) || read_exact(input, &packet_count, 4)
        || fixture_count > 16 || packet_count > 16 || read_exact(input, &model, sizeof(model))) {
        errno = EINVAL; error("fixture header"); goto out;
    }
    for (int i = 0; i < 6; ++i) if (model.scale[i] <= 0) {
        errno = EINVAL; error("nonpositive model scale"); goto out;
    }
    int model_fd = bpf_object__find_map_fd_by_name(object, "nn_parameters");
    int index_fd = bpf_object__find_map_fd_by_name(object, "nn_idx");
    int tail_fd = bpf_object__find_map_fd_by_name(object, "progs");
    flow_fd = bpf_object__find_map_fd_by_name(object, "flow_map");
    for (int32_t slot = 0; slot < 2; ++slot) {
        struct Net observed;
        if (bpf_map_update_elem(model_fd, &slot, &model, BPF_ANY)
            || bpf_map_lookup_elem(model_fd, &slot, &observed) || memcmp(&model, &observed, sizeof(model))) {
            error("model write/readback"); goto out;
        }
        fprintf(events, "{\"event\":\"model\",\"slot\":%d,\"bytes_verified\":%zu}\n", slot, sizeof(model));
    }
    int32_t zero = 0;
    if (bpf_map_update_elem(index_fd, &zero, &zero, BPF_ANY) || empty_tail_calls(tail_fd)) {
        error("private map initialization"); goto out;
    }
    fprintf(events, "{\"event\":\"tail_call_slots\",\"slots\":6,\"empty\":true}\n");
    unsigned char packet[512]; uint32_t length;
    if (packet_read(input, packet, &length)) goto out;
    struct flow key; packet_key(packet, &key);
    for (uint32_t i = 0; i < fixture_count; ++i) {
        int64_t raw[6]; int32_t snapshots[6][32] = {};
        struct flow_attribute attr = {};
        if (read_exact(input, raw, sizeof(raw))) goto out;
        attr.max_packet_length = raw[0]; attr.max_duration = raw[1]; attr.min_packet_length = raw[2];
        attr.dst_port = raw[3]; attr.header_length = raw[4]; attr.num_packet = raw[5];
        if (bpf_map_update_elem(flow_fd, &key, &attr, BPF_ANY)) { error("seed fixture features"); goto out; }
        if (stages(packet, length, &key, "fixture", i, snapshots)) goto out;
        if (bpf_map_lookup_elem(flow_fd, &key, &attr)) { error("read fixture features"); goto out; }
        fprintf(events, "{\"event\":\"fixture\",\"index\":%u,\"features\":", i); features(&attr);
        fprintf(events, ",\"stages\":"); tensors(snapshots);
        fprintf(events, ",\"prediction_derived\":%d}\n", snapshots[5][0] > snapshots[5][1] ? 0 : 1);
        fflush(events);
    }
    for (uint32_t i = 0; i < packet_count; ++i) {
        uint32_t reset;
        if (read_exact(input, &reset, 4) || packet_read(input, packet, &length)) goto out;
        if (reset && bpf_map_delete_elem(flow_fd, &key) && errno != ENOENT) { error("reset private flow"); goto out; }
        if (invoke(6, packet, length, "packet", i)) goto out;
        struct flow_attribute attr; int32_t snapshots[6][32] = {};
        int present = bpf_map_lookup_elem(flow_fd, &key, &attr) == 0;
        if (!present && errno != ENOENT) { error("read packet features"); goto out; }
        int run_stages = present && (packet[47] & 5) && packet[26] == 33 && packet[29] == 73;
        if (run_stages && stages(packet, length, &key, "packet", i, snapshots)) goto out;
        fprintf(events, "{\"event\":\"packet\",\"index\":%u,\"flow_present\":%s", i, present ? "true" : "false");
        if (present) {
            fprintf(events, ",\"features\":"); features(&attr);
            fprintf(events, ",\"last_packet_time\":%lld,\"detection_start_time\":%llu", (long long)attr.last_packet_time,
                    (unsigned long long)attr.detection_start_time);
        }
        if (run_stages) { fprintf(events, ",\"stages\":"); tensors(snapshots); }
        fprintf(events, "}\n"); fflush(events);
    }
    if (fgetc(input) != EOF) { errno = EINVAL; error("trailing fixture data"); goto out; }
    if (empty_tail_calls(tail_fd)) goto out;
out:
    if (input) fclose(input);
    bpf_object__close(object);
    if (loaded) cleanup_ids();
    for (int i = 0; i < 8; ++i) {
        if (execute && logs[i]) {
            char path[4096];
            snprintf(path, sizeof(path), "%s/verifier-%s.log", argv[5], i < 7 ? names[i] : "btf");
            FILE *f = fopen(path, "wx");
            if (f) { fputs(logs[i], f); fclose(f); }
            else error("save verifier log");
        }
        free(logs[i]);
    }
    fclose(events);
    return failed ? 1 : 0;
}
