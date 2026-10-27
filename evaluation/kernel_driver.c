/* Exercise the unmodified baseline object, without attaching to an interface. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <linux/magic.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Import the real map value layouts, but not their BPF-only declarations. */
typedef int32_t s32;
typedef int64_t s64;
typedef uint64_t u64;
#define __uint(name, value) int name
#define __type(name, type) type *name
#define SEC(name) __attribute__((unused))
#include "../src/common.h"
#include "../src/params.bpf.h"
#undef SEC
#undef __type
#undef __uint

_Static_assert(sizeof(struct Net) == 5216, "model wire ABI changed");
_Static_assert(offsetof(struct Net, mean) == 5120, "model mean offset changed");
_Static_assert(offsetof(struct Net, scale) == 5168, "model scale offset changed");
_Static_assert(sizeof(int) == 4, "baseline flow key requires 32-bit int");

#define BLOCKED 77
#define PACKET_CAPACITY 128
#define STAGE_COUNT 6

static volatile sig_atomic_t interrupted;
static const char *const stage_names[STAGE_COUNT] = {
    "xdp_preprocessing", "xdp_input_linear", "xdp_input_relu",
    "xdp_hidden_linear", "xdp_hidden_relu", "xdp_output_linear"
};
static const char *const trace_names[STAGE_COUNT] = {
    "normalized", "input_linear", "input_relu", "hidden_linear", "hidden_relu", "output"
};
static const size_t trace_sizes[STAGE_COUNT] = {6, 32, 32, 32, 32, 2};

struct driver {
    struct bpf_object *object;
    FILE *vectors;
    int flow_fd, progs_fd, parameters_fd, index_fd;
    int stages[STAGE_COUNT], entry_fd;
    int status;
    bool executed, private_created, features_started, vector_comma, feature_comma;
    bool cleanup_complete;
    char reason[1024];
    char private_root[64];
    unsigned char packet[PACKET_CAPACITY], packet_out[PACKET_CAPACITY];
    struct xdp_md short_context;
    uint32_t short_input_size;
    struct flow key;
};

static void on_signal(int number)
{
    interrupted = number;
}

static int libbpf_log(enum libbpf_print_level level, const char *format, va_list args)
{
    (void)level;
    return vfprintf(stderr, format, args);
}

static int fail(struct driver *driver, int status, const char *format, ...)
{
    va_list args;
    if (driver->status == 0) {
        driver->status = status;
        va_start(args, format);
        vsnprintf(driver->reason, sizeof(driver->reason), format, args);
        va_end(args);
        fprintf(stderr, "%s\n", driver->reason);
    }
    return -1;
}

static int check_signal(struct driver *driver)
{
    if (interrupted)
        return fail(driver, 1, "Interrupted by signal %d", (int)interrupted);
    return 0;
}

static bool missing_prerequisite(int error)
{
    return error == EPERM || error == EACCES || error == ENOSYS || error == EOPNOTSUPP;
}

static int system_error(struct driver *driver, const char *operation, int error)
{
    if (interrupted)
        return check_signal(driver);
    return fail(driver, missing_prerequisite(error) ? BLOCKED : 1,
                "%s: %s (errno %d)", operation, strerror(error), error);
}

static void json_string(const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;
    putchar('"');
    for (; *cursor; ++cursor) {
        if (*cursor == '"' || *cursor == '\\')
            printf("\\%c", *cursor);
        else if (*cursor < 0x20 || *cursor >= 0x7f)
            printf("\\u%04x", (unsigned)*cursor);
        else
            putchar(*cursor);
    }
    putchar('"');
}

static void json_array(const int32_t *values, size_t count)
{
    putchar('[');
    for (size_t i = 0; i < count; ++i)
        printf("%s%" PRId32, i ? "," : "", values[i]);
    putchar(']');
}

static int open_inputs(struct driver *driver, const char *model_path,
                       const char *vectors_path, struct Net *model)
{
    FILE *stream = fopen(model_path, "rb");
    struct stat metadata;
    size_t count;
    int extra, error;
    if (!stream)
        return system_error(driver, "Opening model binary", errno);
    count = fread(model, 1, sizeof(*model), stream);
    extra = fgetc(stream);
    error = ferror(stream);
    if (fclose(stream) != 0 && !error)
        error = errno;
    if (error)
        return fail(driver, 1, "Reading model binary failed");
    if (count != sizeof(*model) || extra != EOF)
        return fail(driver, 1, "Model binary must contain exactly %zu bytes", sizeof(*model));
    for (size_t i = 0; i < 6; ++i)
        if (model->scale[i] == 0)
            return fail(driver, 1, "Model normalization scale[%zu] is zero", i);
    driver->vectors = fopen(vectors_path, "rb");
    if (!driver->vectors)
        return system_error(driver, "Opening vectors binary", errno);
    if (fstat(fileno(driver->vectors), &metadata) != 0)
        return system_error(driver, "Inspecting vectors binary", errno);
    if (!S_ISREG(metadata.st_mode) || metadata.st_size <= 0 ||
        metadata.st_size % (6 * sizeof(int64_t)) != 0)
        return fail(driver, 1, "Vectors binary must be a nonempty regular file of complete six-int64 records");
    return check_signal(driver);
}

static int make_private_root(struct driver *driver)
{
    struct statfs filesystem;
    if (statfs("/sys/fs/bpf", &filesystem) != 0) {
        int error = errno;
        if (error == ENOENT || error == ENOTDIR)
            return fail(driver, BLOCKED, "bpffs is unavailable at /sys/fs/bpf: %s", strerror(error));
        return system_error(driver, "Inspecting /sys/fs/bpf", error);
    }
    if ((unsigned long)filesystem.f_type != BPF_FS_MAGIC)
        return fail(driver, BLOCKED, "/sys/fs/bpf is not a mounted bpffs filesystem");
    snprintf(driver->private_root, sizeof(driver->private_root),
             "/sys/fs/bpf/nn_ebpf_eval_XXXXXX");
    if (!mkdtemp(driver->private_root))
        return system_error(driver, "Creating private bpffs directory", errno);
    driver->private_created = true;
    /* mkdtemp creates mode 0700; an explicit chmod also defeats a restrictive umask. */
    if (chmod(driver->private_root, 0700) != 0)
        return system_error(driver, "Restricting private bpffs directory", errno);
    return check_signal(driver);
}

static int map_abi(struct driver *driver, const char *name, enum bpf_map_type type,
                   uint32_t key_size, uint32_t value_size, uint32_t entries, int *fd)
{
    struct bpf_map *map = bpf_object__find_map_by_name(driver->object, name);
    struct bpf_map_info info = {0};
    uint32_t info_size = sizeof(info);
    if (!map || bpf_map__type(map) != type || bpf_map__key_size(map) != key_size ||
        bpf_map__value_size(map) != value_size || bpf_map__max_entries(map) != entries)
        return fail(driver, 1, "Baseline map %s does not match the host ABI", name);
    *fd = bpf_map__fd(map);
    if (*fd < 0)
        return fail(driver, 1, "Baseline map %s has no loaded file descriptor", name);
    if (bpf_obj_get_info_by_fd(*fd, &info, &info_size) != 0)
        return system_error(driver, "Inspecting loaded map ABI", errno);
    if (info.type != (uint32_t)type || info.key_size != key_size ||
        info.value_size != value_size || info.max_entries != entries)
        return fail(driver, 1, "Loaded map %s does not match the host ABI", name);
    return 0;
}

static int load_object(struct driver *driver, const char *object_path, const struct Net *model)
{
    struct bpf_object_open_opts options = {
        .sz = sizeof(options), .pin_root_path = driver->private_root
    };
    struct bpf_map *map;
    struct bpf_program *program;
    char expected[PATH_MAX];
    int32_t zero = 0;
    long error;
    int result;
    driver->object = bpf_object__open_file(object_path, &options);
    error = libbpf_get_error(driver->object);
    if (!driver->object || error) {
        driver->object = NULL;
        if (error == -ENOENT || error == -ENOTDIR || (!error && (errno == ENOENT || errno == ENOTDIR)))
            return fail(driver, BLOCKED, "Baseline BPF object is unavailable: %s", object_path);
        return system_error(driver, "Opening baseline BPF object", error ? (int)-error : errno);
    }
    /* Reject unexpected auto-pins before load; cleanup only owns these two names. */
    bpf_object__for_each_map(map, driver->object) {
        const char *pin = bpf_map__pin_path(map);
        const char *name = bpf_map__name(map);
        bool pinned_model = strcmp(name, "nn_idx") == 0 || strcmp(name, "nn_parameters") == 0;
        if (pinned_model) {
            snprintf(expected, sizeof(expected), "%s/%s", driver->private_root, name);
            if (!pin || strcmp(pin, expected) != 0)
                return fail(driver, 1, "Map %s is not scoped to the private pin root", name);
        } else if (pin) {
            return fail(driver, 1, "Unexpected auto-pinned map %s in baseline object", name);
        }
    }
    if (check_signal(driver) != 0)
        return -1;
    result = bpf_object__load(driver->object);
    if (result != 0)
        return system_error(driver, "Loading baseline BPF object", result < 0 ? -result : errno);
    if (map_abi(driver, "flow_map", BPF_MAP_TYPE_HASH, sizeof(struct flow),
                sizeof(struct flow_attribute), MAX_PACKET_REACORD, &driver->flow_fd) != 0 ||
        map_abi(driver, "progs", BPF_MAP_TYPE_PROG_ARRAY, sizeof(uint32_t), sizeof(uint32_t),
                1024, &driver->progs_fd) != 0 ||
        map_abi(driver, "nn_parameters", BPF_MAP_TYPE_ARRAY, sizeof(int32_t),
                sizeof(struct Net), 2, &driver->parameters_fd) != 0 ||
        map_abi(driver, "nn_idx", BPF_MAP_TYPE_ARRAY, sizeof(int32_t), sizeof(int32_t),
                1, &driver->index_fd) != 0)
        return -1;
    for (size_t i = 0; i <= STAGE_COUNT; ++i) {
        const char *name = i == STAGE_COUNT ? "xdp_prog" : stage_names[i];
        program = bpf_object__find_program_by_name(driver->object, name);
        if (!program || bpf_program__type(program) != BPF_PROG_TYPE_XDP || bpf_program__fd(program) < 0)
            return fail(driver, 1, "Missing loaded XDP program %s", name);
        if (i == STAGE_COUNT)
            driver->entry_fd = bpf_program__fd(program);
        else
            driver->stages[i] = bpf_program__fd(program);
    }
    if (bpf_map_update_elem(driver->parameters_fd, &zero, model, BPF_ANY) != 0 ||
        bpf_map_update_elem(driver->index_fd, &zero, &zero, BPF_ANY) != 0)
        return system_error(driver, "Writing private model maps", errno);
    return check_signal(driver);
}

/* Byte-oriented packet construction avoids host struct padding and bitfield ABI. */
static size_t make_packet(struct driver *driver, unsigned payload, unsigned tcp_header,
                          unsigned char flags)
{
    unsigned char *packet = driver->packet;
    uint16_t short_value;
    memset(packet, 0, sizeof(driver->packet));
    packet[12] = 0x08;
    packet[13] = 0x00;
    packet[14] = 0x45;
    short_value = htons((uint16_t)(20 + tcp_header + payload));
    memcpy(packet + 16, &short_value, sizeof(short_value));
    packet[22] = 64;
    packet[23] = IPPROTO_TCP;
    packet[26] = 33; packet[27] = 33; packet[28] = 33; packet[29] = 73;
    packet[30] = 33; packet[31] = 33; packet[32] = 33; packet[33] = 1;
    short_value = htons(40000);
    memcpy(packet + 34, &short_value, sizeof(short_value));
    short_value = htons(5001);
    memcpy(packet + 36, &short_value, sizeof(short_value));
    packet[46] = (unsigned char)((tcp_header / 4) << 4);
    packet[47] = flags;
    return 14 + 20 + tcp_header + payload;
}

static void set_flow_key(struct driver *driver)
{
    uint32_t address;
    uint16_t port;
    memset(&driver->key, 0, sizeof(driver->key));
    memcpy(&address, driver->packet + 26, sizeof(address));
    driver->key.saddr = (int)address;
    memcpy(&address, driver->packet + 30, sizeof(address));
    driver->key.daddr = (int)address;
    memcpy(&port, driver->packet + 34, sizeof(port));
    driver->key.sport = port;
    memcpy(&port, driver->packet + 36, sizeof(port));
    driver->key.dport = port;
}

static int run_program(struct driver *driver, int fd, size_t packet_size, uint32_t *retval)
{
    struct bpf_test_run_opts options = {
        .sz = sizeof(options), .data_in = driver->packet, .data_out = driver->packet_out,
        .data_size_in = packet_size, .data_size_out = sizeof(driver->packet_out), .repeat = 1
    };
    struct xdp_md context;
    /* Keep the complete frame Ethernet-sized, but end its linear region at the
     * requested boundary. The test-run API puts the remaining byte(s) in XDP
     * fragments. The baseline parser must therefore see a short linear header,
     * without violating the kernel's whole-frame minimum or emitting traffic. */
    if (packet_size < ETH_HLEN) {
        memset(&context, 0, sizeof(context));
        memset(&driver->short_context, 0, sizeof(driver->short_context));
        context.data_end = packet_size;
        options.data_size_in = ETH_HLEN;
        options.ctx_in = &context;
        options.ctx_size_in = sizeof(context);
        options.ctx_out = &driver->short_context;
        options.ctx_size_out = sizeof(driver->short_context);
        driver->short_input_size = options.data_size_in;
    }
    int result;
    if (check_signal(driver) != 0)
        return -1;
    result = bpf_prog_test_run_opts(fd, &options);
    if (result != 0) {
        char operation[112];
        snprintf(operation, sizeof(operation),
                 "BPF_PROG_TEST_RUN (linear bytes %zu, frame bytes %u)",
                 packet_size, options.data_size_in);
        return system_error(driver, operation, result < 0 ? -result : errno);
    }
    driver->executed = true;
    if (packet_size < ETH_HLEN &&
        (options.ctx_size_out != sizeof(driver->short_context) ||
         options.data_size_out != driver->short_input_size ||
         driver->short_context.data_meta != 0 ||
         driver->short_context.data != 0 ||
         driver->short_context.data_end != packet_size))
        return fail(driver, 1, "Test-run context did not preserve the short linear packet and full frame");
    *retval = options.retval;
    if (options.retval != XDP_PASS)
        return fail(driver, 1, "BPF_PROG_TEST_RUN returned %u instead of XDP_PASS", options.retval);
    return check_signal(driver);
}

static int tail_slots(struct driver *driver, bool populate)
{
    for (uint32_t i = 0; i < STAGE_COUNT; ++i) {
        if (check_signal(driver) != 0)
            return -1;
        if (populate) {
            uint32_t fd = driver->stages[i];
            if (bpf_map_update_elem(driver->progs_fd, &i, &fd, BPF_ANY) != 0)
                return system_error(driver, "Populating private tail-call map", errno);
        } else if (bpf_map_delete_elem(driver->progs_fd, &i) != 0 && errno != ENOENT) {
            return system_error(driver, "Clearing private tail-call map", errno);
        }
    }
    return 0;
}

static int read_flow(struct driver *driver, struct flow_attribute *attribute)
{
    if (bpf_map_lookup_elem(driver->flow_fd, &driver->key, attribute) != 0)
        return system_error(driver, "Reading private flow state", errno);
    return 0;
}

static int seed_vector(struct driver *driver, const int64_t vector[6])
{
    struct flow_attribute attribute = {
        .max_packet_length = vector[0], .max_duration = vector[1],
        .min_packet_length = vector[2], .dst_port = vector[3],
        .header_length = vector[4], .num_packet = vector[5], .nn_idx = 0
    };
    if (bpf_map_update_elem(driver->flow_fd, &driver->key, &attribute, BPF_ANY) != 0)
        return system_error(driver, "Seeding private inference flow", errno);
    return 0;
}

static int run_vectors(struct driver *driver)
{
    int64_t vector[6];
    int32_t traces[STAGE_COUNT][32], chain[2];
    struct flow_attribute attribute;
    size_t index = 0, count, packet_size = make_packet(driver, 0, 20, 0x10);
    uint32_t retval;
    set_flow_key(driver);
    if (tail_slots(driver, false) != 0)
        return -1;
    while ((count = fread(vector, 1, sizeof(vector), driver->vectors)) != 0) {
        if (count != sizeof(vector))
            return fail(driver, 1, "Incomplete vector record at index %zu", index);
        if (seed_vector(driver, vector) != 0)
            return -1;
        for (size_t stage = 0; stage < STAGE_COUNT; ++stage) {
            const int32_t *values;
            if (run_program(driver, driver->stages[stage], packet_size, &retval) != 0 ||
                read_flow(driver, &attribute) != 0)
                return -1;
            values = stage == 0 || stage == 3 || stage == 4 ? attribute.hidden2 : attribute.hidden1;
            memcpy(traces[stage], values, trace_sizes[stage] * sizeof(*values));
        }
        if (seed_vector(driver, vector) != 0 || tail_slots(driver, true) != 0 ||
            run_program(driver, driver->stages[0], packet_size, &retval) != 0 ||
            read_flow(driver, &attribute) != 0 || tail_slots(driver, false) != 0)
            return -1;
        memcpy(chain, attribute.hidden1, sizeof(chain));
        printf("%s{\"index\":%zu", driver->vector_comma ? "," : "", index);
        for (size_t stage = 0; stage < STAGE_COUNT; ++stage) {
            printf(",\"%s\":", trace_names[stage]);
            json_array(traces[stage], trace_sizes[stage]);
        }
        printf(",\"label\":%d,\"chain_output\":", traces[5][0] > traces[5][1] ? 0 : 1);
        json_array(chain, 2);
        printf(",\"chain_label\":%d}", chain[0] > chain[1] ? 0 : 1);
        driver->vector_comma = true;
        ++index;
        if (ferror(stdout))
            return fail(driver, 1, "Writing kernel JSON output failed");
    }
    if (ferror(driver->vectors))
        return fail(driver, 1, "Reading vectors binary failed");
    if (index == 0)
        return fail(driver, 1, "Vectors binary contains no records");
    return check_signal(driver);
}

static int clear_flows(struct driver *driver)
{
    struct flow key;
    for (unsigned i = 0; i <= MAX_PACKET_REACORD; ++i) {
        if (check_signal(driver) != 0)
            return -1;
        if (bpf_map_get_next_key(driver->flow_fd, NULL, &key) != 0) {
            if (errno == ENOENT)
                return 0;
            return system_error(driver, "Enumerating private flow map", errno);
        }
        if (bpf_map_delete_elem(driver->flow_fd, &key) != 0)
            return system_error(driver, "Clearing private flow map", errno);
    }
    return fail(driver, 1, "Private flow map could not be emptied");
}

static int flow_count(struct driver *driver, unsigned *count)
{
    struct flow key, next;
    bool first = true;
    *count = 0;
    for (;;) {
        if (bpf_map_get_next_key(driver->flow_fd, first ? NULL : &key, &next) != 0) {
            if (errno == ENOENT)
                return 0;
            return system_error(driver, "Counting private flow entries", errno);
        }
        key = next;
        first = false;
        if (++*count > MAX_PACKET_REACORD)
            return fail(driver, 1, "Private flow enumeration exceeded map capacity");
        if (check_signal(driver) != 0)
            return -1;
    }
}

static int monotonic_ns(struct driver *driver, int64_t *result)
{
    struct timespec stamp;
    if (clock_gettime(CLOCK_MONOTONIC, &stamp) != 0)
        return system_error(driver, "Sampling CLOCK_MONOTONIC", errno);
    if (stamp.tv_sec > (INT64_MAX - stamp.tv_nsec) / 1000000000)
        return fail(driver, 1, "CLOCK_MONOTONIC value exceeds signed-int64 range");
    *result = (int64_t)stamp.tv_sec * 1000000000 + stamp.tv_nsec;
    return 0;
}

static void print_feature_state(const struct flow_attribute *attribute)
{
    printf("{\"max_packet_length\":%" PRId64 ",\"max_duration\":%" PRId64
           ",\"min_packet_length\":%" PRId64 ",\"dst_port\":%" PRId64
           ",\"header_length\":%" PRId64 ",\"num_packet\":%" PRId64
           ",\"last_packet_time\":%" PRId64 "}",
           attribute->max_packet_length, attribute->max_duration,
           attribute->min_packet_length, attribute->dst_port,
           attribute->header_length, attribute->num_packet, attribute->last_packet_time);
}

static int run_features(struct driver *driver)
{
    static const unsigned payloads[3] = {10, 40, 0};
    static const unsigned headers[3] = {20, 24, 20};
    static const unsigned char flags[3] = {0x02, 0x10, 0x01};
    static const int64_t deltas[3] = {0, 5000000, 1000000};
    static const char *const skip_names[6] = {
        "source_mismatch", "non_ipv4", "non_tcp", "truncated_ethernet", "truncated_ipv4", "truncated_tcp"
    };
    struct flow_attribute attribute;
    uint32_t retval;
    if (clear_flows(driver) != 0 || tail_slots(driver, false) != 0)
        return -1;
    for (size_t i = 0; i < 3; ++i) {
        int64_t before, after, seeded = 0, previous_max = 0;
        size_t size = make_packet(driver, payloads[i], headers[i], flags[i]);
        set_flow_key(driver);
        if (i) {
            if (read_flow(driver, &attribute) != 0 || monotonic_ns(driver, &seeded) != 0)
                return -1;
            previous_max = attribute.max_duration;
            if (seeded < deltas[i])
                return fail(driver, 1, "Monotonic uptime is too short for controlled feature timing");
            seeded -= deltas[i];
            attribute.last_packet_time = seeded;
            if (bpf_map_update_elem(driver->flow_fd, &driver->key, &attribute, BPF_EXIST) != 0)
                return system_error(driver, "Seeding previous feature timestamp", errno);
        }
        if (monotonic_ns(driver, &before) != 0 ||
            run_program(driver, driver->entry_fd, size, &retval) != 0 ||
            monotonic_ns(driver, &after) != 0 || read_flow(driver, &attribute) != 0)
            return -1;
        printf("%s{\"name\":\"valid_%zu\",\"kind\":\"valid\",\"payload_bytes\":%u,"
               "\"tcp_header_bytes\":%u,\"retval\":%u,\"time_before_ns\":%" PRId64
               ",\"time_after_ns\":%" PRId64 ",\"seeded_previous_ns\":",
               driver->feature_comma ? "," : "", i + 1, payloads[i], headers[i], retval, before, after);
        if (i)
            printf("%" PRId64, seeded);
        else
            printf("null");
        printf(",\"previous_max_duration\":%" PRId64 ",\"state\":", previous_max);
        print_feature_state(&attribute);
        putchar('}');
        driver->feature_comma = true;
    }
    for (size_t i = 0; i < 6; ++i) {
        unsigned entries;
        size_t size = make_packet(driver, 0, 20, 0x10);
        if (clear_flows(driver) != 0)
            return -1;
        switch (i) {
        case 0: driver->packet[29] = 74; break;
        case 1: driver->packet[12] = 0x86; driver->packet[13] = 0xdd; break;
        case 2: driver->packet[23] = IPPROTO_UDP; break;
        case 3: size = 13; break;
        case 4: size = 33; break;
        case 5: size = 53; break;
        }
        if (run_program(driver, driver->entry_fd, size, &retval) != 0 || flow_count(driver, &entries) != 0)
            return -1;
        printf("%s{\"name\":\"%s\",\"kind\":\"skipped\",\"retval\":%u,\"flow_entries\":%u",
               driver->feature_comma ? "," : "", skip_names[i], retval, entries);
        if (size < ETH_HLEN)
            printf(",\"test_run_context\":{\"input_bytes\":%u,\"data\":%u,"
                   "\"data_end\":%u,\"data_meta\":%u}",
                   driver->short_input_size, driver->short_context.data,
                   driver->short_context.data_end, driver->short_context.data_meta);
        putchar('}');
        driver->feature_comma = true;
        if (entries != 0)
            return fail(driver, 1, "Skipped packet %s created %u flow entries", skip_names[i], entries);
    }
    return check_signal(driver);
}

static void cleanup(struct driver *driver)
{
    static const char *const pin_names[2] = {"nn_idx", "nn_parameters"};
    char path[PATH_MAX];
    bool complete = true;
    int result;
    if (driver->vectors) {
        if (fclose(driver->vectors) != 0)
            fail(driver, 1, "Closing vectors binary failed: %s", strerror(errno));
        driver->vectors = NULL;
    }
    if (driver->object) {
        bpf_object__close(driver->object);
        driver->object = NULL;
    }
    if (driver->private_created) {
        for (size_t i = 0; i < 2; ++i) {
            snprintf(path, sizeof(path), "%s/%s", driver->private_root, pin_names[i]);
            do {
                result = unlink(path);
            } while (result != 0 && errno == EINTR);
            if (result != 0 && errno != ENOENT) {
                fprintf(stderr, "Cleaning private pin %s: %s\n", path, strerror(errno));
                complete = false;
            }
        }
        do {
            result = rmdir(driver->private_root);
        } while (result != 0 && errno == EINTR);
        if (result != 0) {
            fprintf(stderr, "Removing private pin directory %s: %s\n", driver->private_root, strerror(errno));
            complete = false;
        }
    }
    driver->cleanup_complete = complete;
    if (!complete) {
        driver->status = 1;
        snprintf(driver->reason, sizeof(driver->reason), "Private bpffs cleanup did not complete; inspect %s",
                 driver->private_root);
    }
}

int main(int argc, char **argv)
{
    struct driver driver = {0};
    struct Net model;
    struct sigaction action = {.sa_handler = on_signal};
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    libbpf_set_print(libbpf_log);
    printf("{\"schema_version\":1,\"vectors\":[");
    sigemptyset(&action.sa_mask);
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 || sigaction(SIGTERM, &action, NULL) != 0 ||
        sigaction(SIGPIPE, &ignore, NULL) != 0) {
        system_error(&driver, "Installing controlled-cleanup signal handlers", errno);
        goto finish;
    }
    if (argc != 4) {
        fail(&driver, 1, "Usage: kernel-driver OBJECT_PATH MODEL_BINARY VECTORS_BINARY");
        goto finish;
    }
    if (open_inputs(&driver, argv[2], argv[3], &model) != 0 ||
        make_private_root(&driver) != 0 || load_object(&driver, argv[1], &model) != 0 ||
        run_vectors(&driver) != 0)
        goto finish;
    printf("],\"feature_cases\":[");
    driver.features_started = true;
    run_features(&driver);
finish:
    check_signal(&driver);
    cleanup(&driver);
    check_signal(&driver);
    if (!driver.features_started)
        printf("],\"feature_cases\":[");
    printf("],\"executed\":%s,\"status\":", driver.executed ? "true" : "false");
    json_string(driver.status == 0 ? "pass" : driver.status == BLOCKED ? "blocked" : "fail");
    printf(",\"reason\":");
    json_string(driver.reason);
    printf(",\"cleanup\":{\"private_pin_root\":");
    if (driver.private_created)
        json_string(driver.private_root);
    else
        printf("null");
    printf(",\"complete\":%s}}\n", driver.cleanup_complete ? "true" : "false");
    if (fflush(stdout) != 0 || ferror(stdout)) {
        fprintf(stderr, "Writing kernel JSON output failed: %s\n", strerror(errno));
        return 1;
    }
    return driver.status;
}
