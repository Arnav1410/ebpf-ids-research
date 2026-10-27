/* Nonprivileged TC parser/pipeline characterization. Never kernel evidence. */
#include <stdint.h>
#include <string.h>
#include "../id_scan.h"
#include "../tc_ids.bpf.c"
#undef PARAMS_BPF_H
#include "../../src/mlp_params.bpf.h"
static struct flow keys[8];
static struct flow_attribute attrs[8];
static int count;
static struct Net model;
static struct ids_tc_stats counters;
static struct tc_result record;
static int32_t active;
static const unsigned char *frame;
static unsigned int frame_length;
static uint64_t now;
int tc_test_load(void *ctx, unsigned int offset, void *dst, unsigned int length)
{
    (void)ctx;
    if (offset > frame_length || length > frame_length - offset) return -1;
    memcpy(dst, frame + offset, length); return 0;
}
void *validation_lookup(void *map, const void *key)
{
    if (map == &stats) return &counters;
    if (map == &results) return &record;
    if (map == &nn_idx) return &active;
    if (map == &nn_parameters) return *(const int32_t *)key >= 0 && *(const int32_t *)key < 2 ? &model : 0;
    if (map == &flow_map)
        for (int i = 0; i < count; ++i) if (!memcmp(&keys[i], key, sizeof(keys[i]))) return &attrs[i];
    return 0;
}
long validation_update(void *map, const void *key, const void *value, unsigned long long flags)
{
    (void)flags;
    if (map != &flow_map || count >= 8 || validation_lookup(map, key)) return -1;
    memcpy(&keys[count], key, sizeof(keys[count])); memcpy(&attrs[count], value, sizeof(attrs[count]));
    ++count; return 0;
}
unsigned long long validation_clock(void) { return now; }
void validation_tail_call(struct xdp_md *ctx, void *map, unsigned int slot)
{
    (void)map;
    int (*functions[])(struct __sk_buff *) = {tc_preprocessing, tc_input_linear, tc_input_relu,
                                             tc_hidden_linear, tc_hidden_relu, tc_output_linear};
    if (slot < 6) functions[slot]((struct __sk_buff *)ctx);
}
void host_reset(void)
{
    count = 0; active = 0;
    memset(&counters, 0, sizeof(counters)); memset(&record, 0, sizeof(record));
    memset(keys, 0, sizeof(keys)); memset(attrs, 0, sizeof(attrs));
    memcpy(model.layer_0_weight, layer_0_weight, sizeof(layer_0_weight));
    memcpy(model.layer_1_weight, layer_1_weight, sizeof(layer_1_weight));
    memcpy(model.layer_2_weight, layer_2_weight, sizeof(layer_2_weight));
    memcpy(model.mean, mean, sizeof(mean)); memcpy(model.scale, scale, sizeof(scale));
}
int host_packet(const unsigned char *data, unsigned int len, uint64_t timestamp)
{
    frame = data; frame_length = len; now = timestamp;
    struct __sk_buff skb = {.len = len}; return tc_entry(&skb);
}
int host_parse(const unsigned char *data, unsigned int len)
{
    frame = data; frame_length = len;
    struct __sk_buff skb = {.len = len}; struct flow f = {}; struct tcphdr tcp; u64 segment;
    return tc_parse(&skb, &f, &tcp, &segment);
}
void host_record(int64_t *features, int32_t *tensors, int32_t *label, uint64_t *mask)
{
    memcpy(features, record.features, sizeof(record.features));
    memcpy(tensors, record.tensors, sizeof(record.tensors)); *label = record.label; *mask = record.stage_mask;
}
void host_stats(uint64_t *out) { memcpy(out, &counters, sizeof(counters)); }

/* Test the exact registry-walk helper using a synthetic GET_NEXT_ID callback.
 * These tests do not call bpf() and do not establish kernel cleanup.
 */
static int scan_mode;
static int test_next_id(uint32_t previous, uint32_t *next)
{
    if (scan_mode == 1) return -ENOENT;
    if (scan_mode == 2) return -EPERM;
    if (scan_mode == 3) { *next = previous; return 0; }
    if (scan_mode == 4 && previous == 7) return -EIO;
    if (previous == 0) { *next = 7; return 0; }
    if (previous == 7) { *next = 56; return 0; }
    return -ENOENT;
}
int host_scan_ids(int mode, char *buffer, unsigned int length)
{
    scan_mode = mode;
    FILE *stream = fmemopen(buffer, length, "w");
    if (!stream) return -errno;
    int ret = tc_scan_ids(stream, test_next_id);
    fclose(stream);
    return ret;
}
