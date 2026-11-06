/* Host-only characterization of the TC C source. Never kernel evidence. */
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>
#include "../id_scan.h"
#include "../tc_ids.bpf.c"
#undef PARAMS_BPF_H
#include "../../src/mlp_params.bpf.h"
#define HOST_CAPACITY 64
static struct flow keys[HOST_CAPACITY];
static struct tc_flow attrs[HOST_CAPACITY];
static struct tc_result records[HOST_CAPACITY];
static int recorded[HOST_CAPACITY], count, capacity = HOST_CAPACITY;
static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static struct Net model;
static struct ids_tc_stats counters;
static int32_t active;
static int missing_slot = -1, result_failure, creator_race, stats_missing;
static _Thread_local struct tc_workspace work;
static _Thread_local const unsigned char *frame;
static _Thread_local unsigned int frame_length;
static _Thread_local uint64_t now;
static _Thread_local struct flow last_key;
static _Thread_local int held;
static int find(const struct flow *key)
{
    for (int i = 0; i < count; ++i) if (!memcmp(&keys[i], key, sizeof(*key))) return i;
    return -1;
}
void tc_test_lock(struct bpf_spin_lock *lock)
{
    assert(!held);
    while (__sync_lock_test_and_set(&lock->val, 1)) {}
    held = 1;
}
void tc_test_unlock(struct bpf_spin_lock *lock)
{
    assert(held); held = 0; __sync_lock_release(&lock->val);
}
int tc_test_load(void *ctx, unsigned int offset, void *dst, unsigned int length)
{
    assert(!held); (void)ctx;
    if (offset > frame_length || length > frame_length - offset) return -1;
    memcpy(dst, frame + offset, length); return 0;
}
void *validation_lookup(void *map, const void *key)
{
    assert(!held);
    if (map == &stats) return stats_missing ? NULL : &counters;
    if (map == &workspace) return &work;
    if (map == &nn_idx) return &active;
    if (map == &nn_parameters) return *(const int32_t *)key >= 0 && *(const int32_t *)key < 2 ? &model : 0;
    pthread_mutex_lock(&table_lock);
    int i = find(key);
    void *value = i < 0 ? NULL : map == &flow_map ? (void *)&attrs[i] :
                  (map == &results && recorded[i] ? (void *)&records[i] : NULL);
    pthread_mutex_unlock(&table_lock);
    return value;
}
long validation_update(void *map, const void *key, const void *value, unsigned long long flags)
{
    assert(!held); (void)flags;
    pthread_mutex_lock(&table_lock);
    int i = find(key), ret = 0;
    if (map == &flow_map) {
        if (i >= 0 || count >= capacity) ret = -1;
        else {
            i = count++; memcpy(&keys[i], key, sizeof(keys[i]));
            memcpy(&attrs[i], value, sizeof(attrs[i]));
            if (creator_race) { creator_race = 0; ret = -1; } /* winner inserted */
        }
    } else if (map == &results) {
        if (i < 0 || result_failure) ret = -1;
        else { memcpy(&records[i], value, sizeof(records[i])); recorded[i] = 1; }
    } else ret = -1;
    pthread_mutex_unlock(&table_lock);
    return ret;
}
unsigned long long validation_clock(void) { assert(!held); return now; }
int tc_test_tail(void *ctx, unsigned int slot)
{
    assert(!held);
    int (*functions[])(struct __sk_buff *) = {tc_preprocessing, tc_input_linear, tc_input_relu,
                                             tc_hidden_linear, tc_hidden_relu, tc_output_linear};
    if (slot >= 6 || (int)slot == missing_slot) return 0;
    functions[slot](ctx); return 1;
}
void host_reset(void)
{
    count = 0; active = 0; missing_slot = -1; result_failure = creator_race = stats_missing = 0;
    capacity = HOST_CAPACITY; held = 0;
    memset(&counters, 0, sizeof(counters)); memset(&work, 0, sizeof(work));
    memset(keys, 0, sizeof(keys)); memset(attrs, 0, sizeof(attrs));
    memset(records, 0, sizeof(records)); memset(recorded, 0, sizeof(recorded));
    memset(&last_key, 0, sizeof(last_key));
    memcpy(model.layer_0_weight, layer_0_weight, sizeof(layer_0_weight));
    memcpy(model.layer_1_weight, layer_1_weight, sizeof(layer_1_weight));
    memcpy(model.layer_2_weight, layer_2_weight, sizeof(layer_2_weight));
    memcpy(model.mean, mean, sizeof(mean)); memcpy(model.scale, scale, sizeof(scale));
}
int host_packet(const unsigned char *data, unsigned int len, uint64_t timestamp)
{
    frame = data; frame_length = len; now = timestamp;
    struct __sk_buff skb = {.len = len}; struct tcphdr tcp; u64 segment;
    tc_parse(&skb, &last_key, &tcp, &segment);
    return tc_entry(&skb);
}
int host_parse(const unsigned char *data, unsigned int len)
{
    frame = data; frame_length = len;
    struct __sk_buff skb = {.len = len}; struct flow f = {}; struct tcphdr tcp; u64 segment;
    return tc_parse(&skb, &f, &tcp, &segment);
}
void host_select_port(unsigned int port)
{
    last_key = (struct flow){.saddr=__builtin_bswap32(555819337),
        .daddr=__builtin_bswap32(555819265), .sport=__builtin_bswap16((uint16_t)port),
        .dport=__builtin_bswap16(5001)};
}
void host_record(int64_t *features, int32_t *tensors, int32_t *label, uint64_t *mask)
{
    struct tc_result zero = {}, *record = validation_lookup(&results, &last_key);
    if (!record) record = &zero;
    memcpy(features, record->features, sizeof(record->features));
    memcpy(tensors, record->tensors, sizeof(record->tensors)); *label = record->label; *mask = record->stage_mask;
}
void host_stats(uint64_t *out) { memcpy(out, &counters, 12 * sizeof(uint64_t)); }
void host_extra(uint64_t *out) { memcpy(out, &counters.flow_full, 6 * sizeof(uint64_t)); }
void host_flow(uint64_t *out)
{
    struct tc_flow *f = validation_lookup(&flow_map, &last_key);
    memset(out, 0, 8 * sizeof(uint64_t));
    if (!f) return;
    tc_test_lock(&f->lock);
    out[0]=f->packets; out[1]=f->bytes; out[2]=f->state; out[3]=f->sequence;
    out[4]=f->failures; out[5]=f->duplicates; out[6]=f->max_duration; out[7]=f->timestamp_reorders;
    tc_test_unlock(&f->lock);
}
void host_missing_slot(int slot) { missing_slot = slot; }
void host_result_failure(int value) { result_failure = value; }
void host_creator_race(void) { creator_race = 1; }
void host_capacity(int value) { capacity = value; }
void host_model_slot(int value) { active = value; }
void host_missing_stats(int value) { stats_missing = value; }
void host_busy(int value) { work.busy = value; }
int host_is_busy(void) { return work.busy; }

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
