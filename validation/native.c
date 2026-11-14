/* Compiles original production code; all substitutions are local to validation.
 * No BPF syscall, real socket, interface operation, or kernel helper is used. */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/xdp.bpf.c"
/* The two original parameter headers share a guard; include both locally. */
#undef PARAMS_BPF_H
#include "../src/mlp_params.bpf.h"

#define HOST_CAPACITY 64
static struct flow keys[HOST_CAPACITY];
static struct flow_attribute attributes[HOST_CAPACITY];
static struct Net models[2];
static int count, capacity = HOST_CAPACITY, active;
static unsigned long long timestamp;
static int32_t snapshots[6][32];
static int stages_seen, predictions, last_label, calls[6];

void *validation_lookup(void *map, const void *key)
{
    if (map == &nn_idx) return *(const int32_t *)key == 0 ? &active : NULL;
    if (map == &nn_parameters) {
        int idx = *(const int32_t *)key;
        return idx >= 0 && idx < 2 ? &models[idx] : NULL;
    }
    if (map == &flow_map)
        for (int i = 0; i < count; ++i)
            if (!memcmp(key, &keys[i], sizeof(keys[i]))) return &attributes[i];
    return NULL;
}

long validation_update(void *map, const void *key, const void *value,
                       unsigned long long flags)
{
    if (map != &flow_map || flags != BPF_NOEXIST || count >= capacity) return -1;
    if (validation_lookup(map, key)) return -1;
    memcpy(&keys[count], key, sizeof(keys[count]));
    memcpy(&attributes[count], value, sizeof(attributes[count]));
    ++count;
    return 0;
}

unsigned long long validation_clock(void) { return timestamp; }

void validation_printk(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)va_arg(ap, uint64_t);
    (void)va_arg(ap, uint64_t);
    last_label = va_arg(ap, int);
    va_end(ap);
    ++predictions;
}

void validation_tail_call(struct xdp_md *ctx, void *map, unsigned int index)
{
    if (map != &progs || index >= 6) return;
    struct flow key = {};
    if (flow_tuple(ctx, &key)) return;
    struct flow_attribute *attr = validation_lookup(&flow_map, &key);
    if (!attr) return;
    ++calls[index];
    if (index) {
        const int32_t *p = index == 1 || index == 4 || index == 5
                             ? attr->hidden2 : attr->hidden1;
        memcpy(snapshots[index - 1], p, (index == 1 ? 6 : 32) * sizeof(*p));
        stages_seen |= 1 << (index - 1);
    }
    int (*functions[])(struct xdp_md *) = {
        xdp_preprocessing, xdp_input_linear, xdp_input_relu,
        xdp_hidden_linear, xdp_hidden_relu, xdp_output_linear
    };
    int before = predictions;
    functions[index](ctx);
    if (index == 5 && predictions > before) {
        memcpy(snapshots[5], attr->hidden1, 2 * sizeof(int32_t));
        stages_seen |= 1 << 5;
    }
}

void native_reset(void)
{
    memset(keys, 0, sizeof(keys));
    memset(attributes, 0, sizeof(attributes));
    memset(calls, 0, sizeof(calls));
    memset(snapshots, 0, sizeof(snapshots));
    count = predictions = stages_seen = active = 0;
    last_label = -1;
    capacity = HOST_CAPACITY;
    timestamp = 0;
    for (int i = 0; i < 2; ++i) {
        memcpy(models[i].layer_0_weight, layer_0_weight, sizeof(layer_0_weight));
        memcpy(models[i].layer_1_weight, layer_1_weight, sizeof(layer_1_weight));
        memcpy(models[i].layer_2_weight, layer_2_weight, sizeof(layer_2_weight));
        memcpy(models[i].mean, mean, sizeof(mean));
        memcpy(models[i].scale, scale, sizeof(scale));
    }
}

void native_normalize(int64_t *x, int32_t *y, int64_t *mu, int64_t *sigma, int n)
{ standard_scaler(x, y, mu, sigma, n); }
void native_linear(int32_t *w, int32_t *x, int32_t *y, int m, int n)
{ linear_layer(w, x, y, m, n); }
void native_relu(int32_t *x, int n) { relu(x, n); }

int native_mlp(int64_t *x, int32_t *out)
{
    standard_scaler(x, out, models[0].mean, models[0].scale, 6);
    linear_layer(models[0].layer_0_weight, out, out + 32, 32, 6);
    memcpy(out + 64, out + 32, 32 * sizeof(*out));
    relu(out + 64, 32);
    linear_layer(models[0].layer_1_weight, out + 64, out + 96, 32, 32);
    memcpy(out + 128, out + 96, 32 * sizeof(*out));
    relu(out + 128, 32);
    linear_layer(models[0].layer_2_weight, out + 128, out + 160, 2, 32);
    return out[160] > out[161] ? 0 : 1;
}

int native_packet(const unsigned char *data, size_t length, uint64_t ns)
{
    timestamp = ns;
    struct xdp_md ctx = {(uintptr_t)data, (uintptr_t)data + length};
    return xdp_prog(&ctx);
}
int native_flow_count(void) { return count; }
void native_capacity(int n) { capacity = n >= 0 && n <= HOST_CAPACITY ? n : HOST_CAPACITY; }
int native_prediction_count(void) { return predictions; }
int native_label(void) { return last_label; }
int native_stage_mask(void) { return stages_seen; }
int native_call_count(int n) { return n >= 0 && n < 6 ? calls[n] : -1; }
void native_snapshot(int32_t *out) { memcpy(out, snapshots, sizeof(snapshots)); }

int native_flow(int index, int64_t *out)
{
    if (index < 0 || index >= count) return -1;
    struct flow_attribute *a = &attributes[index];
    int64_t values[] = {a->max_packet_length, a->max_duration, a->min_packet_length,
                       a->dst_port, a->header_length, a->num_packet,
                       a->last_packet_time, a->detection_start_time};
    memcpy(out, values, sizeof(values));
    return 0;
}

int native_classify(int32_t a, int32_t b)
{
    /* Isolate the ORIGINAL final program's comparison using synthetic logits.
     * Only this process's mock model is modified, then reset. */
    native_reset();
    count = 1;
    attributes[0].num_packet = 1;
    attributes[0].hidden2[0] = 65536;
    memset(models[0].layer_2_weight, 0, sizeof(models[0].layer_2_weight));
    models[0].layer_2_weight[0] = a;
    models[0].layer_2_weight[32] = b;
    unsigned char packet[54] = {};
    struct ethhdr *eth = (void *)packet;
    struct iphdr *ip = (void *)(packet + 14);
    eth->h_proto = htons(0x0800); ip->protocol = IPPROTO_TCP;
    struct xdp_md ctx = {(uintptr_t)packet, (uintptr_t)packet + sizeof(packet)};
    xdp_output_linear(&ctx);
    int label = last_label;
    native_reset();
    return label;
}

/* Deliberately invalid arithmetic is isolated in subprocesses under UBSan. */
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    native_reset();
    volatile int32_t sink;
    if (!strcmp(argv[1], "accumulator-overflow")) {
        int32_t w[] = {INT32_MIN, INT32_MIN}, x[] = {INT32_MIN, INT32_MIN}, y[1];
        native_linear(w, x, y, 1, 2); sink = y[0];
    } else if (!strcmp(argv[1], "negation-overflow")) {
        int64_t x[] = {-32768}, mu[] = {0}, sigma[] = {1}; int32_t y[1];
        native_normalize(x, y, mu, sigma, 1); sink = y[0];
    } else if (!strcmp(argv[1], "zero-divisor")) {
        int64_t x[] = {1}, mu[] = {0}, sigma[] = {0}; int32_t y[1];
        native_normalize(x, y, mu, sigma, 1); sink = y[0];
    } else if (!strcmp(argv[1], "flow-counter-overflow")) {
        count = 1; attributes[0].num_packet = INT64_MAX;
        struct tcphdr tcp = {}; tcp.doff = 5;
        update_flow_attribute(&keys[0], &tcp, 20); sink = 0;
    } else return 2;
    printf("%d\n", sink);
    return 0;
}
