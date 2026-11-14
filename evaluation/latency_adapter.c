/* HOST ONLY. Reuse unchanged arithmetic and full existing validation wrappers.
 * No BPF syscalls, interface operations, packet parsing or model mutation. */
#define _GNU_SOURCE
#include <time.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>
#ifdef LATENCY_XDP
#include "../validation/native.c"
#else
#include "tc_vectors.c"
#endif

#define BARRIER() __asm__ __volatile__("" ::: "memory")
#define NOINLINE __attribute__((noinline))
typedef int (*inference_fn)(int64_t *, int32_t *, int32_t *);

void latency_init(void)
{
#ifdef LATENCY_XDP
    native_reset();
#else
    host_reset();
#endif
}

/* Six arithmetic operations, including normalization and retained tensors.
 * TC's map/stage dispatch, telemetry, synchronization and publication are
 * excluded here and included in full_wrapper below. No new arithmetic. */
static NOINLINE int resident_math(int64_t *raw, int32_t *out, int32_t *label)
{
#ifdef LATENCY_XDP
    *label = native_mlp(raw, out);
    return 0;
#else
#ifdef IDS_LAYER_SPECIFIC
    int error = ls_normalize(raw, out, model.mean, model.scale, &model.calibration);
    if (error) return error;
    if (ls_valid(&model.calibration)) return LS_CONFIG;
    error = ls_linear(model.layer_0_weight, out, out + 32, 32, 6,
                      model.calibration.q_normalized + 16 - model.calibration.q_output[0]);
    if (error) return error;
#else
    standard_scaler(raw, out, model.mean, model.scale, 6);
    linear_layer(model.layer_0_weight, out, out + 32, 32, 6);
#endif
    memcpy(out + 64, out + 32, 32 * sizeof(*out));
    relu(out + 64, 32);
#ifdef IDS_LAYER_SPECIFIC
    if (ls_valid(&model.calibration)) return LS_CONFIG;
    error = ls_linear(model.layer_1_weight, out + 64, out + 96, 32, 32,
                      model.calibration.q_output[0] + 16 - model.calibration.q_output[1]);
    if (error) return error;
#else
    linear_layer(model.layer_1_weight, out + 64, out + 96, 32, 32);
#endif
    memcpy(out + 128, out + 96, 32 * sizeof(*out));
    relu(out + 128, 32);
#ifdef IDS_LAYER_SPECIFIC
    if (ls_valid(&model.calibration)) return LS_CONFIG;
    error = ls_linear(model.layer_2_weight, out + 128, out + 160, 2, 32,
                      model.calibration.q_output[1] + 16 - model.calibration.q_output[2]);
    if (error) return error;
#else
    linear_layer(model.layer_2_weight, out + 128, out + 160, 2, 32);
#endif
    *label = out[160] > out[161] ? 0 : 1;
    return 0;
#endif
}

static NOINLINE int full_wrapper(int64_t *raw, int32_t *out, int32_t *label)
{
#ifdef LATENCY_XDP
    *label = native_mlp(raw, out);
    return 0;
#else
    return vector_infer(raw, out, label);
#endif
}

static NOINLINE int empty_call(int64_t *raw, int32_t *out, int32_t *label)
{
    (void)raw; (void)out; (void)label;
    BARRIER();
    return 0;
}

struct latency_report {
    uint64_t elapsed_ns, successful, failed, first_bad, checksum;
    int32_t start_cpu, end_cpu;
};

static int clock_ns(uint64_t *out)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &now)) return -1;
    *out = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
    return 0;
}

uint64_t latency_clock_resolution_ns(void)
{
    struct timespec value;
    if (clock_getres(CLOCK_MONOTONIC_RAW, &value)) return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + value.tv_nsec;
}

/* kind 0: untimed warmup; 1: individual timings; 2: batch (two clock calls);
 * 3: empty indirect call/timer-pair control, NOT an inference.
 * Validation and checksum consumption always happen outside measured regions.
 * Output stores from inference itself are naturally part of its timed work. */
int latency_run(int scope, int kind, unsigned int n, int64_t *inputs,
                const int32_t *expected, const int32_t *expected_labels,
                uint64_t *durations, int32_t *output, int32_t *labels,
                struct latency_report *report)
{
    if (scope < 0 || scope > 1 || kind < 0 || kind > 3 || !n || n > 20000
        || !inputs || !expected || !expected_labels || !durations || !output || !labels || !report)
        return -1;
    memset(report, 0, sizeof(*report)); report->first_bad = UINT64_MAX;
    report->start_cpu = sched_getcpu();
    inference_fn fn = kind == 3 ? empty_call : scope ? full_wrapper : resident_math;
    uint64_t start = 0, end = 0;
    if (kind == 2 && clock_ns(&start)) return -2;
    BARRIER();
    for (unsigned int i = 0; i < n; ++i) {
        uint64_t before = 0, after = 0;
        if ((kind == 1 || kind == 3) && clock_ns(&before)) return -2;
        BARRIER();
        int status = fn(inputs + 6 * i, output + 192 * i, labels + i);
        BARRIER();
        if ((kind == 1 || kind == 3) && clock_ns(&after)) return -2;
        if (kind == 1 || kind == 3) {
            if (after <= before) return -3;
            durations[i] = after - before;
        }
        /* Record return status without putting result validation in batch time.
         * Labels are a second output; statuses temporarily occupy durations in
         * untimed/batch modes and are consumed after the batch timer stops. */
        if (kind == 0 || kind == 2) durations[i] = status != 0;
        else if (status) labels[i] = -1;
    }
    BARRIER();
    if (kind == 2) {
        if (clock_ns(&end) || end <= start) return -3;
        report->elapsed_ns = end - start;
    }
    /* For individual timing this pass is after ALL calls, so equality checks
     * cannot sit between the per-inference timers and disturb the next sample. */
    const int sizes[] = {6, 32, 32, 32, 32, 2};
    for (unsigned int i = 0; i < n; ++i) {
        int bad = kind != 3 && (labels[i] != expected_labels[i]
                    || ((kind == 0 || kind == 2) && durations[i]));
        if (kind != 3) for (int stage = 0; stage < 6; ++stage) {
            const int32_t *values = output + 192 * i + 32 * stage;
            if (memcmp(values, expected + 192 * i + 32 * stage, sizes[stage] * sizeof(*values))) bad = 1;
            for (int j = 0; j < sizes[stage]; ++j)
                report->checksum = (report->checksum * 1099511628211ULL) ^ (uint32_t)values[j];
        }
        if (bad) { report->failed++; if (report->first_bad == UINT64_MAX) report->first_bad = i; }
        else report->successful++;
    }
    report->end_cpu = sched_getcpu();
    return 0;
}
