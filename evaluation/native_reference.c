/* Host conformance driver: execute the baseline header, not a reimplementation.
 * -fwrapv makes signed C overflow match the eBPF ALU's modular semantics.
 * The generated vmlinux header is skipped to avoid libc typedef collisions. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define __VMLINUX_H__
#include "../src/mlp.bpf.h"

int main(int argc, char **argv)
{
    int32_t weights[1280], normalized[6], input_linear[32], input_relu[32];
    int32_t hidden_linear[32], hidden_relu[32], output[2], label;
    int64_t mean[6], scale[6], features[6];
    FILE *model, *vectors;
    size_t count;
    if (argc != 3) {
        fprintf(stderr, "Usage: native_reference MODEL_BINARY VECTORS_BINARY\n");
        return 2;
    }
    model = fopen(argv[1], "rb");
    if (!model) { perror("model"); return 1; }
    if (fread(weights, sizeof(*weights), 1280, model) != 1280 ||
        fread(mean, sizeof(*mean), 6, model) != 6 ||
        fread(scale, sizeof(*scale), 6, model) != 6 || fgetc(model) != EOF) {
        fprintf(stderr, "Invalid model payload\n"); fclose(model); return 1;
    }
    fclose(model);
    for (int i = 0; i < 6; ++i) {
        if (!scale[i]) { fprintf(stderr, "Zero normalization divisor\n"); return 1; }
    }
    vectors = fopen(argv[2], "rb");
    if (!vectors) { perror("vectors"); return 1; }
    while ((count = fread(features, sizeof(*features), 6, vectors)) == 6) {
        standard_scaler(features, normalized, mean, scale, 6);
        linear_layer(weights, normalized, input_linear, 32, 6);
        for (int i = 0; i < 32; ++i) input_relu[i] = input_linear[i];
        relu(input_relu, 32);
        linear_layer(weights + 192, input_relu, hidden_linear, 32, 32);
        for (int i = 0; i < 32; ++i) hidden_relu[i] = hidden_linear[i];
        relu(hidden_relu, 32);
        linear_layer(weights + 1216, hidden_relu, output, 2, 32);
        label = output[0] > output[1] ? 0 : 1;
        if (fwrite(normalized, sizeof(*normalized), 6, stdout) != 6 ||
            fwrite(input_linear, sizeof(*input_linear), 32, stdout) != 32 ||
            fwrite(input_relu, sizeof(*input_relu), 32, stdout) != 32 ||
            fwrite(hidden_linear, sizeof(*hidden_linear), 32, stdout) != 32 ||
            fwrite(hidden_relu, sizeof(*hidden_relu), 32, stdout) != 32 ||
            fwrite(output, sizeof(*output), 2, stdout) != 2 ||
            fwrite(&label, sizeof(label), 1, stdout) != 1) {
            perror("output"); fclose(vectors); return 1;
        }
    }
    if (count || ferror(vectors)) {
        fprintf(stderr, "Truncated vector payload\n"); fclose(vectors); return 1;
    }
    fclose(vectors);
    return fflush(stdout) == 0 ? 0 : 1;
}
