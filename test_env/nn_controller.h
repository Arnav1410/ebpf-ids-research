#ifndef TEST_ENV_NN_CONTROLLER_H
#define TEST_ENV_NN_CONTROLLER_H
#include "flow_controller.h"
#include "nn.h"
int nn_arguments(struct flow_controller *, int, char **);
int nn_validate_object(struct bpf_object *);
int nn_prepare(struct bpf_object *);
int nn_collect_ids(struct bpf_object *);
int nn_prune_rx(int);
int nn_after_selftest(void);
int nn_clear_tails(void);
int nn_prepare_snapshot(int cpu_count, __u64 *cpu_values);
void nn_print_snapshot(void);
void nn_print_program_ids(void);
void nn_print_map_ids(void);
void nn_print_ready(void);
int nn_vectors(int, char **, const struct stat *);
#endif
