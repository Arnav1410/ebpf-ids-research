OUTPUT := $(abspath .output)
CLANG ?= clang-12
BPFTOOL := $(abspath ../.output/bpftool/bpftool)
LIBBPF := $(abspath ../.output/libbpf/libbpf.a)
INCLUDE := $(abspath ../.output/libbpf/usr/include)
MULTIARCH ?= $(shell gcc -print-multiarch)
BPF_FLAGS := -g -O3 -target bpf -mcpu=v3 -I$(OUTPUT) -I$(INCLUDE) -I/usr/include/$(MULTIARCH)
BASE := ../src/common.h ../src/params.bpf.h ../src/handler.bpf.h ../src/mlp.bpf.h
.PHONY: all
all: $(OUTPUT)/tc_min.bpf.o $(OUTPUT)/tc_ids.bpf.o $(OUTPUT)/controller
.PHONY: layer-specific
layer-specific: all $(OUTPUT)/tc_ids_layer.bpf.o $(OUTPUT)/controller_layer
LS_HEADERS := ../quantization/arithmetic.h ../quantization/params.bpf.h ../quantization/calibrated.h
$(OUTPUT):
	mkdir -p $@
$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
$(OUTPUT)/%.bpf.o: %.bpf.c abi.h flow_key.h $(BASE) $(OUTPUT)/vmlinux.h
	$(CLANG) $(BPF_FLAGS) -c $< -o $@
$(OUTPUT)/controller: controller.c deploy_guard.h kernel_checks.h bidirectional_checks.h abi.h flow_key.h id_scan.h ../quantization/benchmark.h ../src/params.bpf.h ../src/mlp_params.bpf.h | $(OUTPUT)
	$(CLANG) -O2 -g -Wall -Wextra -pthread -I$(INCLUDE) $< $(LIBBPF) -lelf -lz -o $@
$(OUTPUT)/tc_ids_layer.bpf.o: tc_ids.bpf.c abi.h flow_key.h $(BASE) $(LS_HEADERS) $(OUTPUT)/vmlinux.h
	$(CLANG) $(BPF_FLAGS) -DIDS_LAYER_SPECIFIC -c $< -o $@
$(OUTPUT)/controller_layer: controller.c deploy_guard.h kernel_checks.h bidirectional_checks.h abi.h flow_key.h id_scan.h $(LS_HEADERS) ../quantization/kernel_checks.h ../quantization/benchmark.h ../src/mlp_params.bpf.h | $(OUTPUT)
	$(CLANG) -O2 -g -Wall -Wextra -pthread -DIDS_LAYER_SPECIFIC -I$(INCLUDE) $< $(LIBBPF) -lelf -lz -o $@

# Separate binaries: original source parameters and existing rollback stay intact.
FRESH_MODEL := ../deployment/models/fresh/mlp_params.bpf.h
FRESH_CALIBRATED := ../deployment/models/fresh/calibrated.h
FRESH_FLAGS := -DIDS_MODEL_HEADER='"../deployment/models/fresh/mlp_params.bpf.h"'
.PHONY: demo-models
demo-models: layer-specific $(OUTPUT)/controller_fresh $(OUTPUT)/controller_fresh_layer
$(OUTPUT)/controller_fresh: controller.c deploy_guard.h kernel_checks.h bidirectional_checks.h abi.h flow_key.h id_scan.h ../quantization/benchmark.h ../src/params.bpf.h $(FRESH_MODEL) | $(OUTPUT)
	$(CLANG) -O2 -g -Wall -Wextra -pthread $(FRESH_FLAGS) -I$(INCLUDE) $< $(LIBBPF) -lelf -lz -o $@
$(OUTPUT)/controller_fresh_layer: controller.c deploy_guard.h kernel_checks.h bidirectional_checks.h abi.h flow_key.h id_scan.h $(LS_HEADERS) ../quantization/kernel_checks.h ../quantization/benchmark.h $(FRESH_MODEL) $(FRESH_CALIBRATED) | $(OUTPUT)
	$(CLANG) -O2 -g -Wall -Wextra -pthread -DIDS_LAYER_SPECIFIC $(FRESH_FLAGS) -DIDS_CALIBRATED_HEADER='"../deployment/models/fresh/calibrated.h"' -I../quantization -I$(INCLUDE) $< $(LIBBPF) -lelf -lz -o $@
