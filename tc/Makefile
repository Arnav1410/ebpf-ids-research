OUTPUT := $(abspath .output)
CLANG ?= clang-12
BPFTOOL := $(abspath ../.output/bpftool/bpftool)
LIBBPF := $(abspath ../.output/libbpf/libbpf.a)
INCLUDE := $(abspath ../.output/libbpf/usr/include)
BPF_FLAGS := -g -O3 -target bpf -I$(OUTPUT) -I$(INCLUDE) -I/usr/include/x86_64-linux-gnu
BASE := ../src/common.h ../src/params.bpf.h ../src/handler.bpf.h ../src/mlp.bpf.h
.PHONY: all
all: $(OUTPUT)/tc_min.bpf.o $(OUTPUT)/tc_ids.bpf.o $(OUTPUT)/controller
$(OUTPUT):
	mkdir -p $@
$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
$(OUTPUT)/%.bpf.o: %.bpf.c abi.h $(BASE) $(OUTPUT)/vmlinux.h
	$(CLANG) $(BPF_FLAGS) -c $< -o $@
$(OUTPUT)/controller: controller.c abi.h id_scan.h ../src/common.h ../src/params.bpf.h ../src/mlp_params.bpf.h | $(OUTPUT)
	$(CLANG) -O2 -g -Wall -Wextra -I$(INCLUDE) $< $(LIBBPF) -lelf -lz -o $@
