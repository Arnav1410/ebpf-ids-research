ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
SOURCE := $(ROOT)/test_env
OUTPUT ?= $(ROOT)/.output/test-env
CLANG ?= clang-12
CC ?= cc
BPFTOOL ?= $(ROOT)/.output/bpftool/bpftool
LIBBPF_INCLUDE ?= $(ROOT)/.output/libbpf/usr/include
LIBBPF_OBJ ?= $(ROOT)/.output/libbpf/libbpf.a

CPPFLAGS += -I$(LIBBPF_INCLUDE)
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Werror -std=gnu11
PRIVATE_SCOPE := $(SOURCE)/private_scope.c
PRIVATE_HEADERS := $(SOURCE)/private_scope.h
NN_JSON := $(SOURCE)/nn_json.c

.PHONY: all clean
.DELETE_ON_ERROR:
all: $(OUTPUT)/probe.bpf.o $(OUTPUT)/probe-loader $(OUTPUT)/flow.bpf.o $(OUTPUT)/flow-loader $(OUTPUT)/flow-inspect $(OUTPUT)/nn.bpf.o $(OUTPUT)/nn-loader $(OUTPUT)/nn-vectors $(OUTPUT)/nn-collect

$(OUTPUT):
	mkdir -p "$@"

$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > "$@"

$(OUTPUT)/probe.bpf.o: $(SOURCE)/probe.bpf.c $(OUTPUT)/vmlinux.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -I$(OUTPUT) $(CPPFLAGS) -c "$<" -o "$@"

$(OUTPUT)/flow.bpf.o: $(SOURCE)/flow.bpf.c $(SOURCE)/flow.h $(OUTPUT)/vmlinux.h
	$(CLANG) -O2 -g -Wall -Wextra -Werror -target bpf -mcpu=v3 -I$(OUTPUT) $(CPPFLAGS) -c "$<" -o "$@"

$(OUTPUT)/probe-loader: $(SOURCE)/probe_loader.c $(PRIVATE_SCOPE) $(PRIVATE_HEADERS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" $(PRIVATE_SCOPE) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

$(OUTPUT)/flow-loader: $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/flow_controller.h $(SOURCE)/flow.h $(PRIVATE_SCOPE) $(PRIVATE_HEADERS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DFLOW_BACKEND $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(PRIVATE_SCOPE) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

$(OUTPUT)/flow-inspect: $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/flow_controller.h $(SOURCE)/flow.h $(PRIVATE_SCOPE) $(PRIVATE_HEADERS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) -DFLOW_BACKEND -DFLOW_INSPECT $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(PRIVATE_SCOPE) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

$(OUTPUT)/nn.bpf.o: $(SOURCE)/nn.bpf.c $(SOURCE)/nn_bpf.h $(SOURCE)/nn.h $(SOURCE)/flow.bpf.c $(SOURCE)/flow.h $(ROOT)/src/mlp.bpf.h $(OUTPUT)/vmlinux.h
	$(CLANG) -O2 -g -fwrapv -Wall -Wextra -Werror -target bpf -mcpu=v3 -I$(OUTPUT) $(CPPFLAGS) -c "$<" -o "$@"

$(OUTPUT)/nn-loader $(OUTPUT)/nn-vectors: $(PRIVATE_SCOPE) $(PRIVATE_HEADERS) $(NN_JSON) $(SOURCE)/nn_json.h

$(OUTPUT)/nn-loader: $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/nn_controller.c $(SOURCE)/nn_controller.h $(SOURCE)/nn_context.c $(SOURCE)/nn_context.h $(SOURCE)/nn.h $(SOURCE)/flow_controller.h $(SOURCE)/flow.h $(OUTPUT)/vmlinux.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) -I$(OUTPUT) $(CFLAGS) -fwrapv -DFLOW_BACKEND -DNN_BACKEND $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/nn_controller.c $(SOURCE)/nn_context.c $(PRIVATE_SCOPE) $(NN_JSON) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

$(OUTPUT)/nn-vectors: $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/nn_controller.c $(SOURCE)/nn_controller.h $(SOURCE)/nn_context.c $(SOURCE)/nn_context.h $(SOURCE)/nn.h $(SOURCE)/flow_controller.h $(SOURCE)/flow.h $(OUTPUT)/vmlinux.h $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) -I$(OUTPUT) $(CFLAGS) -fwrapv -DFLOW_BACKEND -DNN_BACKEND -DNN_VECTORS $(SOURCE)/probe_loader.c $(SOURCE)/flow_controller.c $(SOURCE)/nn_controller.c $(SOURCE)/nn_context.c $(PRIVATE_SCOPE) $(NN_JSON) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

$(OUTPUT)/nn-collect: $(SOURCE)/nn_collect.c $(SOURCE)/nn.h $(SOURCE)/nn_json.h $(NN_JSON) $(SOURCE)/flow_controller.c $(SOURCE)/flow_controller.h $(SOURCE)/flow.h $(PRIVATE_SCOPE) $(PRIVATE_HEADERS) $(LIBBPF_OBJ) | $(OUTPUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCE)/nn_collect.c $(SOURCE)/flow_controller.c $(PRIVATE_SCOPE) $(NN_JSON) $(LIBBPF_OBJ) $(LDFLAGS) -lelf -lz -pthread $(LDLIBS) -o "$@"

clean:
	rm -f "$(OUTPUT)/probe.bpf.o" "$(OUTPUT)/probe-loader" "$(OUTPUT)/flow.bpf.o" "$(OUTPUT)/flow-loader" "$(OUTPUT)/flow-inspect" "$(OUTPUT)/nn.bpf.o" "$(OUTPUT)/nn-loader" "$(OUTPUT)/nn-vectors" "$(OUTPUT)/nn-collect" "$(OUTPUT)/vmlinux.h"
