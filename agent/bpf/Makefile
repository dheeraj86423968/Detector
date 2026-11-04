# Builds pdp-ebpf: the CO-RE kernel program (pdp_ebpf.bpf.c) embedded as a libbpf skeleton in a statically linked
# loader. Needs clang, llvm-strip, bpftool, libbpf-dev, libelf-dev, zlib1g-dev, libzstd-dev (see agent.Dockerfile).
#   make                       vmlinux.h from $(BTF) (default: this machine's kernel), then pdp-ebpf
#   make BTF=/path/to/vmlinux  generate vmlinux.h from another BTF blob (the header only supplies type names: CO-RE
#                              relocates every field access against the endpoint's own BTF at load time)
BPFTOOL ?= bpftool
CLANG   ?= clang
STRIP   ?= llvm-strip
CC      ?= cc
BTF     ?= /sys/kernel/btf/vmlinux
STATIC  ?= -static
ARCH    := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CFLAGS  ?= -O2 -g -Wall
LIBS    := -lbpf -lelf -lz -lzstd -lpthread

pdp-ebpf: pdp_ebpf.c pdp_ebpf.skel.h pdp_ebpf.h
	$(CC) $(CFLAGS) -I. pdp_ebpf.c -o $@ $(STATIC) $(LIBS)

pdp_ebpf.skel.h: pdp_ebpf.bpf.o
	$(BPFTOOL) gen skeleton $< name pdp_ebpf_bpf > $@

pdp_ebpf.bpf.o: pdp_ebpf.bpf.c pdp_ebpf.h vmlinux.h
	$(CLANG) -g -O2 -Wall -Wno-missing-declarations -target bpf -D__TARGET_ARCH_$(ARCH) -I. -c $< -o $@
	$(STRIP) -g $@

vmlinux.h:
	$(BPFTOOL) btf dump file $(BTF) format c > $@

clean:
	rm -f pdp-ebpf pdp_ebpf.skel.h pdp_ebpf.bpf.o vmlinux.h

.PHONY: clean
