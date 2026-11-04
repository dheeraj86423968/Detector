# Slim endpoint agent image: CPU-only PyTorch + PyG, the engine and agent code, nltk punkt, strace and the libbpf
# CO-RE eBPF collector. No gensim, no server, no CUDA — a deployable endpoint runtime, not the training image.
#
# Stage 1 compiles the eBPF collector once: vmlinux.h is generated from BTF (by default the build machine's
# /sys/kernel/btf/vmlinux; for another blob put it in agent/bpf/ and pass --build-arg BTF=<file name>), the program is
# compiled with clang against it and embedded as a libbpf skeleton in the statically linked loader `pdp-ebpf`.
# At run time libbpf relocates it against the endpoint's own BTF: no kernel headers, no compiler, no bcc, no tracefs
# (raw tracepoints only). Run with the host pid namespace and BPF privileges (deploy/systemd/pdp-agent.service).
FROM ubuntu:24.04 AS bpf
ENV DEBIAN_FRONTEND=noninteractive
# Ubuntu ships bpftool only inside the kernel-versioned linux-tools packages (its /usr/sbin/bpftool wrapper wants a
# tools package matching `uname -r`), so the versioned binary is called directly.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang llvm make gcc libc6-dev libbpf-dev libelf-dev zlib1g-dev libzstd-dev linux-tools-generic \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s "$(ls /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool 2>/dev/null | head -n1)" /usr/local/bin/bpftool && bpftool version
ARG BTF=/sys/kernel/btf/vmlinux
WORKDIR /src
COPY agent/bpf/ /src/
RUN case "$BTF" in /sys/*) ;; *) test -f "/src/$BTF" && cp "/src/$BTF" /tmp/btf && BTF=/tmp/btf ;; esac \
    && make clean && make BTF="$BTF" && ls -l pdp-ebpf && ./pdp-ebpf --help 2>&1 | head -1

FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    NLTK_DATA=/usr/share/nltk_data \
    PYTHONPATH=/opt/pdp/engine:/opt/pdp/agent:/opt/pdp/sim \
    PATH=/opt/venv/bin:$PATH \
    PDP_EBPF_LOADER=/opt/pdp/bin/pdp-ebpf
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv strace gosu ca-certificates tzdata coreutils tar \
    && rm -rf /var/lib/apt/lists/*
# CPU PyTorch wheel (small), then PyG and the few inference deps
RUN python3 -m venv /opt/venv \
    && pip install torch==2.4.1+cpu --index-url https://download.pytorch.org/whl/cpu \
    && pip install "torch-geometric==2.5.3" "numpy<2" "nltk==3.8.1" "cryptography==42.0.5"
COPY deploy/docker/nltk_data /usr/share/nltk_data
COPY --from=bpf /src/pdp-ebpf /opt/pdp/bin/pdp-ebpf
WORKDIR /opt/pdp
COPY engine /opt/pdp/engine
COPY agent /opt/pdp/agent
COPY sim /opt/pdp/sim
RUN useradd -r -u 10001 pdp && mkdir -p /var/lib/pdp && chown pdp:pdp /var/lib/pdp \
    && python -c "import torch, torch_geometric, nltk, cryptography; print('agent deps ok', torch.__version__)" \
    && /opt/pdp/bin/pdp-ebpf --help 2>&1 | head -1
# strace/ebpf/sandbox endpoints need ptrace / BPF privileges, auditd endpoints read /var/log/audit: run as root by
# default; drop to the unprivileged pdp user where the collector does not need it (PDP_RUN_USER=pdp).
COPY deploy/docker/agent-entrypoint.sh /opt/pdp/agent-entrypoint.sh
RUN chmod +x /opt/pdp/agent-entrypoint.sh
ENTRYPOINT ["/opt/pdp/agent-entrypoint.sh"]
CMD ["run"]
