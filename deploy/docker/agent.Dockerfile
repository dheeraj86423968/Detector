# Slim endpoint agent image: CPU-only PyTorch + PyG, the engine and agent code, nltk punkt, strace and bcc (eBPF).
# No gensim, no server, no CUDA — a deployable endpoint runtime, not the training image.
#
# Ubuntu 24.04 because the eBPF collector needs bcc's Python bindings (python3-bpfcc, built for the distro Python).
# bcc compiles the kernel program at start-up against the *host* kernel's headers: mount them read-only
#   -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro
# and run with the host pid namespace and BPF privileges (see deploy/docker-compose.bench.yml, agent-ebpf).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    NLTK_DATA=/usr/share/nltk_data \
    PYTHONPATH=/opt/pdp/engine:/opt/pdp/agent:/opt/pdp/sim \
    PATH=/opt/venv/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv python3-bpfcc strace gosu ca-certificates tzdata coreutils tar \
    && rm -rf /var/lib/apt/lists/*
# venv that still sees the distro's bcc module; CPU PyTorch wheel (small), then PyG and the few inference deps
RUN python3 -m venv --system-site-packages /opt/venv \
    && pip install torch==2.4.1+cpu --index-url https://download.pytorch.org/whl/cpu \
    && pip install "torch-geometric==2.5.3" "numpy<2" "nltk==3.8.1" "cryptography==42.0.5"
COPY deploy/docker/nltk_data /usr/share/nltk_data
WORKDIR /opt/pdp
COPY engine /opt/pdp/engine
COPY agent /opt/pdp/agent
COPY sim /opt/pdp/sim
RUN useradd -r -u 10001 pdp && mkdir -p /var/lib/pdp && chown pdp:pdp /var/lib/pdp \
    && python -c "import torch, torch_geometric, nltk, cryptography, bcc; print('agent deps ok', torch.__version__)"
# strace/ebpf/sandbox endpoints need ptrace / BPF privileges, auditd endpoints read /var/log/audit: run as root by
# default; drop to the unprivileged pdp user where the collector does not need it (PDP_RUN_USER=pdp).
COPY deploy/docker/agent-entrypoint.sh /opt/pdp/agent-entrypoint.sh
RUN chmod +x /opt/pdp/agent-entrypoint.sh
ENTRYPOINT ["/opt/pdp/agent-entrypoint.sh"]
CMD ["run"]
