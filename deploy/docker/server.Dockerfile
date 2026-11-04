# Server / worker / benchmark-agent image.
# Self-contained by default: builds from a public PyTorch CUDA base and installs the library versions the research
# image used, so it builds on any host without the local pidsmaker-pids image. The base is torch 2.1.2 / CUDA 12.1,
# which supports Ada GPUs such as the NVIDIA L4 (compute 8.9) as well as Ampere; torch 1.13 did not support Ada.
# For bit-for-bit parity with the original study pass --build-arg BASE=pidsmaker-pids:latest (torch 1.13 + cu117),
# but note that base cannot use an L4 GPU.
ARG BASE=pytorch/pytorch:2.1.2-cuda12.1-cudnn8-runtime
FROM ${BASE}
USER root
# apt: strace for the sandbox collector; build-essential occasionally needed by wheels
RUN apt-get update && apt-get install -y --no-install-recommends strace libgomp1 gosu && rm -rf /var/lib/apt/lists/*
# Python deps pinned to the research versions (torch comes from the base). On the research base these are already
# present and reinstalling is a no-op; on the public base they bring it up to the same environment.
RUN pip install --no-cache-dir \
      "torch-geometric==2.5.3" "gensim==4.3.1" "nltk==3.8.1" "numpy==1.26.4" "scipy<1.13" \
      "psycopg2-binary==2.9.9" "fastapi==0.110.3" "uvicorn[standard]==0.29.0" "cryptography==42.0.5" "python-multipart==0.0.9" \
    && pip uninstall -y wandb >/dev/null 2>&1 || true
# nltk punkt tokenizer data (the featuriser tokenises labels with nltk; the backend has no internet egress at runtime)
COPY deploy/docker/nltk_data /usr/share/nltk_data
ENV NLTK_DATA=/usr/share/nltk_data PDP_ENGINE_PATH=/opt/pdp/engine PYTHONPATH=/opt/pdp/engine:/opt/pdp/server:/opt/pdp/agent:/opt/pdp/sim PYTHONUNBUFFERED=1
WORKDIR /opt/pdp
COPY engine /opt/pdp/engine
COPY server /opt/pdp/server
COPY agent /opt/pdp/agent
COPY sim /opt/pdp/sim
COPY deploy/entrypoint.sh /opt/pdp/entrypoint.sh
RUN chmod +x /opt/pdp/entrypoint.sh && useradd -r -u 10001 pdp && mkdir -p /data /pki && chown pdp:pdp /data /pki
ENTRYPOINT ["/opt/pdp/entrypoint.sh"]
CMD ["api"]
