FROM python:3.9-slim-bookworm
ENV PIP_NO_CACHE_DIR=1 PYTHONHASHSEED=0 DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 graphviz && rm -rf /var/lib/apt/lists/*
RUN pip install torch==2.1.2+cu121 --extra-index-url https://download.pytorch.org/whl/cu121
RUN pip install torch_geometric==2.6.1 && pip install pyg_lib==0.4.0 torch_scatter==2.1.2 torch_sparse==0.6.18 torch_cluster==1.6.3 \
    torch_spline_conv==1.2.2 -f https://data.pyg.org/whl/torch-2.1.0+cu121.html
RUN pip install dgl -f https://data.dgl.ai/wheels/torch-2.1/cu121/repo.html
RUN pip install psycopg2-binary==2.9.9 tqdm scikit-learn==1.6.1 networkx==3.2.1 xxhash==3.2.0 graphviz==0.20.1 psutil scipy==1.13.1 \
    matplotlib==3.9.4 wandb==0.24.2 chardet==5.2.0 nltk==3.8.1 igraph==0.11.5 cairocffi==1.7.0 wget==3.2 gensim==4.4.0 pytz==2024.1 \
    pandas==2.3.3 yacs==0.1.8 transformers==4.39.3 numpy==1.26.4 umap-learn==0.5.6 flask==3.0.3 tensorboardX==2.6.2.2 ogb PyYAML pydantic
RUN useradd -u 1000 -m runner
RUN pip install torchdata==0.7.1 PyMetis==2023.1.1
USER runner
WORKDIR /work
