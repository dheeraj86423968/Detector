"""ProvFusion data preparation (stages graphs -> featurization -> embed -> merged DGL .pt) without the multi-GB
intermediate files. Runs INSIDE the baselines container with the unmodified ProvFusion checkout mounted read-only at
/pf. Every algorithmic step is ProvFusion's own code:
  - word2vec: edge_featurization.build_feature_word2vec.main(cfg)               (unchanged)
  - day graphs: graph_construction.build_orthrus_graphs.gen_edge_fused_tw(...)  (unchanged; its torch.save of each
    day's networkx graph is intercepted and the graph is processed in memory instead of being written to disk)
  - edge embedding: the loop body of embed_edges_feature_word2vec.gen_vectorized_graphs (copied verbatim below,
    in-memory graph instead of a torch.load from disk)
  - DGL conversion: graphmae.datasets.data_util.convert_to_dgl_data + reverse_graph, and the merged tuple layout of
    preprocess.preprocess_dataset / Custimized (graphs, edge_counts, num_features, edge_features, 3, reverse_graphs).
Differences to the released pipeline: (1) graphs are ordered chronologically within a split (Custimized uses
os.walk order, which is filesystem dependent); (2) days that are in no split are skipped after construction.
Usage: pf_prepare.py DATASET --out /out [--spec spec.json]   (spec = a DATASET_DEFAULT_CONFIG entry for new sets)
"""
import argparse, json, os, re, sys, time, types
sys.path[:0] = ["/pf/data_preparation", "/pf"]
import numpy as np, torch
import config as C

ap = argparse.ArgumentParser()
ap.add_argument("dataset"); ap.add_argument("--out", required=True); ap.add_argument("--spec", default="")
ap.add_argument("--db", default="", help="override database name")
a = ap.parse_args()
if a.spec:
    C.DATASET_DEFAULT_CONFIG[a.dataset] = json.load(open(a.spec))
if a.db:
    C.DATASET_DEFAULT_CONFIG[a.dataset]["database"] = C.DATASET_DEFAULT_CONFIG[a.dataset]["database_all_file"] = a.db
C.ROOT_ARTIFACT_DIR = os.path.join(a.out, "artifacts")
C.DATABASE_DEFAULT_CONFIG.update(host=os.environ.get("DB_HOST", "postgres"), password=os.environ.get("DB_PASSWORD", "postgres"))
args = C.get_runtime_required_args(args=[a.dataset])
cfg = C.get_yml_cfg(args)
ds = cfg.dataset
log = lambda m: print(time.strftime("%H:%M:%S"), m, flush=True)
log(f"dataset {a.dataset} db={ds.database} train={ds.train_files} val={ds.val_files} test={ds.test_files} range={ds.start_end_day_range}")

# seeds exactly as prepare_data.py does before the stages
import random
if cfg.edge_featurization.embed_nodes.use_seed:
    random.seed(cfg._seed); np.random.seed(cfg._seed); torch.manual_seed(cfg._seed); torch.cuda.manual_seed_all(cfg._seed)

from provnet_utils import init_database_connection, get_indexid2msg
from edge_featurization import build_feature_word2vec as W, embed_edges_feature_word2vec as E
from graph_construction import build_orthrus_graphs as G
from graphmae.datasets.data_util import convert_to_dgl_data, reverse_graph
from torch_geometric.data import TemporalData

t0 = time.time()
# stage 3 (featurization) first: it only reads node messages from the database
W.main(cfg)
log(f"word2vec done {time.time()-t0:.0f}s")
fw = cfg.edge_featurization.embed_nodes.feature_word2vec
cur, con = init_database_connection(cfg)
indexid2msg = get_indexid2msg(cur, use_cmd=fw.use_cmd, use_port=fw.use_port)
indexid2msg = dict(sorted(indexid2msg.items(), key=lambda item: int(item[0])))
indexid2vec = E.get_indexid2vec(indexid2msg=indexid2msg, model_path=fw._model_dir + "feature_word2vec.model",
                                use_node_types=fw.use_node_types, decline_percentage=fw.decline_rate)
del indexid2msg
etype2oh = E.gen_relation_onehot(rel2id=E.rel2id)
ntype2oh = E.gen_relation_onehot(rel2id=E.ntype2id)
log(f"node vectors {len(indexid2vec)} {time.time()-t0:.0f}s")

split_of = {}
for s, files in (("train", ds.train_files), ("val", ds.val_files), ("test", ds.test_files)):
    for f in files:
        split_of[f] = s
graphs = {"train": [], "val": [], "test": []}; rgraphs = {"train": [], "val": [], "test": []}
order = {"train": [], "val": [], "test": []}
stats = {}
train_etypes = {}


def embed_in_memory(graph):  # == embed_edges_feature_word2vec.gen_vectorized_graphs loop body (verbatim logic)
    sorted_edges = graph.edges(data=True, keys=True)
    dataset = TemporalData()
    src, dst, msg, t = [], [], [], []
    for u, v, k, attr in sorted_edges:
        src.append(int(u)); dst.append(int(v))
        msg.append(torch.cat([ntype2oh[graph.nodes[u]['node_type']], torch.from_numpy(indexid2vec[int(u)]),
                              etype2oh[attr["label"]], ntype2oh[graph.nodes[v]['node_type']],
                              torch.from_numpy(indexid2vec[int(v)])]))
        t.append(int(attr["time"]))
    dataset.src = torch.tensor(src).to(torch.long); dataset.dst = torch.tensor(dst).to(torch.long)
    dataset.t = torch.tensor(t).to(torch.long); dataset.msg = torch.vstack(msg).to(torch.float)
    return dataset


def intercept_save(obj, path, *a_, **k_):
    m = re.search(r"graph_(\d+)", path)
    key = f"graph_{m.group(1)}"
    sp = split_of.get(key)
    stats[key] = {"nodes": obj.number_of_nodes(), "fused_edges": obj.number_of_edges(), "split": sp}
    if sp is None:
        log(f"{key}: in no split, skipped"); return
    if sp == "train":
        for _, _, attr in obj.edges(data=True):
            train_etypes[attr["label"]] = train_etypes.get(attr["label"], 0) + 1
    td = embed_in_memory(obj)
    g = convert_to_dgl_data(td); del td
    graphs[sp].append(g); rgraphs[sp].append(reverse_graph(g)); order[sp].append(key)
    stats[key].update(dgl_nodes=g.num_nodes(), dgl_edges=g.num_edges())
    log(f"{key} ({sp}): {stats[key]}")


G.torch = types.SimpleNamespace(save=intercept_save)
logger = G.get_logger(name="graph_construction_edge_fused_tw", filename=os.path.join(cfg.graph_construction.build_graphs._logs_dir, "g.log"))
nodeid2msg = G.get_node_list(cur=cur, cfg=cfg)
G.gen_edge_fused_tw(cur=cur, nodeid2msg=nodeid2msg, logger=logger, cfg=cfg)
del nodeid2msg
for sp in graphs:
    idx = sorted(range(len(order[sp])), key=lambda i: int(order[sp][i].split("_")[1]))
    graphs[sp] = [graphs[sp][i] for i in idx]; rgraphs[sp] = [rgraphs[sp][i] for i in idx]; order[sp] = [order[sp][i] for i in idx]
    assert graphs[sp], f"empty split {sp}"
num_features = graphs["train"][0].ndata["feat"].shape[1]
edge_features = graphs["train"][0].edata["label"].shape[1]
out = os.path.join(a.out, f"{a.dataset.lower()}_merged.pt")
torch.save((graphs, torch.zeros(11), num_features, edge_features, 3, rgraphs), out)
json.dump({"order": order, "days": stats, "train_fused_edge_type_counts": train_etypes,
           "seconds": round(time.time() - t0)}, open(os.path.join(a.out, "prepare_stats.json"), "w"), indent=1)
log(f"saved {out} {os.path.getsize(out)/1e9:.2f} GB, {time.time()-t0:.0f}s")
