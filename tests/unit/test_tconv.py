"""The agent's pure-torch TransformerConv equals PyG's on the ORTHRUS configuration (same weights, same output)."""
import sys

import torch
from torch_geometric.nn import TransformerConv as PygConv

from pdp_engine.tconv import TransformerConv

fails = 0


def check(ok, msg):
    global fails
    print(("PASS " if ok else "FAIL ") + msg)
    fails += 0 if ok else 1


torch.manual_seed(0)
for cfg in ({"in": 100, "out": 256, "heads": 8, "concat": True}, {"in": 2048, "out": 256, "heads": 1, "concat": False}):
    ref = PygConv(cfg["in"], cfg["out"], heads=cfg["heads"], concat=cfg["concat"], dropout=0.3, edge_dim=10).eval()
    mine = TransformerConv(cfg["in"], cfg["out"], heads=cfg["heads"], concat=cfg["concat"], dropout=0.3, edge_dim=10).eval()
    missing = mine.load_state_dict(ref.state_dict(), strict=True)
    n, e = 500, 3000
    x = torch.randn(n, cfg["in"])
    ei = torch.randint(0, n, (2, e))
    ea = torch.nn.functional.one_hot(torch.randint(0, 10, (e,)), 10).float()
    with torch.no_grad():
        a, b = ref(x, ei, ea), mine(x, ei, ea)
    d = (a - b).abs().max().item()
    check(a.shape == b.shape and d < 1e-5, f"heads={cfg['heads']} concat={cfg['concat']}: same state dict keys, max |diff| {d:.2e}")

# the full detector-2 model loads the same weights into either implementation
import pdp_engine.models as M
from pdp_engine.models import OrthrusModel
m1 = OrthrusModel(259).eval()
sd = m1.state_dict()
M.TransformerConv = TransformerConv
m2 = OrthrusModel(259).eval()
m2.load_state_dict(sd, strict=True)
check(set(m2.state_dict()) == set(sd), "ORTHRUS state dict loads strictly into the pure-torch layers")

print("FAILURES:", fails)
sys.exit(1 if fails else 0)
