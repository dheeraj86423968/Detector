"""Loss weights for a new dataset (PROTOCOL.md rule): balanced N/(K n_c) over the TRAINING graphs' DGL edge labels
(classes 0..9), capped at 30, 0 for absent classes and class 10. Prints a comma-separated list."""
import sys, torch, numpy as np
g = torch.load(sys.argv[1])[0]
c = torch.zeros(11)
for x in g["train"]:
    c += x.edata["label"].sum(0)
n = c.numpy()[:10]; m = n > 0
w = np.zeros(11); w[:10][m] = np.minimum(30.0, n[m].sum() / (m.sum() * n[m]))
print("counts", np.round(c.numpy()).tolist(), file=sys.stderr)
print(",".join(f"{x:.4f}" for x in w))
