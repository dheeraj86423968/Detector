"""Deterministic evidence behind each attack detected by 0.10 (variant P2) on the 16 development sets.
For every attack: layers that alerted one of its ground-truth nodes, and for corroborated ground-truth alerts the
deterministic alerts adjacent to that node in its one-hop window context (the anchor). Classes:
  rule_gt      an information-flow rule alerted a ground-truth node
  rule_anchor  no rule on a ground-truth node, but a rule alert anchors a corroborated ground-truth node
  novelty_gt   only layer 1 (or its corroborated repeat) on ground-truth nodes, no rule evidence
  novelty_anchor  only a corroborated ground-truth node, anchored by layer-1 alerts
Usage: python3 evidence13.py ../lab_v10/results"""
import gzip, json, glob, sys
from collections import defaultdict, Counter
res = sys.argv[1] if len(sys.argv) > 1 else "../lab_v10/results"
classes, out = Counter(), []
for f in sorted(glob.glob(f"{res}/rows13-*.json.gz")):
    r = json.load(gzip.open(f)); rows = r["rows"]["P2"]
    if r["set"] == "ATLASV2_EDR-h2":            # no ground-truth nodes on h2
        continue
    det = defaultdict(list)
    for x in rows:
        if x["layer"] in ("novelty", "rules"):
            det[x["window_start_ns"]].append(x)
    gt_layers, anchors, corr_gt = defaultdict(set), defaultdict(set), defaultdict(bool)
    for x in rows:
        for a in x["attacks"]:
            if x["layer"] in ("novelty", "rules"):
                gt_layers[a].add(x["layer"])
            else:
                corr_gt[a] = True
                if x["rule"] == "novel_executable_repeat":
                    gt_layers[a].add("novelty")
                ctx = r["ctx"].get(x["ctx"], {})
                nb = {e["src"] for e in ctx.get("edges", [])} | {e["dst"] for e in ctx.get("edges", [])}
                anchors[a] |= {y["layer"] for y in det[x["window_start_ns"]] if y["node_uuid"] in nb}
    for a in r["attacks"]:
        g, an = gt_layers.get(a, set()), anchors.get(a, set())
        if "rules" in g: c = "rule_gt"
        elif "rules" in an: c = "rule_anchor"
        elif "novelty" in g: c = "novelty_gt"
        elif "novelty" in an: c = "novelty_anchor"
        elif corr_gt[a]: c = "corroborated_unanchored"
        else: c = "missed"
        only_corr = corr_gt[a] and not g
        classes[c] += 1
        out.append({"set": r["set"], "attack": a, "class": c, "gt_layers": sorted(g), "anchor_layers": sorted(an),
                    "only_corroboration_on_gt": only_corr})
json.dump({"attacks": out, "classes": classes}, open("evidence13.json", "w"), indent=1)
for o in out: print(o["set"], o["attack"], o["class"], "only-corr" if o["only_corroboration_on_gt"] else "")
print(dict(classes), "only corroboration on a labelled node:", sum(o["only_corroboration_on_gt"] for o in out))
