"""Compile SigmaHQ rules into the JSON the engine's Sigma layer loads (pdp_engine/sigma_rules.json; 0.12, lab_v12).

    python -m pdp_server.tools.sigma_compile /path/to/sigma-checkout --release r2026-07-01 --commit <sha> \
        --out engine/pdp_engine/sigma_rules.json

Only the core `rules/` folder, products windows and linux, and the categories the provenance telemetry records
(process_creation, image_load, file_event, network_connection). A rule is excluded (with the reason recorded) when
- its status is deprecated / unsupported, or it has no level,
- a negated part of its condition uses a field the telemetry does not have (it would fire more than intended),
- it uses a modifier or condition feature the engine does not implement (base64offset, aggregations, ...).
Rules keep their id, title, level, status, author and references (Detection Rule License 1.1)."""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

import yaml

CATEGORIES = {
    "process_creation": {"Image", "CommandLine", "ParentImage", "ParentCommandLine"},
    "image_load": {"Image", "ImageLoaded"},
    "file_event": {"Image", "TargetFilename"},
    "network_connection": {"Image", "DestinationIp", "DestinationPort", "Initiated"},
}
PRODUCTS = ("windows", "linux")
MODIFIERS = {"contains", "startswith", "endswith", "all", "windash", "re", "cidr"}


class Unsupported(Exception):
    pass


# ------------------------------------------------------------------------------------------------ conditions
_TOK = re.compile(r"\s*(\(|\)|[^\s()]+)")


def tokenize(cond: str) -> list[str]:
    toks, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = _TOK.match(cond, pos)
        if not m:
            raise Unsupported(f"condition token at {pos}")
        toks.append(m.group(1)); pos = m.end()
    return toks


def parse_condition(cond: str):
    """Sigma condition -> AST: ["or", a, b...] | ["and", ...] | ["not", x] | ["sel", name] | ["of", "1"|"all", pattern]."""
    if "|" in cond:
        raise Unsupported("aggregation")
    toks = tokenize(cond)
    i = 0

    def peek():
        return toks[i].lower() if i < len(toks) else None

    def take():
        nonlocal i
        t = toks[i]; i += 1
        return t

    def p_or():
        a = [p_and()]
        while peek() == "or":
            take(); a.append(p_and())
        return a[0] if len(a) == 1 else ["or", *a]

    def p_and():
        a = [p_not()]
        while peek() == "and":
            take(); a.append(p_not())
        return a[0] if len(a) == 1 else ["and", *a]

    def p_not():
        if peek() == "not":
            take(); return ["not", p_not()]
        return p_atom()

    def p_atom():
        t = peek()
        if t is None:
            raise Unsupported("unexpected end of condition")
        if t == "(":
            take(); x = p_or()
            if peek() != ")":
                raise Unsupported("unbalanced parenthesis")
            take(); return x
        if t in ("1", "all", "any"):
            q = take().lower()
            if peek() != "of":
                raise Unsupported(f"'{q}' without 'of'")
            take()
            pat = take()
            return ["of", "all" if q == "all" else "1", pat]
        if t in ("and", "or", ")"):
            raise Unsupported(f"unexpected {t}")
        return ["sel", take()]

    ast = p_or()
    if i != len(toks):
        raise Unsupported("trailing tokens in condition")
    return ast


def expand(ast, names: list[str]):
    """Replace 'of' quantifiers by and/or over the matching selection names."""
    if ast[0] == "of":
        pat = ast[2]
        if pat == "them":
            sel = [n for n in names if not n.startswith("_")]
        else:
            rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$")
            sel = [n for n in names if rx.match(n)]
        if not sel:
            raise Unsupported(f"'{pat}' matches no selection")
        sub = [["sel", n] for n in sel]
        return sub[0] if len(sub) == 1 else ["and" if ast[1] == "all" else "or", *sub]
    if ast[0] == "sel":
        if ast[1] not in names:
            raise Unsupported(f"unknown selection {ast[1]}")
        return ast
    return [ast[0], *[expand(x, names) for x in ast[1:]]]


def polarity(ast, neg=False, out=None):
    """{selection name: set of polarities (True = negated)}."""
    out = {} if out is None else out
    if ast[0] == "sel":
        out.setdefault(ast[1], set()).add(neg)
    elif ast[0] == "not":
        polarity(ast[1], not neg, out)
    else:
        for x in ast[1:]:
            polarity(x, neg, out)
    return out


# ------------------------------------------------------------------------------------------------ selections
def compile_value(v):
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return v
    raise Unsupported(f"value type {type(v).__name__}")


def compile_selection(body) -> dict:
    """A selection: a map (fields AND-ed), a list of maps (OR), or a list of keywords (full text)."""
    if isinstance(body, dict):
        return {"maps": [compile_map(body)]}
    if isinstance(body, list):
        if all(isinstance(x, dict) for x in body):
            return {"maps": [compile_map(x) for x in body]}
        if all(isinstance(x, (str, int)) for x in body):
            return {"keywords": [str(x) for x in body]}
    if isinstance(body, str):
        return {"keywords": [body]}
    raise Unsupported("selection shape")


def compile_map(m: dict) -> list:
    out = []
    for key, val in m.items():
        parts = key.split("|")
        field, mods = parts[0], parts[1:]
        bad = [x for x in mods if x not in MODIFIERS]
        if bad:
            raise Unsupported(f"modifier {bad[0]}")
        vals = val if isinstance(val, list) else [val]
        out.append([field, mods, [compile_value(v) for v in vals]])
    return out


def fields_of(sel: dict) -> set[str]:
    if "keywords" in sel:
        return {"<keywords>"}
    return {f for m in sel["maps"] for f, _, _ in m}


def compile_rule(r: dict, path: str) -> dict:
    ls = r.get("logsource") or {}
    product, category = ls.get("product"), ls.get("category")
    if product not in PRODUCTS or category not in CATEGORIES:
        raise Unsupported("logsource")
    if ls.get("service"):
        raise Unsupported("logsource service")
    if r.get("status") in ("deprecated", "unsupported"):
        raise Unsupported(f"status {r.get('status')}")
    if r.get("level") not in ("informational", "low", "medium", "high", "critical"):
        raise Unsupported("level")
    det = dict(r["detection"])
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if isinstance(cond, list):
        cond = " or ".join(f"({c})" for c in cond)
    if not isinstance(cond, str):
        raise Unsupported("condition")
    sels = {name: compile_selection(body) for name, body in det.items()}
    ast = expand(parse_condition(cond), list(sels))
    pol = polarity(ast)
    supported = CATEGORIES[category]
    for name, ps in pol.items():
        if True in ps:   # negated somewhere: every field it uses must exist in the telemetry
            missing = fields_of(sels[name]) - supported
            if missing:
                raise Unsupported(f"filter on unavailable field {sorted(missing)[0]}")
    positive = set().union(*[fields_of(sels[n]) for n, ps in pol.items() if False in ps]) if pol else set()
    if not (positive & supported):
        raise Unsupported("no positive selection on an available field")
    return {"id": r.get("id"), "title": r.get("title"), "level": r["level"], "status": r.get("status"),
            "product": product, "category": category, "author": r.get("author"),
            "tags": [t for t in (r.get("tags") or []) if isinstance(t, str)],
            "references": (r.get("references") or [])[:3],
            "parent": bool(positive & {"ParentImage", "ParentCommandLine"}),
            "sel": sels, "cond": ast, "path": path}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("sigma_dir")
    ap.add_argument("--release", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    rules, excluded = [], {}
    files = sorted(glob.glob(os.path.join(a.sigma_dir, "rules", "**", "*.yml"), recursive=True))
    for f in files:
        rel = os.path.relpath(f, a.sigma_dir)
        for r in yaml.safe_load_all(open(f, encoding="utf-8")):
            if not r or "detection" not in r:
                continue
            ls = r.get("logsource") or {}
            if ls.get("product") not in PRODUCTS or ls.get("category") not in CATEGORIES:
                continue
            try:
                rules.append(compile_rule(r, rel))
            except Unsupported as e:
                excluded.setdefault(str(e).split(" ")[0] if "filter" not in str(e) else "filter on unavailable field", []).append(rel)
    out = {"source": "SigmaHQ (https://github.com/SigmaHQ/sigma)", "release": a.release, "commit": a.commit,
           "license": "Detection Rule License (DRL) 1.1, https://github.com/SigmaHQ/Detection-Rule-License; "
                      "each rule keeps its title, id and author",
           "categories": {k: sorted(v) for k, v in CATEGORIES.items()},
           "excluded": {k: len(v) for k, v in excluded.items()}, "rules": rules}
    with open(a.out, "w") as fh:
        json.dump(out, fh, separators=(",", ":"))
    by = {}
    for r in rules:
        by[(r["product"], r["category"], r["level"])] = by.get((r["product"], r["category"], r["level"]), 0) + 1
    print(f"{len(rules)} rules compiled, excluded: { {k: len(v) for k, v in excluded.items()} }", file=sys.stderr)
    for k in sorted(by):
        print(f"  {k}: {by[k]}", file=sys.stderr)


if __name__ == "__main__":
    main()
