"""CLI.
  python -m pdp_sim extract --dataset CADETS_E3 --gt-dir /home/pids/Ground_Truth/orthrus --out sim/attacks
  python -m pdp_sim run --store <window store> --bundle <bundle dir> --spec spec.json --out result.json [--device cuda]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "engine"))

ATTACKS = {  # dataset -> (database, [(name, gt csv, start, end)]) in US/Eastern (framework convention)
    "CADETS_E3": ("cadets_e3", [("CADETS_E3_Nginx_Backdoor_06", "E3-CADETS/node_Nginx_Backdoor_06.csv", "2018-04-06 11:20:00", "2018-04-06 12:09:00"),
                                ("CADETS_E3_Nginx_Backdoor_12", "E3-CADETS/node_Nginx_Backdoor_12.csv", "2018-04-12 13:59:00", "2018-04-12 14:39:00"),
                                ("CADETS_E3_Nginx_Backdoor_13", "E3-CADETS/node_Nginx_Backdoor_13.csv", "2018-04-13 09:03:00", "2018-04-13 09:16:00")]),
    "THEIA_E3": ("theia_e3", [("THEIA_E3_Browser_Extension_Drakon_Dropper", "E3-THEIA/node_Browser_Extension_Drakon_Dropper.csv", "2018-04-12 12:40:00", "2018-04-12 13:30:00"),
                              ("THEIA_E3_Firefox_Backdoor_Drakon_In_Memory", "E3-THEIA/node_Firefox_Backdoor_Drakon_In_Memory.csv", "2018-04-10 14:30:00", "2018-04-10 15:00:00")]),
}


def log(m):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "-", m, flush=True)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    x = sub.add_parser("extract"); x.add_argument("--dataset", required=True); x.add_argument("--gt-dir", required=True); x.add_argument("--out", required=True)
    x.add_argument("--host", default="postgres"); x.add_argument("--cap", type=int, default=20000)
    r = sub.add_parser("run"); r.add_argument("--store", required=True); r.add_argument("--bundle", required=True); r.add_argument("--spec", required=True)
    r.add_argument("--out", required=True); r.add_argument("--device", default="cpu")
    a = ap.parse_args()
    if a.cmd == "extract":
        from pdp_engine.sources.pg_replay import ns
        from pdp_sim import transplant
        db, items = ATTACKS[a.dataset]
        for name, gt, s, e in items:
            info = transplant.extract(db, os.path.join(a.gt_dir, gt), ns(s), ns(e), os.path.join(a.out, name + ".json"), name, host=a.host, cap=a.cap)
            log(f"extracted {info}")
    else:
        from pdp_engine.data import WindowStore
        from pdp_sim.campaign import Campaign, Spec
        spec = Spec.from_dict(json.load(open(a.spec)))
        c = Campaign(spec, WindowStore(a.store), a.bundle, device=a.device, log=log)
        out = c.run()
        json.dump(out, open(a.out, "w"), indent=1, default=str)
        s = out["summary"]
        log(f"done: detection {s['detection_rate']:.2f} {s['detection_rate_ci']} fp/day {s['fp_per_day']:.1f} robustness {s['robustness']}")


if __name__ == "__main__":
    main()
