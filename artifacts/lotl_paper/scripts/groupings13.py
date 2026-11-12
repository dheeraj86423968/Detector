"""Grouping variants of lab 0.10 grid 2 (artifacts/lab_v10/PROTOCOL.md), run through the server's own code."""
import incidents010 as inc   # lotl_paper: 0.10 shipped grouping (frozen), as inc13-final.json

H = 3600 * 10**9


def with_settings(rows, gap=None, recur=None):
    old = inc.GAP_NS, inc.RECUR_NS
    inc.GAP_NS = gap or old[0]; inc.RECUR_NS = recur or 0
    try:
        return inc.group(rows)
    finally:
        inc.GAP_NS, inc.RECUR_NS = old


GROUPINGS = {"G0": lambda rows: with_settings(rows), "G1": lambda rows: with_settings(rows, recur=24 * H), "G2": lambda rows: with_settings(rows, recur=7 * 24 * H),
             "G3": lambda rows: with_settings(rows, gap=2 * H)}
