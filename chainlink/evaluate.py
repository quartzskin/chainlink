import json
import tempfile
from pathlib import Path

from .correlate import reconstruct
from .generate import generate
from .models import load_config
from .parsers import load_dir


def score_chain(chain, truth):
    t_ids = truth["events"]
    c_ids = {e.id for e in chain.events}
    hit = c_ids & set(t_ids)
    prec = len(hit) / len(c_ids) if c_ids else 0.0
    rec = len(hit) / len(t_ids)
    pos = {e.id: i for i, e in enumerate(chain.timeline)}
    pairs = [(a, b) for i, a in enumerate(t_ids) for b in t_ids[i + 1 :] if a in pos and b in pos]
    order = sum(pos[a] < pos[b] for a, b in pairs) / len(pairs) if pairs else 0.0
    found = 0
    for g in truth["gaps"]:
        ids = set(g["ids"])
        if any(x.kind == g["kind"] and ({x.before, x.after} & ids) for x in chain.gaps):
            found += 1
    return {"precision": prec, "recall": rec, "order": order, "gap_recall": found / len(truth["gaps"])}


def naive_order(events, truth):
    ids = [e.id for e in sorted(events, key=lambda e: e.t) if e.id in set(truth["events"])]
    pos = {i: k for k, i in enumerate(ids)}
    t = truth["events"]
    pairs = [(a, b) for i, a in enumerate(t) for b in t[i + 1 :] if a in pos and b in pos]
    return sum(pos[a] < pos[b] for a, b in pairs) / len(pairs)


def run_one(seed, noise=1.0):
    with tempfile.TemporaryDirectory() as d:
        generate(d, seed, noise)
        cfg = load_config(Path(d) / "config.json")
        truth = json.loads((Path(d) / "truth.json").read_text())
        events, _ = load_dir(d, cfg)
        chains = reconstruct(events, cfg)
    t = set(truth["events"])
    if not chains:
        return {"precision": 0, "recall": 0, "order": 0, "gap_recall": 0, "chains": 0, "time_sort": 0}
    best = max(chains, key=lambda c: len({e.id for e in c.events} & t))
    res = score_chain(best, truth)
    res["chains"] = len(chains)
    res["time_sort"] = naive_order(events, truth)
    return res


def evaluate(seeds=20, noise=1.0):
    rows = [run_one(s, noise) for s in range(1, seeds + 1)]
    keys = ["precision", "recall", "order", "gap_recall", "time_sort", "chains"]
    return {k: sum(r[k] for r in rows) / len(rows) for k in keys}, rows
