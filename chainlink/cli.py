import argparse
import json
import sys
from pathlib import Path

from .correlate import reconstruct
from .evaluate import evaluate
from .generate import generate
from .models import load_config
from .parsers import load_dir
from .report import render


def _analyze(a):
    cfg = load_config(a.config or Path(a.logdir) / "config.json")
    events, skipped = load_dir(a.logdir, cfg)
    chains = reconstruct(events, cfg)
    if a.json:
        print(
            json.dumps(
                [
                    {
                        "score": c.score,
                        "events": [e.id for e in c.timeline],
                        "gaps": [{"kind": g.kind, "text": g.text} for g in c.gaps],
                    }
                    for c in chains
                ],
                indent=2,
            )
        )
    else:
        Path(a.out).write_text(render(chains, len(events), skipped), encoding="utf-8")
        print(f"{len(events)} events, {len(chains)} chain(s) -> {a.out}")
    return 0


def _generate(a):
    generate(a.outdir, a.seed)
    print(f"wrote sample logs, config.json and truth.json to {a.outdir}")
    return 0


def _evaluate(a):
    mean, _ = evaluate(a.seeds, a.noise)
    print(f"seeds={a.seeds} noise={a.noise}")
    for k, v in mean.items():
        print(f"  {k:<11} {v:.3f}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="chainlink")
    sub = p.add_subparsers(dest="cmd", required=True)
    an = sub.add_parser("analyze", help="reconstruct attack chains from a log directory")
    an.add_argument("logdir")
    an.add_argument("--config")
    an.add_argument("--out", default="report.html")
    an.add_argument("--json", action="store_true")
    an.set_defaults(fn=_analyze)
    ge = sub.add_parser("generate", help="write a synthetic intrusion with ground truth")
    ge.add_argument("outdir")
    ge.add_argument("--seed", type=int, default=1)
    ge.set_defaults(fn=_generate)
    ev = sub.add_parser("evaluate", help="score reconstruction against generated ground truth")
    ev.add_argument("--seeds", type=int, default=20)
    ev.add_argument("--noise", type=float, default=1.0)
    ev.set_defaults(fn=_evaluate)
    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except (OSError, KeyError, ValueError) as exc:
        print(f"chainlink: {exc}", file=sys.stderr)
        return 1
