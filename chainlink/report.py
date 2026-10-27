from html import escape

CSS = """
body{font-family:system-ui,sans-serif;margin:16px auto;max-width:1100px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:3px 6px;border-bottom:1px solid #ccc;vertical-align:top}
.bad{background:#ffecec}.gap{border-left:3px solid #c80;padding:4px 8px;margin:6px 0}
.neg{color:#b00}
"""
COLORS = {
    "proc": "#3b6ee0",
    "auth": "#2a9d5c",
    "authfail": "#999",
    "proxy": "#c46a1d",
    "dns": "#8a5cc2",
    "fw": "#c0392b",
}


def _t(dt):
    return dt.strftime("%H:%M:%S")


def _svg(chain):
    tl = chain.timeline
    lanes = sorted({e.lane for e in tl})
    t0 = min(e.lo for e in tl)
    span = max((max(e.hi for e in tl) - t0).total_seconds(), 1)
    w, row = 900, 26
    x = lambda d: 110 + (d - t0).total_seconds() / span * (w - 130)  # noqa: E731
    out = [f'<svg width="{w}" height="{len(lanes) * row + 24}" font-size="11">']
    for i, ln in enumerate(lanes):
        y = i * row + 18
        out.append(
            f'<text x="4" y="{y + 4}">{escape(ln)}</text>'
            f'<line x1="104" x2="{w - 10}" y1="{y}" y2="{y}" stroke="#e3e6ec"/>'
        )
    for e in tl:
        y = lanes.index(e.lane) * row + 18
        c = COLORS.get(e.kind, "#555")
        out.append(
            f'<line x1="{x(e.lo):.1f}" x2="{x(e.hi):.1f}" y1="{y}" y2="{y}" stroke="{c}" stroke-width="2"/>'
            f'<circle cx="{x(e.t):.1f}" cy="{y}" r="{5 if e.suspicious else 3}" fill="{c}">'
            f"<title>{escape(_t(e.t))} {escape(e.summary)}</title></circle>"
        )
    for g in chain.gaps:
        out.append(
            f'<rect x="{x(max(g.t_lo, t0)):.1f}" y="2" width="{max(3, x(g.t_hi) - x(max(g.t_lo, t0))):.1f}" '
            f'height="{len(lanes) * row + 4}" fill="#f0a500" opacity=".18"><title>{escape(g.text)}</title></rect>'
        )
    out.append("</svg>")
    return "".join(out)


def render(chains, nevents, skipped):
    h = [
        f"<!doctype html><meta charset=utf-8><title>chainlink report</title><style>{CSS}</style>",
        "<h1>chainlink</h1>",
        f"<p>{nevents} events parsed, {skipped} unparseable lines skipped, "
        f"{len(chains)} candidate chain(s). Scores are heuristic confidence, capped at 0.9; "
        "timestamps are UTC after skew correction (circle = best estimate, bar = uncertainty).</p>",
    ]
    if not chains:
        h.append("<p>No chain with at least two suspicious linked events was found.</p>")
    for n, c in enumerate(chains, 1):
        h.append(f"<div><h2>Chain {n} score {c.score:.2f}, {len(c.events)} events, {len(c.gaps)} gap(s)</h2>")
        h.append(_svg(c))
        h.append(
            "<table><tr><th>time (UTC)</th><th>±s</th><th>lane</th><th>kind</th><th>event</th><th>why flagged</th></tr>"
        )
        for e in c.timeline:
            h.append(
                f'<tr class="{"bad" if e.suspicious else ""}"><td>{_t(e.t)}</td><td>{e.unc:.0f}</td>'
                f"<td>{escape(e.lane)}</td><td>{e.kind}</td><td><code>{escape(e.summary)}</code></td>"
                f"<td>{escape(e.suspicious or '')}</td></tr>"
            )
        h.append(
            "</table><h3>Links and evidence</h3><table><tr><th>score</th><th>from</th><th>to</th><th>evidence</th></tr>"
        )
        names = {e.id: e for e in c.events}
        for lk in sorted(c.links, key=lambda k: -k.score)[:40]:
            ev = "; ".join(f"{escape(x.rule)} ({x.weight}): {escape(x.text)}" for x in lk.evidence)
            flag = ' <span class="neg">(timestamps contradict this direction)</span>' if lk.contradicted else ""
            h.append(
                f"<tr><td>{lk.score:.2f}</td><td>{escape(names[lk.a].id)}</td>"
                f"<td>{escape(names[lk.b].id)}</td><td>{ev}{flag}</td></tr>"
            )
        h.append("</table>")
        if c.alternatives:
            h.append("<h3>Plausible alternative orderings</h3><ul>")
            for a in c.alternatives:
                x, y = (names[i] for i in a["swap"])
                h.append(
                    f"<li>{a['p']:.0%}: <code>{escape(y.summary[:60])}</code> may have come before "
                    f"<code>{escape(x.summary[:60])}</code> (timestamps overlap within clock uncertainty)</li>"
                )
            h.append("</ul>")
        h.append("<h3>Gaps - what the logs should show but do not</h3>")
        for g in c.gaps or []:
            h.append(f'<div class="gap"><b>{g.kind}</b> {_t(g.t_lo)}-{_t(g.t_hi)}: {escape(g.text)}</div>')
        if not c.gaps:
            h.append("<p>None found.</p>")
        h.append("</div>")
    return "\n".join(h)
