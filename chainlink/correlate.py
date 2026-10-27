import heapq
import math
import statistics
from dataclasses import dataclass, field
from datetime import timedelta

WINDOW_S = 3600
MIN_EDGE = 0.5
MAX_SCORE = 0.9
GAP_S = 900
SWAP_LIMIT = 5


@dataclass
class Evidence:
    rule: str
    weight: float
    text: str
    directed: bool = False
    structural: bool = True


@dataclass
class Link:
    a: str
    b: str
    score: float
    evidence: list[Evidence]
    first: str | None = None
    contradicted: bool = False


@dataclass
class Gap:
    kind: str
    text: str
    t_lo: object
    t_hi: object
    after: str | None = None
    before: str | None = None


@dataclass
class Chain:
    events: list
    links: list[Link]
    score: float
    timeline: list = field(default_factory=list)
    alternatives: list = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)


def _ordered_rules(a, b, cfg):
    out = []
    if (
        a.pid is not None
        and a.pid == b.ppid
        and a.device == b.device
        and a.kind in ("proc", "auth")
        and b.kind == "proc"
    ):
        out.append(Evidence("lineage", 0.9, f"{a.device} pid {a.pid} is the parent of {b.proc} ({b.pid})", True))
    if a.kind == "fw" and b.kind == "auth" and a.src_ip == b.src_ip and a.dst_ip == cfg.devices[b.device].ip:
        out.append(Evidence("flow-login", 0.7, f"allowed flow {a.src_ip}->{a.dst_ip}:{a.port} precedes login", True))
    if a.kind == "proc" and b.kind in ("proxy", "dns", "fw") and a.host and a.host == b.host:
        target = b.domain or b.dst_ip
        if target and target in a.cmd:
            out.append(Evidence("cmd-names-target", 0.55, f"command line on {a.host} names {target}", True))
    if a.kind == "proc" and b.kind == "auth":
        origin = cfg.host_for_ip(b.src_ip)
        target_ip = cfg.devices[b.device].ip
        if origin == a.host and (target_ip in a.cmd or b.device in a.cmd):
            out.append(
                Evidence("cmd-names-target", 0.55, f"command on {a.host} names {b.device}, login arrives from it", True)
            )
    if a.kind == "dns" and b.kind == "proxy" and a.domain == b.domain and a.src_ip == b.src_ip:
        if (b.t - a.t).total_seconds() < 60:
            out.append(Evidence("dns-then-request", 0.6, f"lookup of {a.domain} then request by {a.src_ip}", True))
    if a.kind == "proxy" and b.kind == "proxy" and a.src_ip == b.src_ip and a.domain == b.domain and a.suspicious:
        out.append(Evidence("repeat-contact", 0.5, f"repeated contact with {a.domain}", False))
    if (
        a.kind == "proc"
        and b.kind in ("proxy", "dns", "fw")
        and a.host
        and a.host == b.host
        and a.user
        and a.user == b.user
        and abs((b.t - a.t).total_seconds()) < 120
    ):
        out.append(Evidence("same-host-user", 0.3, f"{a.user} active on {a.host} within 2 min", False, False))
    if b.kind in ("auth", "fw") and a.suspicious and a.host and a.host == cfg.host_for_ip(b.src_ip):
        out.append(
            Evidence(
                "origin-had-activity",
                0.4,
                f"login source {b.src_ip} ({a.host}) had suspicious activity just before",
                True,
            )
        )
    return out


def _symmetric_rules(a, b):
    if a.user and a.user == b.user and a.user != "-":
        w = 0.25 if a.lane != b.lane else 0.2
        return [Evidence("same-user", w, f"same user {a.user}", False, False)]
    return []


def _combine(ev):
    p = 1.0
    for e in ev:
        p *= 1 - e.weight
    return 1 - p


def build_links(events, cfg):
    links = []
    for i, a in enumerate(events):
        for b in events[i + 1 :]:
            gap = (b.t - a.t).total_seconds()
            if gap > WINDOW_S:
                break
            fwd = _ordered_rules(a, b, cfg)
            rev = _ordered_rules(b, a, cfg)
            ev = fwd + rev + _symmetric_rules(a, b)
            if not any(e.structural for e in ev):
                continue
            directed = [e for e in fwd + rev if e.directed]
            first = None
            contradicted = False
            if directed:
                f_first = bool([e for e in fwd if e.directed])
                first = a.id if f_first else b.id
                early, late = (a, b) if f_first else (b, a)
                contradicted = (early.t - late.t).total_seconds() > early.unc + late.unc
            score = _combine(ev)
            slack = max(0.0, abs(gap) - a.unc - b.unc - 300)
            score /= 1 + slack / 1800
            if contradicted:
                score *= 0.5
            if score >= MIN_EDGE:
                links.append(Link(a.id, b.id, round(score, 3), ev, first, contradicted))
    return links


def _components(events, links):
    parent = {e.id: e.id for e in events}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for lk in links:
        parent[find(lk.a)] = find(lk.b)
    groups = {}
    for e in events:
        groups.setdefault(find(e.id), []).append(e)
    return list(groups.values())


def _order(events, links):
    by_id = {e.id: e for e in events}
    succ = {e.id: set() for e in events}
    indeg = {e.id: 0 for e in events}
    for lk in links:
        if lk.first and not lk.contradicted:
            other = lk.b if lk.first == lk.a else lk.a
            if other not in succ[lk.first]:
                succ[lk.first].add(other)
                indeg[other] += 1
    heap = [(by_id[i].t, i) for i, d in indeg.items() if d == 0]
    heapq.heapify(heap)
    order = []
    while heap:
        _, i = heapq.heappop(heap)
        order.append(by_id[i])
        for j in succ[i]:
            indeg[j] -= 1
            if indeg[j] == 0:
                heapq.heappush(heap, (by_id[j].t, j))
    seen = {e.id for e in order}
    order += sorted((e for e in events if e.id not in seen), key=lambda e: e.t)
    return order, succ


def _reaches(succ, x, y):
    stack, seen = [x], set()
    while stack:
        n = stack.pop()
        if n == y:
            return True
        if n not in seen:
            seen.add(n)
            stack.extend(succ[n])
    return False


def p_before(x, y):
    # unc is treated as roughly a 2-sigma bound on each timestamp
    sigma = math.hypot(x.unc, y.unc) / 2
    z = (y.t - x.t).total_seconds() / sigma
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


def _alternatives(order, succ):
    cands = []
    for k in range(len(order) - 1):
        x, y = order[k], order[k + 1]
        overlap = x.hi >= y.lo and y.hi >= x.lo
        if overlap and not _reaches(succ, x.id, y.id):
            swapped = order[:k] + [y, x] + order[k + 2 :]
            cands.append((1 - p_before(x, y), swapped, (x.id, y.id)))
    cands.sort(key=lambda c: -c[0])
    return [{"p": round(p, 2), "order": o, "swap": s} for p, o, s in cands[:SWAP_LIMIT]]


def _find_gaps(order, links, cfg, all_events):
    gaps = []
    ids = {e.id for e in order}
    pids = {(e.device, e.pid) for e in all_events if e.pid is not None}
    incoming = {}
    for lk in links:
        if lk.first:
            other = lk.b if lk.first == lk.a else lk.a
            incoming.setdefault(other, []).append(lk.first)
    by_id = {e.id: e for e in order}
    for e in order:
        if e.kind == "proc" and e.ppid and e.ppid > 1 and (e.device, e.ppid) not in pids:
            gaps.append(
                Gap(
                    "missing-parent",
                    f"parent process {e.ppid} of {e.proc} on {e.device} is not in the logs",
                    e.lo - _secs(600),
                    e.hi,
                    before=e.id,
                )
            )
        if e.kind == "auth" and cfg.host_for_ip(e.src_ip):
            kinds = {by_id[i].kind for i in incoming.get(e.id, []) if i in ids}
            if "fw" not in kinds:
                gaps.append(
                    Gap(
                        "missing-flow",
                        f"login on {e.device} from {e.src_ip} has no matching firewall flow",
                        e.lo - _secs(300),
                        e.hi,
                        before=e.id,
                    )
                )
            if "proc" not in kinds:
                gaps.append(
                    Gap(
                        "missing-initiator",
                        f"no logged command on {cfg.host_for_ip(e.src_ip)} that started the login on {e.device}",
                        e.lo - _secs(600),
                        e.hi,
                        before=e.id,
                    )
                )
        if e.kind == "fw" and e.port == 22 and e.dst_ip:
            dst = cfg.host_for_ip(e.dst_ip)
            if dst and not any(
                o.kind == "auth" and o.device == dst and o.src_ip == e.src_ip and 0 <= (o.t - e.t).total_seconds() < 120
                for o in all_events
            ):
                gaps.append(
                    Gap(
                        "missing-login",
                        f"allowed flow to {dst}:22 with no login record on {dst}",
                        e.lo,
                        e.hi + _secs(120),
                        after=e.id,
                    )
                )
    for x, y in zip(order, order[1:]):
        d = (y.t - x.t).total_seconds()
        if d > GAP_S:
            gaps.append(
                Gap(
                    "quiet-period",
                    f"{d / 60:.0f} min between linked events with nothing recorded",
                    x.hi,
                    y.lo,
                    after=x.id,
                    before=y.id,
                )
            )
    series = {}
    for e in order:
        if e.kind == "proxy" and e.suspicious:
            series.setdefault((e.src_ip, e.domain), []).append(e)
    for (ip, dom), s in series.items():
        if len(s) < 4:
            continue
        gaps_s = [(b.t - a.t).total_seconds() for a, b in zip(s, s[1:])]
        med = statistics.median(gaps_s)
        if med > 0 and gaps_s[0] > 1.8 * med:
            s, gaps_s = s[1:], gaps_s[1:]  # first contact is staging, not a beacon
        for a, b, g in zip(s, s[1:], gaps_s):
            if med > 0 and g > 1.8 * med:
                gaps.append(
                    Gap(
                        "missed-beacons",
                        f"~{round(g / med) - 1} expected contact(s) with {dom} from {ip} not logged",
                        a.hi,
                        b.lo,
                        after=a.id,
                        before=b.id,
                    )
                )
    return gaps


def _secs(n):
    return timedelta(seconds=n)


def _chain_score(events, links):
    best = {}
    for lk in links:
        for i in (lk.a, lk.b):
            best[i] = max(best.get(i, 0), lk.score)
    mean_best = sum(best.get(e.id, 0) for e in events) / len(events)
    frac = sum(1 for e in events if e.suspicious) / len(events)
    return round(min(MAX_SCORE, mean_best * (0.7 + 0.3 * frac)), 2)


def reconstruct(events, cfg):
    links = build_links(events, cfg)
    chains = []
    for comp in _components(events, links):
        if len(comp) < 3 or sum(1 for e in comp if e.suspicious) < 2:
            continue
        ids = {e.id for e in comp}
        clinks = [lk for lk in links if lk.a in ids and lk.b in ids]
        order, succ = _order(comp, clinks)
        chain = Chain(comp, clinks, _chain_score(comp, clinks), order, _alternatives(order, succ))
        chain.gaps = _find_gaps(order, clinks, cfg, events)
        chains.append(chain)
    chains.sort(key=lambda c: -c.score * math.log(len(c.events) + 1))
    return chains
