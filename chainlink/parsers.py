import csv
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .models import Event

MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}

AUTH_RE = re.compile(
    r"^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+sshd\[(\d+)\]:\s+"
    r"(Accepted|Failed)\s+\w+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)"
)
FW_RE = re.compile(r"^(\S+)\s+(\S+)\s+(.*)$")
DNS_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+query\s+client=(\S+)\s+name=(\S+)")
ADMIN_PORTS = {22, 3389, 5985}
SUSPICIOUS_CMD = [
    (re.compile(r"-enc\b|-nop\b|frombase64", re.I), "encoded or hidden powershell"),
    (re.compile(r"\b(tar|7z|zip|rar)\b.*(czf|\ba\b|-r)", re.I), "archiving tool"),
    (re.compile(r"\bcurl\b.*(-T|--upload-file)|\bwget\b.*--post", re.I), "upload via command line"),
    (re.compile(r"\bssh(\.exe)?\s+\S+@", re.I), "remote shell to another host"),
    (re.compile(r"/tmp/\.\w+"), "hidden file in /tmp"),
]


def _stamp(cfg, device, dt):
    # naive timestamps are device-local; aware ones already carry an offset
    dev = cfg.devices[device]
    if dt.tzinfo is None:
        dt = (dt - timedelta(minutes=dev.tz_offset_min)).replace(tzinfo=UTC)
    t = dt.astimezone(UTC) - timedelta(seconds=dev.skew_s)
    return t, dev.skew_unc_s + 1.0


def _device_of(path):
    return Path(path).name.split(".")[0]


def parse_auth(path, cfg):
    device = _device_of(path)
    out, skipped = [], 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        m = AUTH_RE.match(line)
        if not m:
            skipped += 1
            continue
        mon, day, hh, mm, ss, host, pid, verdict, user, ip, port = m.groups()
        t, unc = _stamp(cfg, device, datetime(cfg.default_year, MONTHS[mon], int(day), int(hh), int(mm), int(ss)))
        ok = verdict == "Accepted"
        out.append(
            Event(
                id=f"{Path(path).name}:{n}",
                device=device,
                kind="auth" if ok else "authfail",
                t=t,
                unc=unc,
                user=user,
                src_ip=ip,
                host=host,
                pid=int(pid),
                port=int(port),
                summary=f"{'login' if ok else 'failed login'} {user} on {host} from {ip}",
            )
        )
    return out, skipped


def parse_proc(path, cfg):
    device = _device_of(path)
    out, skipped = [], 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        try:
            r = json.loads(line)
            t, unc = _stamp(cfg, device, datetime.fromisoformat(r["time"]))
        except (ValueError, KeyError):
            skipped += 1
            continue
        cmd = r.get("cmd", "")
        proc = r["image"]
        out.append(
            Event(
                id=f"{Path(path).name}:{n}",
                device=device,
                kind="proc",
                t=t,
                unc=unc,
                user=r.get("user"),
                host=r.get("host", device),
                pid=r.get("pid"),
                ppid=r.get("ppid"),
                proc=proc,
                cmd=cmd,
                summary=f"{proc}: {cmd}"[:140],
            )
        )
    return out, skipped


def parse_proxy(path, cfg):
    device = _device_of(path)
    out, skipped = [], 0
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for n, row in enumerate(csv.reader(lines), 1):
        if n == 1 and row[:1] == ["epoch"]:
            continue
        try:
            ts = datetime.fromtimestamp(float(row[0]), UTC)
            t, unc = _stamp(cfg, device, ts)
            ip, user, method, domain, url_path, nbytes = row[1:7]
            nbytes = int(nbytes)
        except (ValueError, IndexError):
            skipped += 1
            continue
        out.append(
            Event(
                id=f"{Path(path).name}:{n}",
                device=device,
                kind="proxy",
                t=t,
                unc=unc,
                user=user or None,
                src_ip=ip,
                host=cfg.host_for_ip(ip),
                domain=domain,
                nbytes=nbytes,
                summary=f"{method} {domain}{url_path} ({nbytes} B)",
            )
        )
    return out, skipped


def parse_dns(path, cfg):
    device = _device_of(path)
    out, skipped = [], 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        m = DNS_RE.match(line)
        if not m:
            skipped += 1
            continue
        ts, ip, name = m.groups()
        t, unc = _stamp(cfg, device, datetime.fromtimestamp(float(ts), UTC))
        out.append(
            Event(
                id=f"{Path(path).name}:{n}",
                device=device,
                kind="dns",
                t=t,
                unc=unc,
                src_ip=ip,
                host=cfg.host_for_ip(ip),
                domain=name,
                summary=f"DNS query {name}",
            )
        )
    return out, skipped


def parse_fw(path, cfg):
    device = _device_of(path)
    out, skipped = [], 0
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        m = FW_RE.match(line)
        try:
            ts = datetime.fromisoformat(m.group(1))
            kv = dict(p.split("=", 1) for p in m.group(3).split())
            t, unc = _stamp(cfg, device, ts)
            src, dst, port = kv["SRC"], kv["DST"], int(kv["DPT"])
        except (AttributeError, ValueError, KeyError):
            skipped += 1
            continue
        out.append(
            Event(
                id=f"{Path(path).name}:{n}",
                device=device,
                kind="fw",
                t=t,
                unc=unc,
                src_ip=src,
                dst_ip=dst,
                port=port,
                host=cfg.host_for_ip(src),
                nbytes=int(kv.get("BYTES", 0)),
                summary=f"{kv.get('ACTION', '?')} {src} -> {dst}:{port}",
            )
        )
    return out, skipped


PARSERS = {
    "auth.log": parse_auth,
    "proc.jsonl": parse_proc,
    "proxy.csv": parse_proxy,
    "dns.log": parse_dns,
    "fw.log": parse_fw,
}


def flag_suspicious(events, cfg):
    for e in events:
        if e.kind == "proc":
            for rx, why in SUSPICIOUS_CMD:
                if rx.search(e.cmd):
                    e.suspicious = why
                    break
        elif e.kind in ("proxy", "dns"):
            if e.domain and not cfg.is_known_domain(e.domain):
                e.suspicious = "domain outside the baseline list"
        elif e.kind == "fw":
            external = not e.dst_ip.startswith(("10.", "192.168."))
            if external and e.host != "proxy01":
                e.suspicious = "direct outbound flow from an internal host"
            elif e.port in ADMIN_PORTS:
                e.suspicious = "admin-port flow between internal hosts"


def load_dir(path, cfg):
    events, skipped = [], 0
    for f in sorted(Path(path).iterdir()):
        for suffix, fn in PARSERS.items():
            if f.name.endswith("." + suffix):
                evs, sk = fn(f, cfg)
                events += evs
                skipped += sk
    flag_suspicious(events, cfg)
    events.sort(key=lambda e: e.t)
    return events, skipped
