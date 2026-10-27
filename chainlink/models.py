import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path


@dataclass
class Device:
    name: str
    ip: str
    tz_offset_min: int = 0
    skew_s: float = 0.0
    skew_unc_s: float = 5.0


@dataclass
class Config:
    devices: dict[str, Device]
    default_year: int = 2025
    known_domains: list[str] = field(default_factory=list)

    def host_for_ip(self, ip):
        for d in self.devices.values():
            if d.ip == ip:
                return d.name
        return None

    def is_known_domain(self, name):
        return any(name == k or name.endswith("." + k) for k in self.known_domains)


def load_config(path):
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    devices = {n: Device(name=n, **d) for n, d in raw["devices"].items()}
    return Config(devices, raw.get("default_year", 2025), raw.get("known_domains", []))


@dataclass
class Event:
    id: str
    device: str
    kind: str
    t: datetime
    unc: float
    summary: str
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    port: int | None = None
    host: str | None = None
    pid: int | None = None
    ppid: int | None = None
    proc: str | None = None
    cmd: str = ""
    domain: str | None = None
    nbytes: int = 0
    suspicious: str | None = None

    @property
    def lo(self):
        return self.t - timedelta(seconds=self.unc)

    @property
    def hi(self):
        return self.t + timedelta(seconds=self.unc)

    @property
    def lane(self):
        return self.host or self.device
