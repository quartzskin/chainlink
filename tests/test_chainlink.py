import json
from datetime import UTC, datetime

import pytest

from chainlink.cli import main
from chainlink.correlate import p_before, reconstruct
from chainlink.evaluate import evaluate, run_one
from chainlink.generate import generate
from chainlink.models import Config, Device, load_config
from chainlink.parsers import load_dir, parse_auth, parse_proc
from chainlink.report import render


@pytest.fixture
def cfg():
    return Config(
        {
            "srv01": Device("srv01", "10.0.0.21", tz_offset_min=60, skew_s=30, skew_unc_s=5),
            "ws01": Device("ws01", "10.0.0.11"),
        },
        known_domains=["github.com"],
    )


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    d = generate(tmp_path_factory.mktemp("logs"), seed=3)
    c = load_config(d / "config.json")
    events, skipped = load_dir(d, c)
    return d, c, events, skipped, json.loads((d / "truth.json").read_text())


def test_auth_applies_timezone_and_skew(tmp_path, cfg):
    f = tmp_path / "srv01.auth.log"
    f.write_text(
        "Mar 10 10:00:30 srv01 sshd[9]: Accepted publickey for bob from 10.0.0.11 port 22 ssh2\ngarbage line\n"
    )
    (ev,), skipped = parse_auth(f, cfg)
    assert ev.t == datetime(2025, 3, 10, 9, 0, 0, tzinfo=UTC)
    assert ev.unc == 6.0 and skipped == 1


def test_proc_skips_malformed(tmp_path, cfg):
    f = tmp_path / "ws01.proc.jsonl"
    f.write_text('{"time":"2025-03-10T09:00:00","image":"a","cmd":"x","pid":1,"ppid":0}\n{bad\n{"image":"a"}\n')
    evs, skipped = parse_proc(f, cfg)
    assert len(evs) == 1 and skipped == 2


def test_p_before_is_symmetric_around_equal_times(sample):
    _, _, events, _, _ = sample
    a = events[0]
    assert p_before(a, a) == pytest.approx(0.5)


def test_attack_chain_found_and_ranked_first(sample):
    _, c, events, _, truth = sample
    chains = reconstruct(events, c)
    ids = {e.id for e in chains[0].events}
    assert set(truth["events"]) <= ids
    assert len(chains[0].events) <= len(truth["events"]) + 1


def test_decoy_session_not_merged(sample):
    _, c, events, _, truth = sample
    for ch in reconstruct(events, c):
        ids = {e.id for e in ch.events}
        assert not (ids & set(truth["events"]) and any(e.user == "bob" for e in ch.events))


def test_injected_gaps_detected(sample):
    _, c, events, _, _ = sample
    kinds = {g.kind for g in reconstruct(events, c)[0].gaps}
    assert {"missing-parent", "missing-flow", "missed-beacons"} <= kinds


def test_alternatives_only_for_overlapping_events(sample):
    _, c, events, _, _ = sample
    for alt in reconstruct(events, c)[0].alternatives:
        x, y = (next(e for e in events if e.id == i) for i in alt["swap"])
        assert x.hi >= y.lo


def test_no_chain_without_suspicious_events(tmp_path, cfg):
    f = tmp_path / "ws01.proc.jsonl"
    f.write_text(
        "\n".join(
            json.dumps(
                {
                    "time": f"2025-03-10T09:00:0{i}",
                    "image": "ls",
                    "cmd": "ls",
                    "user": "a",
                    "pid": i + 10,
                    "ppid": i + 9,
                }
            )
            for i in range(5)
        )
    )
    events, _ = load_dir(tmp_path, cfg)
    assert reconstruct(events, cfg) == []


def test_report_escapes_html(sample):
    _, c, events, skipped, _ = sample
    chains = reconstruct(events, c)
    chains[0].timeline[0].summary = "<script>alert(1)</script>"
    html = render(chains, len(events), skipped)
    assert "<script>alert" not in html and "&lt;script&gt;" in html


def test_evaluation_quality():
    mean, _ = evaluate(seeds=5)
    assert mean["recall"] == 1.0 and mean["precision"] >= 0.9
    assert mean["order"] >= 0.97 and mean["gap_recall"] == 1.0


def test_generation_is_deterministic(tmp_path):
    a = generate(tmp_path / "a", seed=7)
    b = generate(tmp_path / "b", seed=7)
    assert (a / "dns01.dns.log").read_text() == (b / "dns01.dns.log").read_text()
    assert run_one(7)["recall"] == run_one(7)["recall"]


def test_cli_roundtrip(tmp_path, capsys):
    assert main(["generate", str(tmp_path)]) == 0
    out = tmp_path / "r.html"
    assert main(["analyze", str(tmp_path), "--out", str(out)]) == 0
    assert "Chain 1" in out.read_text(encoding="utf-8")
    assert main(["analyze", str(tmp_path), "--json"]) == 0
    assert '"score"' in capsys.readouterr().out


def test_cli_missing_config_returns_error(tmp_path, capsys):
    assert main(["analyze", str(tmp_path)]) == 1
