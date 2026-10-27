# chainlink

Reconstructs a candidate attack chain from logs of several devices whose clocks disagree, and says what it could not see.

Inputs (one file per device, named `<device>.<kind>`): `auth.log` (sshd), `proc.jsonl` (process creation), `proxy.csv`, `dns.log`, `fw.log`. A `config.json` gives each device's IP, timezone offset, clock skew and skew uncertainty, plus a list of known-good domains.

```
python -m chainlink generate demo            # synthetic intrusion + config.json + truth.json
python -m chainlink analyze demo --out report.html
python -m chainlink analyze demo --json
python -m chainlink evaluate --seeds 20
```

No dependencies beyond Python 3.11+ (pytest and ruff for development).

## How it works

1. **Normalise time.** Naive timestamps are treated as device-local: the configured tz offset and skew are removed to get UTC. Each event keeps an uncertainty (skew uncertainty + 1 s), drawn as a bar in the report.
2. **Flag suspicious events** with simple rules: encoded/hidden PowerShell, archiving, upload via curl, ssh to another host, hidden files in `/tmp`, domains outside the known list, direct outbound firewall flows from non-proxy hosts, admin-port flows.
3. **Link events** within an hour of each other. Every link carries named evidence with a weight: parent/child pid lineage, allowed flow followed by a login, a command line naming the target host or domain, DNS lookup then request, repeated beacon contact, a login whose source host just did something suspicious. Weights combine as noisy-OR; same-user / same-host evidence alone never creates a link. Distance beyond the clock uncertainty discounts the score, and a link whose causal direction contradicts the timestamps is halved and not used for ordering.
4. **Order** each connected component topologically over causal links, falling back to corrected time. For adjacent events whose uncertainty windows overlap and that no causal path orders, the report offers the swapped ordering with a probability (Gaussian on the time difference).
5. **Find gaps**: a parent pid absent from the logs, a login with no matching firewall flow or no logged initiating command, an allowed port-22 flow with no login record, quiet periods over 15 minutes, and missing beacons in a regular series.

Chain scores are heuristic confidence, capped at 0.9, not probabilities.

## Evaluation

`generate` writes `truth.json` alongside the logs: the true attack events, in true order, and the injected gaps (a missing parent process, an unlogged firewall hop, a dropped beacon). The scenario is a phish → C2 beaconing → ssh to a server → ssh to a database → staged archive → exfil, with a benign admin session and background noise (DNS, proxy, failed logins, cron) as decoys. Clock skews, a timezone offset, and per-seed timestamp jitter are applied.

Mean over seeds 1-20 (`python -m chainlink evaluate --seeds 20`), best-matching chain:

| metric | value |
|---|---|
| precision | 1.000 |
| recall | 1.000 |
| pairwise order accuracy | 0.998 |
| plain time-sort baseline | 0.988 |
| injected gaps found | 1.000 |

Same results at 5x noise. Caveats: this is a synthetic scenario written by the same author as the rules, so it shows the mechanism works, not that it generalises. The benign admin session also shows up as a second, lower-scored chain (it is built from the same ssh evidence, so it is genuinely hard to distinguish without context); the attacker chain ranks first. The order gain over a plain time sort is small because the skews in the demo are modest.

## Tests

`pytest -q` covers parsing with tz/skew, malformed lines, chain recovery, decoy separation, gap detection, alternative orderings, HTML escaping, determinism and the CLI.

## License

MIT
