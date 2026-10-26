# honeypot-log-analyzer

Analyze SSH honeypot logs: attacker IPs, credentials tried, commands and IOC export.

## What it does

`honeypot.py` reads Cowrie-style JSON-lines SSH honeypot logs and reports:

- **Top attacker IPs** — by event count, with first/last seen timestamps
- **Most-tried usernames, passwords and combos** — what credential stuffing looks like against the honeypot
- **Session durations** — connect-to-close timing, with an average across sessions
- **Commands run** — what attackers do once inside
- **IOC export** — IPs, usernames and commands as CSV, ready to feed into a blocklist or a ticket

## Quick start

```bash
python3 honeypot.py sample_logs.jsonl
python3 honeypot.py sample_logs.jsonl --ioc-csv iocs.csv
```

No third-party packages are needed. Python 3.8+ only.

## Usage

```
python3 honeypot.py <log.jsonl> [--ioc-csv <out.csv>]
```

The bundled `sample_logs.jsonl` is synthetic (documentation IP ranges only) so the tool runs and tests offline.

## Layout

```
honeypot.py         # JSON-lines parser + analysis + CSV export (stdlib only)
sample_logs.jsonl   # bundled synthetic Cowrie-style sample log
tests/
  test_honeypot.py
```

## Design notes (custom mods)

- **Bundled synthetic sample log.** The tool ships a small, fully synthetic Cowrie-style log, so it runs and tests offline with no real honeypot and no real attacker data.
- **Session durations from connect/close pairs.** Sessions are matched by session id and timed from `cowrie.session.connect` to `cowrie.session.closed`, giving a real dwell-time picture instead of just event counts.
- **IOC export is a first-class output, not an afterthought.** The CSV carries type, value, count and first/last seen per indicator, in a shape that drops straight into a blocklist workflow.

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
