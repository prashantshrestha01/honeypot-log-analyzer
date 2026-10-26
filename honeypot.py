"""Analyze Cowrie-style SSH honeypot JSON logs, stdlib only.

Reads JSON-lines logs (one event per line), summarizes attacker
activity, and exports indicators of compromise (IOCs) as CSV.

Cowrie event ids handled: cowrie.login.success / .failed (credentials
tried), cowrie.session.connect / .closed (session duration),
cowrie.command.input (commands run).
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp to epoch seconds; None if unparseable."""
    if value is None:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


def parse_log(path):
    """Parse a JSON-lines honeypot log. Returns a list of event dicts."""
    events = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # skip malformed lines, keep triaging the rest
    return events


def analyze(events):
    """Summarize events: IPs, credentials, sessions, commands, IOCs."""
    ip_counts = Counter()
    user_counts = Counter()
    pass_counts = Counter()
    combo_counts = Counter()
    command_counts = Counter()
    sessions = {}
    first_seen, last_seen = {}, {}
    for ev in events:
        src = ev.get("src_ip")
        if src:
            ip_counts[src] += 1
        ts = parse_timestamp(ev.get("timestamp"))
        for key, counter in (("src_ip", None),):
            pass
        eventid = ev.get("eventid", "")
        if eventid in ("cowrie.login.success", "cowrie.login.failed"):
            user, password = ev.get("username"), ev.get("password")
            if user:
                user_counts[user] += 1
            if password:
                pass_counts[password] += 1
            if user and password:
                combo_counts[(user, password)] += 1
        if eventid == "cowrie.session.connect":
            sessions[ev.get("session")] = {"start": ts, "src_ip": src}
        if eventid == "cowrie.session.closed":
            session = sessions.get(ev.get("session"))
            if session and session["start"] is not None and ts is not None:
                session["duration"] = round(ts - session["start"], 1)
        if eventid == "cowrie.command.input":
            cmd = ev.get("input", "")
            if cmd:
                command_counts[cmd] += 1
        # First/last seen per IP for the IOC export.
        if src and ts is not None:
            first_seen[src] = min(ts, first_seen.get(src, ts))
            last_seen[src] = max(ts, last_seen.get(src, ts))

    durations = [s["duration"] for s in sessions.values() if "duration" in s]
    avg_duration = round(sum(durations) / len(durations), 1) if durations else 0.0
    iocs = []
    for ip, count in ip_counts.most_common():
        iocs.append({"type": "src_ip", "value": ip, "count": count,
                     "first_seen": first_seen.get(ip), "last_seen": last_seen.get(ip)})
    for user, count in user_counts.most_common():
        iocs.append({"type": "username", "value": user, "count": count,
                     "first_seen": None, "last_seen": None})
    for cmd, count in command_counts.most_common():
        iocs.append({"type": "command", "value": cmd, "count": count,
                     "first_seen": None, "last_seen": None})
    return {
        "event_count": len(events),
        "session_count": len(sessions),
        "avg_session_duration_s": avg_duration,
        "top_ips": ip_counts.most_common(10),
        "top_usernames": user_counts.most_common(10),
        "top_passwords": pass_counts.most_common(10),
        "top_combos": [(f"{u}/{p}", c) for (u, p), c in combo_counts.most_common(10)],
        "top_commands": command_counts.most_common(10),
        "iocs": iocs,
    }


def write_ioc_csv(summary, path):
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["type", "value", "count",
                                                "first_seen", "last_seen"])
        writer.writeheader()
        writer.writerows(summary["iocs"])


def render_text(summary):
    lines = [f"Events: {summary['event_count']}  Sessions: {summary['session_count']}  "
             f"Avg session: {summary['avg_session_duration_s']}s", ""]
    for label, key in (("Top attacker IPs", "top_ips"),
                       ("Most-tried usernames", "top_usernames"),
                       ("Most-tried passwords", "top_passwords"),
                       ("Most-tried combos", "top_combos"),
                       ("Commands run", "top_commands")):
        lines.append(f"{label}:")
        for value, count in summary[key]:
            lines.append(f"  {value} ({count}x)")
        if not summary[key]:
            lines.append("  none")
        lines.append("")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Analyze Cowrie SSH honeypot logs and export IOCs.")
    parser.add_argument("log", help="JSON-lines honeypot log file")
    parser.add_argument("--ioc-csv", help="write IOC export CSV to this path")
    args = parser.parse_args(argv)
    try:
        events = parse_log(args.log)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    summary = analyze(events)
    print(render_text(summary))
    if args.ioc_csv:
        write_ioc_csv(summary, args.ioc_csv)
        print(f"IOC CSV written to {args.ioc_csv} ({len(summary['iocs'])} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
