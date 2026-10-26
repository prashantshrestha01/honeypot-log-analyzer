"""Tests for honeypot.py, run against the bundled synthetic sample
log (203.0.113.0/24 and 198.51.100.0/24 are documentation ranges --
no real attacker data is involved)."""

import csv
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from honeypot import parse_log, analyze, write_ioc_csv

SAMPLE = os.path.join(os.path.dirname(__file__), "..", "sample_logs.jsonl")


class TestHoneypot(unittest.TestCase):
    def setUp(self):
        self.events = parse_log(SAMPLE)
        self.summary = analyze(self.events)

    def test_event_and_session_counts(self):
        self.assertEqual(self.summary["event_count"], 10)
        self.assertEqual(self.summary["session_count"], 2)

    def test_top_ip(self):
        self.assertEqual(self.summary["top_ips"][0][0], "203.0.113.10")
        self.assertEqual(self.summary["top_ips"][0][1], 7)

    def test_credentials(self):
        self.assertEqual(self.summary["top_usernames"][0][0], "root")
        self.assertIn(("root/admin", 1), self.summary["top_combos"])

    def test_session_duration(self):
        # s1: 10:00:00 -> 10:02:00 = 120s; s2: 30s; average 75s.
        self.assertEqual(self.summary["avg_session_duration_s"], 75.0)

    def test_commands(self):
        commands = dict(self.summary["top_commands"])
        self.assertEqual(commands["uname -a"], 1)
        self.assertEqual(commands["cat /etc/passwd"], 1)

    def test_ioc_csv_export(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
        tmp.close()
        try:
            write_ioc_csv(self.summary, tmp.name)
            with open(tmp.name, newline="") as fh:
                rows = list(csv.DictReader(fh))
        finally:
            os.unlink(tmp.name)
        types = {r["type"] for r in rows}
        self.assertIn("src_ip", types)
        self.assertIn("username", types)
        self.assertIn("command", types)
        ip_rows = [r for r in rows if r["value"] == "203.0.113.10"]
        self.assertEqual(ip_rows[0]["count"], "7")

    def test_malformed_lines_skipped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
            fh.write("not json\n")
            fh.write('{"eventid": "cowrie.session.connect", "src_ip": "192.0.2.1", '
                     '"timestamp": "2026-10-20T10:00:00Z", "session": "x"}\n')
            path = fh.name
        try:
            events = parse_log(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()
