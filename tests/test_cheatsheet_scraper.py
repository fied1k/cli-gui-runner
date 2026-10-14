import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cheatsheet_scraper import (
    CheatsheetExtractor,
    detect_primary_command,
    is_switch_token,
    looks_like_valid_cli,
    auto_parameterize_command,
    normalize_command_string,
    generate_label_from_command,
    parse_webpage,
    save_commands_file
)


class TestCheatsheetScraper(unittest.TestCase):
    def test_cheatsheet_extractor_code_blocks(self):
        html = """
        <html>
        <head><title>Nmap Cheat Sheet</title></head>
        <body>
            <h2>BASIC SCANS<a href="#basic">#</a></h2>
            <pre>
nmap &lt;target&gt; # Basic scan (top 1000 ports)
nmap -sn &lt;target&gt; # Ping scan (host discovery only)
nmap -Pn &lt;target&gt; # Skip host discovery, treat as online
            </pre>
        </body>
        </html>
        """
        parser = CheatsheetExtractor()
        parser.feed(html)
        self.assertEqual(len(parser.candidates), 3)
        self.assertEqual(parser.candidates[0]["cmd"], "nmap <target>")
        self.assertEqual(parser.candidates[0]["desc"], "Basic scan (top 1000 ports)")
        self.assertEqual(parser.candidates[1]["cmd"], "nmap -sn <target>")
        self.assertEqual(parser.candidates[2]["desc"], "Skip host discovery, treat as online")

    def test_cheatsheet_extractor_tables(self):
        html = """
        <table>
            <tr><th>Option</th><th>Description</th></tr>
            <tr><td><code>-sS</code></td><td>SYN Stealth Scan</td></tr>
            <tr><td><code>-sT</code></td><td>TCP Connect Scan</td></tr>
        </table>
        """
        parser = CheatsheetExtractor()
        parser.feed(html)
        self.assertEqual(len(parser.candidates), 2)
        self.assertEqual(parser.candidates[0]["cmd"], "-sS")
        self.assertEqual(parser.candidates[0]["desc"], "SYN Stealth Scan")

    def test_detect_primary_command(self):
        candidates = [
            {"cmd": "nmap -sV <target>"},
            {"cmd": "nmap -p 80 <target>"},
            {"cmd": "nmap -O <target>"}
        ]
        cmd = detect_primary_command(candidates, url="https://example.com/cheatsheets/nmap", title="Nmap Reference")
        self.assertEqual(cmd, "nmap")

        cmd2 = detect_primary_command([], url="https://example.com/cheatsheets/curl", title="cURL Docs")
        self.assertEqual(cmd2, "curl")

    def test_is_switch_token(self):
        self.assertTrue(is_switch_token("-sV"))
        self.assertTrue(is_switch_token("--script=vuln"))
        self.assertTrue(is_switch_token("-p-"))
        self.assertFalse(is_switch_token("nmap"))
        self.assertFalse(is_switch_token("target"))

    def test_auto_parameterize_command(self):
        cmd = "nmap -p 80,443 192.168.1.1"
        parameterized = auto_parameterize_command(cmd)
        self.assertIn("<Target_IP>", parameterized)
        self.assertIn("<Port>", parameterized)

    def test_generate_label_clean_no_hash(self):
        label = generate_label_from_command("nmap -Pn <target>", desc="Skip host discovery, treat as online", heading="BASIC SCANS#")
        self.assertNotIn("#", label)
        self.assertEqual(label, "Skip host discovery")

    def test_parse_webpage_full_pipeline(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Nmap Cheat Sheet — OffensiveRamen</title></head>
        <body>
            <h2>BASIC SCANS<a href="#basic">#</a></h2>
            <pre>
nmap &lt;target&gt; # Basic scan
nmap -sn &lt;target&gt; # Ping scan
            </pre>
            <h2>SWITCHES<a href="#switches">#</a></h2>
            <table>
                <tr><td><code>-sV</code></td><td>Service version detection</td></tr>
            </table>
        </body>
        </html>
        """
        primary_cmd, entries = parse_webpage(html, url="https://offensiveramen.com/cheatsheets/nmap")
        self.assertEqual(primary_cmd, "nmap")
        self.assertEqual(len(entries), 3)

        # Check synthesized switch row
        switch_entry = entries[2]
        self.assertEqual(switch_entry[0], "-sV")
        self.assertEqual(switch_entry[1], "nmap -sV <target>")
        self.assertEqual(switch_entry[2], "Service version detection")

    def test_save_commands_file(self):
        entries = [
            ("Basic scan", "nmap <target>", "Basic scan (top 1000 ports)"),
            ("Ping scan", "nmap -sn <target>", "Ping scan (host discovery only)")
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "nmap.txt")
            save_commands_file(out_file, "nmap", "https://example.com/nmap", entries)

            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("# Format: Button Name | Command Template | Description", content)
            self.assertIn("# Command: nmap", content)
            self.assertIn("Basic scan | nmap <target> | Basic scan (top 1000 ports)", content)
            self.assertIn("Ping scan | nmap -sn <target> | Ping scan (host discovery only)", content)


if __name__ == "__main__":
    unittest.main()
