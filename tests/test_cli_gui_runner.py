"""Unit tests for CLI Quick-Reference GUI Runner logic."""

import unittest
from cli_gui_runner import CommandRunnerGUI


class DummyApp:
    """Mock helper inheriting parsing methods without instantiating Tkinter."""
    parse_line = CommandRunnerGUI.parse_line
    _normalize_command_string = CommandRunnerGUI._normalize_command_string
    _generate_label_from_command = CommandRunnerGUI._generate_label_from_command
    format_raw_paste_text = CommandRunnerGUI.format_raw_paste_text


class TestCommandParsing(unittest.TestCase):
    def setUp(self):
        self.app = DummyApp()

    def test_parse_line_three_parts(self):
        line = "Ping Host | ping -c 4 <Target> | Send ICMP ping"
        label, cmd, desc = self.app.parse_line(line)
        self.assertEqual(label, "Ping Host")
        self.assertEqual(cmd, "ping -c 4 <Target>")
        self.assertEqual(desc, "Send ICMP ping")

    def test_parse_line_raw_command(self):
        line = "traceroute <Target_Host>"
        label, cmd, desc = self.app.parse_line(line)
        self.assertEqual(cmd, "traceroute <Target_Host>")
        self.assertEqual(label, "traceroute <Target_Host>")

    def test_normalize_command_string(self):
        raw = "$ ssh [Username]@<Host> -p {Port}"
        normalized = self.app._normalize_command_string(raw)
        self.assertEqual(normalized, "ssh <Username>@<Host> -p {Port}")

    def test_format_tsv_input(self):
        tsv_data = (
            "Action\tCommand\tDescription\n"
            "List Interfaces\ttshark -D\tShows all available network interfaces.\n"
            "Live Capture\ttshark -i <interface>\tCaptures and streams live traffic.\n"
        )
        entries = self.app.format_raw_paste_text(tsv_data)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0][0], "List Interfaces")
        self.assertEqual(entries[0][1], "tshark -D")
        self.assertEqual(entries[0][2], "Shows all available network interfaces.")

    def test_format_inline_comments(self):
        text = "whois <Domain_Name> # Lookup domain registration info"
        entries = self.app.format_raw_paste_text(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][1], "whois <Domain_Name>")
        self.assertEqual(entries[0][2], "Lookup domain registration info")

    def test_format_preceding_comments(self):
        text = "# Check current disk space\ndf -h"
        entries = self.app.format_raw_paste_text(text)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0][1], "df -h")
        self.assertEqual(entries[0][2], "Check current disk space")


if __name__ == "__main__":
    unittest.main()
