import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cli_gui_runner import CommandRunnerGUI


class DummyApp(CommandRunnerGUI):
    """Mock helper inheriting methods without instantiating full Tkinter UI."""
    def __init__(self):
        class MockVar:
            def get(self):
                return False
        self.auto_param_var = MockVar()


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

    def test_categorized_txt_loading(self):
        sample_txt = (
            "# Profile: Kismet Wireless\n"
            "# === Starting Kismet ===\n"
            "Console UI | kismet | Start Kismet console\n"
            "# === Capture Sources ===\n"
            "-c (WiFi) | kismet -c <interface> | Capture on WiFi\n"
            "# === REFERENCE & TIPS ===\n"
            "# • Web UI: http://localhost:2501\n"
        )
        test_path = os.path.join(os.path.dirname(__file__), "temp_sample.txt")
        try:
            with open(test_path, "w", encoding="utf-8") as f:
                f.write(sample_txt)
            self.app.profiles = {}
            self.app.profile_labels = {}
            self.app.file_label = type("MockLabel", (), {"config": lambda *a, **k: None})()
            self.app.render_profile = lambda prof: None

            self.app.load_commands(test_path)
            self.assertIn("temp_sample", self.app.profiles)
            prof = self.app.profiles["temp_sample"]
            self.assertEqual(len(prof.commands), 2)
            self.assertIn("Starting Kismet", prof.categories)
            self.assertIn("Capture Sources", prof.categories)
            self.assertEqual(len(prof.reference_notes), 1)
            self.assertIn("Web UI: http://localhost:2501", prof.reference_notes[0])
        finally:
            if os.path.exists(test_path):
                os.remove(test_path)

    def test_verification_dialog_swap_logic(self):
        from cheatsheet_engine import CheatSheetProfile, CommandItem
        prof = CheatSheetProfile(sheet_id="test", title="Test")
        prof.add_command(CommandItem(switch="nmap -sS", template="Stealth Scan", description="TCP SYN Scan"))
        # In this inverted case:
        self.assertEqual(prof.commands[0].switch, "nmap -sS")
        self.assertEqual(prof.commands[0].template, "Stealth Scan")

        # Swap columns
        for cmd in prof.commands:
            cmd.switch, cmd.template = cmd.template, cmd.switch

        self.assertEqual(prof.commands[0].switch, "Stealth Scan")
        self.assertEqual(prof.commands[0].template, "nmap -sS")

    def test_verification_dialog_mapping_reassignment(self):
        from cheatsheet_engine import CheatSheetProfile, CommandItem, ROLE_SWITCH, ROLE_TEMPLATE, ROLE_DESC
        from cli_gui_runner import ParserVerificationDialog

        prof = CheatSheetProfile(sheet_id="remap_test", title="Remap Test")
        raw_rows = [
            ["Perform stealth port scan", "nmap -sS <target>", "-sS"],
            ["Detect remote operating system", "nmap -O <target>", "-O"]
        ]

        # Col 0: Desc, Col 1: Template, Col 2: Switch
        mapping = {ROLE_DESC: 0, ROLE_TEMPLATE: 1, ROLE_SWITCH: 2, "category": -1}

        # Test headless logic using dialog helper
        dialog = ParserVerificationDialog.__new__(ParserVerificationDialog)
        dialog.profile = prof
        dialog.raw_rows = raw_rows
        dialog.col_count = 3
        dialog.current_mapping = mapping
        dialog.registry = type("MockReg", (), {})()
        from cheatsheet_engine import get_mapping_registry
        dialog.registry = get_mapping_registry()
        dialog._refresh_tree = lambda *a: None
        dialog.rule_var = type("MockVar", (), {"get": lambda *a: "Custom Mapping"})()
        dialog.strategy_badge = type("MockBadge", (), {"config": lambda *a, **k: None})()

        dialog._apply_current_mapping()

        self.assertEqual(len(dialog.profile.commands), 2)
        # Verify first command has correct mappings
        self.assertEqual(dialog.profile.commands[0].description, "Perform stealth port scan")
        self.assertEqual(dialog.profile.commands[0].template, "nmap -sS <target>")
        self.assertEqual(dialog.profile.commands[0].switch, "-sS")

        # Verify second command
        self.assertEqual(dialog.profile.commands[1].description, "Detect remote operating system")
        self.assertEqual(dialog.profile.commands[1].template, "nmap -O <target>")
        self.assertEqual(dialog.profile.commands[1].switch, "-O")


if __name__ == "__main__":
    unittest.main()
