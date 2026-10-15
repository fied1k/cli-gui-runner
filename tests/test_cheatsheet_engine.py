import os
import sys
import unittest
import py_compile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cheatsheet_engine import (
    CommandItem,
    CheatSheetProfile,
    VariableNormalizer,
    OffensiveRamenHTMLParser,
    TabularColumnMapper,
    KeyValueBlockParser,
    StandaloneGenerator,
)


class TestCheatSheetEngine(unittest.TestCase):
    def test_variable_normalizer(self):
        cmd = "nmap -sV -p 22,80,443 192.168.1.1/24"
        normalized = VariableNormalizer.normalize(cmd)
        self.assertIn("<subnet_cidr>", normalized)
        self.assertIn("<port>", normalized)

        mac_cmd = "airodump-ng --bssid 00:11:22:33:44:55 wlan0"
        norm_mac = VariableNormalizer.normalize(mac_cmd)
        self.assertIn("<mac_address>", norm_mac)

        bracket_cmd = "ssh [user]@[host]"
        norm_bracket = VariableNormalizer.normalize(bracket_cmd)
        self.assertIn("<user>", norm_bracket)
        self.assertIn("<host>", norm_bracket)

    def test_offensive_ramen_parser(self):
        sample_html = """
        <html>
        <head><title>Kismet Cheat Sheet</title></head>
        <body>
        <h2 class="cs-h">Starting Kismet</h2>
        <pre class="cs-sheet">
# Start with console UI
kismet

# Specify capture interface
kismet -c wlan0

# Daemon mode
kismet --daemonize
        </pre>
        <h2 class="cs-h">Reference Info</h2>
        <pre class="cs-sheet">
- Default login: admin:password
- Web UI: http://localhost:2501
        </pre>
        </body>
        </html>
        """
        profile = OffensiveRamenHTMLParser.parse_html(sample_html, sheet_id="test_kismet", title="Test Kismet")
        self.assertEqual(profile.sheet_id, "test_kismet")
        self.assertEqual(profile.title, "Test Kismet")
        self.assertIn("Starting Kismet", profile.categories)
        self.assertEqual(len(profile.commands), 3)

        # Check that switches, templates, and descriptions exist
        for cmd in profile.commands:
            self.assertTrue(cmd.switch)
            self.assertTrue(cmd.template)
            self.assertTrue(cmd.description)

        # Check reference notes
        self.assertEqual(len(profile.reference_notes), 2)
        self.assertTrue(any("Default login: admin:password" in note for note in profile.reference_notes))

    def test_tabular_column_mapper_standard(self):
        rows = [
            "Switch\tExample\tDescription",
            "-sn\tnmap -sn 192.168.1.0/24\tPing scan without port scan",
            "-p\tnmap -p 80,443 10.0.0.1\tScan specific ports",
        ]
        items, conf = TabularColumnMapper.parse_rows(rows, default_category="Nmap Scanning")
        self.assertEqual(len(items), 2)
        self.assertGreaterEqual(conf, 0.9)
        self.assertEqual(items[0].switch, "-sn")
        self.assertIn("<subnet_cidr>", items[0].template)
        self.assertEqual(items[0].description, "Ping scan without port scan")

    def test_tabular_column_mapper_markdown(self):
        rows = [
            "| Switch | Example | Description |",
            "| --- | --- | --- |",
            "| -i | tshark -i eth0 | Capture on interface |",
            "| -w | tshark -w out.pcap | Write packets to file |",
        ]
        items, conf = TabularColumnMapper.parse_rows(rows, default_category="Capture")
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].switch, "-i")
        self.assertIn("tshark", items[0].template)
        self.assertEqual(items[0].description, "Capture on interface")

    def test_key_value_block_parser(self):
        text = """
        Switch: -c | Example: kismet -c wlan0 | Description: Specify wireless capture source
        Switch: --daemonize ; Example: kismet --daemonize ; Description: Launch in background
        """
        items = KeyValueBlockParser.parse(text, default_category="Starting")
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0].switch, "-c")
        self.assertIn("kismet -c", items[0].template)
        self.assertEqual(items[0].description, "Specify wireless capture source")

    def test_profile_serialization(self):
        profile = CheatSheetProfile(sheet_id="demo", title="Demo Sheet")
        profile.add_command(CommandItem(switch="Ping", template="ping <Target>", description="Send ICMP packets", category="Net"))
        profile.reference_notes.append("Run as root for raw sockets")

        # Test export txt
        txt = profile.export_commands_txt()
        self.assertIn("Ping | ping <Target> | Send ICMP packets", txt)
        self.assertIn("Run as root for raw sockets", txt)

        # Test to_dict and from_dict
        d = profile.to_dict()
        reloaded = CheatSheetProfile.from_dict(d)
        self.assertEqual(reloaded.sheet_id, "demo")
        self.assertEqual(len(reloaded.commands), 1)
        self.assertEqual(reloaded.commands[0].switch, "Ping")
        self.assertEqual(reloaded.reference_notes[0], "Run as root for raw sockets")

    def test_standalone_generator_compilation(self):
        profile = CheatSheetProfile(sheet_id="kismet_test", title="Kismet Test Runner")
        profile.add_command(CommandItem(switch="Kismet Console", template="kismet", description="Launch Kismet UI", category="Startup"))
        profile.add_command(CommandItem(switch="Convert PCAP", template="kismetdb_to_pcap --in <kismet_db> --out <output_pcap>", description="Convert to PCAP", category="Tools"))

        code = StandaloneGenerator.generate_python_code(profile)
        self.assertIn("Kismet Test Runner", code)
        self.assertIn("StandaloneRunnerApp", code)

        # Compile code directly in memory to verify syntax
        compiled_obj = compile(code, "<standalone_runner>", "exec")
        self.assertIsNotNone(compiled_obj)


if __name__ == "__main__":
    unittest.main()
