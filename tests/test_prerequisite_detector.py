import os
import shutil
import unittest
from unittest.mock import MagicMock, patch

from prerequisite_detector import (
    PrerequisiteDetector,
    ToolPrerequisite,
    APT_PACKAGE_MAP,
    WINGET_PACKAGE_MAP
)


class TestPrerequisiteDetector(unittest.TestCase):

    def setUp(self):
        # Reset caches before tests
        PrerequisiteDetector._wsl_status_cache = None
        PrerequisiteDetector._wsl_tool_cache = {}

    def test_extract_required_tools(self):
        commands = [
            ("Start Bettercap", "bettercap -iface wlan0mon", "Start bettercap"),
            ("Run Nmap Scan", "nmap -sV -p 80,443 <target>", "Port scan"),
            ("Sudo Run", "sudo bettercap -eval 'net.recon on'", "Recon"),
            ("Cat File", "cat /etc/passwd", "View file"),
            ("Python Script", "python -m caplets.runner", "Run runner"),
            ("Tshark Capture", "tshark -i eth0 -w dump.pcap", "Packet capture")
        ]
        tools = PrerequisiteDetector.extract_required_tools(commands)
        self.assertIn("bettercap", tools)
        self.assertEqual(tools["bettercap"], 2)  # Found twice (direct and sudo)
        self.assertIn("nmap", tools)
        self.assertIn("tshark", tools)
        self.assertIn("python", tools)
        self.assertNotIn("cat", tools)
        self.assertNotIn("sudo", tools)

    @patch("shutil.which")
    def test_inspect_tool_native_windows(self, mock_which):
        mock_which.return_value = r"C:\Program Files\Nmap\nmap.exe"

        prereq = PrerequisiteDetector.inspect_tool("nmap", 3)
        self.assertEqual(prereq.status, "READY_WINDOWS")
        self.assertEqual(prereq.execution_mode, "native")
        self.assertEqual(prereq.windows_path, r"C:\Program Files\Nmap\nmap.exe")
        self.assertTrue(prereq.windows_in_path)

    @patch("shutil.which")
    @patch.object(PrerequisiteDetector, "check_wsl_status")
    @patch.object(PrerequisiteDetector, "check_tool_in_wsl")
    def test_inspect_tool_wsl_fallback(self, mock_check_tool, mock_check_wsl, mock_which):
        # Tool is NOT in Windows PATH
        mock_which.return_value = None
        # WSL is available (Ubuntu)
        mock_check_wsl.return_value = (True, "Ubuntu")
        # Tool IS found in WSL
        mock_check_tool.return_value = "/usr/bin/bettercap"

        prereq = PrerequisiteDetector.inspect_tool("bettercap", 5)
        self.assertEqual(prereq.status, "READY_WSL")
        self.assertEqual(prereq.execution_mode, "wsl")
        self.assertEqual(prereq.wsl_path, "/usr/bin/bettercap")

    @patch("shutil.which")
    @patch.object(PrerequisiteDetector, "check_wsl_status")
    @patch.object(PrerequisiteDetector, "check_tool_in_wsl")
    def test_inspect_tool_missing_both_with_wsl(self, mock_check_tool, mock_check_wsl, mock_which):
        mock_which.return_value = None
        mock_check_wsl.return_value = (True, "Ubuntu")
        mock_check_tool.return_value = None

        prereq = PrerequisiteDetector.inspect_tool("dnswalk", 1)
        self.assertEqual(prereq.status, "MISSING_BOTH")
        self.assertEqual(prereq.execution_mode, "unresolved")
        self.assertIn("sudo apt install -y dnswalk", prereq.install_cmd_wsl)

    @patch("shutil.which")
    @patch.object(PrerequisiteDetector, "find_python_installations_windows")
    @patch.object(PrerequisiteDetector, "is_directory_in_windows_path")
    def test_inspect_python_needs_path(self, mock_is_in_path, mock_find_py, mock_which):
        mock_which.return_value = None
        mock_find_py.return_value = [r"C:\Python315\python.exe"]
        mock_is_in_path.return_value = False

        prereq = PrerequisiteDetector.inspect_tool("python", 1)
        self.assertEqual(prereq.status, "NEEDS_PATH")
        self.assertEqual(prereq.windows_path, r"C:\Python315\python.exe")
        self.assertFalse(prereq.windows_in_path)

    def test_resolve_command_execution(self):
        prereqs = {
            "nmap": ToolPrerequisite("nmap"),
            "bettercap": ToolPrerequisite("bettercap")
        }
        prereqs["nmap"].status = "READY_WINDOWS"
        prereqs["bettercap"].status = "READY_WSL"
        prereqs["bettercap"].wsl_distro = "Ubuntu"

        mode, final_cmd, note = PrerequisiteDetector.resolve_command_execution("nmap -sV 192.168.1.1", prereqs)
        self.assertEqual(mode, "native")
        self.assertEqual(final_cmd, "nmap -sV 192.168.1.1")

        mode, final_cmd, note = PrerequisiteDetector.resolve_command_execution("bettercap -iface wlan0", prereqs)
        self.assertEqual(mode, "wsl")
        self.assertEqual(final_cmd, "wsl bettercap -iface wlan0")
        self.assertIn("detected in WSL (Ubuntu)", note)


if __name__ == "__main__":
    unittest.main()
