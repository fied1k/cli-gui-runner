import os
import shutil
import tempfile
import unittest
from cheatsheet_engine import (
    SectionCommentWorkflowParser,
    VariableNormalizer,
    CommandItem,
    CheatSheetProfile
)

SAMPLE_BETTERCAP_SNIPPET = """
<section class="cs-section">
  <h2 class="cs-h" id="installation">INSTALLATION<a class="cs-anchor" href="#installation">#</a></h2>
  <pre class="cs-sheet" tabindex="0">sudo apt install bettercap                  # Kali/Debian
brew install bettercap                      # macOS
go install github.com/bettercap/bettercap@latest  # Go

# Start
sudo bettercap
sudo bettercap -iface eth0                  # Specific interface
sudo bettercap -caplet script.cap           # Run caplet</pre>
</section>

<section class="cs-section">
  <h2 class="cs-h" id="wifi-attacks">WIFI ATTACKS<a class="cs-anchor" href="#wifi-attacks">#</a></h2>
  <pre class="cs-sheet" tabindex="0">wifi.recon on                               # Scan for APs
wifi.deauth AP_BSSID                        # Deauth all clients
wifi.deauth CLIENT_MAC                      # Deauth specific client</pre>
</section>

<section class="cs-section">
  <h2 class="cs-h" id="common-attack-workflows">COMMON ATTACK WORKFLOWS<a class="cs-anchor" href="#common-attack-workflows">#</a></h2>
  <pre class="cs-sheet" tabindex="0"># 1. MITM + credential capture
net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets 10.10.10.0/24
arp.spoof on
net.sniff on

# 2. DNS spoofing + phishing
set arp.spoof.targets 10.10.10.5
arp.spoof on
set dns.spoof.domains login.company.com
set dns.spoof.address 10.10.10.100
dns.spoof on</pre>
</section>

<section class="cs-section">
  <h2 class="cs-h" id="tips">TIPS<a class="cs-anchor" href="#tips">#</a></h2>
  <pre class="cs-sheet" tabindex="0">- Use fullduplex for reliable MITM
- Caplets automate complex attack chains</pre>
</section>
"""


class TestCommentWorkflowParser(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.caplets_dir = os.path.join(self.temp_dir, "caplets")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_inline_comment_button_derivation(self):
        profile = SectionCommentWorkflowParser.parse_html(
            SAMPLE_BETTERCAP_SNIPPET,
            sheet_id="bettercap",
            title="Bettercap",
            caplets_dir=self.caplets_dir
        )
        commands = {c.switch: c for c in profile.commands}

        self.assertIn("Kali/Debian", commands)
        self.assertEqual(commands["Kali/Debian"].template, "sudo apt install bettercap")
        self.assertEqual(commands["Kali/Debian"].description, "sudo apt install bettercap")

        self.assertIn("macOS", commands)
        self.assertEqual(commands["macOS"].template, "brew install bettercap")
        self.assertEqual(commands["macOS"].description, "brew install bettercap")

    def test_active_prefix_and_first_command(self):
        profile = SectionCommentWorkflowParser.parse_html(
            SAMPLE_BETTERCAP_SNIPPET,
            sheet_id="bettercap",
            title="Bettercap",
            caplets_dir=self.caplets_dir
        )
        commands = {c.switch: c for c in profile.commands}

        # First command below '# Start' takes 'Start'
        self.assertIn("Start", commands)
        self.assertEqual(commands["Start"].template, "sudo bettercap")

        # Subsequent commands with inline comments append to prefix
        self.assertIn("Start Specific interface", commands)
        self.assertIn("Start Run caplet", commands)

    def test_workflow_caplet_generation(self):
        profile = SectionCommentWorkflowParser.parse_html(
            SAMPLE_BETTERCAP_SNIPPET,
            sheet_id="bettercap",
            title="Bettercap",
            caplets_dir=self.caplets_dir
        )
        commands = {c.switch: c for c in profile.commands}

        self.assertIn("MITM + credential capture", commands)
        self.assertEqual(
            commands["MITM + credential capture"].template,
            "sudo bettercap -caplet caplets/MITM_credential_capture.cap"
        )

        cap_file = os.path.join(self.caplets_dir, "MITM_credential_capture.cap")
        self.assertTrue(os.path.isfile(cap_file))
        with open(cap_file, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        self.assertEqual(lines, [
            "net.probe on",
            "set arp.spoof.fullduplex true",
            "set arp.spoof.targets 10.10.10.0/24",
            "arp.spoof on",
            "net.sniff on"
        ])

    def test_tips_section_filtered_from_commands(self):
        profile = SectionCommentWorkflowParser.parse_html(
            SAMPLE_BETTERCAP_SNIPPET,
            sheet_id="bettercap",
            title="Bettercap",
            caplets_dir=self.caplets_dir
        )
        cats = [c.category for c in profile.commands]
        self.assertNotIn("TIPS", cats)
        self.assertTrue(any("Use fullduplex" in n for n in profile.reference_notes))

    def test_resolve_target_variables_autofill_and_fallback(self):
        # 1. When values are supplied -> substitute
        cmd = "set arp.spoof.targets <target_ip>"
        resolved = SectionCommentWorkflowParser.resolve_target_variables(
            cmd,
            target_ip="192.168.1.100",
            original_cmd="set arp.spoof.targets 10.10.10.5"
        )
        self.assertEqual(resolved, "set arp.spoof.targets 192.168.1.100")

        # 2. When value is blank -> fall back to original text
        resolved_empty = SectionCommentWorkflowParser.resolve_target_variables(
            cmd,
            target_ip="",
            original_cmd="set arp.spoof.targets 10.10.10.5"
        )
        self.assertEqual(resolved_empty, "set arp.spoof.targets 10.10.10.5")

        # 3. MAC address auto-fill and fallback
        mac_cmd = "wifi.deauth <ap_bssid>"
        resolved_mac = SectionCommentWorkflowParser.resolve_target_variables(
            mac_cmd,
            target_mac="11:22:33:44:55:66",
            original_cmd="wifi.deauth AP_BSSID"
        )
        self.assertEqual(resolved_mac, "wifi.deauth 11:22:33:44:55:66")

        resolved_mac_fallback = SectionCommentWorkflowParser.resolve_target_variables(
            mac_cmd,
            target_mac="",
            original_cmd="wifi.deauth AP_BSSID"
        )
        self.assertEqual(resolved_mac_fallback, "wifi.deauth AP_BSSID")

        # 4. Domain auto-fill and fallback
        dom_cmd = "set dns.spoof.domains <domain_name>"
        resolved_dom = SectionCommentWorkflowParser.resolve_target_variables(
            dom_cmd,
            target_domain="mytest.internal",
            original_cmd="set dns.spoof.domains example.com"
        )
        self.assertEqual(resolved_dom, "set dns.spoof.domains mytest.internal")

        resolved_dom_fallback = SectionCommentWorkflowParser.resolve_target_variables(
            dom_cmd,
            target_domain="",
            original_cmd="set dns.spoof.domains example.com"
        )
        self.assertEqual(resolved_dom_fallback, "set dns.spoof.domains example.com")


if __name__ == "__main__":
    unittest.main()
