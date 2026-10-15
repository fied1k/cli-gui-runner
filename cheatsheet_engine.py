"""Cheat Sheet Converter & Multi-Strategy Parsing Engine.

A dedicated modular subsystem that ingests heterogeneous cheat sheet formats
(OffensiveRamen HTML, Markdown tables, TSV, key-value blocks, raw CLI notes),
normalizes parameters, detects categories, generates standalone programs,
and manages portable cheat sheet profiles.
"""

import os
import re
import json
import urllib.request
import urllib.error
from html.parser import HTMLParser
from typing import List, Dict, Tuple, Optional, Any


# -----------------------------------------------------------------------------
# Comprehensive Knowledge Base for CLI Switches & Explanations
# -----------------------------------------------------------------------------
KNOWN_SWITCH_DESCRIPTIONS: Dict[str, str] = {
    # Kismet
    "-c": "Specify capture source interface (e.g. -c wlan0 or -c hci0)",
    "--daemonize": "Run Kismet as a background daemon service without console UI",
    "--override": "Override Kismet configuration settings (e.g. --override wardrive)",
    "--gps": "Configure GPS hardware receiver (serial or network gpsd)",
    "--log-types": "Specify active logging output formats (e.g. pcapng, kismet)",
    "--log-prefix": "Define custom filename prefix for generated log files",
    "kismetdb_to_pcap": "Convert .kismet SQLite database log to standard PCAP for Wireshark",
    "kismetdb_to_wiglecsv": "Convert .kismet database log to WiGLE.net upload CSV format",
    "kismetdb_to_kml": "Export captured geolocation coordinates to Google Earth KML map",
    "kismet_cap_linux_wifi": "Remote distributed sensor capture streaming over network to Kismet server",
    # Nmap
    "-sn": "Host discovery ping scan without port scanning",
    "-pn": "Skip host discovery ping probes; treat all targets as online",
    "-ss": "TCP SYN stealth port scan (half-open, default with root)",
    "-st": "TCP connect port scan (full three-way handshake, no root needed)",
    "-su": "UDP port scan for open UDP services and ports",
    "-sa": "TCP ACK scan to map firewall rulesets and filtered ports",
    "-sw": "TCP Window scan to determine open vs filtered ports",
    "-sm": "TCP Maimon scan (FIN/ACK probes for BSD-derived systems)",
    "-sl": "List scan; simply lists targets without sending packets",
    "-ps": "TCP SYN discovery ping on specified ports",
    "-pa": "TCP ACK discovery ping on specified ports",
    "-pu": "UDP discovery ping on specified ports",
    "-pr": "ARP discovery ping on local network segment",
    "-n": "Never perform DNS reverse resolution (faster scan)",
    "-r": "Scan ports sequentially rather than randomized",
    "-p": "Scan specified port(s) or port ranges (e.g. 22,80,443)",
    "-p-": "Scan all 65,535 TCP/UDP ports",
    "-f": "Fast scan mode; scans the 100 most common ports",
    "-top-ports": "Scan the specified number of top most common ports",
    "-sv": "Probe open ports to determine service name and version info",
    "-a": "Aggressive scan (enables OS detection, version scan, script scanning, and traceroute)",
    "-o": "Detect remote operating system via TCP/IP fingerprinting",
    "-t0": "Paranoid timing (serial scan, maximum IDS evasion)",
    "-t1": "Sneaky timing (slow scan for IDS evasion)",
    "-t2": "Polite timing (slows down to consume less target bandwidth)",
    "-t3": "Normal timing (default Nmap scan speed)",
    "-t4": "Aggressive timing (faster scan on reliable networks)",
    "-t5": "Insane timing (extremely fast scan for fast networks)",
    "-sc": "Scan with default safe Nmap scripts",
    "-script": "Execute specified NSE script(s) or script categories",
    "-script=vuln": "Audit target for known vulnerabilities using NSE scripts",
    "-script=default": "Run default safe script checks",
    "-script=auth": "Run authentication and credential checks",
    "-script=discovery": "Run network discovery and directory enumeration scripts",
    "-script=safe": "Run safe non-intrusive scripts",
    "-script-args": "Pass custom arguments to NSE scripts",
    "-mtu": "Set custom MTU packet offset size to evade packet filters",
    "-d": "Cloak port scan using decoy IP addresses",
    "-s": "Spoof source IP address",
    "-g": "Use specified source port number (e.g. 53 for DNS)",
    "-proxies": "Relay connections through HTTP or SOCKS4 proxies",
    "-data-length": "Append random payload bytes to avoid IDS signatures",
    "-on": "Save scan results in normal human-readable format",
    "-ox": "Save scan results in XML format",
    "-og": "Save scan results in grepable format",
    "-oa": "Save scan results in all three major formats (Nmap, XML, Grepable)",
    "-v": "Increase verbosity level of scan output",
    "-vv": "Increase verbosity to maximum level",
    "-open": "Show only open (or possibly open) ports",
    "-reason": "Display the reason a port is in a particular state",
    "-packet-trace": "Print full summary of every packet sent and received",
    "-iflist": "Print host interface list and system routes",
    "-resume": "Resume an aborted scan from output file",
    "-6": "Enable IPv6 scanning",
    "-h": "Display Nmap help and command-line options reference",
    "-ir": "Choose random targets to scan",
    "-exclude": "Exclude specified hosts or subnets from scan",
    "-excludefile": "Exclude hosts listed in file from scan",
    "-il": "Input targets from list file",
    "-randomize-hosts": "Shuffle target host order before scanning",
    # TShark / Wireshark
    "-i": "Capture and stream live traffic from specified interface",
    "-c": "Stop capture automatically after receiving count packets",
    "-w": "Save raw captured packets directly to pcapng file",
    "-y": "Apply Wireshark display filter expression",
    # Utilities
    "ping": "Send ICMP echo request packets to target host",
    "curl": "Transfer data from or to a server using supported protocols",
    "find": "Search for files in directory hierarchy matching pattern",
    "df": "Show disk space usage of file systems",
    "traceroute": "Trace network packet hops to remote destination",
    "whois": "Lookup domain registration and ownership information",
    "ssh": "Open secure shell session on remote server",
    "xsltproc": "Transform XML file using XSLT stylesheet into HTML",
    "ndiff": "Compare two Nmap XML scan output files to detect differences",
}

KNOWN_EXECUTABLES = {
    "kismet", "kismet_cap_linux_wifi", "kismetdb_to_pcap", "kismetdb_to_wiglecsv", "kismetdb_to_kml",
    "nmap", "tshark", "wireshark", "tcpdump", "ping", "traceroute", "tracert", "curl", "wget",
    "find", "grep", "df", "whois", "dig", "nslookup", "ssh", "scp", "rsync", "netstat", "ss",
    "arp", "route", "ip", "ifconfig", "iwconfig", "airmon-ng", "airodump-ng", "aireplay-ng",
    "aircrack-ng", "hydra", "john", "hashcat", "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz",
    "sudo", "apt", "apt-get", "systemctl", "service", "gpsd", "xsltproc", "ndiff",
    "bettercap", "brew", "go", "net.probe", "net.show", "net.recon", "net.clear", "net.sniff",
    "arp.spoof", "dns.spoof", "http.proxy", "https.proxy", "wifi.recon", "wifi.show",
    "wifi.deauth", "wifi.ap", "ble.recon", "ble.show", "ble.enum", "ble.write", "api.rest", "set"
}


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
class CommandItem:
    def __init__(self, switch: str, template: str, description: str, category: str = "General", original: str = ""):
        self.switch = switch.strip()
        self.template = template.strip()
        self.description = description.strip()
        self.category = category.strip()
        self.original = (original or template).strip()

    def to_dict(self) -> Dict[str, str]:
        d = {
            "switch": self.switch,
            "template": self.template,
            "description": self.description,
            "category": self.category
        }
        if self.original:
            d["original"] = self.original
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "CommandItem":
        return cls(
            switch=data.get("switch", ""),
            template=data.get("template", ""),
            description=data.get("description", ""),
            category=data.get("category", "General"),
            original=data.get("original", "")
        )


class CheatSheetProfile:
    def __init__(self, sheet_id: str, title: str, source: str = "", default_file: str = ""):
        self.sheet_id = sheet_id
        self.title = title
        self.source = source
        self.default_file = default_file
        self.categories: List[str] = []
        self.commands: List[CommandItem] = []
        self.reference_notes: List[str] = []

    def add_command(self, item: CommandItem):
        if item.category not in self.categories:
            self.categories.append(item.category)
        self.commands.append(item)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sheet_id": self.sheet_id,
            "title": self.title,
            "source": self.source,
            "default_file": self.default_file,
            "categories": self.categories,
            "commands": [c.to_dict() for c in self.commands],
            "reference_notes": self.reference_notes
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheatSheetProfile":
        profile = cls(
            sheet_id=data.get("sheet_id", "sheet"),
            title=data.get("title", "Cheat Sheet"),
            source=data.get("source", ""),
            default_file=data.get("default_file", "")
        )
        profile.categories = data.get("categories", [])
        profile.reference_notes = data.get("reference_notes", [])
        for c in data.get("commands", []):
            profile.commands.append(CommandItem.from_dict(c))
        return profile

    def save_json(self, filepath: str):
        os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_json(cls, filepath: str) -> "CheatSheetProfile":
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def export_commands_txt(self) -> str:
        """Serializes profile to human-readable 'Switch | Template | Description' format with category headers."""
        lines = [
            f"# Profile: {self.title}",
            f"# Source: {self.source}" if self.source else "",
            "# Format: Switch / Button Name | Command Template | Description",
            ""
        ]
        curr_cat = None
        for cmd in self.commands:
            if cmd.category != curr_cat:
                curr_cat = cmd.category
                lines.append(f"\n# === {curr_cat} ===")
            lines.append(f"{cmd.switch} | {cmd.template} | {cmd.description}")

        if self.reference_notes:
            lines.append("\n# === REFERENCE & TIPS ===")
            for note in self.reference_notes:
                lines.append(f"# • {note}")

        return "\n".join(lines).strip() + "\n"


# -----------------------------------------------------------------------------
# Smart Variable Normalizer
# -----------------------------------------------------------------------------
class VariableNormalizer:
    """Detects hardcoded values and replaces them with clean <variable> placeholders."""

    @staticmethod
    def normalize(cmd: str) -> str:
        cmd = re.sub(r"^[\$>]\s+", "", cmd.strip())
        cmd = re.sub(r"\[([A-Za-z0-9_\-]+)\]", r"<\1>", cmd)

        # Shield existing placeholders
        shielded = {}
        def _shield(m):
            k = f"__SHIELD_{len(shielded)}__"
            shielded[k] = m.group(0)
            return k

        cmd = re.sub(r"[<\{][^>\}\s]+[>\}]", _shield, cmd)

        # 1. URL endpoints
        cmd = re.sub(r"https?://(?:localhost|127\.0\.0\.1|[\w.\-]+)(?::\d+)?(/[^\"'\s\\]*)?", r"http://<host>:2501\1", cmd)

        # 2. Wireless Interfaces & source strings
        cmd = re.sub(r"\b(wlan\d+mon)\b", "<monitor_interface>", cmd)
        cmd = re.sub(r"\b(wlan\d+|eth\d+|en\d+|ath\d+)\b", "<interface>", cmd)
        cmd = re.sub(r"\b(hci\d+)\b", "<hci_interface>", cmd)
        cmd = re.sub(r"\b(rtl\w+-\d+)\b", "<sdr_device>", cmd)

        # 3. Channels & Hop parameters
        cmd = re.sub(r'(channels=["\']?)[0-9, ]+(["\']?)', r'\1<channels>\2', cmd)
        cmd = re.sub(r'\bchannel=\d+\b', 'channel=<channel>', cmd)
        cmd = re.sub(r'\bhoprate=\d+\b', 'hoprate=<hops_per_sec>', cmd)
        cmd = re.sub(r'\bname=[\w\-]+', 'name=<source_name>', cmd)

        # 4. Specific File Extensions
        cmd = re.sub(r'\b[\w.\-]+\.kismet\b', '<kismet_db>', cmd)
        cmd = re.sub(r'\b[\w.\-]+\.pcapng\b', '<output_pcapng>', cmd)
        cmd = re.sub(r'\b[\w.\-]+\.pcap\b', '<output_pcap>', cmd)
        cmd = re.sub(r'\b[\w.\-]+\.kml\b', '<output_kml>', cmd)
        cmd = re.sub(r'\b[\w.\-]+\.csv\b', '<output_csv>', cmd)
        cmd = re.sub(r'\b[\w.\-]+\.xml\b', '<output_xml>', cmd)

        # 5. MAC addresses
        cmd = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', '<mac_address>', cmd)

        # 6. IPv4 Subnets and Addresses
        cmd = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b', '<subnet_cidr>', cmd)
        cmd = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b', '<target_ip>:<port>', cmd)
        cmd = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '<target_ip>', cmd)

        # 7. Ports
        cmd = re.sub(r'(\s(?:-p|--port)\s+)(?:\d+(?:[,-]\d+)*)\b', r'\1<port>', cmd)

        # 8. HTTP Methods
        cmd = re.sub(r'(\s(?:-X|--request)\s+)(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', r'\1<http_method>', cmd, flags=re.IGNORECASE)

        # 9. Domain names and wildcards
        cmd = re.sub(r'\b\*\.[a-zA-Z0-9\-.]+\b', '<domain_name>', cmd)
        def _replace_domain(m):
            val = m.group(0)
            if any(val.lower().startswith(p) for p in ("arp.", "net.", "dns.", "http.", "https.", "wifi.", "ble.", "api.")):
                return val
            return "<domain_name>"
        cmd = re.sub(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|edu|gov|mil|io|co|local|lan)\b', _replace_domain, cmd, flags=re.IGNORECASE)

        # 10. Uppercase variable names (e.g. AP_BSSID, CLIENT_MAC, TARGET_BSSID, DEVICE_MAC)
        cmd = re.sub(r'\b(AP_BSSID|TARGET_BSSID|CLIENT_MAC|DEVICE_MAC|BSSID|UUID|DATA)\b', lambda m: f"<{m.group(1).lower()}>", cmd)

        # 11. GPS hardware serial
        cmd = re.sub(r'/dev/tty(?:USB|ACM|AMA)\d+', '<gps_device_path>', cmd)
        cmd = re.sub(r'\bHOST:3501\b', '<remote_host>:3501', cmd)

        # Unshield
        for k, v in shielded.items():
            cmd = cmd.replace(k, v)

        return cmd.strip()


# -----------------------------------------------------------------------------
# Parser Strategy A: OffensiveRamen / Structured HTML Parser
# -----------------------------------------------------------------------------
class OffensiveRamenHTMLParser(HTMLParser):
    """
    Parses sectioned OffensiveRamen HTML pages.
    Extracts category headings (<h2 class="cs-h">), preformatted code blocks,
    multi-line shell commands with backslashes, inline comments, and separates
    prose/tips from runnable CLI commands.
    """
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.profile = CheatSheetProfile(sheet_id="imported_sheet", title="Cheat Sheet")
        self.current_section = "General"
        self.in_h2 = False
        self.h2_buf = []
        self.in_pre = False
        self.pre_buf = []
        self.ignore_tags = {"script", "style", "nav", "svg", "header", "footer"}
        self.ignore_depth = 0

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t in self.ignore_tags:
            self.ignore_depth += 1
            return
        if self.ignore_depth > 0:
            return

        if t in ("h1", "h2"):
            self.in_h2 = True
            self.h2_buf = []
        elif t == "pre":
            self.in_pre = True
            self.pre_buf = []

    def handle_endtag(self, tag):
        t = tag.lower()
        if t in self.ignore_tags and self.ignore_depth > 0:
            self.ignore_depth -= 1
            return
        if self.ignore_depth > 0:
            return

        if t in ("h1", "h2") and self.in_h2:
            self.in_h2 = False
            heading = " ".join("".join(self.h2_buf).split()).strip()
            heading = re.sub(r"[#\s]+$", "", heading).strip()
            if heading and not heading.lower().startswith("on this page") and heading != "KISMET":
                self.current_section = heading.title()

        elif t == "pre" and self.in_pre:
            self.in_pre = False
            raw_text = "".join(self.pre_buf)
            self._process_pre_block(raw_text, self.current_section)

    def handle_data(self, data):
        if self.ignore_depth > 0:
            return
        if self.in_h2:
            self.h2_buf.append(data)
        elif self.in_pre:
            self.pre_buf.append(data)

    def _process_pre_block(self, raw_text: str, section_name: str):
        # Join backslash continuations
        cleaned = re.sub(r"\\\s*\r?\n\s*", " ", raw_text)
        lines = cleaned.splitlines()

        pending_desc = ""
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                pending_desc = ""
                continue

            # If line is bullet point (informational, not executable)
            if re.match(r"^[-*•]\s+", line):
                note = re.sub(r"^[-*•]\s+", "", line).strip()
                if note:
                    self.profile.reference_notes.append(f"[{section_name}] {note}")
                continue

            # Descriptive comments
            if line.startswith("#"):
                comment = line.lstrip("#").strip()
                if comment and not comment.startswith("===") and not comment.startswith("http"):
                    pending_desc = comment
                continue

            # Inline trailing comment
            desc = pending_desc
            if " #" in line:
                cmd_part, inline_comment = line.split(" #", 1)
                line = cmd_part.strip()
                if not desc:
                    desc = inline_comment.strip()

            # Normalize command template
            normalized_cmd = VariableNormalizer.normalize(line)
            tokens = normalized_cmd.split()
            if not tokens:
                continue

            first_token = os.path.basename(tokens[0]).lower().lstrip("$>")
            if first_token not in KNOWN_EXECUTABLES and not first_token.startswith(("kismet", "nmap", "tshark", "curl", "sudo")):
                # Likely non-command prose text
                if len(line) < 180 and not line.startswith("<"):
                    self.profile.reference_notes.append(f"[{section_name}] {line}")
                continue

            # Extract switch / button label
            switch_label = self._extract_button_label(tokens, normalized_cmd, desc)
            if not desc:
                desc = self._find_description(switch_label, normalized_cmd)

            self.profile.add_command(CommandItem(
                switch=switch_label,
                template=normalized_cmd,
                description=desc,
                category=section_name
            ))
            pending_desc = ""

    def _extract_button_label(self, tokens: List[str], cmd: str, desc: str) -> str:
        if not tokens:
            return "Command"

        first_tool = os.path.basename(tokens[0]).lower().lstrip("$>")

        # 1. Specialized tools
        if first_tool.startswith("kismetdb_to_"):
            target_fmt = first_tool.replace("kismetdb_to_", "").upper()
            return f"DB -> {target_fmt}"

        if first_tool == "kismet_cap_linux_wifi":
            return "Remote Sensor"

        # 2. Curl API calls
        if first_tool == "curl":
            endpoint = re.search(r"http://[^/]+(/[^?\s\"']+)", cmd)
            if endpoint:
                ep_name = os.path.basename(endpoint.group(1))
                if len(ep_name) <= 15:
                    return f"API: {ep_name}"
            if desc and len(desc) <= 18:
                return f"API: {desc}"
            return "curl API"

        # 3. Sudo / Usermod / Package management
        if first_tool == "sudo" and len(tokens) > 1:
            sub = tokens[1].lower()
            if sub in ("apt", "apt-get") and len(tokens) > 2:
                return f"apt {tokens[2]}"
            if sub == "usermod":
                return "usermod +kismet"
            return f"{sub}"

        # 4. Kismet options & tuning
        if first_tool == "kismet":
            if "--override" in cmd and "wardrive" in cmd:
                return "Wardrive Mode"
            if "--daemonize" in cmd:
                return "--daemonize"
            if "--gps" in cmd:
                if "serial:" in cmd:
                    return "GPS (Serial)"
                if "gpsd:" in cmd:
                    return "GPS (gpsd)"
                return "--gps"
            if "--log-types" in cmd:
                return "--log-types"
            if "--log-prefix" in cmd:
                return "--log-prefix"
            if "-c" in cmd:
                if ":type=linuxbluetooth" in cmd:
                    return "-c (Bluetooth)"
                if ":type=rtl433" in cmd:
                    return "-c (RTL433 SDR)"
                if ":type=rtladsb" in cmd:
                    return "-c (ADS-B)"
                if ":hop=true" in cmd:
                    return "-c (Hop: ON)"
                if ":hop=false" in cmd or "channel=" in cmd:
                    ch_m = re.search(r"channel=([0-9a-zA-Z]+)", cmd)
                    return f"-c (Lock Ch:{ch_m.group(1)})" if ch_m else "-c (Lock Chan)"
                if "channels=" in cmd:
                    return "-c (Channels)"
                if "hoprate=" in cmd:
                    return "-c (Hop Rate)"
                if "band=" in cmd:
                    b_m = re.search(r"band=([0-9a-zA-Z.]+)", cmd)
                    return f"-c (Band: {b_m.group(1)})" if b_m else "-c (Band)"
                if "name=" in cmd:
                    return "-c (Named Source)"
                if desc and any(k in desc.lower() for k in ("monitor", "wifi", "multiple")):
                    return f"-c ({desc})"
                return "-c <interface>"

        # 5. Generic flags
        flags = [t for t in tokens[1:] if t.startswith("-") and len(t) <= 24]
        if flags:
            return flags[0]

        if len(tokens) >= 2 and not tokens[1].startswith("<"):
            return f"{tokens[0]} {tokens[1]}"

        return tokens[0]

    def _find_description(self, label: str, cmd: str) -> str:
        clean_lbl = label.lower().strip()
        if clean_lbl in KNOWN_SWITCH_DESCRIPTIONS:
            return KNOWN_SWITCH_DESCRIPTIONS[clean_lbl]

        for flag in re.findall(r"-[a-zA-Z0-9_\-]+", cmd):
            if flag.lower() in KNOWN_SWITCH_DESCRIPTIONS:
                return KNOWN_SWITCH_DESCRIPTIONS[flag.lower()]

        tokens = cmd.split()
        if tokens:
            base = os.path.basename(tokens[0]).lower()
            if base in KNOWN_SWITCH_DESCRIPTIONS:
                return KNOWN_SWITCH_DESCRIPTIONS[base]
            return f"Execute {tokens[0]} command with configured options"
        return "Execute command template"

    @classmethod
    def parse_html(cls, html_content: str, sheet_id: str = "sheet", title: str = "Cheat Sheet") -> CheatSheetProfile:
        parser = cls()
        parser.profile.sheet_id = sheet_id
        parser.profile.title = title
        parser.feed(html_content)
        return parser.profile

    @classmethod
    def parse_file(cls, filepath: str, sheet_id: str = "sheet", title: str = "Cheat Sheet") -> CheatSheetProfile:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return cls.parse_html(content, sheet_id=sheet_id, title=title)


# -----------------------------------------------------------------------------
# Parser Strategy A.2: Section & Comment-Driven Workflow Parser (e.g. Bettercap)
# -----------------------------------------------------------------------------
class SectionCommentWorkflowParser:
    """Parses hierarchical, comment-driven cheatsheet sections.
    
    Extracts:
    1. Category headers (e.g. INSTALLATION, NETWORK DISCOVERY, ARP SPOOFING (MITM)).
    2. Button names derived from inline comments (# Kali/Debian -> 'Kali/Debian').
    3. Active prefix tracking from standalone comments (# Start -> 'Start', 'Start Specific interface').
    4. Attack workflow bundling: Multi-line sequences under numbered comments (# 1. MITM + credential capture)
       are compiled into caplet automation files (caplets/MITM_credential_capture.cap) with runner buttons.
    5. JavaScript proxy scripts: Extracted into caplets/*.js.
    """

    @staticmethod
    def sanitize_filename(name: str) -> str:
        clean = re.sub(r"^\d+\.\s*", "", name.strip())
        clean = re.sub(r"[^\w\s\-]", "", clean)
        clean = re.sub(r"[\s\-]+", "_", clean)
        return clean.strip("_")

    @classmethod
    def parse_html(
        cls,
        html_content: str,
        sheet_id: str = "bettercap",
        title: str = "Bettercap",
        caplets_dir: str = "caplets"
    ) -> CheatSheetProfile:
        import html as html_lib

        profile = CheatSheetProfile(
            sheet_id=sheet_id,
            title=title,
            source="OffensiveRamen",
            default_file=f"{sheet_id}.txt"
        )
        os.makedirs(caplets_dir, exist_ok=True)

        sections = re.findall(
            r'<section[^>]*class="[^"]*cs-section[^"]*"[^>]*>\s*<h2[^>]*>(.*?)</h2>\s*<pre[^>]*>(.*?)</pre>',
            html_content,
            re.DOTALL
        )
        if not sections:
            sections = re.findall(
                r'<h2[^>]*>(.*?)</h2>\s*(?:<div[^>]*>)?\s*<pre[^>]*>(.*?)</pre>',
                html_content,
                re.DOTALL
            )

        for h_raw, c_raw in sections:
            clean_h = re.sub(r'<[^>]+>', '', h_raw).replace('#', '').strip()
            c = html_lib.unescape(c_raw).strip()

            if not clean_h or clean_h.upper().startswith(("TIPS", "ON THIS PAGE", "MENU", "TOOLS", "SISTER SITE")):
                if clean_h.upper().startswith("TIPS"):
                    for l in c.splitlines():
                        note = l.strip().lstrip("-*• ").strip()
                        if note:
                            profile.reference_notes.append(f"[TIPS] {note}")
                continue

            # Case 1: Multi-line attack workflows -> Generate .cap scripts
            if "WORKFLOW" in clean_h.upper():
                blocks = re.split(r'(?m)^(?=#\s*\d+\.)', c)
                for block in blocks:
                    block = block.strip()
                    if not block:
                        continue
                    lines = block.splitlines()
                    title_line = lines[0].lstrip("#").strip()
                    cmd_lines = [l.strip() for l in lines[1:] if l.strip() and not l.strip().startswith("#")]
                    if not cmd_lines:
                        continue

                    cap_filename = cls.sanitize_filename(title_line) + ".cap"
                    cap_path = os.path.join(caplets_dir, cap_filename)
                    with open(cap_path, "w", encoding="utf-8") as f:
                        f.write("\n".join(cmd_lines) + "\n")

                    btn_name = re.sub(r"^\d+\.\s*", "", title_line).strip()
                    cap_rel_path = f"caplets/{cap_filename}".replace("\\", "/")
                    runner_cmd = f"sudo {sheet_id} -caplet {cap_rel_path}"
                    profile.add_command(CommandItem(
                        switch=btn_name,
                        template=runner_cmd,
                        description=runner_cmd,
                        category=clean_h,
                        original=runner_cmd
                    ))
                continue

            # Case 2: JavaScript proxy scripts -> Generate .js files
            if "PROXY SCRIPTS" in clean_h.upper() or "JAVASCRIPT" in clean_h.upper():
                js_blocks = re.split(r'(?m)^(?=//)', c)
                for block in js_blocks:
                    block = block.strip()
                    if not block:
                        continue
                    lines = block.splitlines()
                    title_line = lines[0].lstrip("/").strip()
                    js_code = "\n".join(lines[1:])
                    js_filename = cls.sanitize_filename(title_line) + ".js"
                    js_path = os.path.join(caplets_dir, js_filename)
                    with open(js_path, "w", encoding="utf-8") as f:
                        f.write(js_code.strip() + "\n")

                    js_rel_path = f"caplets/{js_filename}".replace("\\", "/")
                    runner_cmd = f"set http.proxy.script {js_rel_path}"
                    profile.add_command(CommandItem(
                        switch=title_line,
                        template=runner_cmd,
                        description=runner_cmd,
                        category=clean_h,
                        original=runner_cmd
                    ))
                continue

            # Case 3: Regular command & switch sections
            lines = c.splitlines()
            active_prefix = None
            first_after_prefix = False

            for raw_line in lines:
                line = raw_line.strip()
                if not line:
                    continue

                # Header comment lines
                if line.startswith("#"):
                    comment = line.lstrip("#").strip()
                    if comment and not comment.startswith("==="):
                        # Detect if informational comment like '# Captures credentials from:'
                        if comment.endswith(":") or "captures credentials from" in comment.lower():
                            profile.reference_notes.append(f"[{clean_h}] {comment}")
                            active_prefix = None
                        else:
                            active_prefix = comment
                            first_after_prefix = True
                    continue

                # Command line
                if " #" in line:
                    cmd_part, inline_comment = line.split(" #", 1)
                    cmd_str = cmd_part.strip()
                    inline_desc = inline_comment.strip()
                    if active_prefix:
                        btn_name = f"{active_prefix} {inline_desc}"
                        first_after_prefix = False
                    else:
                        btn_name = inline_desc
                    desc = cmd_str
                else:
                    cmd_str = line
                    if active_prefix and first_after_prefix:
                        btn_name = active_prefix
                        first_after_prefix = False
                    else:
                        btn_name = cmd_str
                    desc = cmd_str

                normalized_cmd = VariableNormalizer.normalize(cmd_str)
                profile.add_command(CommandItem(
                    switch=btn_name,
                    template=normalized_cmd,
                    description=desc,
                    category=clean_h,
                    original=cmd_str
                ))

        return profile

    @staticmethod
    def resolve_target_variables(
        cmd: str,
        target_ip: str = "",
        target_domain: str = "",
        target_mac: str = "",
        target_iface: str = "",
        original_cmd: str = ""
    ) -> str:
        """Substitutes user-supplied target variables, falling back to original defaults when empty."""
        result = cmd

        # 1. Target IP / Host / Subnet
        if target_ip:
            result = re.sub(r"<target_ip>|<victim_ip>|<redirect_ip>|<target>|<ip>|<target_host>", target_ip, result)
            if "/" in target_ip:
                result = re.sub(r"<target_subnet>|<subnet_cidr>", target_ip, result)
        elif original_cmd:
            # Fallback to original text for IP if available
            orig_ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b", original_cmd)
            if orig_ip_match and orig_ip_match.group(0) != "0.0.0.0":
                result = re.sub(r"<target_ip>|<victim_ip>|<redirect_ip>|<target>|<target_subnet>|<subnet_cidr>", orig_ip_match.group(0), result)

        # 2. Target Domain / Website
        if target_domain:
            result = re.sub(r"<domain_name>|<target_domain>|<domain>|<website>|<url>", target_domain, result)
        elif original_cmd:
            orig_dom_match = re.search(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|edu|gov|io|co|local)\b", original_cmd)
            if orig_dom_match:
                result = re.sub(r"<domain_name>|<target_domain>|<domain>|<website>|<url>", orig_dom_match.group(0), result)

        # 3. AP_BSSID / MAC
        if target_mac:
            result = re.sub(r"<ap_bssid>|<target_bssid>|<client_mac>|<device_mac>|<mac_address>|<bssid>|<mac>", target_mac, result)
        elif original_cmd:
            orig_mac_match = re.search(r"\b(AP_BSSID|TARGET_BSSID|CLIENT_MAC|DEVICE_MAC)\b", original_cmd)
            if orig_mac_match:
                result = re.sub(r"<ap_bssid>|<target_bssid>|<client_mac>|<device_mac>|<mac_address>", orig_mac_match.group(0), result)

        # 4. Interface
        if target_iface:
            result = re.sub(r"<interface>|<iface>|<monitor_interface>", target_iface, result)
        elif original_cmd:
            orig_iface_match = re.search(r"\b(eth\d+|wlan\d+mon|wlan\d+)\b", original_cmd)
            if orig_iface_match:
                result = re.sub(r"<interface>|<iface>|<monitor_interface>", orig_iface_match.group(0), result)

        return result


# -----------------------------------------------------------------------------
# Parser Strategy B: Tabular & Delimited Column Mapper with Learned Mappings
# -----------------------------------------------------------------------------
ROLE_SWITCH = "switch"
ROLE_TEMPLATE = "template"
ROLE_DESC = "desc"
ROLE_CATEGORY = "category"
ROLE_IGNORE = "ignore"

FIELD_ROLE_LABELS: Dict[str, str] = {
    ROLE_SWITCH: "Switch (Button Text)",
    ROLE_TEMPLATE: "Example (Command Template)",
    ROLE_DESC: "Description",
    ROLE_CATEGORY: "Category",
    ROLE_IGNORE: "Ignore / Skip"
}

ROLE_CHOICES: List[Tuple[str, str]] = [
    (ROLE_SWITCH, "Switch (Button Text)"),
    (ROLE_TEMPLATE, "Example (Command Template)"),
    (ROLE_DESC, "Description"),
    (ROLE_CATEGORY, "Category"),
    (ROLE_IGNORE, "Ignore / Skip")
]


class LearnedMappingRule:
    """Represents a persistent learned or preset column-to-field mapping rule."""
    def __init__(
        self,
        name: str,
        mapping: Dict[str, int],
        col_count: int = 3,
        headers: Optional[List[str]] = None,
        delimiter: Optional[str] = None,
        description: str = "",
        signature: Optional[Dict[str, Any]] = None,
        is_builtin: bool = False,
        use_count: int = 0
    ):
        self.name = name
        self.mapping = dict(mapping)
        self.col_count = col_count
        self.headers = [h.lower().strip() for h in (headers or []) if h.strip()]
        self.delimiter = delimiter
        self.description = description
        self.signature = signature or {}
        self.is_builtin = is_builtin
        self.use_count = use_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "mapping": self.mapping,
            "col_count": self.col_count,
            "headers": self.headers,
            "delimiter": self.delimiter,
            "description": self.description,
            "signature": self.signature,
            "is_builtin": self.is_builtin,
            "use_count": self.use_count
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LearnedMappingRule":
        return cls(
            name=data.get("name", "Custom Rule"),
            mapping=data.get("mapping", {"switch": 0, "template": 1, "desc": 2, "category": -1}),
            col_count=data.get("col_count", 3),
            headers=data.get("headers", []),
            delimiter=data.get("delimiter", None),
            description=data.get("description", ""),
            signature=data.get("signature", {}),
            is_builtin=data.get("is_builtin", False),
            use_count=data.get("use_count", 0)
        )


class TabularParseResult:
    """Wrapper that can unpack as (items, confidence) for backwards compatibility while providing rich metadata."""
    def __init__(
        self,
        items: List[CommandItem],
        confidence: float,
        rule_name: str = "Standard (Switch | Example | Description)",
        raw_rows: Optional[List[List[str]]] = None,
        headers: Optional[List[str]] = None,
        mapping: Optional[Dict[str, int]] = None
    ):
        self.items = items
        self.confidence = confidence
        self.rule_name = rule_name
        self.raw_rows = raw_rows or []
        self.headers = headers or []
        self.mapping = mapping or {"switch": 0, "template": 1, "desc": 2, "category": -1}

    def __iter__(self):
        return iter((self.items, self.confidence))

    def __getitem__(self, index):
        return (self.items, self.confidence)[index]


class LearnedMappingRegistry:
    """
    Manages persistent learned field-mapping rules.
    Remembers user-defined mappings and automatically matches them against new inputs.
    """
    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath or os.path.join(os.path.dirname(__file__), "profiles", "learned_mappings.json")
        self.rules: Dict[str, LearnedMappingRule] = {}
        self.header_keywords: Dict[str, List[str]] = {
            ROLE_SWITCH: ["switch", "flag", "option", "button", "name", "param", "parameter", "arg", "sw"],
            ROLE_TEMPLATE: ["example", "command", "syntax", "template", "usage", "exec", "code", "run", "cmd"],
            ROLE_DESC: ["desc", "description", "detail", "details", "explanation", "info", "meaning", "purpose", "notes", "summary"],
            ROLE_CATEGORY: ["cat", "category", "section", "group", "type", "topic"]
        }
        self.load()

    def _init_defaults(self):
        defaults = [
            LearnedMappingRule(
                name="Standard (Switch | Example | Description)",
                mapping={"switch": 0, "template": 1, "desc": 2, "category": -1},
                col_count=3,
                headers=["switch", "example", "description"],
                description="Column 0: Switch/Button, Column 1: Command Template, Column 2: Description",
                signature={"roles": ["switch", "template", "desc"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Inverted (Example | Switch | Description)",
                mapping={"switch": 1, "template": 0, "desc": 2, "category": -1},
                col_count=3,
                headers=["example", "switch", "description"],
                description="Column 0: Command Template, Column 1: Switch/Button, Column 2: Description",
                signature={"roles": ["template", "switch", "desc"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Doc Style (Description | Example | Switch)",
                mapping={"switch": 2, "template": 1, "desc": 0, "category": -1},
                col_count=3,
                headers=["description", "example", "switch"],
                description="Column 0: Description, Column 1: Command Template, Column 2: Switch",
                signature={"roles": ["desc", "template", "switch"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Action Table (Description | Switch | Example)",
                mapping={"switch": 1, "template": 2, "desc": 0, "category": -1},
                col_count=3,
                headers=["description", "switch", "example"],
                description="Column 0: Description, Column 1: Switch, Column 2: Command Template",
                signature={"roles": ["desc", "switch", "template"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Categorized (Category | Switch | Example | Description)",
                mapping={"category": 0, "switch": 1, "template": 2, "desc": 3},
                col_count=4,
                headers=["category", "switch", "example", "description"],
                description="Column 0: Category, Column 1: Switch, Column 2: Command, Column 3: Description",
                signature={"roles": ["category", "switch", "template", "desc"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Two-Column (Example | Description)",
                mapping={"switch": -1, "template": 0, "desc": 1, "category": -1},
                col_count=2,
                headers=["example", "description"],
                description="Column 0: Command Template, Column 1: Description (Switch auto-generated)",
                signature={"roles": ["template", "desc"]},
                is_builtin=True
            ),
            LearnedMappingRule(
                name="Two-Column (Switch | Example)",
                mapping={"switch": 0, "template": 1, "desc": -1, "category": -1},
                col_count=2,
                headers=["switch", "example"],
                description="Column 0: Switch, Column 1: Command Template (Description auto-generated)",
                signature={"roles": ["switch", "template"]},
                is_builtin=True
            )
        ]
        for d in defaults:
            self.rules[d.name] = d

    def _ensure_builtins(self):
        defaults_registry = LearnedMappingRegistry.__new__(LearnedMappingRegistry)
        defaults_registry.rules = {}
        defaults_registry._init_defaults()
        for k, v in defaults_registry.rules.items():
            if k not in self.rules:
                self.rules[k] = v

    def load(self):
        if not os.path.exists(self.filepath):
            self._init_defaults()
            self.save()
            return

        try:
            with open(self.filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.rules = {}
            for item in data.get("rules", []):
                r = LearnedMappingRule.from_dict(item)
                self.rules[r.name] = r
            if "header_keywords" in data:
                for k, v in data["header_keywords"].items():
                    if k in self.header_keywords:
                        self.header_keywords[k] = list(dict.fromkeys(self.header_keywords[k] + v))
            self._ensure_builtins()
        except Exception as e:
            print(f"[LearnedMappingRegistry] Error loading {self.filepath}: {e}")
            self._init_defaults()

    def save(self):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.filepath)), exist_ok=True)
            payload = {
                "rules": [r.to_dict() for r in self.rules.values()],
                "header_keywords": self.header_keywords
            }
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[LearnedMappingRegistry] Error saving {self.filepath}: {e}")

    @staticmethod
    def classify_column(values: List[str]) -> str:
        """Classifies a list of column values into an inferred role: template, switch, desc, or category."""
        clean_vals = [v.strip() for v in values if v.strip()]
        if not clean_vals:
            return ROLE_DESC

        total = len(clean_vals)
        flag_cnt = 0
        cmd_cnt = 0
        prose_cnt = 0

        for val in clean_vals:
            # 1. Flag check
            if val.startswith(("-", "--", "/")) or (len(val) <= 15 and " " not in val and re.match(r"^[A-Za-z0-9_\-]+$", val)):
                flag_cnt += 1

            # 2. Command check
            tokens = val.split()
            first_tok = os.path.basename(tokens[0]).lower().lstrip("$>") if tokens else ""
            if (
                first_tok in KNOWN_EXECUTABLES
                or val.startswith(("$", ">"))
                or re.search(r"\b-[a-zA-Z0-9_\-]+", val)
                or re.search(r"[<\{][^>\}\s]+[>\}]", val)
            ):
                cmd_cnt += 1

            # 3. Prose check
            if len(val) >= 28 or len(tokens) >= 4 or any(w in val.lower() for w in ("the", "to", "for", "scan", "detect", "displays", "shows")):
                prose_cnt += 1

        if cmd_cnt / total >= 0.45:
            return ROLE_TEMPLATE
        if flag_cnt / total >= 0.45:
            return ROLE_SWITCH
        if prose_cnt / total >= 0.40:
            return ROLE_DESC

        return ROLE_DESC

    def learn_rule(
        self,
        name: str,
        mapping: Dict[str, int],
        headers: Optional[List[str]] = None,
        sample_rows: Optional[List[List[str]]] = None,
        col_count: Optional[int] = None,
        delimiter: Optional[str] = None,
        description: str = ""
    ) -> LearnedMappingRule:
        """Registers a newly learned field-mapping rule and updates keyword dictionaries."""
        if not col_count:
            valid_indices = [idx for idx in mapping.values() if idx >= 0]
            col_count = max(valid_indices) + 1 if valid_indices else 3

        # Learn header keywords
        if headers:
            for role, idx in mapping.items():
                if 0 <= idx < len(headers):
                    hdr = headers[idx].lower().strip()
                    if hdr and hdr not in self.header_keywords.get(role, []):
                        self.header_keywords.setdefault(role, []).append(hdr)

        # Build signature from sample rows
        signature: Dict[str, Any] = {}
        if sample_rows:
            inferred_roles = []
            for col_idx in range(col_count):
                col_vals = [row[col_idx] for row in sample_rows if col_idx < len(row)]
                inferred_roles.append(self.classify_column(col_vals))
            signature["roles"] = inferred_roles

        rule = LearnedMappingRule(
            name=name,
            mapping=mapping,
            col_count=col_count,
            headers=headers or [],
            delimiter=delimiter,
            description=description or f"Learned mapping for {col_count} columns",
            signature=signature,
            is_builtin=False
        )
        self.rules[name] = rule
        self.save()
        return rule

    def match_rule(
        self,
        headers: Optional[List[str]] = None,
        sample_rows: Optional[List[List[str]]] = None,
        col_count: Optional[int] = None,
        delimiter: Optional[str] = None
    ) -> Tuple[Optional[LearnedMappingRule], float]:
        """Matches input against learned rules and returns (best_rule, confidence)."""
        # 1. Exact or keyword header matching
        if headers and len(headers) >= 2:
            norm_hdrs = [h.lower().strip() for h in headers if h.strip()]
            for rule in self.rules.values():
                if rule.headers and len(rule.headers) == len(norm_hdrs):
                    if all(rh in nh or nh in rh for rh, nh in zip(rule.headers, norm_hdrs)):
                        return rule, 0.98

            best_kw_rule = None
            best_kw_score = 0
            for rule in self.rules.values():
                if rule.col_count == len(norm_hdrs):
                    score = 0
                    for role, idx in rule.mapping.items():
                        if 0 <= idx < len(norm_hdrs):
                            hdr = norm_hdrs[idx]
                            if any(kw in hdr for kw in self.header_keywords.get(role, [])):
                                score += 1
                    if score > best_kw_score:
                        best_kw_score = score
                        best_kw_rule = rule

            if best_kw_rule and best_kw_score >= 2:
                return best_kw_rule, 0.95

        # 2. Structural signature matching from sample rows
        if sample_rows and col_count:
            inferred_roles = []
            for col_idx in range(col_count):
                vals = [r[col_idx] for r in sample_rows if col_idx < len(r)]
                inferred_roles.append(self.classify_column(vals))

            best_sig_rule = None
            best_sig_score = 0
            for rule in self.rules.values():
                if rule.col_count == col_count and "roles" in rule.signature:
                    match_count = sum(1 for a, b in zip(rule.signature["roles"], inferred_roles) if a == b)
                    if match_count > best_sig_score:
                        best_sig_score = match_count
                        best_sig_rule = rule

            if best_sig_rule and best_sig_score >= min(col_count, 2):
                return best_sig_rule, 0.90

            for rule in self.rules.values():
                if rule.col_count == col_count:
                    match_count = 0
                    for role, idx in rule.mapping.items():
                        if 0 <= idx < len(inferred_roles) and inferred_roles[idx] == role:
                            match_count += 1
                    if match_count >= 2:
                        return rule, 0.88

        return None, 0.50

    def apply_mapping_to_parts(
        self,
        parts: List[str],
        mapping: Dict[str, int],
        default_category: str = "General"
    ) -> CommandItem:
        """Applies a column mapping dictionary to split tokens and returns a CommandItem."""
        sw_idx = mapping.get(ROLE_SWITCH, -1)
        tm_idx = mapping.get(ROLE_TEMPLATE, -1)
        ds_idx = mapping.get(ROLE_DESC, -1)
        ct_idx = mapping.get(ROLE_CATEGORY, -1)

        sw = parts[sw_idx].strip() if (0 <= sw_idx < len(parts)) else ""
        tm = parts[tm_idx].strip() if (0 <= tm_idx < len(parts)) else ""
        ds = parts[ds_idx].strip() if (0 <= ds_idx < len(parts)) else ""
        ct = parts[ct_idx].strip() if (0 <= ct_idx < len(parts)) else default_category

        norm_tm = VariableNormalizer.normalize(tm) if tm else ""
        if not sw:
            sw = TabularColumnMapper._default_switch(norm_tm, ds)
        if not ds:
            ds = TabularColumnMapper._default_desc(sw, norm_tm)

        return CommandItem(switch=sw, template=norm_tm, description=ds, category=ct or default_category)


_GLOBAL_REGISTRY: Optional[LearnedMappingRegistry] = None


def get_mapping_registry(filepath: Optional[str] = None) -> LearnedMappingRegistry:
    """Returns the singleton LearnedMappingRegistry instance."""
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None or filepath is not None:
        _GLOBAL_REGISTRY = LearnedMappingRegistry(filepath)
    return _GLOBAL_REGISTRY


class TabularColumnMapper:
    """
    Parses table data with flexible column orders.
    Employs persistent learned mappings, header recognition, and structural heuristics.
    """
    @staticmethod
    def parse_rows(
        rows: List[str],
        default_category: str = "General",
        rule_name: Optional[str] = None,
        explicit_mapping: Optional[Dict[str, int]] = None
    ) -> TabularParseResult:
        entries: List[CommandItem] = []
        if not rows:
            return TabularParseResult(entries, 1.0, "Empty")

        registry = get_mapping_registry()

        # Clean rows and identify headers
        detected_headers: List[str] = []
        data_rows: List[str] = []
        parsed_row_cells: List[List[str]] = []

        first_non_empty = None
        for r in rows:
            clean_r = r.strip()
            if not clean_r or clean_r.startswith("#"):
                continue
            if all(c in "-|: \t" for c in clean_r):
                continue
            if first_non_empty is None:
                first_non_empty = clean_r
            else:
                data_rows.append(clean_r)

        if not first_non_empty:
            return TabularParseResult(entries, 1.0, "Empty")

        # Determine delimiter
        delim = "\t" if "\t" in first_non_empty else ("|" if "|" in first_non_empty else ("," if "," in first_non_empty else None))

        def split_row(r_str: str) -> List[str]:
            if delim:
                parts = [p.strip() for p in r_str.split(delim)]
            else:
                parts = re.split(r"\s{2,}|\t+", r_str)
            if parts and not parts[0]:
                parts.pop(0)
            if parts and not parts[-1]:
                parts.pop(-1)
            return parts

        first_parts = split_row(first_non_empty)

        # Check if first row is a header
        header_terms = {"switch", "flag", "option", "example", "command", "syntax", "desc", "description", "category", "action", "usage", "meaning", "param", "details"}
        is_header = any(any(t in p.lower() for t in header_terms) for p in first_parts)

        if is_header:
            detected_headers = first_parts
        else:
            data_rows.insert(0, first_non_empty)

        # Parse all data rows into token lists
        for dr in data_rows:
            cells = split_row(dr)
            if len(cells) >= 2:
                parsed_row_cells.append(cells)

        col_count = len(parsed_row_cells[0]) if parsed_row_cells else (len(detected_headers) if detected_headers else 3)

        # Resolve mapping rule
        active_mapping: Optional[Dict[str, int]] = None
        applied_rule_name = "Heuristic Auto-Detect"
        confidence = 0.85

        if explicit_mapping:
            active_mapping = explicit_mapping
            applied_rule_name = rule_name or "Custom Mapping"
            confidence = 1.0
        elif rule_name and rule_name in registry.rules:
            rule = registry.rules[rule_name]
            active_mapping = rule.mapping
            applied_rule_name = rule.name
            confidence = 0.96
        else:
            # Check learned mappings
            matched_rule, match_conf = registry.match_rule(
                headers=detected_headers if detected_headers else None,
                sample_rows=parsed_row_cells[:12],
                col_count=col_count,
                delimiter=delim
            )
            if matched_rule:
                active_mapping = matched_rule.mapping
                applied_rule_name = matched_rule.name
                confidence = match_conf

        if active_mapping:
            for cells in parsed_row_cells:
                item = registry.apply_mapping_to_parts(cells, active_mapping, default_category=default_category)
                entries.append(item)
        else:
            # Fallback to heuristic assignment
            for cells in parsed_row_cells:
                sw, ex, dsc = TabularColumnMapper._heuristic_assign(cells)
                if not dsc:
                    dsc = TabularColumnMapper._default_desc(sw, ex)
                entries.append(CommandItem(switch=sw, template=ex, description=dsc, category=default_category))
            applied_rule_name = "Heuristic Auto-Detect"
            confidence = 0.90 if detected_headers else 0.80

        return TabularParseResult(
            items=entries,
            confidence=confidence,
            rule_name=applied_rule_name,
            raw_rows=parsed_row_cells,
            headers=detected_headers,
            mapping=active_mapping or {"switch": 0, "template": 1, "desc": 2, "category": -1}
        )

    @staticmethod
    def _heuristic_assign(parts: List[str]) -> Tuple[str, str, str]:
        if len(parts) == 2:
            p0, p1 = parts[0], parts[1]
            if p0.startswith(("-", "--", "/")):
                return p0, VariableNormalizer.normalize(p1), ""
            elif p1.startswith(("-", "--", "/")):
                return p1, VariableNormalizer.normalize(p0), ""
            else:
                return p0, VariableNormalizer.normalize(p1), ""

        p0, p1, p2 = parts[0], parts[1], parts[2]
        is_p0_switch = p0.startswith(("-", "--", "/")) or len(p0) <= 20
        is_p1_cmd = any(p1.lower().startswith(exe) for exe in KNOWN_EXECUTABLES) or p1.startswith(("$", ">"))
        is_p0_cmd = any(p0.lower().startswith(exe) for exe in KNOWN_EXECUTABLES) or p0.startswith(("$", ">"))
        is_p1_switch = p1.startswith(("-", "--", "/"))

        if is_p0_cmd and is_p1_switch:
            return p1, VariableNormalizer.normalize(p0), p2
        elif is_p0_switch and is_p1_cmd:
            return p0, VariableNormalizer.normalize(p1), p2
        else:
            return p0, VariableNormalizer.normalize(p1), p2

    @staticmethod
    def _default_switch(cmd: str, desc: str = "") -> str:
        tokens = cmd.split()
        if not tokens:
            return "Command"
        flags = [t for t in tokens[1:] if t.startswith("-") and len(t) <= 18]
        if flags:
            return " ".join(flags[:2])
        base = os.path.basename(tokens[0])
        if len(tokens) > 1 and not tokens[1].startswith(("<", "{", "[")):
            return f"{base} {tokens[1]}"
        if desc and len(desc) <= 18:
            return desc
        return base

    @staticmethod
    def _default_desc(switch: str, example: str) -> str:
        clean = switch.lower().strip()
        if clean in KNOWN_SWITCH_DESCRIPTIONS:
            return KNOWN_SWITCH_DESCRIPTIONS[clean]
        for f in re.findall(r"-[a-zA-Z0-9_\-]+", example):
            if f.lower() in KNOWN_SWITCH_DESCRIPTIONS:
                return KNOWN_SWITCH_DESCRIPTIONS[f.lower()]
        return f"Run {switch} command"


# -----------------------------------------------------------------------------
# Parser Strategy C: Key-Value Block Parser
# -----------------------------------------------------------------------------
class KeyValueBlockParser:
    """Parses explicit Switch: ... Example: ... Description: ... blocks or lines."""
    @staticmethod
    def parse(text: str, default_category: str = "General") -> List[CommandItem]:
        entries: List[CommandItem] = []
        # Single-line format
        for line in text.splitlines():
            line = line.strip()
            match = re.search(
                r"(?:^|[\s|;,])switch\s*[:=]\s*(?P<sw>[^|;\n\r]+?)"
                r"[\s|;,]+example\s*[:=]\s*(?P<ex>[^|;\n\r]+?)"
                r"(?:[\s|;,]+description\s*[:=]\s*(?P<desc>[^|;\n\r]+))?$",
                line,
                re.IGNORECASE
            )
            if match:
                sw = match.group("sw").strip()
                ex = VariableNormalizer.normalize(match.group("ex").strip())
                desc = match.group("desc").strip() if match.group("desc") else ""
                if not desc:
                    desc = TabularColumnMapper._default_desc(sw, ex)
                entries.append(CommandItem(switch=sw, template=ex, description=desc, category=default_category))

        return entries


# -----------------------------------------------------------------------------
# Standalone Program Code Generator
# -----------------------------------------------------------------------------
class StandaloneGenerator:
    """Generates a standalone, self-contained single-file Tkinter application for a profile."""
    @staticmethod
    def generate_python_code(profile: CheatSheetProfile) -> str:
        data_json = json.dumps(profile.to_dict(), indent=2)
        template = r'''#!/usr/bin/env python3
"""
Standalone Runner for __PROFILE_TITLE__
Generated by CLI GUI Runner Engine. Zero external dependencies required.
"""

import os
import re
import json
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

PROFILE_DATA = __PROFILE_DATA_JSON__

class StandaloneRunnerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("__PROFILE_TITLE__ — Quick GUI Runner")
        self.root.geometry("980x660")
        self.current_process = None
        self._build_ui()

    def _build_ui(self):
        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="__PROFILE_TITLE__", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(toolbar, text="Stop Command", command=self.stop_process, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT)

        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook, weight=3)

        categories = PROFILE_DATA.get("categories", ["Commands"])
        all_commands = PROFILE_DATA.get("commands", [])

        for cat_name in categories:
            cat_frame = ttk.Frame(self.notebook, padding=6)
            self.notebook.add(cat_frame, text=cat_name)

            canvas = tk.Canvas(cat_frame, highlightthickness=0)
            scrollbar = ttk.Scrollbar(cat_frame, orient="vertical", command=canvas.yview)
            card_grid = ttk.Frame(canvas)

            card_grid.bind("<Configure>", lambda e, c=canvas: c.configure(scrollregion=c.bbox("all")))
            canvas.create_window((0, 0), window=card_grid, anchor="nw")
            canvas.configure(yscrollcommand=scrollbar.set)

            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

            cat_cmds = [c for c in all_commands if c.get("category", "") == cat_name]
            row, col = 0, 0
            for cmd_info in cat_cmds:
                card = ttk.Frame(card_grid, padding=6, relief="groove")
                card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

                btn = ttk.Button(
                    card, text=cmd_info.get("switch", "Run"),
                    command=lambda ci=cmd_info: self.on_command_click(ci)
                )
                btn.pack(fill=tk.X, pady=(0, 2))

                desc_lbl = ttk.Label(card, text=cmd_info.get("description", ""), font=("Segoe UI", 8), foreground="#555555", wraplength=260)
                desc_lbl.pack(anchor="w")

                col += 1
                if col >= 3:
                    col = 0
                    row += 1

            for c in range(3):
                card_grid.columnconfigure(c, weight=1)

        term_container = ttk.LabelFrame(paned, text="Live Output", padding=5)
        paned.add(term_container, weight=2)
        self.output_area = ScrolledText(term_container, bg="#1e1e1e", fg="#d4d4d4", font=("Consolas", 10), height=10)
        self.output_area.pack(fill=tk.BOTH, expand=True)

    def on_command_click(self, cmd_info):
        template = cmd_info.get("template", "")
        variables = list(dict.fromkeys(re.findall(r"[<{]([^>}\s]+)[>}]", template)))
        if not variables:
            if messagebox.askyesno("Execute", f"Run command?\n\n{template}"):
                self.execute(template)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Configure: {cmd_info.get('switch', 'Command')}")
        dialog.geometry("520x360")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text=template, font=("Consolas", 9), foreground="#005fb8", wraplength=480).pack(padx=10, pady=8)
        form = ttk.Frame(dialog, padding=10)
        form.pack(fill=tk.BOTH, expand=True)

        entries = {}
        for idx, var in enumerate(variables):
            ttk.Label(form, text=f"{var.replace('_', ' ')}:").grid(row=idx, column=0, sticky="w", pady=4, padx=(0, 8))
            entry = ttk.Entry(form, width=32)
            entry.grid(row=idx, column=1, sticky="ew", pady=4)
            entries[var] = entry

            if any(k in var.lower() for k in ("file", "db", "pcap", "kml", "csv", "path")):
                def make_browse(ent=entry, v=var):
                    return lambda: ent.delete(0, tk.END) or ent.insert(0, filedialog.askopenfilename() or "")
                ttk.Button(form, text="Browse...", width=9, command=make_browse(entry, var)).grid(row=idx, column=2, padx=4)

        form.columnconfigure(1, weight=1)

        def submit():
            final_cmd = template
            for v, ent in entries.items():
                val = ent.get().strip()
                if not val:
                    messagebox.showwarning("Input Needed", f"Please provide {v}", parent=dialog)
                    return
                final_cmd = final_cmd.replace(f"<{v}>", val).replace(f"{{{v}}}", val).replace(f"[{v}]", val)
            dialog.destroy()
            self.execute(final_cmd)

        btn_bar = ttk.Frame(dialog, padding=8)
        btn_bar.pack(fill=tk.X)
        ttk.Button(btn_bar, text="Run Command", command=submit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

    def log(self, text):
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)

    def execute(self, cmd):
        if self.current_process and self.current_process.poll() is None:
            messagebox.showwarning("Busy", "A command is already running.")
            return

        self.output_area.delete("1.0", tk.END)
        self.log(f"$ {cmd}\n" + "-" * 60 + "\n")
        self.stop_btn.config(state=tk.NORMAL)

        def target():
            try:
                self.current_process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                for line in self.current_process.stdout:
                    self.root.after(0, self.log, line)
                rc = self.current_process.wait()
                self.root.after(0, self.log, f"\n[Process exited with code {rc}]\n")
            except Exception as e:
                self.root.after(0, self.log, f"\n[Error]: {e}\n")
            finally:
                self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))

        threading.Thread(target=target, daemon=True).start()

    def stop_process(self):
        if self.current_process and self.current_process.poll() is None:
            self.current_process.terminate()
            self.log("\n[Terminated by user]\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = StandaloneRunnerApp(root)
    root.mainloop()
'''
        return template.replace("__PROFILE_TITLE__", profile.title).replace("__PROFILE_DATA_JSON__", data_json)
