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
    "sudo", "apt", "apt-get", "systemctl", "service", "gpsd", "xsltproc", "ndiff"
}


# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------
class CommandItem:
    def __init__(self, switch: str, template: str, description: str, category: str = "General"):
        self.switch = switch.strip()
        self.template = template.strip()
        self.description = description.strip()
        self.category = category.strip()

    def to_dict(self) -> Dict[str, str]:
        return {
            "switch": self.switch,
            "template": self.template,
            "description": self.description,
            "category": self.category
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "CommandItem":
        return cls(
            switch=data.get("switch", ""),
            template=data.get("template", ""),
            description=data.get("description", ""),
            category=data.get("category", "General")
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

        # 9. Domain names
        cmd = re.sub(r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|edu|gov|mil|io|co|local|lan|internal)\b', '<domain_name>', cmd, flags=re.IGNORECASE)

        # 10. GPS hardware serial
        cmd = re.sub(r'/dev/tty(?:USB|ACM|AMA)\d+', '<gps_device_path>', cmd)
        cmd = re.sub(r'\bHOST:3501\b', '<remote_host>:3501', cmd)
        cmd = re.sub(r'\bUUID\b', '<uuid>', cmd)

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
# Parser Strategy B: Tabular & Delimited Column Mapper (TSV / Pipe / Markdown)
# -----------------------------------------------------------------------------
class TabularColumnMapper:
    """
    Parses table data with flexible column orders:
    Detects Switch, Example, and Description whether columns are ordered
    (Switch, Example, Desc), (Example, Switch, Desc), or custom.
    """
    @staticmethod
    def parse_rows(rows: List[str], default_category: str = "General") -> Tuple[List[CommandItem], float]:
        entries: List[CommandItem] = []
        if not rows:
            return entries, 1.0

        switch_col = -1
        example_col = -1
        desc_col = -1
        has_header = False

        # Check first non-empty row for header names
        first_row = rows[0]
        delim = "\t" if "\t" in first_row else ("|" if "|" in first_row else None)
        if delim:
            raw_cells = [c.strip().lower() for c in first_row.split(delim) if c.strip()]
            for idx, c in enumerate(raw_cells):
                if any(k in c for k in ("switch", "flag", "option", "button", "name", "action")):
                    switch_col = idx
                elif any(k in c for k in ("example", "command", "syntax", "template", "usage", "exec")):
                    example_col = idx
                elif any(k in c for k in ("desc", "detail", "explanation", "info", "meaning", "purpose")):
                    desc_col = idx

            if switch_col != -1 and example_col != -1:
                has_header = True

        data_rows = rows[1:] if has_header else rows
        for row_str in data_rows:
            line = row_str.strip()
            if not line or line.startswith("#"):
                continue

            # Skip markdown separator rows like | --- | --- | --- |
            if all(c in "-|: \t" for c in line):
                continue

            delim = "\t" if "\t" in line else ("|" if "|" in line else None)
            if not delim:
                continue

            parts = [p.strip() for p in line.split(delim)]
            # Clean markdown table boundary bars
            if parts and not parts[0]:
                parts.pop(0)
            if parts and not parts[-1]:
                parts.pop(-1)

            if len(parts) < 2:
                continue

            if has_header and switch_col < len(parts) and example_col < len(parts):
                sw = parts[switch_col]
                ex = VariableNormalizer.normalize(parts[example_col])
                dsc = parts[desc_col] if (desc_col != -1 and desc_col < len(parts)) else ""
            else:
                sw, ex, dsc = TabularColumnMapper._heuristic_assign(parts)

            if not dsc:
                dsc = TabularColumnMapper._default_desc(sw, ex)

            entries.append(CommandItem(switch=sw, template=ex, description=dsc, category=default_category))

        confidence = 0.95 if has_header else 0.85
        return entries, confidence

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
            # Example | Switch | Description
            return p1, VariableNormalizer.normalize(p0), p2
        elif is_p0_switch and is_p1_cmd:
            # Switch | Example | Description
            return p0, VariableNormalizer.normalize(p1), p2
        else:
            # Standard: Switch/Label | Command | Description
            return p0, VariableNormalizer.normalize(p1), p2

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
