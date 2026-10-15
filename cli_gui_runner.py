import os
import sys
import shutil
import re
import ssl
import json
import subprocess
import threading
import urllib.request
import urllib.error
from html.parser import HTMLParser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter.scrolledtext import ScrolledText

from cheatsheet_engine import (
    CommandItem,
    CheatSheetProfile,
    VariableNormalizer,
    OffensiveRamenHTMLParser,
    TabularColumnMapper,
    KeyValueBlockParser,
    StandaloneGenerator,
    LearnedMappingRule,
    LearnedMappingRegistry,
    get_mapping_registry,
    ROLE_SWITCH,
    ROLE_TEMPLATE,
    ROLE_DESC,
    ROLE_CATEGORY,
    ROLE_IGNORE,
    FIELD_ROLE_LABELS,
    ROLE_CHOICES,
)
from prerequisite_detector import PrerequisiteDetector, ToolPrerequisite

__version__ = "0.8.0"

# Ensure working directory matches script location for relative assets
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if os.path.isdir(SCRIPT_DIR) and not hasattr(sys, "_MEIPASS"):
    try:
        os.chdir(SCRIPT_DIR)
    except Exception:
        pass

DEFAULT_COMMANDS_FILE = os.path.join(SCRIPT_DIR, "commands.txt") if not hasattr(sys, "_MEIPASS") else "commands.txt"
PASTE_COMMANDS_PATH = os.path.join(SCRIPT_DIR, "PasteCommands.txt") if not hasattr(sys, "_MEIPASS") else "PasteCommands.txt"

SAMPLE_COMMANDS = """# Format: Button Name | Command Template | Description (Optional)
# Or simply paste raw commands with <variable> or {variable} placeholders!

Ping Host | ping -c 4 <IP_or_Hostname> | Send 4 ICMP echo requests to a target
Port Scan (Nmap) | nmap -sV -p <Port_Range> <Target_IP> | Scan specific ports and detect versions
Find Files by Name | find <Directory> -name "*<Search_Term>*" | Search for files recursively
Check Disk Space | df -h | Show current disk usage (No variables required)
Custom cURL Request | curl -I -X <HTTP_Method> <URL> | Fetch HTTP headers from a URL
"""

SAMPLE_PASTE_FILE = """# === PASTE RAW COMMANDS OR CHEAT SHEETS BELOW ===
# The parser uses context and repetition to find the command on each line:
# [Text before command] -> Button Label | [Command] | [Text after command] -> Description

Fast Service Scan nmap -sV -p 22,80,443 192.168.1.105 Probes open ports to determine service versions
Ping Sweep Subnet nmap -sn 10.10.14.0/24 Discovers online hosts without port scanning
Stealth SYN Scan sudo nmap -sS 192.168.1.1 Performs a half-open TCP port scan
OS Detection nmap -O 192.168.1.1 Identifies the remote operating system via TCP/IP fingerprinting
Directory Brute Force gobuster dir -u https://target-site.com/app -w /usr/share/wordlists/common.txt Brute forces hidden web directories
Remote SSH Login ssh root@192.168.1.25 -p 2222 Connects to a remote SSH server on a custom port
Domain Lookup whois example.org Queries domain registration and ownership records
"""

KNOWN_CLI_TOOLS = {
    "nmap", "ping", "curl", "wget", "ssh", "scp", "sftp", "rsync", "git", "docker",
    "kubectl", "helm", "terraform", "ansible", "find", "grep", "egrep", "fgrep",
    "awk", "sed", "tar", "zip", "unzip", "gzip", "gunzip", "netstat", "ss", "ip",
    "ifconfig", "iwconfig", "traceroute", "tracert", "tracepath", "mtr", "dig",
    "nslookup", "host", "whois", "gobuster", "ffuf", "feroxbuster", "dirb", "wfuzz",
    "hydra", "medusa", "ncrack", "sqlmap", "nikto", "wpscan", "john", "hashcat",
    "msfconsole", "msfvenom", "nc", "netcat", "ncat", "socat", "tcpdump", "tshark",
    "wireshark", "arp", "arping", "route", "iptables", "nft", "ufw", "firewall-cmd",
    "systemctl", "service", "journalctl", "ps", "pgrep", "pkill", "kill", "killall",
    "top", "htop", "btop", "df", "du", "free", "ls", "ll", "stat", "file", "chmod",
    "chown", "chgrp", "cp", "mv", "rm", "mkdir", "rmdir", "touch", "ln", "cat",
    "tac", "head", "tail", "less", "more", "sort", "uniq", "wc", "cut", "tr", "tee",
    "xargs", "python", "python3", "pip", "pip3", "node", "npm", "npx", "cargo", "go",
    "gcc", "g++", "clang", "make", "cmake", "apt", "apt-get", "yum", "dnf", "pacman",
    "zypper", "brew", "choco", "winget", "powershell", "pwsh", "cmd", "ipconfig",
    "netsh", "net", "sc", "tasklist", "taskkill", "sfc", "dism", "enum4linux",
    "smbclient", "rpcclient", "crackmapexec", "netexec", "impacket", "responder",
    "snmpwalk", "onesixtyone", "ldapsearch", "openssl", "ssh-keygen", "mount", "umount",
    "lsblk", "fdisk", "parted", "dd", "crontab", "at", "uname", "hostname", "id",
    "whoami", "last", "w", "env", "export", "alias", "history", "ffmpeg", "exiftool"
}

COMMAND_PREFIXES = {"sudo", "doas", "time", "watch", "nohup", "proxychains", "proxychains4", "strace", "ltrace"}

FLAGS_TAKING_ARGS = {
    "-p", "--port", "--ports", "-t", "--target", "--targets", "-u", "--url", "--user",
    "--username", "-w", "--wordlist", "-o", "-oN", "-oX", "-oG", "-oA", "--output",
    "-i", "-iL", "--interface", "--input", "-I", "-X", "--request", "-H", "--header",
    "-d", "--data", "-c", "-n", "--namespace", "-l", "-L", "-P", "--password",
    "-s", "-b", "-e", "-f", "--file", "-m", "-T", "--script", "--auth", "--rate",
    "--max-rate", "--min-rate", "--top-ports", "-D", "-S", "-g", "--source-port",
    "-x", "--proxy", "-A", "--user-agent", "-k", "-r"
}

ENGLISH_PROSE_WORDS = {
    "a", "an", "the", "to", "for", "of", "in", "on", "at", "by", "with", "from",
    "into", "onto", "upon", "out", "over", "under", "and", "or", "but", "nor",
    "so", "yet", "is", "are", "was", "were", "be", "been", "being", "have", "has",
    "had", "do", "does", "did", "will", "would", "shall", "should", "can", "could",
    "may", "might", "must", "this", "that", "these", "those", "it", "its", "all",
    "any", "each", "every", "no", "not", "only", "own", "same", "than", "too",
    "very", "just", "where", "when", "why", "how", "what", "which", "who", "whom",
    "scan", "scans", "scanning", "check", "checks", "checking", "list", "lists",
    "listing", "show", "shows", "showing", "display", "displays", "finds",
    "search", "searches", "send", "sends", "fetch", "fetches", "get", "gets",
    "set", "sets", "run", "runs", "perform", "performs", "probe", "probes",
    "detect", "detects", "identify", "identifies", "connect", "connects", "query",
    "queries", "test", "tests", "brute", "force", "forces", "discover", "discovers",
    "enable", "enables", "disable", "disables", "print", "prints", "save", "saves",
    "export", "exports", "import", "imports", "create", "creates", "delete", "deletes",
    "remove", "removes", "start", "starts", "stop", "stops", "restart", "restarts",
    "host", "hosts", "target", "targets", "port", "ports", "file", "files",
    "directory", "directories", "network", "subnet", "domain", "server", "remote",
    "local", "custom", "specific", "current", "active", "open", "common", "default",
    "service", "services", "version", "versions", "system", "operating", "via", "using"
}


class WebCommandExtractor(HTMLParser):
    """
    Parses an HTML webpage to extract CLI commands along with their contextual
    headings, table descriptions, or surrounding explanatory text.
    """
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignore_tags = {"script", "style", "noscript", "svg", "head", "nav", "footer"}
        self.ignore_depth = 0

        self.tag_stack = []
        self.current_heading = ""
        self.last_prose = ""

        # Buffer states
        self.in_heading = False
        self.heading_buf = []

        self.in_code = False
        self.code_buf = []

        self.in_tr = False
        self.tr_cells = []
        self.in_td = False
        self.td_buf = []
        self.td_code_buf = []

        self.in_block = False
        self.block_buf = []
        self.block_codes = []

        # List of raw candidate dicts: {"cmd": ..., "label": ..., "desc": ...}
        self.candidates = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.ignore_tags:
            self.ignore_depth += 1
            return
        if self.ignore_depth > 0:
            return

        self.tag_stack.append(tag)

        if tag in ("h1", "h2", "h3", "h4"):
            self.in_heading = True
            self.heading_buf = []
        elif tag == "tr":
            self.in_tr = True
            self.tr_cells = []
        elif tag in ("td", "th") and self.in_tr:
            self.in_td = True
            self.td_buf = []
            self.td_code_buf = []
        elif tag in ("p", "li", "dt", "dd"):
            self.in_block = True
            self.block_buf = []
            self.block_codes = []
        elif tag in ("pre", "code", "kbd", "samp"):
            if not self.in_code:
                self.in_code = True
                self.code_buf = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.ignore_tags:
            if self.ignore_depth > 0:
                self.ignore_depth -= 1
            return
        if self.ignore_depth > 0:
            return

        if self.tag_stack and self.tag_stack[-1] == tag:
            self.tag_stack.pop()

        if tag in ("h1", "h2", "h3", "h4") and self.in_heading:
            self.in_heading = False
            heading_text = " ".join("".join(self.heading_buf).split()).strip()
            if heading_text:
                self.current_heading = heading_text
                self.last_prose = ""

        elif tag in ("pre", "code", "kbd", "samp") and self.in_code:
            # Only close code when leaving the outermost code/pre tag
            if not any(t in ("pre", "code", "kbd", "samp") for t in self.tag_stack):
                self.in_code = False
                raw_code = "".join(self.code_buf).strip()
                if raw_code:
                    if self.in_td:
                        self.td_code_buf.append(raw_code)
                    elif self.in_block:
                        self.block_codes.append(raw_code)
                    else:
                        self._process_code_block(raw_code, self.current_heading, self.last_prose)

        elif tag in ("td", "th") and self.in_td:
            self.in_td = False
            cell_text = " ".join("".join(self.td_buf).split()).strip()
            cell_codes = list(self.td_code_buf)
            self.tr_cells.append((cell_text, cell_codes))

        elif tag == "tr" and self.in_tr:
            self.in_tr = False
            self._process_table_row(self.tr_cells)

        elif tag in ("p", "li", "dt", "dd") and self.in_block:
            self.in_block = False
            full_text = " ".join("".join(self.block_buf).split()).strip()
            if self.block_codes:
                # Remove the code strings from the surrounding block text to isolate description
                surrounding = full_text
                for c in self.block_codes:
                    surrounding = surrounding.replace(c, " ").strip()
                surrounding = re.sub(r"^[\s\-:—–|]+|[\s\-:—–|]+$", "", surrounding).strip()
                for c in self.block_codes:
                    self._process_code_block(c, self.current_heading, surrounding or self.last_prose)
            else:
                if full_text and len(full_text) < 220:
                    self.last_prose = full_text

    def handle_data(self, data):
        if self.ignore_depth > 0:
            return
        if self.in_heading:
            self.heading_buf.append(data)
        if self.in_code:
            self.code_buf.append(data)
        if self.in_td:
            self.td_buf.append(data)
        if self.in_block:
            self.block_buf.append(data)

    def _process_table_row(self, cells):
        """Extracts command + description pairs from HTML table rows."""
        if not cells:
            return

        # Case 1: At least one cell explicitly wrapped a command in <code>
        code_cell_idx = -1
        for idx, (text, codes) in enumerate(cells):
            if codes:
                code_cell_idx = idx
                break

        if code_cell_idx != -1:
            codes = cells[code_cell_idx][1]
            other_texts = [t for i, (t, _) in enumerate(cells) if i != code_cell_idx and t]
            desc = " - ".join(other_texts) if other_texts else self.current_heading
            label = other_texts[0] if other_texts and len(other_texts[0]) <= 35 else self.current_heading
            for code_str in codes:
                self._process_code_block(code_str, label, desc)
            return

        # Case 2: Plain-text table row where one cell is a command and another is description
        if len(cells) >= 2:
            c0, c1 = cells[0][0], cells[1][0]
            if c0 and c1:
                # Check if cell 0 looks like a command and cell 1 is description, or vice-versa
                self.candidates.append({"raw_line": f"{c1} | {c0} | {c1}", "is_table_fallback": True, "c0": c0, "c1": c1})

    def _process_code_block(self, raw_code, heading_context, prose_context):
        """Splits single or multi-line code blocks into individual command candidates."""
        # Join backslash-continued lines
        cleaned = re.sub(r"\\\s*\r?\n\s*", " ", raw_code)
        lines = cleaned.splitlines()

        inline_comment_desc = ""
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue

            # Capture # comment lines inside <pre> blocks as descriptions for the next command
            if line.startswith("#"):
                comment_text = line.lstrip("#").strip()
                if comment_text and not comment_text.startswith("!"):
                    inline_comment_desc = comment_text
                continue

            # Handle inline trailing comments
            if " #" in line:
                cmd_part, comment_part = line.split(" #", 1)
                line = cmd_part.strip()
                if not inline_comment_desc:
                    inline_comment_desc = comment_part.strip()

            desc = inline_comment_desc or prose_context or heading_context
            label = inline_comment_desc if (inline_comment_desc and len(inline_comment_desc) <= 32) else heading_context
            inline_comment_desc = ""

            self.candidates.append({
                "cmd": line,
                "label": label,
                "desc": desc
            })


class ParserVerificationDialog(tk.Toplevel):
    """
    Interactive confirmation and field-mapping modal for parsed cheat sheets.
    Displays extracted categories, buttons (switch), templates (example), and descriptions.
    Allows changing field mappings for any column, selecting from learned parsing strategies,
    swapping columns, and learning/remembering new mapping rules for future cheat sheets.
    """
    def __init__(
        self,
        parent,
        profile: CheatSheetProfile,
        confidence: float = 1.0,
        on_confirm=None,
        raw_rows: Optional[List[List[str]]] = None,
        headers: Optional[List[str]] = None,
        applied_rule_name: str = "Standard (Switch | Example | Description)",
        initial_mapping: Optional[Dict[str, int]] = None
    ):
        super().__init__(parent)
        self.profile = profile
        self.confidence = confidence
        self.on_confirm = on_confirm
        self.raw_rows = raw_rows or []
        self.headers = headers or []
        self.applied_rule_name = applied_rule_name
        self.registry = get_mapping_registry()

        # If raw_rows was not provided, synthesize from profile.commands
        if not self.raw_rows and self.profile.commands:
            self.raw_rows = [
                [cmd.switch, cmd.template, cmd.description]
                for cmd in self.profile.commands
            ]

        self.col_count = len(self.raw_rows[0]) if self.raw_rows else 3

        # Initial mapping
        if initial_mapping:
            self.current_mapping = dict(initial_mapping)
        elif self.applied_rule_name in self.registry.rules:
            self.current_mapping = dict(self.registry.rules[self.applied_rule_name].mapping)
        else:
            self.current_mapping = {ROLE_SWITCH: 0, ROLE_TEMPLATE: 1, ROLE_DESC: 2, ROLE_CATEGORY: -1}

        self.title(f"Verify & Map Fields: {profile.title}")
        self.geometry("980x640")
        self.minsize(780, 480)
        self.transient(parent)
        self.grab_set()

        # Build UI
        self._build_header_banner()
        self._build_mapping_controls()
        self._build_preview_table()
        self._build_action_bar()

        self._refresh_tree()

    def _build_header_banner(self):
        banner = ttk.Frame(self, padding=(12, 10, 12, 6))
        banner.pack(fill=tk.X)

        conf_pct = int(self.confidence * 100)
        conf_color = "#107c10" if conf_pct >= 90 else ("#d83b01" if conf_pct < 70 else "#0078d4")

        title_row = ttk.Frame(banner)
        title_row.pack(fill=tk.X)
        ttk.Label(
            title_row,
            text=f"Verify Field Mapping for '{self.profile.title}'",
            font=("Segoe UI", 12, "bold")
        ).pack(side=tk.LEFT)

        self.strategy_badge = ttk.Label(
            title_row,
            text=f"Strategy: {self.applied_rule_name} ({conf_pct}% conf)",
            font=("Segoe UI", 9, "bold"),
            foreground=conf_color
        )
        self.strategy_badge.pack(side=tk.RIGHT)

        ttk.Label(
            banner,
            text="Map input columns to their corresponding roles (Switch, Command Template, Description, Category). "
                 "The system remembers your mapping and adds it as a persistent way to parse future inputs.",
            font=("Segoe UI", 9),
            foreground="#555555"
        ).pack(anchor="w", pady=(2, 0))

    def _build_mapping_controls(self):
        map_frame = ttk.LabelFrame(self, text="Field Mapping Configuration", padding=8)
        map_frame.pack(fill=tk.X, padx=12, pady=(4, 6))

        # Top row: Strategy preset selector
        top_row = ttk.Frame(map_frame)
        top_row.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(top_row, text="Parsing Strategy / Learned Rule:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        rule_names = list(self.registry.rules.keys()) + ["Custom Mapping"]
        self.rule_var = tk.StringVar(value=self.applied_rule_name if self.applied_rule_name in rule_names else "Custom Mapping")
        self.rule_combo = ttk.Combobox(top_row, textvariable=self.rule_var, values=rule_names, state="readonly", width=42)
        self.rule_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.rule_combo.bind("<<ComboboxSelected>>", self._on_rule_selected)

        ttk.Button(top_row, text="Swap Switch & Example", command=self.swap_columns).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(top_row, text="Save as Learned Rule...", command=self.save_as_learned_rule).pack(side=tk.LEFT, padx=(0, 6))

        # Bottom row: Column-by-column role dropdowns
        cols_container = ttk.Frame(map_frame)
        cols_container.pack(fill=tk.X)

        self.col_combos = []
        role_labels_list = list(FIELD_ROLE_LABELS.values())

        for idx in range(self.col_count):
            c_box = ttk.Frame(cols_container, padding=4, relief="groove")
            c_box.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

            hdr_name = f" \"{self.headers[idx]}\"" if (idx < len(self.headers) and self.headers[idx]) else ""
            ttk.Label(c_box, text=f"Column {idx + 1}{hdr_name}:", font=("Segoe UI", 8, "bold")).pack(anchor="w")

            initial_role = ROLE_IGNORE
            for r_key, r_idx in self.current_mapping.items():
                if r_idx == idx:
                    initial_role = r_key
                    break

            var = tk.StringVar(value=FIELD_ROLE_LABELS.get(initial_role, "Ignore / Skip"))
            cb = ttk.Combobox(c_box, textvariable=var, values=role_labels_list, state="readonly", width=22)
            cb.pack(fill=tk.X, pady=(2, 0))
            cb.bind("<<ComboboxSelected>>", lambda e, col=idx, v=var: self._on_col_role_changed(col, v.get()))
            self.col_combos.append(var)

    def _on_col_role_changed(self, col_idx: int, selected_label: str):
        role_key = ROLE_IGNORE
        for k, v in FIELD_ROLE_LABELS.items():
            if v == selected_label:
                role_key = k
                break

        if role_key != ROLE_IGNORE:
            for k in list(self.current_mapping.keys()):
                if self.current_mapping[k] == col_idx:
                    self.current_mapping[k] = -1
            self.current_mapping[role_key] = col_idx
        else:
            for k in list(self.current_mapping.keys()):
                if self.current_mapping[k] == col_idx:
                    self.current_mapping[k] = -1

        for idx, var in enumerate(self.col_combos):
            assigned_role = ROLE_IGNORE
            for r_key, r_idx in self.current_mapping.items():
                if r_idx == idx:
                    assigned_role = r_key
                    break
            var.set(FIELD_ROLE_LABELS.get(assigned_role, "Ignore / Skip"))

        self.rule_var.set("Custom Mapping")
        self._apply_current_mapping()

    def _on_rule_selected(self, event=None):
        rule_name = self.rule_var.get()
        if rule_name in self.registry.rules:
            rule = self.registry.rules[rule_name]
            self.current_mapping = dict(rule.mapping)
            for idx, var in enumerate(self.col_combos):
                assigned_role = ROLE_IGNORE
                for r_key, r_idx in self.current_mapping.items():
                    if r_idx == idx:
                        assigned_role = r_key
                        break
                var.set(FIELD_ROLE_LABELS.get(assigned_role, "Ignore / Skip"))
            self._apply_current_mapping()

    def swap_columns(self):
        sw_idx = self.current_mapping.get(ROLE_SWITCH, -1)
        tm_idx = self.current_mapping.get(ROLE_TEMPLATE, -1)
        self.current_mapping[ROLE_SWITCH] = tm_idx
        self.current_mapping[ROLE_TEMPLATE] = sw_idx

        for idx, var in enumerate(self.col_combos):
            assigned_role = ROLE_IGNORE
            for r_key, r_idx in self.current_mapping.items():
                if r_idx == idx:
                    assigned_role = r_key
                    break
            var.set(FIELD_ROLE_LABELS.get(assigned_role, "Ignore / Skip"))

        for cmd in self.profile.commands:
            cmd.switch, cmd.template = cmd.template, cmd.switch

        self.rule_var.set("Custom Mapping")
        self._apply_current_mapping()

    def _apply_current_mapping(self):
        if not self.raw_rows:
            self._refresh_tree()
            return

        new_commands = []
        for cells in self.raw_rows:
            item = self.registry.apply_mapping_to_parts(cells, self.current_mapping)
            new_commands.append(item)

        self.profile.commands = new_commands
        cats = list(dict.fromkeys(c.category for c in new_commands))
        self.profile.categories = cats or ["General"]

        self._refresh_tree()
        if hasattr(self, "strategy_badge") and self.strategy_badge and hasattr(self, "rule_var"):
            try:
                self.strategy_badge.config(text=f"Mapping: {self.rule_var.get()}")
            except Exception:
                pass

    def save_as_learned_rule(self):
        name = simpledialog.askstring(
            "Save Learned Mapping Rule",
            "Enter a name for this parsing rule so the program remembers it:",
            initialvalue=f"Custom-{self.col_count}Col",
            parent=self
        )
        if not name or not name.strip():
            return

        name = name.strip()
        rule = self.registry.learn_rule(
            name=name,
            mapping=self.current_mapping,
            headers=self.headers,
            sample_rows=self.raw_rows,
            col_count=self.col_count,
            description=f"User-taught mapping for {self.col_count} columns"
        )

        all_rules = list(self.registry.rules.keys()) + ["Custom Mapping"]
        self.rule_combo.config(values=all_rules)
        self.rule_var.set(name)
        self.strategy_badge.config(text=f"Saved & Applied: {name}")
        messagebox.showinfo(
            "Mapping Saved",
            f"Rule '{name}' has been learned and saved!\nFuture inputs matching this layout will be parsed automatically.",
            parent=self
        )

    def _build_preview_table(self):
        tbl_frame = ttk.Frame(self, padding=(12, 0, 12, 8))
        tbl_frame.pack(fill=tk.BOTH, expand=True)

        cols = ("cat", "switch", "template", "desc")
        self.tree = ttk.Treeview(tbl_frame, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("cat", text="Category")
        self.tree.heading("switch", text="Switch (Button Text)")
        self.tree.heading("template", text="Example (Command Template)")
        self.tree.heading("desc", text="Description")

        self.tree.column("cat", width=140, anchor="w")
        self.tree.column("switch", width=160, anchor="w")
        self.tree.column("template", width=300, anchor="w")
        self.tree.column("desc", width=320, anchor="w")

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tbl_frame.columnconfigure(0, weight=1)
        tbl_frame.rowconfigure(0, weight=1)

    def _refresh_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for cmd in self.profile.commands:
            self.tree.insert("", tk.END, values=(cmd.category, cmd.switch, cmd.template, cmd.description))

    def _build_action_bar(self):
        btn_bar = ttk.Frame(self, padding=12)
        btn_bar.pack(fill=tk.X)

        self.remember_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            btn_bar,
            text="Remember this field mapping as a learned parsing rule",
            variable=self.remember_var
        ).pack(side=tk.LEFT)

        ttk.Button(btn_bar, text="Confirm & Import Cheat Sheet", command=self.confirm).pack(side=tk.RIGHT, padx=6)
        ttk.Button(btn_bar, text="Cancel", command=self.destroy).pack(side=tk.RIGHT)

    def confirm(self):
        if self.remember_var.get() and self.rule_var.get() == "Custom Mapping":
            rule_name = f"Learned ({' | '.join(self.headers[:3])})" if self.headers else f"Learned {self.col_count}-Col"
            self.registry.learn_rule(
                name=rule_name,
                mapping=self.current_mapping,
                headers=self.headers,
                sample_rows=self.raw_rows,
                col_count=self.col_count
            )
        if self.on_confirm:
            self.on_confirm(self.profile)
        self.destroy()


class CommandRunnerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CLI Quick-Reference & Multi-Cheat Sheet Runner")
        self.root.geometry("1080x700")
        self.current_process = None
        self.current_file = DEFAULT_COMMANDS_FILE
        self.auto_param_var = tk.BooleanVar(value=True)
        self.persistent_console_var = tk.BooleanVar(value=True)

        self.profiles = {}
        self.profile_labels = {}
        self.current_profile = None
        self.current_prerequisites = {}

        self._ensure_default_files()
        self._build_ui()
        self._load_all_profiles()
        if "kismet" in self.profiles:
            self.switch_profile("kismet")
        elif "general" in self.profiles:
            self.switch_profile("general")
        else:
            self.load_commands(self.current_file)

    def _ensure_default_files(self):
        if not os.path.exists(DEFAULT_COMMANDS_FILE):
            with open(DEFAULT_COMMANDS_FILE, "w", encoding="utf-8") as f:
                f.write(SAMPLE_COMMANDS.strip() + "\n")

        if not os.path.exists(PASTE_COMMANDS_PATH):
            with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                f.write(SAMPLE_PASTE_FILE.strip() + "\n")

    def _build_ui(self):
        # Top Toolbar Row 1: Profile Selector & Core Actions
        tb1 = ttk.Frame(self.root, padding=(8, 6, 8, 2))
        tb1.pack(fill=tk.X)

        ttk.Label(tb1, text="Cheat Sheet Profile:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.profile_combo = ttk.Combobox(tb1, state="readonly", width=34)
        self.profile_combo.pack(side=tk.LEFT, padx=(0, 8))
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_dropdown_change)

        ttk.Button(tb1, text="Export Standalone .py...", command=self.export_standalone_profile).pack(side=tk.LEFT, padx=3)
        ttk.Button(tb1, text="Import Sheet / Web...", command=self.open_smart_importer).pack(side=tk.LEFT, padx=3)
        ttk.Button(tb1, text="Quick Paste...", command=self.open_paste_editor).pack(side=tk.LEFT, padx=3)

        self.prereq_btn = ttk.Button(tb1, text="Prerequisites: Scanning...", command=self.open_prerequisites_dialog)
        self.prereq_btn.pack(side=tk.LEFT, padx=3)

        self.stop_btn = ttk.Button(tb1, text="Stop Running Command", command=self.stop_process, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT)

        # Top Toolbar Row 2: File management & parameters
        tb2 = ttk.Frame(self.root, padding=(8, 2, 8, 6))
        tb2.pack(fill=tk.X)

        ttk.Button(tb2, text="Open File...", command=self.browse_file).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(tb2, text="Reload Active", command=self.reload_active).pack(side=tk.LEFT, padx=4)
        ttk.Button(tb2, text="Import PasteCommands.txt", command=self.import_paste_commands).pack(side=tk.LEFT, padx=4)

        ttk.Checkbutton(
            tb2,
            text="Auto-detect <Variables>",
            variable=self.auto_param_var
        ).pack(side=tk.LEFT, padx=6)

        ttk.Checkbutton(
            tb2,
            text="Persistent Console Window",
            variable=self.persistent_console_var
        ).pack(side=tk.LEFT, padx=6)

        self.file_label = ttk.Label(tb2, text="", foreground="#555555")
        self.file_label.pack(side=tk.LEFT, padx=6)

        # Top Toolbar Row 3: Target Variables Auto-Fill Bar
        tb_targets = ttk.Frame(self.root, padding=(8, 2, 8, 4))
        tb_targets.pack(fill=tk.X)

        ttk.Label(tb_targets, text="Target Variables:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(tb_targets, text="IP/Host:").pack(side=tk.LEFT, padx=(0, 2))
        self.target_ip_entry = ttk.Entry(tb_targets, width=14)
        self.target_ip_entry.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(tb_targets, text="Website/Domain:").pack(side=tk.LEFT, padx=(0, 2))
        self.target_domain_entry = ttk.Entry(tb_targets, width=16)
        self.target_domain_entry.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(tb_targets, text="AP_BSSID / MAC:").pack(side=tk.LEFT, padx=(0, 2))
        self.target_mac_entry = ttk.Entry(tb_targets, width=18)
        self.target_mac_entry.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(tb_targets, text="Interface:").pack(side=tk.LEFT, padx=(0, 2))
        self.target_iface_entry = ttk.Entry(tb_targets, width=10)
        self.target_iface_entry.pack(side=tk.LEFT, padx=(0, 6))

        def clear_targets():
            self.target_ip_entry.delete(0, tk.END)
            self.target_domain_entry.delete(0, tk.END)
            self.target_mac_entry.delete(0, tk.END)
            self.target_iface_entry.delete(0, tk.END)

        ttk.Button(tb_targets, text="Clear", width=6, command=clear_targets).pack(side=tk.LEFT, padx=4)

        ttk.Label(
            tb_targets,
            text="(Auto-fills commands; blank keeps original text)",
            foreground="#666666",
            font=("Segoe UI", 8)
        ).pack(side=tk.LEFT, padx=6)

        # Main Split Pane (Buttons / Category tabs on top, Live Terminal on bottom)
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Button Container for Categories or flat grid
        self.btn_container = ttk.LabelFrame(paned, text="Available Commands (Click to Configure & Run)", padding=4)
        paned.add(self.btn_container, weight=3)

        # Backward compatibility placeholders
        self.canvas = tk.Canvas(self.btn_container, highlightthickness=0)
        self.button_frame = ttk.Frame(self.canvas)

        # Terminal Output Frame
        term_container = ttk.LabelFrame(paned, text="Live Execution Output", padding=5)
        paned.add(term_container, weight=1)

        self.output_area = ScrolledText(
            term_container, bg="#1e1e1e", fg="#d4d4d4",
            font=("Consolas", 10), insertbackground="white", height=12
        )
        self.output_area.pack(fill=tk.BOTH, expand=True)

    # -------------------------------------------------------------------------
    # Webpage Command Scraper & Interactive Importer
    # -------------------------------------------------------------------------
    def _looks_like_valid_cli(self, cmd_str, batch_executables=None):
        """
        Validates whether an extracted code snippet is an actual CLI invocation
        rather than a single flag, programming language code, HTML/JSON, or prose.
        """
        cmd = re.sub(r"^(?:\$|#|root@[^\s:#]+[:#]|user@[^\s:$]+[\$])\s+", "", cmd_str.strip())
        if not cmd or len(cmd) < 2 or len(cmd) > 260:
            return False

        # Reject obvious programming / markup constructs
        bad_prefixes = (
            "function ", "def ", "class ", "import ", "from ", "return ", "var ",
            "let ", "const ", "if ", "for ", "while ", "<div", "<span", "<html",
            "http://", "https://", "//", "/*", "*/", "{", "}", "[", "]"
        )
        if cmd.lower().startswith(bad_prefixes):
            return False
        if any(seq in cmd for seq in ("();", "=>", "function(", "console.log", "System.out", "<?php")):
            return False

        tokens = cmd.split()
        if not tokens:
            return False

        # Reject standalone flags like "-sV" with no command
        first = tokens[0].lower()
        if first in COMMAND_PREFIXES and len(tokens) > 1:
            first = tokens[1].lower()

        base_exe = os.path.basename(first)
        if not re.match(r"^[a-z0-9_.\-]+$", base_exe) or base_exe.startswith("-"):
            return False

        # Known CLI tool or repeated batch executable
        is_known = (base_exe in KNOWN_CLI_TOOLS) or (batch_executables and base_exe in batch_executables)
        has_cli_args = any(self._is_strict_cli_token(t) for t in tokens[1:])

        if is_known and (len(tokens) >= 2 or base_exe in ("df", "free", "top", "htop", "ps", "ls", "whoami", "id", "ipconfig", "ifconfig", "netstat", "ss", "history")):
            return True

        if has_cli_args and base_exe not in ENGLISH_PROSE_WORDS and tokens[0] == tokens[0].lower():
            return True

        return False

    def extract_commands_from_html(self, html_content):
        """
        Parses HTML content, correlates commands with headings/descriptions,
        applies batch repetition + variable detection, and returns (label, cmd, desc) tuples.
        """
        parser = WebCommandExtractor()
        parser.feed(html_content)

        # Gather raw command lines to run Pass 1 repetition & context detection
        raw_cmd_lines = []
        for item in parser.candidates:
            if "cmd" in item:
                raw_cmd_lines.append(item["cmd"])
            elif item.get("is_table_fallback"):
                raw_cmd_lines.extend([item["c0"], item["c1"]])

        batch_executables = self._detect_batch_executables(raw_cmd_lines)

        extracted = []
        seen_cmds = set()

        for item in parser.candidates:
            if item.get("is_table_fallback"):
                c0, c1 = item["c0"], item["c1"]
                if self._looks_like_valid_cli(c0, batch_executables) and not self._looks_like_valid_cli(c1, batch_executables):
                    raw_cmd, desc, label = c0, c1, ""
                elif self._looks_like_valid_cli(c1, batch_executables) and not self._looks_like_valid_cli(c0, batch_executables):
                    raw_cmd, desc, label = c1, c0, c0 if len(c0) <= 32 else ""
                else:
                    continue
            else:
                raw_cmd = item["cmd"]
                label = item.get("label", "")
                desc = item.get("desc", "")

            # Strip shell prompts like '$ ' or 'root@kali:~# '
            clean_cmd = re.sub(r"^(?:\$|#|root@[^\s:#]+[:#]|user@[^\s:$]+[\$])\s+", "", raw_cmd.strip())

            # If a single code line has trailing prose or a leading label, split it smartly
            if not self._looks_like_valid_cli(clean_cmd, batch_executables):
                lbl_part, split_cmd, dsc_part = self._split_label_command_desc(clean_cmd, batch_executables)
                if split_cmd and self._looks_like_valid_cli(split_cmd, batch_executables):
                    clean_cmd = split_cmd
                    if lbl_part and not label:
                        label = lbl_part
                    if dsc_part and not desc:
                        desc = dsc_part
                else:
                    continue

            cmd_template = self._normalize_command_string(clean_cmd)
            if not cmd_template or cmd_template.lower() in seen_cmds:
                continue
            seen_cmds.add(cmd_template.lower())

            # Clean up label & description pipes so they don't break the 3-column format
            label = (label or "").replace("|", "-").strip()
            desc = (desc or "").replace("|", "-").strip()

            if not label or len(label) > 36:
                label = self._generate_label_from_command(cmd_template, desc)
            if not desc:
                desc = label if label else f"Template: {cmd_template}"

            extracted.append((label, cmd_template, desc))

        return extracted

    def open_webpage_importer(self):
        """Opens a dialog to fetch a webpage URL, scan it for CLI commands, preview, and append to commands.txt."""
        win = tk.Toplevel(self.root)
        win.title("Scan Webpage for CLI Commands")
        win.geometry("840x580")
        win.transient(self.root)
        win.grab_set()

        top_frame = ttk.Frame(win, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Webpage URL:").pack(side=tk.LEFT, padx=(0, 6))
        url_var = tk.StringVar(value="https://")
        url_entry = ttk.Entry(top_frame, textvariable=url_var, width=65)
        url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 6))
        url_entry.focus_set()

        status_var = tk.StringVar(value="Enter a documentation or cheat-sheet URL and click 'Scan Webpage'.")

        preview_label = ttk.Label(
            win,
            text="Extracted Commands (Editable before saving — Format: Button Label | Command Template | Description):",
            font=("Segoe UI", 9, "bold")
        )
        preview_label.pack(anchor="w", padx=10, pady=(4, 2))

        preview_box = ScrolledText(win, font=("Consolas", 9), height=22, bg="#f4f6f8", fg="#004578")
        preview_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        status_lbl = ttk.Label(win, textvariable=status_var, foreground="#555555")
        status_lbl.pack(anchor="w", padx=10, pady=2)

        def fetch_and_scan(event=None):
            url = url_var.get().strip()
            if not url or url == "https://":
                messagebox.showwarning("Missing URL", "Please enter a valid webpage URL.", parent=win)
                return
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
                url_var.set(url)

            scan_btn.config(state=tk.DISABLED)
            status_var.set(f"Fetching and scanning {url} ...")
            preview_box.delete("1.0", tk.END)

            def worker():
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    req = urllib.request.Request(
                        url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CLI-GUI-Runner/1.0"
                        }
                    )
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                        charset = resp.headers.get_content_charset() or "utf-8"
                        raw_bytes = resp.read()
                        html_text = raw_bytes.decode(charset, errors="replace")

                    content_type = resp.headers.get("Content-Type", "").lower()
                    # If the URL is a raw text/markdown file (e.g. raw.githubusercontent.com), use raw parser
                    if "text/plain" in content_type or url.lower().endswith((".txt", ".md", ".sh")):
                        entries = self.format_raw_paste_text(html_text)
                    else:
                        entries = self.extract_commands_from_html(html_text)
                        # Fallback to plain-text line scanner if HTML had no <code>/<table> tags
                        if not entries:
                            plain_text = re.sub(r"<[^>]+>", "\n", html_text)
                            entries = self.format_raw_paste_text(plain_text)

                    def update_ui():
                        scan_btn.config(state=tk.NORMAL)
                        if not entries:
                            status_var.set("No valid CLI commands were detected on this page.")
                            messagebox.showinfo("No Commands Found", "Could not detect CLI commands on that page.", parent=win)
                            return

                        for lbl, cmd, dsc in entries:
                            preview_box.insert(tk.END, f"{lbl} | {cmd} | {dsc}\n")
                        status_var.set(f"Discovered {len(entries)} command(s)! Review or edit any lines above, then click 'Append & Create Buttons'.")

                    self.root.after(0, update_ui)

                except Exception as e:
                    def show_err():
                        scan_btn.config(state=tk.NORMAL)
                        status_var.set(f"Error fetching URL: {e}")
                        messagebox.showerror("Fetch Error", f"Failed to load webpage:\n{e}", parent=win)
                    self.root.after(0, show_err)

            threading.Thread(target=worker, daemon=True).start()

        scan_btn = ttk.Button(top_frame, text="Scan Webpage", command=fetch_and_scan)
        scan_btn.pack(side=tk.LEFT)
        url_entry.bind("<Return>", fetch_and_scan)

        def save_extracted_to_commands():
            raw_preview = preview_box.get("1.0", tk.END).strip()
            if not raw_preview:
                messagebox.showwarning("Nothing to Import", "Scan a webpage first so commands appear in the preview box.", parent=win)
                return

            # Also save a copy of what was scraped into PasteCommands.txt for reference
            with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                f.write(f"# Scraped from {url_var.get().strip()}\n" + raw_preview + "\n")

            added, skipped = self._append_entries_to_commands_file(
                [self.parse_line(line) for line in raw_preview.splitlines() if line.strip() and not line.strip().startswith("#")]
            )
            win.destroy()
            messagebox.showinfo(
                "Webpage Import Complete",
                f"Added {added} new command button(s) to '{self.current_file}' ({skipped} duplicate(s) skipped)."
            )

        btn_bar = ttk.Frame(win, padding=10)
        btn_bar.pack(fill=tk.X)
        ttk.Checkbutton(
            btn_bar,
            text="Auto-convert hardcoded IPs/URLs/Ports to <Variables>",
            variable=self.auto_param_var
        ).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="Append & Create Buttons", command=save_extracted_to_commands).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Cancel", command=win.destroy).pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # Smart Contextual & Repetition-Based Command Parser
    # -------------------------------------------------------------------------
    def _is_strict_cli_token(self, token):
        """
        Returns True if a token has unmistakable CLI syntax:
        flags (-sV), variables (<IP>), IPs/subnets, URLs, paths (/etc/..),
        user@host, key=value, globs (*.txt), or quoted arguments.
        """
        if not token or token in ("-", "--", ":", "|", "—"):
            return False

        if re.match(r"^-{1,2}[A-Za-z0-9_\-]+(=.*)?$", token):
            return True
        if re.match(r"^[<\{\[][^>\}\]\s]+[>\}\]]$", token):
            return True
        if re.match(r"^(?:https?|ftp|ssh|ws)://\S+$", token, re.IGNORECASE):
            return True
        if re.match(r"^[a-zA-Z0-9._\-]+@[a-zA-Z0-9._\-]+$", token):
            return True
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2}|:\d{1,5})?$", token):
            return True
        if re.match(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$", token):
            return True
        if any(ch in token for ch in ("/", "\\", "*", "=", "\"", "'", ";", "&")):
            return True
        if re.match(
            r"^[a-zA-Z0-9._\-]+\.(?:txt|log|conf|cfg|ini|json|xml|yaml|yml|sh|py|pl|rb|pcap|cap|lst|dic|db|sql|csv|html|php|js|com|org|net|edu|gov|io|co|local|lan|internal|me|us|uk)$",
            token,
            re.IGNORECASE
        ):
            return True

        return False

    def _detect_batch_executables(self, lines):
        """
        Pass 1: Scans all lines in the batch to discover which command executables
        are being invoked based on repetition across lines and CLI context.
        """
        line_counts = {}
        context_scores = {}

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or "|" in line:
                continue

            tokens = line.split()
            seen_in_line = set()

            for i, tok in enumerate(tokens):
                if tok.startswith("(") or tok.endswith(")") or tok.endswith(":"):
                    continue

                clean = tok.lstrip("$>").lower()
                if not re.match(r"^[a-z0-9_.\-]+$", clean) or len(clean) < 2:
                    continue

                next_tok = tokens[i + 1] if i + 1 < len(tokens) else ""
                next2_tok = tokens[i + 2] if i + 2 < len(tokens) else ""
                prev_tok = tokens[i - 1].lower() if i > 0 else ""

                has_cli_context = False
                if self._is_strict_cli_token(next_tok):
                    has_cli_context = True
                    context_scores[clean] = context_scores.get(clean, 0) + 6
                elif re.match(r"^[a-z0-9_\-]+$", next_tok) and self._is_strict_cli_token(next2_tok):
                    has_cli_context = True
                    context_scores[clean] = context_scores.get(clean, 0) + 5

                if prev_tok in COMMAND_PREFIXES or tok.startswith("$"):
                    has_cli_context = True
                    context_scores[clean] = context_scores.get(clean, 0) + 6

                if clean in KNOWN_CLI_TOOLS:
                    context_scores[clean] = context_scores.get(clean, 0) + 5

                if tok == tok.lower() and (clean not in ENGLISH_PROSE_WORDS or clean in KNOWN_CLI_TOOLS or has_cli_context):
                    if clean not in seen_in_line:
                        seen_in_line.add(clean)
                        line_counts[clean] = line_counts.get(clean, 0) + 1

        batch_executables = {}
        for tok, ctx_score in context_scores.items():
            freq = line_counts.get(tok, 1)
            batch_executables[tok] = ctx_score + (freq * 4)

        for tok, freq in line_counts.items():
            if freq >= 2 and tok not in batch_executables and tok not in ENGLISH_PROSE_WORDS:
                batch_executables[tok] = freq * 4

        return batch_executables

    def _split_label_command_desc(self, line, batch_executables):
        """
        Pass 2: Given a raw line, locates the invoked command using batch context,
        treats everything before it as the Label, and everything after the command's
        arguments as the Description.
        """
        inline_comment = ""
        if " #" in line:
            line, inline_comment = line.split(" #", 1)
            line = line.strip()
            inline_comment = inline_comment.strip()

        token_spans = [(m.group(0), m.start(), m.end()) for m in re.finditer(r"\S+", line)]
        if not token_spans:
            return "", "", ""

        tokens = [t[0] for t in token_spans]
        n = len(tokens)

        best_idx = 0
        best_score = -999

        for i, tok in enumerate(tokens):
            if tok.startswith("(") or tok.endswith(")") or tok.endswith(":"):
                continue

            clean = tok.lstrip("$>").lower()
            if not re.match(r"^[a-z0-9_.\-/\\]+$", clean):
                continue

            base_name = os.path.basename(clean)
            if base_name in COMMAND_PREFIXES and i + 1 < n:
                continue

            score = 0
            if base_name in batch_executables:
                score += batch_executables[base_name]
            if base_name in KNOWN_CLI_TOOLS:
                score += 8

            if tok == tok.lower():
                score += 5
            else:
                score -= 6

            next_tok = tokens[i + 1] if i + 1 < n else ""
            next2_tok = tokens[i + 2] if i + 2 < n else ""
            prev_tok = tokens[i - 1].lower().lstrip("$>") if i > 0 else ""

            if self._is_strict_cli_token(next_tok):
                score += 12
            elif re.match(r"^[a-z0-9_\-]+$", next_tok) and self._is_strict_cli_token(next2_tok):
                score += 8

            if prev_tok in COMMAND_PREFIXES or tok.startswith("$"):
                score += 10

            if base_name in ENGLISH_PROSE_WORDS and base_name not in KNOWN_CLI_TOOLS and not self._is_strict_cli_token(next_tok):
                score -= 15

            if score > best_score:
                best_score = score
                best_idx = i

        cmd_start_idx = best_idx
        while cmd_start_idx > 0 and tokens[cmd_start_idx - 1].lower().lstrip("$>") in COMMAND_PREFIXES:
            cmd_start_idx -= 1

        if cmd_start_idx > 0 and tokens[cmd_start_idx - 1] in ("$", ">"):
            cmd_start_idx -= 1

        cmd_end_idx = best_idx
        expecting_flag_arg = False

        j = best_idx + 1
        while j < n:
            tok = tokens[j]

            if tok in ("-", "--", ":", "—", "|"):
                break

            if self._is_strict_cli_token(tok):
                cmd_end_idx = j
                if tok.startswith("-"):
                    flag_base = tok.split("=")[0]
                    expecting_flag_arg = (flag_base in FLAGS_TAKING_ARGS)
                else:
                    expecting_flag_arg = False
                j += 1
                continue

            if re.match(r"^\d+(?:[,-:]\d+)*$", tok):
                cmd_end_idx = j
                expecting_flag_arg = False
                j += 1
                continue

            if expecting_flag_arg:
                cmd_end_idx = j
                expecting_flag_arg = False
                j += 1
                continue

            if j + 1 < n and self._is_strict_cli_token(tokens[j + 1]):
                if tok == tok.lower() and not tok[0].isupper():
                    cmd_end_idx = j
                    j += 1
                    continue

            if (
                j == best_idx + 1
                and tok == tok.lower()
                and re.match(r"^[a-z0-9_\-]+$", tok)
                and tok not in ENGLISH_PROSE_WORDS
            ):
                cmd_end_idx = j
                j += 1
                continue

            break

        label_str = line[:token_spans[cmd_start_idx][1]].strip()
        label_str = re.sub(r"[\s\-:—]+$", "", label_str).strip()

        cmd_str = line[token_spans[cmd_start_idx][1]:token_spans[cmd_end_idx][2]].strip()

        desc_str = line[token_spans[cmd_end_idx][2]:].strip()
        desc_str = re.sub(r"^[\s\-:—]+", "", desc_str).strip()

        if inline_comment:
            desc_str = f"{desc_str} ({inline_comment})".strip() if desc_str else inline_comment

        return label_str, cmd_str, desc_str

    # -------------------------------------------------------------------------
    # Smart Hardcoded Value -> <Variable> Auto-Parameterizer
    # -------------------------------------------------------------------------
    def _auto_parameterize_command(self, cmd):
        tokens = cmd.split()
        if len(tokens) <= 1:
            return cmd

        executable = tokens[0]
        args_str = cmd[len(executable):]

        shielded = {}
        def _shield_match(match):
            key = f"__VAR_SHIELD_{len(shielded)}__"
            shielded[key] = match.group(0)
            return key

        args_str = re.sub(r"[<\{][^>\}\s]+[>\}]", _shield_match, args_str)

        args_str = re.sub(r"https?://[^\s\"'>]+", "<URL>", args_str)
        args_str = re.sub(
            r"\b[a-zA-Z0-9._\-]+@(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b",
            "<Username>@<Target_Host>",
            args_str
        )
        args_str = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b", "<Subnet_CIDR>", args_str)
        args_str = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b", "<Target_IP>:<Port>", args_str)
        args_str = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<Target_IP>", args_str)
        args_str = re.sub(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "<MAC_Address>", args_str)
        args_str = re.sub(r"(\s(?:-p|--port)\s+)(?:\d+(?:[,-]\d+)*)\b", r"\1<Port>", args_str)
        args_str = re.sub(
            r"(\s(?:-X|--request)\s+)(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b",
            r"\1<HTTP_Method>",
            args_str,
            flags=re.IGNORECASE
        )
        args_str = re.sub(
            r"(?<=\s)(?:[a-zA-Z]:\\[^\s\"']+|\.{0,2}/[a-zA-Z0-9._/\-]+)",
            "<File_Path>",
            args_str
        )
        args_str = re.sub(
            r"\b(?:[a-zA-Z0-9\-]+\.)+(?:com|org|net|edu|gov|mil|io|co|local|lan|internal|info|biz|me|us|uk|ca|de|fr|au|jp)\b",
            "<Domain_Name>",
            args_str,
            flags=re.IGNORECASE
        )

        for key, original_val in shielded.items():
            args_str = args_str.replace(key, original_val)

        return executable + args_str

    def _normalize_command_string(self, cmd):
        cmd = re.sub(r"^[\$>]\s+", "", cmd.strip())
        cmd = re.sub(r"\[([A-Za-z0-9_\-]+)\]", r"<\1>", cmd)
        auto_param = False
        if hasattr(self, "auto_param_var") and self.auto_param_var is not None:
            try:
                auto_param = bool(self.auto_param_var.get())
            except Exception:
                auto_param = False
        if auto_param:
            cmd = self._auto_parameterize_command(cmd)
        return cmd.strip()

    def _generate_label_from_command(self, cmd, desc=""):
        if desc and len(desc) <= 28 and not desc.startswith("Template:"):
            return desc

        tokens = cmd.split()
        if not tokens:
            return "Command"

        idx = 1 if tokens[0].lower() in COMMAND_PREFIXES and len(tokens) > 1 else 0
        base_tool = os.path.basename(tokens[idx]).capitalize()
        flags = [t for t in tokens[idx + 1:] if t.startswith("-") and len(t) <= 6]
        if flags:
            label = f"{base_tool} ({' '.join(flags[:2])})"
        elif len(tokens) > idx + 1 and not tokens[idx + 1].startswith(("<", "{")):
            label = f"{base_tool} {tokens[idx + 1]}"
        else:
            label = base_tool

        return label if len(label) <= 32 else label[:29] + "..."

    def format_raw_paste_text(self, raw_text):
        raw_lines = raw_text.splitlines()
        batch_executables = self._detect_batch_executables(raw_lines)

        formatted_entries = []
        pending_comment = ""

        for raw_line in raw_lines:
            line = raw_line.strip()
            if not line:
                pending_comment = ""
                continue

            if line.startswith("#"):
                comment_body = line.lstrip("#").strip()
                if (
                    not comment_body
                    or comment_body.startswith("===")
                    or "The parser uses context and repetition" in comment_body
                    or "[Text before command]" in comment_body
                ):
                    pending_comment = ""
                else:
                    pending_comment = comment_body
                continue

            if "\t" in line:
                parts = [p.strip() for p in raw_line.split("\t") if p.strip()]
                if len(parts) >= 2:
                    if parts[0].lower() in ("action", "label", "button", "name", "title") and "command" in parts[1].lower():
                        continue
                    label = parts[0]
                    cmd_template = self._normalize_command_string(parts[1])
                    desc = parts[2] if len(parts) > 2 else f"Execute: {cmd_template}"
                    formatted_entries.append((label, cmd_template, desc))
                    pending_comment = ""
                    continue

            if "|" in line:
                label, cmd_template, desc = self.parse_line(line)
                cmd_template = self._normalize_command_string(cmd_template)
                formatted_entries.append((label, cmd_template, desc))
                pending_comment = ""
                continue

            label, raw_cmd, desc = self._split_label_command_desc(line, batch_executables)
            cmd_template = self._normalize_command_string(raw_cmd)

            if pending_comment:
                if not label:
                    label = pending_comment
                elif not desc:
                    desc = pending_comment
                pending_comment = ""

            if not label:
                label = self._generate_label_from_command(cmd_template, desc)

            if not desc:
                desc = label if label else f"Template: {cmd_template}"

            formatted_entries.append((label, cmd_template, desc))

        return formatted_entries

    def _read_paste_sources(self, source_path):
        if not os.path.exists(source_path):
            return ""

        if os.path.isdir(source_path):
            combined = []
            for fname in sorted(os.listdir(source_path)):
                fpath = os.path.join(source_path, fname)
                if os.path.isfile(fpath) and fname.lower().endswith((".txt", ".md", ".conf", ".sh")):
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        combined.append(f.read())
            return "\n".join(combined)
        else:
            with open(source_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

    def _append_entries_to_commands_file(self, entries):
        """Deduplicates and appends (label, cmd_template, desc) tuples to commands.txt, then reloads buttons."""
        existing_commands = set()
        if os.path.exists(self.current_file):
            with open(self.current_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        _, existing_cmd, _ = self.parse_line(line)
                        existing_commands.add(existing_cmd.lower())

        lines_to_append = []
        skipped_duplicates = 0

        for label, cmd_template, desc in entries:
            if not cmd_template:
                continue
            if cmd_template.lower() in existing_commands:
                skipped_duplicates += 1
                continue
            existing_commands.add(cmd_template.lower())
            lines_to_append.append(f"{label} | {cmd_template} | {desc}")

        if lines_to_append:
            with open(self.current_file, "a", encoding="utf-8") as f:
                f.write("\n" + "\n".join(lines_to_append) + "\n")
            self.load_commands(self.current_file)

        return len(lines_to_append), skipped_duplicates

    def import_paste_commands(self):
        raw_text = self._read_paste_sources(PASTE_COMMANDS_PATH)
        if not raw_text.strip():
            messagebox.showinfo("Import PasteCommands", f"No data found in '{PASTE_COMMANDS_PATH}'.")
            return

        new_entries = self.format_raw_paste_text(raw_text)
        if not new_entries:
            messagebox.showinfo(
                "No Commands Detected",
                f"No new commands were found in '{PASTE_COMMANDS_PATH}'.\n\n"
                "Paste your raw CLI commands into PasteCommands.txt and try again."
            )
            return

        added, skipped_duplicates = self._append_entries_to_commands_file(new_entries)
        if added == 0:
            messagebox.showinfo(
                "Already Imported",
                f"All {skipped_duplicates} command template(s) in '{PASTE_COMMANDS_PATH}' already exist in '{self.current_file}'."
            )
            return

        if os.path.isfile(PASTE_COMMANDS_PATH):
            clear_it = messagebox.askyesno(
                "Import Complete",
                f"Formatted and appended {added} command(s) to '{self.current_file}'"
                f" ({skipped_duplicates} duplicate(s) skipped).\n\n"
                f"Clear '{PASTE_COMMANDS_PATH}' for your next batch?"
            )
            if clear_it:
                with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                    f.write("# === PASTE RAW COMMANDS OR CHEAT SHEETS BELOW ===\n\n")

    def open_paste_editor(self):
        editor = tk.Toplevel(self.root)
        editor.title(f"Edit & Import {PASTE_COMMANDS_PATH}")
        editor.geometry("780x540")
        editor.transient(self.root)
        editor.grab_set()

        ttk.Label(
            editor,
            text="Paste unstructured lines below. The parser detects the command by context & repetition and places '|' before and after it:",
            wraplength=750
        ).pack(anchor="w", padx=10, pady=(10, 5))

        text_box = ScrolledText(editor, font=("Consolas", 10), height=14)
        text_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(
            editor,
            text="Live Preview (Label | Command Template | Description):",
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w", padx=10, pady=(5, 2))

        preview_box = ScrolledText(editor, font=("Consolas", 9), height=8, bg="#f4f6f8", fg="#004578")
        preview_box.pack(fill=tk.BOTH, expand=False, padx=10, pady=4)

        if os.path.isfile(PASTE_COMMANDS_PATH):
            with open(PASTE_COMMANDS_PATH, "r", encoding="utf-8", errors="ignore") as f:
                text_box.insert(tk.END, f.read())

        def refresh_preview(event=None):
            raw = text_box.get("1.0", tk.END)
            entries = self.format_raw_paste_text(raw)
            preview_box.delete("1.0", tk.END)
            for lbl, cmd, dsc in entries:
                preview_box.insert(tk.END, f"{lbl} | {cmd} | {dsc}\n")

        text_box.bind("<KeyRelease>", refresh_preview)
        refresh_preview()

        def save_and_import():
            content = text_box.get("1.0", tk.END)
            with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                f.write(content)
            editor.destroy()
            self.import_paste_commands()

        btn_bar = ttk.Frame(editor, padding=10)
        btn_bar.pack(fill=tk.X)
        ttk.Checkbutton(
            btn_bar,
            text="Auto-convert hardcoded values to <Variables>",
            variable=self.auto_param_var,
            command=refresh_preview
        ).pack(side=tk.LEFT)
        ttk.Button(btn_bar, text="Save & Append to commands.txt", command=save_and_import).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Cancel", command=editor.destroy).pack(side=tk.RIGHT)

    # -------------------------------------------------------------------------
    # Existing File Loading & Command Execution Logic
    # -------------------------------------------------------------------------
    def browse_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Command Reference File",
            filetypes=[("All Supported", "*.json *.txt *.md *.conf"), ("JSON Profiles", "*.json"), ("Text Files", "*.txt *.md *.conf"), ("All Files", "*.*")]
        )
        if filepath:
            self.load_commands(filepath)

    def parse_line(self, line):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            label = parts[0]
            cmd_template = parts[1]
            desc = parts[2] if len(parts) > 2 else cmd_template
        else:
            cmd_template = parts[0]
            label = cmd_template if len(cmd_template) <= 35 else cmd_template[:32] + "..."
            desc = cmd_template
        return label, cmd_template, desc

    def _load_all_profiles(self):
        search_dirs = []
        if hasattr(sys, "_MEIPASS"):
            search_dirs.append(os.path.join(sys._MEIPASS, "profiles"))
        search_dirs.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles"))
        cwd_prof = os.path.join(os.getcwd(), "profiles")
        if cwd_prof not in search_dirs:
            search_dirs.append(cwd_prof)

        self.profiles.clear()
        self.profile_labels.clear()

        for profiles_dir in search_dirs:
            if not os.path.exists(profiles_dir):
                continue
            for fname in sorted(os.listdir(profiles_dir)):
                if fname.endswith(".json"):
                    fpath = os.path.join(profiles_dir, fname)
                    try:
                        prof = CheatSheetProfile.load_json(fpath)
                        if prof.sheet_id not in self.profiles:
                            self.profiles[prof.sheet_id] = prof
                            label = f"{prof.title} ({len(prof.commands)} cmds)"
                            self.profile_labels[label] = prof.sheet_id
                    except Exception as e:
                        print(f"Error loading profile {fpath}: {e}")

        # If general profile is not in profiles, build it from DEFAULT_COMMANDS_FILE
        if "general" not in self.profiles and os.path.exists(DEFAULT_COMMANDS_FILE):
            try:
                gen_prof = CheatSheetProfile(sheet_id="general", title="General Quick Tools", default_file=DEFAULT_COMMANDS_FILE)
                with open(DEFAULT_COMMANDS_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        l = line.strip()
                        if l and not l.startswith("#"):
                            sw, tm, ds = self.parse_line(l)
                            gen_prof.add_command(CommandItem(sw, tm, ds, "Quick Tools"))
                self.profiles["general"] = gen_prof
                label = f"{gen_prof.title} ({len(gen_prof.commands)} cmds)"
                self.profile_labels[label] = "general"
            except Exception:
                pass

        if hasattr(self, "profile_combo"):
            self.profile_combo['values'] = list(self.profile_labels.keys())

    def on_profile_dropdown_change(self, event=None):
        selected_label = self.profile_combo.get()
        sheet_id = self.profile_labels.get(selected_label)
        if sheet_id and sheet_id in self.profiles:
            self.switch_profile(sheet_id)

    def switch_profile(self, sheet_id: str):
        if sheet_id not in self.profiles:
            return
        profile = self.profiles[sheet_id]
        self.current_profile = profile
        self.current_file = profile.default_file or f"profiles/{sheet_id}.json"

        # Update combobox selection
        for lbl, sid in self.profile_labels.items():
            if sid == sheet_id:
                self.profile_combo.set(lbl)
                break

        self.file_label.config(text=f"Active Profile: {profile.title}")
        self.root.title(f"{profile.title} — CLI Quick-Reference & Multi-Cheat Sheet Runner")
        self.render_profile(profile)

    def reload_active(self):
        if self.current_profile:
            self.switch_profile(self.current_profile.sheet_id)
        else:
            self.load_commands(self.current_file)

    def render_profile(self, profile: CheatSheetProfile):
        for widget in self.btn_container.winfo_children():
            widget.destroy()

        # If profile has multiple categories or reference notes, use categorized ttk.Notebook
        if len(profile.categories) > 1 or profile.reference_notes:
            notebook = ttk.Notebook(self.btn_container)
            notebook.pack(fill=tk.BOTH, expand=True)

            # Tab for each category
            for cat in profile.categories:
                cat_cmds = [c for c in profile.commands if c.category == cat]
                tab_frame = ttk.Frame(notebook, padding=4)
                notebook.add(tab_frame, text=f"{cat} ({len(cat_cmds)})")
                self._build_card_grid(tab_frame, cat_cmds)

            # All Commands tab
            all_tab = ttk.Frame(notebook, padding=4)
            notebook.add(all_tab, text=f"All Commands ({len(profile.commands)})")
            self._build_card_grid(all_tab, profile.commands)

            # Tips & Reference Notes tab if available
            if profile.reference_notes:
                ref_tab = ttk.Frame(notebook, padding=6)
                notebook.add(ref_tab, text=f"Reference & Tips ({len(profile.reference_notes)})")

                ref_text = ScrolledText(ref_tab, font=("Consolas", 9), bg="#fdfdfd", fg="#222222", wrap=tk.WORD)
                ref_text.pack(fill=tk.BOTH, expand=True)
                ref_text.insert(tk.END, f"# Reference Notes, Authentication & Setup Details for {profile.title}\n\n")
                for note in profile.reference_notes:
                    ref_text.insert(tk.END, f"• {note}\n")
                ref_text.config(state=tk.DISABLED)

        else:
            # Single category / flat view
            self._build_card_grid(self.btn_container, profile.commands)

        self.refresh_prerequisites(profile)

    def refresh_prerequisites(self, profile=None):
        if profile is None:
            profile = getattr(self, "current_profile", None)
        if not profile or not profile.commands:
            if hasattr(self, "prereq_btn"):
                self.prereq_btn.config(text="Prerequisites: None")
            return

        cmds = [(c.label, c.template, c.description) for c in profile.commands]
        prereqs = PrerequisiteDetector.check_prerequisites_for_commands(cmds)
        self.current_prerequisites = {p.name: p for p in prereqs}

        needs_path = [p for p in prereqs if p.status == "NEEDS_PATH"]
        missing = [p for p in prereqs if p.status in ("MISSING_BOTH", "MISSING_NO_WSL")]
        wsl_ready = [p for p in prereqs if p.status == "READY_WSL"]

        if not hasattr(self, "prereq_btn"):
            return

        if needs_path:
            self.prereq_btn.config(text="Prerequisites: Python needs PATH [Fix]")
        elif missing:
            self.prereq_btn.config(text=f"Prerequisites: {len(missing)} Missing [Setup]")
        elif wsl_ready:
            self.prereq_btn.config(text=f"Prerequisites: Ready ({len(wsl_ready)} via WSL)")
        else:
            self.prereq_btn.config(text=f"Prerequisites: All Ready ({len(prereqs)})")

    def open_prerequisites_dialog(self):
        if not hasattr(self, "current_prerequisites") or not self.current_prerequisites:
            if getattr(self, "current_profile", None):
                self.refresh_prerequisites(self.current_profile)

        dialog = tk.Toplevel(self.root)
        dialog.title("Prerequisites & Dependency Health Check")
        dialog.geometry("740x520")
        dialog.minsize(660, 420)
        dialog.transient(self.root)

        is_wsl, wsl_distro = PrerequisiteDetector.check_wsl_status()

        # Header Frame
        hdr = ttk.Frame(dialog, padding=12)
        hdr.pack(fill=tk.X)

        profile_title = self.current_profile.title if getattr(self, "current_profile", None) else "Active Cheat Sheet"
        ttk.Label(hdr, text=f"Prerequisites for: {profile_title}", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        wsl_status_txt = f"WSL Active ({wsl_distro})" if is_wsl else "WSL Not Detected"
        env_lbl = ttk.Label(hdr, text=f"Platform: Windows  •  {wsl_status_txt}", font=("Segoe UI", 9), foreground="#333333")
        env_lbl.pack(anchor="w", pady=(2, 0))

        # Main Table / Treeview
        tbl_frame = ttk.Frame(dialog, padding=(12, 0, 12, 10))
        tbl_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("tool", "cmds", "win_status", "wsl_status", "execution_mode")
        tree = ttk.Treeview(tbl_frame, columns=columns, show="headings", height=10)
        tree.heading("tool", text="Tool / Executable")
        tree.heading("cmds", text="Used In")
        tree.heading("win_status", text="Windows Status")
        tree.heading("wsl_status", text="WSL Status")
        tree.heading("execution_mode", text="Execution Strategy")

        tree.column("tool", width=120, anchor="w")
        tree.column("cmds", width=70, anchor="center")
        tree.column("win_status", width=210, anchor="w")
        tree.column("wsl_status", width=160, anchor="w")
        tree.column("execution_mode", width=150, anchor="center")

        scrollbar = ttk.Scrollbar(tbl_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def populate_tree():
            for item in tree.get_children():
                tree.delete(item)

            for prereq in sorted(getattr(self, "current_prerequisites", {}).values(), key=lambda x: -x.command_count):
                cmd_txt = f"{prereq.command_count} cmds" if prereq.command_count > 0 else "System Core"

                # Windows text
                if prereq.windows_in_path:
                    win_txt = f"In PATH: {os.path.basename(prereq.windows_path)}"
                elif prereq.windows_path:
                    win_txt = "Found on disk (NOT in PATH!)"
                else:
                    win_txt = "Not Found"

                # WSL text
                if prereq.wsl_path:
                    wsl_txt = f"Installed ({os.path.basename(prereq.wsl_path)})"
                elif prereq.wsl_available:
                    wsl_txt = "Available via apt"
                else:
                    wsl_txt = "No WSL"

                # Mode
                if prereq.status == "READY_WINDOWS":
                    mode_txt = "Native Windows"
                elif prereq.status == "READY_WSL":
                    mode_txt = "WSL Interop (Auto)"
                elif prereq.status == "NEEDS_PATH":
                    mode_txt = "Action: Add to PATH"
                else:
                    mode_txt = "Action: Install Needed"

                tree.insert("", tk.END, values=(prereq.name, cmd_txt, win_txt, wsl_txt, mode_txt))

        populate_tree()

        # Action Button Bar
        btn_box = ttk.Frame(dialog, padding=12)
        btn_box.pack(fill=tk.X)

        # Check if Python or any tool needs PATH
        needs_path_tools = [p for p in getattr(self, "current_prerequisites", {}).values() if p.status == "NEEDS_PATH"]

        def do_add_path():
            if not needs_path_tools:
                messagebox.showinfo("PATH Check", "All detected Windows tools are already in PATH!")
                return
            target = needs_path_tools[0]
            target_dir = os.path.dirname(target.windows_path)
            success = PrerequisiteDetector.add_directory_to_user_path(target_dir)
            if success:
                messagebox.showinfo("PATH Updated", f"Successfully added:\n{target_dir}\nto your User PATH environment variable!\n\nProcess environment refreshed.")
                if getattr(self, "current_profile", None):
                    self.refresh_prerequisites(self.current_profile)
                populate_tree()
            else:
                messagebox.showerror("PATH Error", f"Failed to update PATH for {target_dir}.")

        if needs_path_tools:
            ttk.Button(btn_box, text="Add Python to PATH", command=do_add_path).pack(side=tk.LEFT, padx=4)

        # Install missing tools via WSL
        missing_wsl_tools = [p for p in getattr(self, "current_prerequisites", {}).values() if p.status == "MISSING_BOTH"]

        def do_install_wsl():
            if not missing_wsl_tools:
                messagebox.showinfo("WSL Packages", "No missing tools need installation in WSL.")
                return
            target = missing_wsl_tools[0]
            cmd = target.install_cmd_wsl or f"wsl sudo apt install -y {target.name}"
            self.execute_command(cmd)
            messagebox.showinfo("WSL Installation Started", f"Launched WSL installation for '{target.name}' in console window.\n\nAfter completion, click 'Re-Scan Prerequisites'.")

        if is_wsl and missing_wsl_tools:
            ttk.Button(btn_box, text=f"Install {missing_wsl_tools[0].name} in WSL", command=do_install_wsl).pack(side=tk.LEFT, padx=4)

        def do_rescan():
            if getattr(self, "current_profile", None):
                self.refresh_prerequisites(self.current_profile)
            populate_tree()
            messagebox.showinfo("Scan Complete", "Prerequisites scan updated.")

        ttk.Button(btn_box, text="Re-Scan", command=do_rescan).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_box, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)

    def _build_card_grid(self, parent_container, commands):
        canvas = tk.Canvas(parent_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent_container, orient="vertical", command=canvas.yview)
        grid_frame = ttk.Frame(canvas)

        grid_frame.bind(
            "<Configure>",
            lambda e, c=canvas: c.configure(scrollregion=c.bbox("all"))
        )
        canvas.create_window((0, 0), window=grid_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def _on_mousewheel(event, c=canvas):
            c.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        row, col = 0, 0
        max_cols = 3

        for cmd in commands:
            card = ttk.Frame(grid_frame, padding=6, relief="groove")
            card.grid(row=row, column=col, padx=5, pady=5, sticky="nsew")

            btn = ttk.Button(
                card,
                text=cmd.switch,
                command=lambda ci=cmd: self.on_command_click(ci.switch, ci.template, getattr(ci, "original", ci.template))
            )
            btn.pack(fill=tk.X, pady=(0, 2))

            cmd_lbl = ttk.Label(card, text=cmd.template, font=("Consolas", 8), foreground="#005fb8", wraplength=260)
            cmd_lbl.pack(anchor="w", pady=(0, 2))

            desc_lbl = ttk.Label(card, text=cmd.description, font=("Segoe UI", 8), foreground="#444444", wraplength=260)
            desc_lbl.pack(anchor="w")

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

        for c in range(max_cols):
            grid_frame.columnconfigure(c, weight=1)

    def export_standalone_profile(self):
        if not self.current_profile:
            messagebox.showwarning("No Active Profile", "Please select a cheat sheet profile to export.")
            return

        default_name = f"{self.current_profile.sheet_id}_runner.py"
        filepath = filedialog.asksaveasfilename(
            title=f"Export Standalone Runner: {self.current_profile.title}",
            defaultextension=".py",
            initialfile=default_name,
            filetypes=[("Python Script", "*.py"), ("All Files", "*.*")]
        )
        if not filepath:
            return

        code = StandaloneGenerator.generate_python_code(self.current_profile)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(code)

        messagebox.showinfo(
            "Export Successful",
            f"Successfully exported standalone runner for '{self.current_profile.title}' to:\n\n{filepath}\n\n"
            "This script can be executed independently with zero dependencies (pure Python + Tkinter)!"
        )

    def open_smart_importer(self):
        win = tk.Toplevel(self.root)
        win.title("Import Cheat Sheet (Webpage, HTML, Markdown, or Raw Text)")
        win.geometry("780x560")
        win.transient(self.root)
        win.grab_set()

        ttk.Label(
            win,
            text="Import heterogeneous cheat sheets. The engine detects categories, switches, templates, and descriptions:",
            wraplength=740
        ).pack(anchor="w", padx=12, pady=(10, 4))

        notebook = ttk.Notebook(win, padding=8)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Tab 1: Webpage URL
        url_tab = ttk.Frame(notebook, padding=10)
        notebook.add(url_tab, text="Fetch from URL")

        ttk.Label(url_tab, text="Enter Cheat Sheet Webpage URL (e.g. https://offensiveramen.com/cheatsheets/kismet):").pack(anchor="w", pady=(0, 4))
        url_var = tk.StringVar(value="https://offensiveramen.com/cheatsheets/")
        url_entry = ttk.Entry(url_tab, textvariable=url_var, font=("Consolas", 10), width=65)
        url_entry.pack(fill=tk.X, pady=(0, 10))

        # Tab 2: Raw Text / Markdown / TSV / Key-Value
        text_tab = ttk.Frame(notebook, padding=10)
        notebook.add(text_tab, text="Paste Raw Text / Markdown / Table")

        raw_box = ScrolledText(text_tab, font=("Consolas", 9), height=14)
        raw_box.pack(fill=tk.BOTH, expand=True)

        status_var = tk.StringVar(value="Ready to parse.")
        status_lbl = ttk.Label(win, textvariable=status_var, foreground="#0078d4", wraplength=740)
        status_lbl.pack(anchor="w", padx=12, pady=4)

        def parse_and_verify():
            current_tab = notebook.index(notebook.select())
            profile = None
            confidence = 0.85
            raw_data_rows = None
            detected_headers = None
            applied_rule_name = "Standard (Switch | Example | Description)"

            if current_tab == 0:
                url = url_var.get().strip()
                if not url or (url.startswith("https://offensiveramen.com/cheatsheets/") and len(url) <= 39):
                    messagebox.showwarning("Missing URL", "Please enter a specific cheat sheet URL.", parent=win)
                    return

                status_var.set(f"Fetching {url}...")
                win.update_idletasks()
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 CLI-GUI-Runner/1.0"})
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                        charset = resp.headers.get_content_charset() or "utf-8"
                        html_text = resp.read().decode(charset, errors="replace")

                    sheet_name = url.rstrip("/").split("/")[-1].replace("-", " ").replace("_", " ").title()
                    sheet_id = url.rstrip("/").split("/")[-1].lower()

                    if "cs-sheet" in html_text or "cs-h" in html_text or "<pre" in html_text:
                        profile = OffensiveRamenHTMLParser.parse_html(html_text, sheet_id=sheet_id, title=sheet_name)
                        confidence = 0.95
                        raw_data_rows = [[cmd.switch, cmd.template, cmd.description] for cmd in profile.commands]
                        detected_headers = ["Switch", "Example", "Description"]
                        applied_rule_name = "HTML Cheat Sheet Parser"
                    else:
                        entries = self.extract_commands_from_html(html_text)
                        profile = CheatSheetProfile(sheet_id=sheet_id, title=sheet_name, source=url)
                        for lbl, cmd, dsc in entries:
                            profile.add_command(CommandItem(lbl, cmd, dsc, "General"))
                        confidence = 0.85
                        raw_data_rows = [[lbl, cmd, dsc] for lbl, cmd, dsc in entries]
                        detected_headers = ["Button Label", "Command Template", "Description"]
                        applied_rule_name = "HTML Command Extractor"
                except Exception as e:
                    messagebox.showerror("Fetch Error", f"Failed to fetch webpage:\n{e}", parent=win)
                    status_var.set("Fetch failed.")
                    return
            else:
                raw_text = raw_box.get("1.0", tk.END).strip()
                if not raw_text:
                    messagebox.showwarning("Empty Content", "Please paste cheat sheet content first.", parent=win)
                    return

                sheet_id = "custom_sheet"
                sheet_name = "Custom Cheat Sheet"
                lines = raw_text.splitlines()

                if any("switch:" in l.lower() and "example:" in l.lower() for l in lines):
                    items = KeyValueBlockParser.parse(raw_text)
                    profile = CheatSheetProfile(sheet_id=sheet_id, title=sheet_name)
                    for it in items:
                        profile.add_command(it)
                    confidence = 0.92
                    raw_data_rows = [[it.switch, it.template, it.description] for it in items]
                    detected_headers = ["Switch", "Example", "Description"]
                    applied_rule_name = "Key-Value Block Parser"
                elif any("\t" in l or "|" in l for l in lines):
                    res = TabularColumnMapper.parse_rows(lines)
                    profile = CheatSheetProfile(sheet_id=sheet_id, title=sheet_name)
                    for it in res.items:
                        profile.add_command(it)
                    confidence = res.confidence
                    raw_data_rows = res.raw_rows
                    detected_headers = res.headers
                    applied_rule_name = res.rule_name
                else:
                    entries = self.format_raw_paste_text(raw_text)
                    profile = CheatSheetProfile(sheet_id=sheet_id, title=sheet_name)
                    for lbl, cmd, dsc in entries:
                        profile.add_command(CommandItem(lbl, cmd, dsc, "General"))
                    confidence = 0.80
                    raw_data_rows = [[lbl, cmd, dsc] for lbl, cmd, dsc in entries]
                    detected_headers = ["Button Label", "Command Template", "Description"]
                    applied_rule_name = "Raw Prose Parser"

            if not profile or not profile.commands:
                messagebox.showinfo("No Commands Found", "No valid CLI commands could be identified in the provided source.", parent=win)
                status_var.set("No commands identified.")
                return

            def on_confirmed(verified_profile: CheatSheetProfile):
                prof_path = os.path.join("profiles", f"{verified_profile.sheet_id}.json")
                verified_profile.save_json(prof_path)
                verified_profile.default_file = prof_path
                self._load_all_profiles()
                self.switch_profile(verified_profile.sheet_id)
                win.destroy()
                messagebox.showinfo("Import Successful", f"Imported '{verified_profile.title}' with {len(verified_profile.commands)} command(s)!")

            ParserVerificationDialog(
                win,
                profile,
                confidence=confidence,
                on_confirm=on_confirmed,
                raw_rows=raw_data_rows,
                headers=detected_headers,
                applied_rule_name=applied_rule_name
            )

        btn_bar = ttk.Frame(win, padding=10)
        btn_bar.pack(fill=tk.X)
        ttk.Button(btn_bar, text="Analyze & Verify Parsing...", command=parse_and_verify).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Cancel", command=win.destroy).pack(side=tk.RIGHT)

    def load_commands(self, filepath):
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return

        self.current_file = filepath

        if filepath.endswith(".json"):
            try:
                prof = CheatSheetProfile.load_json(filepath)
                self.profiles[prof.sheet_id] = prof
                self.switch_profile(prof.sheet_id)
                return
            except Exception as e:
                print(f"Error parsing json profile {filepath}: {e}")

        # Parse .txt file, grouping by # === Category === if present
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        sheet_id = os.path.splitext(os.path.basename(filepath))[0].lower()
        title = sheet_id.replace("_", " ").replace("-", " ").title()
        profile = CheatSheetProfile(sheet_id=sheet_id, title=title, default_file=filepath)

        curr_category = "General"
        for line in lines:
            s_line = line.strip()
            if not s_line:
                continue

            if s_line.startswith("# ===") and s_line.endswith("==="):
                curr_category = s_line.replace("# ===", "").replace("===", "").strip()
                continue
            elif s_line.startswith("# •") or s_line.startswith("# -"):
                profile.reference_notes.append(s_line.lstrip("# •-").strip())
                continue
            elif s_line.startswith("#"):
                continue

            label, cmd_template, desc = self.parse_line(s_line)
            profile.add_command(CommandItem(label, cmd_template, desc, curr_category))

        self.profiles[sheet_id] = profile
        lbl = f"{profile.title} ({len(profile.commands)} cmds)"
        self.profile_labels[lbl] = sheet_id
        if hasattr(self, "profile_combo"):
            self.profile_combo['values'] = list(self.profile_labels.keys())
            self.profile_combo.set(lbl)
        self.current_profile = profile
        self.file_label.config(text=f"Loaded: {os.path.basename(filepath)}")
        self.render_profile(profile)

    def on_command_click(self, label, cmd_template, original_template=""):
        from cheatsheet_engine import SectionCommentWorkflowParser

        target_ip = self.target_ip_entry.get().strip() if hasattr(self, "target_ip_entry") else ""
        target_domain = self.target_domain_entry.get().strip() if hasattr(self, "target_domain_entry") else ""
        target_mac = self.target_mac_entry.get().strip() if hasattr(self, "target_mac_entry") else ""
        target_iface = self.target_iface_entry.get().strip() if hasattr(self, "target_iface_entry") else ""

        # Auto-fill using top bar values with original text fallback
        resolved_cmd = SectionCommentWorkflowParser.resolve_target_variables(
            cmd_template,
            target_ip=target_ip,
            target_domain=target_domain,
            target_mac=target_mac,
            target_iface=target_iface,
            original_cmd=original_template or cmd_template
        )

        variables = list(dict.fromkeys(re.findall(r"[<\{]([^>\}\s]+)[>\}]", resolved_cmd)))

        if not variables:
            self.execute_command(resolved_cmd)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Configure: {label}")
        dialog.geometry("540x360")
        dialog.minsize(480, 260)
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Command Template:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(10, 0))
        ttk.Label(dialog, text=resolved_cmd, font=("Consolas", 9), foreground="#005fb8", wraplength=510).pack(anchor="w", padx=12, pady=(2, 8))

        form_frame = ttk.Frame(dialog, padding=12)
        form_frame.pack(fill=tk.BOTH, expand=True)

        entries = {}
        for idx, var_name in enumerate(variables):
            clean_label = var_name.replace("_", " ").title()
            ttk.Label(form_frame, text=f"{clean_label}:").grid(row=idx, column=0, sticky="w", pady=5, padx=(0, 8))
            entry = ttk.Entry(form_frame, width=32)
            entry.grid(row=idx, column=1, sticky="ew", pady=5)
            entries[var_name] = entry
            if idx == 0:
                entry.focus_set()

            var_lower = var_name.lower()
            if any(k in var_lower for k in ("file", "db", "pcap", "kml", "csv", "log", "cap", "script", "wordlist", "cert", "key")):
                def make_file_browse(e=entry):
                    return lambda: (
                        lambda path: (e.delete(0, tk.END), e.insert(0, path)) if path else None
                    )(filedialog.askopenfilename(parent=dialog))
                ttk.Button(form_frame, text="Browse File...", width=12, command=make_file_browse(entry)).grid(row=idx, column=2, padx=(6, 0))
            elif any(k in var_lower for k in ("dir", "folder", "path")):
                def make_dir_browse(e=entry):
                    return lambda: (
                        lambda path: (e.delete(0, tk.END), e.insert(0, path)) if path else None
                    )(filedialog.askdirectory(parent=dialog))
                ttk.Button(form_frame, text="Browse Dir...", width=12, command=make_dir_browse(entry)).grid(row=idx, column=2, padx=(6, 0))

        form_frame.columnconfigure(1, weight=1)

        def submit(event=None):
            final_cmd = resolved_cmd
            for var_name, entry_widget in entries.items():
                val = entry_widget.get().strip()
                if not val:
                    # User requirement: if nothing entered, keep original text
                    val = f"<{var_name}>"
                final_cmd = re.sub(rf"[<{{]{re.escape(var_name)}[>}}]", val, final_cmd)

            dialog.destroy()
            self.execute_command(final_cmd)

        dialog.bind("<Return>", submit)

        btn_frame = ttk.Frame(dialog, padding=12)
        btn_frame.pack(fill=tk.X)
        ttk.Button(btn_frame, text="Run Command", command=submit).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)

    def log_output(self, text):
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)

    def execute_command(self, cmd):
        self.output_area.delete("1.0", tk.END)

        # Automatic Prerequisite & WSL Interop Routing
        exec_mode, resolved_cmd, note = PrerequisiteDetector.resolve_command_execution(
            cmd, getattr(self, "current_prerequisites", None)
        )
        if exec_mode == "wsl":
            cmd = resolved_cmd
            self.log_output(f"[{note}]\n")
        elif exec_mode == "missing":
            self.log_output(f"[Warning]: {note}\n")
            if messagebox.askyesno(
                "Prerequisite Tool Missing",
                f"{note}.\n\nWould you like to open the Prerequisites Helper to install or configure it?"
            ):
                self.open_prerequisites_dialog()
                return

        self.log_output(f"$ {cmd}\n")

        # Check if persistent console mode is enabled (default)
        if getattr(self, "persistent_console_var", None) and self.persistent_console_var.get():
            self.log_output("[Running in persistent console window...]\n" + "-" * 60 + "\n")
            try:
                if os.name == "nt":
                    # cmd.exe /K executes command and remains open, preserving errors and output
                    creation_flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10)
                    self.current_process = subprocess.Popen(
                        ["cmd.exe", "/K", cmd],
                        creationflags=creation_flags
                    )
                elif sys.platform == "darwin":
                    escaped = cmd.replace('"', '\\"')
                    self.current_process = subprocess.Popen(
                        ["osascript", "-e", f'tell application "Terminal" to do script "{escaped}"']
                    )
                else:
                    # Linux terminal emulators
                    launched = False
                    for term in ("x-terminal-emulator", "gnome-terminal", "konsole", "xfce4-terminal", "xterm"):
                        if shutil.which(term):
                            self.current_process = subprocess.Popen([term, "-e", f"bash -c '{cmd}; exec bash'"])
                            launched = True
                            break
                    if not launched:
                        self.current_process = subprocess.Popen(f"{cmd}; exec bash", shell=True)

                self.log_output("[Console window launched. Window remains open after execution.]\n")
                if hasattr(self, "stop_btn"):
                    self.stop_btn.config(state=tk.NORMAL)
            except Exception as e:
                self.log_output(f"\n[Console Launch Error]: {e}\n")
            return

        # Embedded streaming execution
        if self.current_process and self.current_process.poll() is None:
            messagebox.showwarning("Busy", "A command is already running. Stop it or wait for it to finish.")
            return

        self.log_output("-" * 60 + "\n")
        self.stop_btn.config(state=tk.NORMAL)

        def target():
            try:
                self.current_process = subprocess.Popen(
                    cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1
                )
                for line in self.current_process.stdout:
                    self.root.after(0, self.log_output, line)

                rc = self.current_process.wait()
                self.root.after(0, self.log_output, f"\n[Process exited with code {rc}]\n")
            except Exception as e:
                self.root.after(0, self.log_output, f"\n[Execution Error]: {e}\n")
            finally:
                self.root.after(0, lambda: self.stop_btn.config(state=tk.DISABLED))

        threading.Thread(target=target, daemon=True).start()

    def stop_process(self):
        if self.current_process and self.current_process.poll() is None:
            self.current_process.terminate()
            self.log_output("\n[Process terminated by user]\n")


def main():
    try:
        root = tk.Tk()
        app = CommandRunnerGUI(root)
        root.mainloop()
    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        print(f"\n[CLI GUI Runner - Fatal Error]:\n{err_msg}", file=sys.stderr)
        try:
            from tkinter import messagebox
            err_win = tk.Tk()
            err_win.withdraw()
            messagebox.showerror("CLI GUI Runner - Fatal Error", f"Failed to start:\n\n{err_msg}")
            err_win.destroy()
        except Exception:
            pass

        # If running from a console window, pause so the window does not close
        if sys.stdin and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            try:
                print("\nPress Enter to exit...", end="", flush=True)
                sys.stdin.readline()
            except Exception:
                pass
        sys.exit(1)


if __name__ == "__main__":
    main()