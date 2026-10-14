#!/usr/bin/env python3
"""
CLI Cheat Sheet Scraper & Command Extractor

Scrapes cheat sheets and documentation web pages for CLI commands, switches,
and descriptions, parameterizes placeholders, and exports them into the
standard format used by CLI-GUI-Runner (Button Name | Command Template | Description),
saving to a text file named after the command (e.g., nmap.txt).
"""

import argparse
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

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
    "whoami", "last", "w", "env", "export", "alias", "history", "ffmpeg", "exiftool",
    "aircrack-ng", "airodump-ng", "airmon-ng", "hashcat", "evil-winrm", "searchsploit"
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


class CheatsheetExtractor(HTMLParser):
    """
    Parses an HTML cheat sheet or documentation page to extract CLI commands,
    switches, headings, and descriptions.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignore_tags = {"script", "style", "noscript", "svg", "head", "nav", "footer"}
        self.ignore_depth = 0

        self.page_title = ""
        self.in_title = False
        self.title_buf = []

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

        # List of raw candidate dicts
        self.candidates = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self.in_title = True
            self.title_buf = []
            return

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
            self.current_cell_is_th = (tag == "th")
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
        if tag == "title":
            self.in_title = False
            self.page_title = " ".join("".join(self.title_buf).split()).strip()
            return

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
            raw_heading = " ".join("".join(self.heading_buf).split()).strip()
            # Strip trailing anchor marks (#, ¶, §, :) commonly found in headers
            cleaned_heading = re.sub(r"[\s#¶§:]+$", "", raw_heading).strip()
            if cleaned_heading:
                self.current_heading = cleaned_heading
                self.last_prose = ""

        elif tag in ("pre", "code", "kbd", "samp") and self.in_code:
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
            is_th = getattr(self, "current_cell_is_th", False)
            self.tr_cells.append((cell_text, cell_codes, is_th))

        elif tag == "tr" and self.in_tr:
            self.in_tr = False
            self._process_table_row(self.tr_cells)

        elif tag in ("p", "li", "dt", "dd") and self.in_block:
            self.in_block = False
            full_text = " ".join("".join(self.block_buf).split()).strip()
            if self.block_codes:
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
        if self.in_title:
            self.title_buf.append(data)
            return

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
        """Extracts command/switch + description pairs from HTML table rows."""
        if not cells:
            return

        # Skip rows where all cells are header <th> cells
        if all(cell[2] for cell in cells):
            return

        # Case 1: At least one cell explicitly wrapped code/switches in <code>
        code_cell_idx = -1
        for idx, (text, codes, is_th) in enumerate(cells):
            if codes:
                code_cell_idx = idx
                break

        if code_cell_idx != -1:
            codes = cells[code_cell_idx][1]
            other_texts = [t for i, (t, _, _) in enumerate(cells) if i != code_cell_idx and t]
            desc = " - ".join(other_texts) if other_texts else self.current_heading
            label = other_texts[0] if other_texts and len(other_texts[0]) <= 35 else self.current_heading
            for code_str in codes:
                self._process_code_block(code_str, label, desc)
            return

        # Case 2: Plain-text table row where one cell is command/switch and another is description
        if len(cells) >= 2:
            c0, c1 = cells[0][0], cells[1][0]
            header_terms = {
                "option", "options", "command", "commands", "flag", "flags",
                "switch", "switches", "syntax", "parameter", "parameters",
                "name", "action", "description", "desc", "details", "summary",
                "meaning", "example", "arguments"
            }
            if c0.lower() in header_terms and c1.lower() in header_terms:
                return

            if c0 and c1:
                self.candidates.append({
                    "raw_line": f"{c1} | {c0} | {c1}",
                    "is_table_fallback": True,
                    "c0": c0,
                    "c1": c1,
                    "heading": self.current_heading
                })

    def _process_code_block(self, raw_code, heading_context, prose_context):
        """Splits single or multi-line code blocks into individual command candidates."""
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

            # Handle inline trailing comments (e.g. nmap <target> # Basic scan)
            if " #" in line:
                cmd_part, comment_part = line.split(" #", 1)
                line = cmd_part.strip()
                if not inline_comment_desc:
                    inline_comment_desc = comment_part.strip()

            desc = inline_comment_desc or prose_context or heading_context
            label = inline_comment_desc or heading_context
            inline_comment_desc = ""

            self.candidates.append({
                "cmd": line,
                "label": label,
                "desc": desc,
                "heading": heading_context
            })


def is_strict_cli_token(token):
    """
    Returns True if a token has unambiguous CLI syntax:
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


def is_switch_token(token):
    """Checks if a string looks like a standalone CLI switch (e.g. -sV, --script=vuln, -p-)."""
    clean = token.strip()
    if re.search(r"\s{2,}|\t", clean):
        return False
    return bool(re.match(r"^-{1,2}[A-Za-z0-9_\-]+(?:=[^\s]+|\s+<[^>]+>|\s+\[[^\]]+\]|\s+[A-Za-z0-9_.\-]+)?$", clean))


def looks_like_valid_cli(cmd_str, batch_executables=None, primary_cmd=None):
    """
    Validates whether an extracted code snippet is an actual CLI invocation
    or switch rather than programming language code, HTML, or prose.
    """
    cmd = re.sub(r"^(?:\$|#|root@[^\s:#]+[:#]|user@[^\s:$]+[\$])\s+", "", cmd_str.strip())
    if not cmd or len(cmd) < 2 or len(cmd) > 260:
        return False

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

    first = tokens[0].lower()
    if first in COMMAND_PREFIXES and len(tokens) > 1:
        first = tokens[1].lower()

    # If it is a switch and we know the primary command, it is valid
    if is_switch_token(tokens[0]):
        return True

    base_exe = os.path.basename(first)
    if not re.match(r"^[a-z0-9_.\-]+$", base_exe) or base_exe.startswith("-"):
        return False

    is_known = (base_exe in KNOWN_CLI_TOOLS) or (batch_executables and base_exe in batch_executables)
    if primary_cmd and base_exe == primary_cmd.lower():
        is_known = True

    has_cli_args = any(is_strict_cli_token(t) for t in tokens[1:])

    if is_known and (len(tokens) >= 2 or base_exe in (
        "df", "free", "top", "htop", "ps", "ls", "whoami", "id", "ipconfig",
        "ifconfig", "netstat", "ss", "history"
    )):
        return True

    if has_cli_args and base_exe not in ENGLISH_PROSE_WORDS and tokens[0] == tokens[0].lower():
        return True

    return False


def detect_primary_command(candidates, url="", title=""):
    """
    Detects the main command executable (e.g., 'nmap', 'curl') for the cheat sheet
    based on frequency in candidates, URL path slug, and page title.
    """
    counts = {}

    for item in candidates:
        cmd_candidate = item.get("cmd", "") or item.get("c0", "") or item.get("c1", "")
        clean = re.sub(r"^(?:\$|#|root@[^\s:#]+[:#]|user@[^\s:$]+[\$])\s+", "", cmd_candidate.strip())
        tokens = clean.split()
        if not tokens:
            continue
        first = tokens[0].lower()
        if first in COMMAND_PREFIXES and len(tokens) > 1:
            first = tokens[1].lower()
        base = os.path.basename(first)
        if base in KNOWN_CLI_TOOLS:
            counts[base] = counts.get(base, 0) + 3
        elif re.match(r"^[a-z0-9_\-]+$", base) and not base.startswith("-") and base not in ENGLISH_PROSE_WORDS:
            counts[base] = counts.get(base, 0) + 1

    # Check URL slug (e.g., /cheatsheets/nmap -> nmap)
    if url:
        parsed_url = urllib.parse.urlparse(url)
        path_parts = [p.lower() for p in parsed_url.path.strip("/").split("/") if p]
        for part in reversed(path_parts):
            clean_part = re.sub(r"[-_]?(?:cheatsheet|cheat-sheet|sheet|commands?)$", "", part)
            if clean_part in KNOWN_CLI_TOOLS:
                counts[clean_part] = counts.get(clean_part, 0) + 10
            elif clean_part and clean_part not in ENGLISH_PROSE_WORDS:
                counts[clean_part] = counts.get(clean_part, 0) + 4

    # Check Title
    if title:
        title_tokens = re.findall(r"[a-zA-Z0-9_\-]+", title.lower())
        for tok in title_tokens:
            if tok in KNOWN_CLI_TOOLS:
                counts[tok] = counts.get(tok, 0) + 8

    if not counts:
        return "command"

    # Return the executable with the highest score
    sorted_cmds = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return sorted_cmds[0][0]


def detect_batch_executables(lines):
    """
    Pass 1: Scans lines to discover which command executables are being invoked
    based on repetition and CLI context.
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
            if is_strict_cli_token(next_tok):
                has_cli_context = True
                context_scores[clean] = context_scores.get(clean, 0) + 6
            elif re.match(r"^[a-z0-9_\-]+$", next_tok) and is_strict_cli_token(next2_tok):
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


def split_label_command_desc(line, batch_executables):
    """
    Locates the invoked command using batch context, treating everything
    before it as the Label, and everything after arguments as Description.
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

        if is_strict_cli_token(next_tok):
            score += 12
        elif re.match(r"^[a-z0-9_\-]+$", next_tok) and is_strict_cli_token(next2_tok):
            score += 8

        if prev_tok in COMMAND_PREFIXES or tok.startswith("$"):
            score += 10

        if base_name in ENGLISH_PROSE_WORDS and base_name not in KNOWN_CLI_TOOLS and not is_strict_cli_token(next_tok):
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

        if is_strict_cli_token(tok):
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

        if j + 1 < n and is_strict_cli_token(tokens[j + 1]):
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


def auto_parameterize_command(cmd):
    """
    Replaces hardcoded IP addresses, subnets, ports, domains, filepaths,
    and URLs with standardized placeholders (<Target_IP>, <Port>, etc.).
    """
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

    # Preserve already parameterized placeholders <var> or {var}
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


def normalize_command_string(cmd, auto_param=True):
    """Cleans up shell prompt prefixes, normalizes brackets, and auto-parameterizes."""
    cmd = re.sub(r"^[\$>]\s+", "", cmd.strip())
    cmd = re.sub(r"\[([A-Za-z0-9_\-]+)\]", r"<\1>", cmd)
    if auto_param:
        cmd = auto_parameterize_command(cmd)
    return cmd.strip()


def generate_label_from_command(cmd, desc="", heading=""):
    """Generates a concise, meaningful button label (~32 chars max)."""
    # 1. If description is concise, use it
    if desc and not desc.startswith("Template:"):
        clean_desc = re.sub(r"[\s#¶§:]+$", "", desc).strip()
        if len(clean_desc) <= 32:
            return clean_desc
        # Try cutting at the first comma or dash if that makes a clean concise label
        first_part = re.split(r"[,;–—\-]|\s*\(", clean_desc)[0].strip()
        if 4 <= len(first_part) <= 32:
            return first_part

    # 2. If heading is concise and clean, use it
    if heading:
        clean_h = re.sub(r"[\s#¶§:]+$", "", heading).strip()
        if clean_h and len(clean_h) <= 32:
            return clean_h

    # 3. Derive from command and flags
    tokens = cmd.split()
    if not tokens:
        return "Command"

    idx = 1 if tokens[0].lower() in COMMAND_PREFIXES and len(tokens) > 1 else 0
    base_tool = os.path.basename(tokens[idx]).capitalize()
    flags = [t for t in tokens[idx + 1:] if t.startswith("-") and len(t) <= 8]
    if flags:
        label = f"{base_tool} ({' '.join(flags[:2])})"
    elif len(tokens) > idx + 1 and not tokens[idx + 1].startswith(("<", "{")):
        label = f"{base_tool} {tokens[idx + 1]}"
    else:
        label = base_tool

    return label if len(label) <= 32 else label[:29] + "..."


def parse_webpage(html_content, url="", auto_param=True):
    """
    Main extraction pipeline:
    Parses HTML content, determines primary command executable, extracts
    commands and switches, auto-parameterizes variables, and formats entries.

    Returns: (primary_command, list_of_tuples[(label, cmd, desc)])
    """
    parser = CheatsheetExtractor()
    parser.feed(html_content)

    primary_cmd = detect_primary_command(parser.candidates, url=url, title=parser.page_title)

    # Gather raw command lines to run batch repetition detection
    raw_cmd_lines = []
    for item in parser.candidates:
        if "cmd" in item:
            raw_cmd_lines.append(item["cmd"])
        elif item.get("is_table_fallback"):
            raw_cmd_lines.extend([item["c0"], item["c1"]])

    batch_executables = detect_batch_executables(raw_cmd_lines)
    if primary_cmd and primary_cmd not in batch_executables:
        batch_executables[primary_cmd] = 50

    extracted = []
    seen_cmds = set()

    for item in parser.candidates:
        heading = item.get("heading", "")
        if item.get("is_table_fallback"):
            c0, c1 = item["c0"], item["c1"]
            if looks_like_valid_cli(c0, batch_executables, primary_cmd) and not looks_like_valid_cli(c1, batch_executables, primary_cmd):
                raw_cmd, desc, label = c0, c1, ""
            elif looks_like_valid_cli(c1, batch_executables, primary_cmd) and not looks_like_valid_cli(c0, batch_executables, primary_cmd):
                raw_cmd, desc, label = c1, c0, c0 if len(c0) <= 32 else ""
            else:
                continue
        else:
            raw_cmd = item["cmd"]
            label = item.get("label", "")
            desc = item.get("desc", "")

        # Clean shell prompts
        clean_cmd = re.sub(r"^(?:\$|#|root@[^\s:#]+[:#]|user@[^\s:$]+[\$])\s+", "", raw_cmd.strip())

        # Check if the line is a switch followed by multiple spaces/tabs and a description
        # e.g.: -t THREADS      Number of threads (default 10)
        switch_desc_match = re.match(r"^(-{1,2}[A-Za-z0-9_\-]+(?:\s+[A-Z0-9_<>{}\[\]]+)?)\s{2,}(.+)$", clean_cmd)
        if switch_desc_match:
            switch_part = switch_desc_match.group(1).strip()
            desc_part = switch_desc_match.group(2).strip()
            switch_part = re.sub(r"\s+([A-Z0-9_]{2,})\b", r" <\1>", switch_part)
            clean_cmd = f"{primary_cmd} {switch_part} <target>"
            label = desc_part if len(desc_part) <= 32 else switch_part
            desc = desc_part
        elif is_switch_token(clean_cmd) and not clean_cmd.startswith(primary_cmd):
            # Synthesize: e.g. "nmap -sV <target>"
            switch_part = clean_cmd
            clean_cmd = f"{primary_cmd} {switch_part} <target>"
            if not label or label == heading:
                label = switch_part

        # If not already a valid CLI token or command, attempt splitting
        if not looks_like_valid_cli(clean_cmd, batch_executables, primary_cmd):
            lbl_part, split_cmd, dsc_part = split_label_command_desc(clean_cmd, batch_executables)
            if split_cmd and looks_like_valid_cli(split_cmd, batch_executables, primary_cmd):
                clean_cmd = split_cmd
                if lbl_part and not label:
                    label = lbl_part
                if dsc_part and not desc:
                    desc = dsc_part
            else:
                continue

        cmd_template = normalize_command_string(clean_cmd, auto_param=auto_param)
        if not cmd_template or cmd_template.lower() in seen_cmds:
            continue
        seen_cmds.add(cmd_template.lower())

        # Clean pipe characters so they don't break the 3-column delimiter
        label = (label or "").replace("|", "-").strip()
        desc = (desc or "").replace("|", "-").strip()
        heading = (heading or "").replace("|", "-").strip()

        # Clean trailing anchor symbols (#, ¶, etc.)
        label = re.sub(r"[\s#¶§:]+$", "", label).strip()
        desc = re.sub(r"[\s#¶§:]+$", "", desc).strip()
        heading = re.sub(r"[\s#¶§:]+$", "", heading).strip()

        # Generate label if missing or too long
        if not label or len(label) > 34 or label.endswith("#"):
            label = generate_label_from_command(cmd_template, desc=desc, heading=heading)
        if not desc:
            desc = label if label else f"Template: {cmd_template}"

        extracted.append((label, cmd_template, desc))

    return primary_cmd, extracted


def fetch_url(url, timeout=15):
    """Fetches HTML content from a URL with custom User-Agent and relaxed SSL context."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CLI-Cheatsheet-Scraper/1.0"
        }
    )
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        charset = resp.headers.get_content_charset() or "utf-8"
        raw_bytes = resp.read()
        return raw_bytes.decode(charset, errors="replace"), url


def save_commands_file(output_path, primary_cmd, source_url, entries):
    """Writes the parsed commands into the standard 3-column format."""
    lines = [
        "# Format: Button Name | Command Template | Description (Optional)",
        f"# Scraped from {source_url}",
        f"# Command: {primary_cmd}",
        ""
    ]
    for label, cmd, desc in entries:
        lines.append(f"{label} | {cmd} | {desc}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run_gui_prompt():
    """Fallback / optional GUI prompt using Tkinter if requested or double-clicked."""
    try:
        import tkinter as tk
        from tkinter import simpledialog, messagebox
    except ImportError:
        print("Tkinter is not available on this Python installation.", file=sys.stderr)
        return None

    root = tk.Tk()
    root.withdraw()
    url = simpledialog.askstring(
        "CLI Cheat Sheet Scraper",
        "Enter website URL to scrape (e.g., https://offensiveramen.com/cheatsheets/nmap):",
        parent=root
    )
    root.destroy()
    return url.strip() if url else None


def main():
    parser = argparse.ArgumentParser(
        description="Scrape CLI cheat sheets into CLI-GUI-Runner compatible command files."
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="URL of the cheat sheet / documentation page to scrape"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Output text file path (defaults to <command>.txt in the current directory)"
    )
    parser.add_argument(
        "--no-auto-param",
        action="store_true",
        help="Disable automatic parameterization of hardcoded IPs, ports, and domains into <Variables>"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Prompt for URL using a graphical dialog box"
    )

    args = parser.parse_args()

    url = args.url
    if args.gui:
        url = run_gui_prompt()
        if not url:
            print("Operation cancelled.")
            return 0
    elif not url:
        # Interactive CLI prompt
        print("=" * 65)
        print("   CLI Cheat Sheet Scraper & Command Extractor")
        print("=" * 65)
        try:
            url_input = input("Enter website URL (e.g., https://offensiveramen.com/cheatsheets/nmap):\n> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            return 1
        if not url_input:
            print("No URL provided. Exiting.")
            return 1
        url = url_input

    print(f"\n[*] Fetching and parsing: {url}")
    try:
        html_content, final_url = fetch_url(url)
    except Exception as e:
        print(f"[!] Error fetching URL: {e}", file=sys.stderr)
        return 1

    auto_param = not args.no_auto_param
    primary_cmd, entries = parse_webpage(html_content, url=final_url, auto_param=auto_param)

    if not entries:
        print("[!] No CLI commands could be identified on that page.", file=sys.stderr)
        return 1

    # Output filename defaults to <primary_cmd>.txt
    output_filename = args.output
    if not output_filename:
        output_filename = f"{primary_cmd}.txt"

    save_commands_file(output_filename, primary_cmd, final_url, entries)

    print(f"[+] Successfully extracted {len(entries)} commands for '{primary_cmd}'!")
    print(f"[+] Saved to: {os.path.abspath(output_filename)}\n")
    print("--- First 5 Extracted Commands Preview ---")
    for lbl, cmd, dsc in entries[:5]:
        print(f"  {lbl} | {cmd} | {dsc}")
    if len(entries) > 5:
        print(f"  ... and {len(entries) - 5} more entries.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
