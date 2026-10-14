import os
import re
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

__version__ = "0.1.0"

DEFAULT_COMMANDS_FILE = "commands.txt"
PASTE_COMMANDS_PATH = "PasteCommands.txt"

SAMPLE_COMMANDS = """# Format: Button Name | Command Template | Description (Optional)
# Or simply paste raw commands with <variable> or {variable} placeholders!

Ping Host | ping -c 4 <IP_or_Hostname> | Send 4 ICMP echo requests to a target
Port Scan (Nmap) | nmap -sV -p <Port_Range> <Target_IP> | Scan specific ports and detect versions
Find Files by Name | find <Directory> -name "*<Search_Term>*" | Search for files recursively
Check Disk Space | df -h | Show current disk usage (No variables required)
Custom cURL Request | curl -I -X <HTTP_Method> <URL> | Fetch HTTP headers from a URL
"""

SAMPLE_PASTE_FILE = """# === PASTE RAW COMMANDS BELOW ===
# Hardcoded IPs, URLs, Subnets, Ports, Domains, and File Paths will be
# automatically converted into <Variable> placeholders when imported!

# Fast Service Scan
nmap -sV -p 22,80,443 192.168.1.105

# Ping Sweep Subnet
nmap -sn 10.10.14.0/24

# Directory Brute Force
gobuster dir -u https://target-site.com/app -w /usr/share/wordlists/common.txt

# Remote SSH Login
$ ssh root@192.168.1.25 -p 2222

whois example.org # Check domain registration
"""


class CommandRunnerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CLI Quick-Reference GUI Runner")
        self.root.geometry("980x640")
        self.current_process = None
        self.current_file = DEFAULT_COMMANDS_FILE
        self.auto_param_var = tk.BooleanVar(value=True)

        self._ensure_default_files()
        self._build_ui()
        self.load_commands(self.current_file)

    def _ensure_default_files(self):
        if not os.path.exists(DEFAULT_COMMANDS_FILE):
            with open(DEFAULT_COMMANDS_FILE, "w", encoding="utf-8") as f:
                f.write(SAMPLE_COMMANDS.strip() + "\n")

        if not os.path.exists(PASTE_COMMANDS_PATH):
            with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                f.write(SAMPLE_PASTE_FILE.strip() + "\n")

    def _build_ui(self):
        # Top Toolbar
        toolbar = ttk.Frame(self.root, padding=8)
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="Open Cheat Sheet...", command=self.browse_file).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(toolbar, text="Reload File", command=lambda: self.load_commands(self.current_file)).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Import PasteCommands.txt", command=self.import_paste_commands).pack(side=tk.LEFT, padx=4)
        ttk.Button(toolbar, text="Quick Paste Editor...", command=self.open_paste_editor).pack(side=tk.LEFT, padx=4)

        ttk.Checkbutton(
            toolbar,
            text="Auto-detect <Variables>",
            variable=self.auto_param_var
        ).pack(side=tk.LEFT, padx=8)

        self.file_label = ttk.Label(toolbar, text=f"Loaded: {self.current_file}", foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=6)

        self.stop_btn = ttk.Button(toolbar, text="Stop Running Command", command=self.stop_process, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.RIGHT)

        # Main Split Pane (Buttons on top, Terminal output on bottom)
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Scrollable Button Grid Frame
        btn_container = ttk.LabelFrame(paned, text="Available Commands (Click to Configure & Run)", padding=5)
        paned.add(btn_container, weight=1)

        self.canvas = tk.Canvas(btn_container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(btn_container, orient="vertical", command=self.canvas.yview)
        self.button_frame = ttk.Frame(self.canvas)

        self.button_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.create_window((0, 0), window=self.button_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Terminal Output Frame
        term_container = ttk.LabelFrame(paned, text="Live Execution Output", padding=5)
        paned.add(term_container, weight=1)

        self.output_area = ScrolledText(
            term_container, bg="#1e1e1e", fg="#d4d4d4",
            font=("Consolas", 10), insertbackground="white", height=12
        )
        self.output_area.pack(fill=tk.BOTH, expand=True)

    # -------------------------------------------------------------------------
    # Smart Hardcoded Value -> <Variable> Auto-Parameterizer
    # -------------------------------------------------------------------------
    def _auto_parameterize_command(self, cmd):
        """
        Scans a raw CLI command and replaces hardcoded URLs, IPs, subnets,
        ports, MAC addresses, user@host strings, file paths, and domains
        with <Variable> placeholders while keeping the base command intact.
        """
        tokens = cmd.split()
        if len(tokens) <= 1:
            return cmd

        # Keep the first token (the executable itself, e.g. /usr/bin/nmap) untouched
        executable = tokens[0]
        args_str = cmd[len(executable):]

        # Temporarily shield existing <var> or {var} placeholders so regexes don't alter them
        shielded = {}
        def _shield_match(match):
            key = f"__VAR_SHIELD_{len(shielded)}__"
            shielded[key] = match.group(0)
            return key

        args_str = re.sub(r"[<\{][^>\}\s]+[>\}]", _shield_match, args_str)

        # 1. URLs (http:// or https://) -> <URL>
        args_str = re.sub(r"https?://[^\s\"'>]+", "<URL>", args_str)

        # 2. user@host or user@IP -> <Username>@<Target_Host>
        args_str = re.sub(
            r"\b[a-zA-Z0-9._-]+@(?:(?:\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b",
            "<Username>@<Target_Host>",
            args_str
        )

        # 3. IPv4 Subnet CIDR (e.g., 192.168.1.0/24) -> <Subnet_CIDR>
        args_str = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",
            "<Subnet_CIDR>",
            args_str
        )

        # 4. IPv4 with Port (e.g., 10.0.0.1:8080) -> <Target_IP>:<Port>
        args_str = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b",
            "<Target_IP>:<Port>",
            args_str
        )

        # 5. Plain IPv4 Address (e.g., 192.168.1.1) -> <Target_IP>
        args_str = re.sub(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "<Target_IP>",
            args_str
        )

        # 6. MAC Address (e.g., 00:1A:2B:3C:4D:5E) -> <MAC_Address>
        args_str = re.sub(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "<MAC_Address>",
            args_str
        )

        # 7. Explicit Port Flags (e.g., -p 80,443 or --port 8080) -> -p <Port>
        args_str = re.sub(
            r"(\s(?:-p|--port)\s+)(?:\d+(?:[,-]\d+)*)\b",
            r"\1<Port>",
            args_str
        )

        # 8. Unix or Windows File Paths in arguments -> <File_Path>
        args_str = re.sub(
            r"(?<=\s)(?:[a-zA-Z]:\\[^\s\"']+|\.{0,2}/[a-zA-Z0-9._/-]+)",
            "<File_Path>",
            args_str
        )

        # 9. Standalone Domain Names -> <Domain_Name>
        args_str = re.sub(
            r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|mil|io|co|local|lan|internal|info|biz|me|us|uk|ca|de|fr|au|jp)\b",
            "<Domain_Name>",
            args_str,
            flags=re.IGNORECASE
        )

        # Restore previously shielded <var> or {var} placeholders
        for key, original_val in shielded.items():
            args_str = args_str.replace(key, original_val)

        return executable + args_str

    def _normalize_command_string(self, cmd):
        """Strips shell prompts, normalizes [var] to <var>, and optionally auto-parameterizes."""
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
        """Creates a clean, readable button title if none was explicitly provided."""
        if desc and len(desc) <= 28 and not desc.startswith("Execute:"):
            return desc

        tokens = cmd.split()
        if not tokens:
            return "Command"

        base_tool = os.path.basename(tokens[0]).capitalize()
        flags = [t for t in tokens[1:] if t.startswith("-") and len(t) <= 6]
        if flags:
            label = f"{base_tool} ({' '.join(flags[:2])})"
        elif len(tokens) > 1 and not tokens[1].startswith(("<", "{")):
            label = f"{base_tool} {tokens[1]}"
        else:
            label = base_tool

        return label if len(label) <= 32 else label[:29] + "..."

    def format_raw_paste_text(self, raw_text):
        """
        Parses unstructured command lines from PasteCommands.txt and returns a list
        of formatted tuples: (label, cmd_template, description).
        """
        formatted_entries = []
        pending_comment = ""

        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line:
                pending_comment = ""
                continue

            # Ignore header instruction comments, capture single descriptive comments
            if line.startswith("#"):
                comment_body = line.lstrip("#").strip()
                if (
                    not comment_body
                    or comment_body.startswith("===")
                    or "automatically converted into" in comment_body
                    or "Hardcoded IPs, URLs" in comment_body
                ):
                    pending_comment = ""
                else:
                    pending_comment = comment_body
                continue

            # Case 1: Tab-separated (TSV) like Action\tCommand\tDescription
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

            # Case 2: Already pipe-formatted (Label | Command | Description)
            if "|" in line:
                label, cmd_template, desc = self.parse_line(line)
                cmd_template = self._normalize_command_string(cmd_template)
                formatted_entries.append((label, cmd_template, desc))
                pending_comment = ""
                continue

            desc = pending_comment
            pending_comment = ""

            # Case 2: Inline trailing comment (e.g., "whois example.org # Check domain")
            if " #" in line:
                cmd_part, inline_comment = line.split(" #", 1)
                line = cmd_part.strip()
                if not desc:
                    desc = inline_comment.strip()

            # Case 3: "Label : Command" or "Label - Command"
            label = ""
            match_sep = re.match(r"^([A-Za-z0-9\s\(\)_\-]{3,30}?)\s+(?::|-)\s+([a-zA-Z0-9\./~].*)$", line)
            if match_sep and not line.startswith(("http://", "https://")):
                label = match_sep.group(1).strip()
                raw_cmd = match_sep.group(2).strip()
            else:
                raw_cmd = line

            cmd_template = self._normalize_command_string(raw_cmd)

            if not desc:
                desc = f"Template: {cmd_template}"

            if not label:
                label = self._generate_label_from_command(cmd_template, desc)

            formatted_entries.append((label, cmd_template, desc))

        return formatted_entries

    def _read_paste_sources(self, source_path):
        """Reads raw text whether PasteCommands.txt is a single file or a directory."""
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

    def import_paste_commands(self):
        """Parses PasteCommands.txt, converts hardcoded values to <Vars>, appends to commands.txt, and reloads."""
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

        for label, cmd_template, desc in new_entries:
            if cmd_template.lower() in existing_commands:
                skipped_duplicates += 1
                continue
            existing_commands.add(cmd_template.lower())
            lines_to_append.append(f"{label} | {cmd_template} | {desc}")

        if not lines_to_append:
            messagebox.showinfo(
                "Already Imported",
                f"All {skipped_duplicates} command template(s) in '{PASTE_COMMANDS_PATH}' already exist in '{self.current_file}'."
            )
            return

        with open(self.current_file, "a", encoding="utf-8") as f:
            f.write("\n" + "\n".join(lines_to_append) + "\n")

        self.load_commands(self.current_file)

        if os.path.isfile(PASTE_COMMANDS_PATH):
            clear_it = messagebox.askyesno(
                "Import Complete",
                f"Formatted and appended {len(lines_to_append)} command(s) to '{self.current_file}'"
                f" ({skipped_duplicates} duplicate(s) skipped).\n\n"
                f"Clear '{PASTE_COMMANDS_PATH}' for your next batch?"
            )
            if clear_it:
                with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                    f.write("# === PASTE RAW COMMANDS BELOW ===\n\n")

    def open_paste_editor(self):
        """In-app editor for PasteCommands.txt with live preview of auto-detected <Variables>."""
        editor = tk.Toplevel(self.root)
        editor.title(f"Edit & Import {PASTE_COMMANDS_PATH}")
        editor.geometry("720x520")
        editor.transient(self.root)
        editor.grab_set()

        ttk.Label(
            editor,
            text="Paste raw CLI commands below. Hardcoded IPs, URLs, Ports, Paths, and Domains will be turned into <Variables>:",
            wraplength=690
        ).pack(anchor="w", padx=10, pady=(10, 5))

        text_box = ScrolledText(editor, font=("Consolas", 10), height=14)
        text_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        ttk.Label(editor, text="Preview of Formatted Output for commands.txt:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=10, pady=(5, 2))
        preview_box = ScrolledText(editor, font=("Consolas", 9), height=7, bg="#f4f6f8", fg="#004578")
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
            filetypes=[("Text Files", "*.txt *.md *.conf"), ("All Files", "*.*")]
        )
        if filepath:
            self.current_file = filepath
            self.file_label.config(text=f"Loaded: {os.path.basename(filepath)}")
            self.load_commands(filepath)

    def parse_line(self, line):
        """Parses either 'Label | Command | Desc' or a raw command string."""
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

    def load_commands(self, filepath):
        for widget in self.button_frame.winfo_children():
            widget.destroy()

        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return

        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        row, col = 0, 0
        max_cols = 3

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            label, cmd_template, desc = self.parse_line(line)

            card = ttk.Frame(self.button_frame, padding=6, relief="groove")
            card.grid(row=row, column=col, padx=6, pady=6, sticky="nsew")

            btn = ttk.Button(
                card, text=label,
                command=lambda c=cmd_template, l=label: self.on_command_click(l, c)
            )
            btn.pack(fill=tk.X, pady=(0, 3))

            desc_lbl = ttk.Label(card, text=desc, font=("Segoe UI", 8), foreground="#555555", wraplength=250)
            desc_lbl.pack(anchor="w")

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

        for c in range(max_cols):
            self.button_frame.columnconfigure(c, weight=1)

    def on_command_click(self, label, cmd_template):
        variables = list(dict.fromkeys(re.findall(r"[<\{]([^>\}\s]+)[>\}]", cmd_template)))

        if not variables:
            if messagebox.askyesno("Execute Command", f"Run command immediately?\n\n{cmd_template}"):
                self.execute_command(cmd_template)
            return

        dialog = tk.Toplevel(self.root)
        dialog.title(f"Configure: {label}")
        dialog.geometry("460x340")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Template:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(10, 0))
        ttk.Label(dialog, text=cmd_template, font=("Consolas", 9), foreground="#005fb8", wraplength=430).pack(anchor="w", padx=12, pady=(0, 10))

        form_frame = ttk.Frame(dialog, padding=12)
        form_frame.pack(fill=tk.BOTH, expand=True)

        entries = {}
        for idx, var_name in enumerate(variables):
            clean_label = var_name.replace("_", " ")
            ttk.Label(form_frame, text=f"{clean_label}:").grid(row=idx, column=0, sticky="w", pady=5, padx=(0, 10))
            entry = ttk.Entry(form_frame, width=35)
            entry.grid(row=idx, column=1, sticky="ew", pady=5)
            entries[var_name] = entry
            if idx == 0:
                entry.focus_set()

        form_frame.columnconfigure(1, weight=1)

        def submit(event=None):
            final_cmd = cmd_template
            for var_name, entry_widget in entries.items():
                val = entry_widget.get().strip()
                if not val:
                    messagebox.showwarning("Missing Input", f"Please provide a value for '{var_name}'.", parent=dialog)
                    return
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
        if self.current_process and self.current_process.poll() is None:
            messagebox.showwarning("Busy", "A command is already running. Stop it or wait for it to finish.")
            return

        self.output_area.delete("1.0", tk.END)
        self.log_output(f"$ {cmd}\n" + "-" * 60 + "\n")
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


if __name__ == "__main__":
    root = tk.Tk()
    app = CommandRunnerGUI(root)
    root.mainloop()