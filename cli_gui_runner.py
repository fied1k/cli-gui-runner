"""CLI Quick-Reference GUI Runner

A graphical user interface for launching parameterized commands, running cheat-sheet
scripts, and monitoring terminal output in real-time.
"""

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
# Supported raw formats that will be auto-formatted into commands.txt:
# 1. Comment line directly above a command:
#    # Traceroute to a host
#    traceroute <Target_Host>
#
# 2. Inline comments:
#    whois <Domain_Name> # Lookup domain registration info
#
# 3. Colon or Dash labeled lines:
#    DNS Lookup - nslookup <Domain_Name>
#
# 4. Raw commands (with <var>, {var}, or [var] placeholders):
#    $ ssh [Username]@<Server_IP> -p {Port}

# Traceroute to Host
traceroute <Target_Host>

whois <Domain_Name> # Lookup domain registration info
$ ssh [Username]@<Server_IP> -p {Port}
"""


class CommandRunnerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CLI Quick-Reference GUI Runner")
        self.root.geometry("920x620")
        self.current_process = None
        self.current_file = DEFAULT_COMMANDS_FILE

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

        ttk.Button(toolbar, text="Open Cheat Sheet...", command=self.browse_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(toolbar, text="Reload File", command=lambda: self.load_commands(self.current_file)).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Import PasteCommands.txt", command=self.import_paste_commands).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="Quick Paste Editor...", command=self.open_paste_editor).pack(side=tk.LEFT, padx=5)

        self.file_label = ttk.Label(toolbar, text=f"Loaded: {self.current_file}", foreground="gray")
        self.file_label.pack(side=tk.LEFT, padx=10)

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
    # Parsing & Import Pipelines
    # -------------------------------------------------------------------------
    def _normalize_command_string(self, cmd):
        """Strips shell prompts and converts [var] placeholders to <var>."""
        cmd = re.sub(r"^[\$>]\s+", "", cmd.strip())
        cmd = re.sub(r"\[([A-Za-z0-9_\-]+)\]", r"<\1>", cmd)
        return cmd.strip()

    def _generate_label_from_command(self, cmd, desc=""):
        """Creates a clean, readable button title if none was explicitly provided."""
        if desc and len(desc) <= 28 and desc != cmd:
            return desc

        tokens = cmd.split()
        if not tokens:
            return "Command"

        base_tool = os.path.basename(tokens[0]).capitalize()
        flags = [t for t in tokens[1:] if t.startswith("-") and len(t) <= 6]
        if flags:
            label = f"{base_tool} ({' '.join(flags[:2])})"
        elif len(tokens) > 1 and not tokens[1].startswith("<") and not tokens[1].startswith("{"):
            label = f"{base_tool} {tokens[1]}"
        else:
            label = base_tool

        return label if len(label) <= 32 else label[:29] + "..."

    def format_raw_paste_text(self, raw_text):
        """
        Parses unstructured command lines from PasteCommands.txt or clipboard
        and returns a list of formatted tuples: (label, cmd_template, description).
        Supports TSV, Pipe-delimited, Colon/Hyphen, and raw commands.
        """
        formatted_entries = []
        pending_comment = ""

        for raw_line in raw_text.splitlines():
            line = raw_line.strip()
            if not line:
                pending_comment = ""
                continue

            # Ignore template header comments, but capture single descriptive comments
            if line.startswith("#"):
                comment_body = line.lstrip("#").strip()
                if (
                    not comment_body
                    or comment_body.startswith("===")
                    or comment_body.lower().startswith("supported raw formats")
                    or comment_body.startswith("1.")
                    or comment_body.startswith("2.")
                    or comment_body.startswith("3.")
                    or comment_body.startswith("4.")
                    or comment_body in (
                        "Traceroute to Host",
                        "traceroute <Target_Host>",
                        "whois <Domain_Name> # Lookup domain registration info",
                        "$ ssh [Username]@<Server_IP> -p {Port}"
                    )
                ):
                    pending_comment = ""
                else:
                    pending_comment = comment_body
                continue

            # Case 1: Tab-separated (TSV) like Action\tCommand\tDescription
            if "\t" in line:
                parts = [p.strip() for p in line.split("\t") if p.strip()]
                if len(parts) >= 2:
                    # Ignore table header if present
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

            # Case 3: Inline trailing comment (e.g., "nmap -sV <IP> # Version scan")
            if " #" in line:
                cmd_part, inline_comment = line.split(" #", 1)
                line = cmd_part.strip()
                if not desc:
                    desc = inline_comment.strip()

            # Case 4: "Label : Command" or "Label - Command"
            label = ""
            match_sep = re.match(r"^([A-Za-z0-9\s\(\)_\-]{3,30}?)\s+(?::|-)\s+([a-zA-Z0-9\./~].*)$", line)
            if match_sep and not line.startswith(("http://", "https://")):
                label = match_sep.group(1).strip()
                cmd_template = self._normalize_command_string(match_sep.group(2))
            else:
                cmd_template = self._normalize_command_string(line)

            if not desc:
                desc = f"Execute: {cmd_template}"

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
        """Parses PasteCommands.txt, formats entries, appends to commands.txt, and reloads UI."""
        raw_text = self._read_paste_sources(PASTE_COMMANDS_PATH)
        if not raw_text.strip():
            messagebox.showinfo("Import", f"'{PASTE_COMMANDS_PATH}' is empty or does not exist.")
            return

        formatted = self.format_raw_paste_text(raw_text)
        if not formatted:
            messagebox.showwarning("Import", "No valid commands could be extracted.")
            return

        target_file = self.current_file if self.current_file else DEFAULT_COMMANDS_FILE
        try:
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(f"\n# --- Imported from {os.path.basename(PASTE_COMMANDS_PATH)} ---\n")
                for label, cmd, desc in formatted:
                    f.write(f"{label} | {cmd} | {desc}\n")

            messagebox.showinfo(
                "Import Successful",
                f"Successfully parsed and appended {len(formatted)} command(s) to '{os.path.basename(target_file)}'."
            )
            self.load_commands(target_file)
        except Exception as e:
            messagebox.showerror("Import Error", f"Failed to save imported commands: {e}")

    def open_paste_editor(self):
        """Opens a quick text editor window to paste or edit commands directly."""
        editor = tk.Toplevel(self.root)
        editor.title("Quick Paste Editor (PasteCommands.txt)")
        editor.geometry("700x500")
        editor.transient(self.root)

        top_info = ttk.Label(
            editor,
            text="Paste raw cheat sheets, TSV tables, or command lists below.\n"
                 "Formats supported: TSV, 'Label | Command | Desc', '# Comment \\n cmd', 'cmd # note', etc.",
            padding=8,
            justify=tk.LEFT
        )
        top_info.pack(fill=tk.X)

        text_box = ScrolledText(editor, wrap=tk.WORD, font=("Consolas", 10), height=18)
        text_box.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        current_content = self._read_paste_sources(PASTE_COMMANDS_PATH)
        if current_content:
            text_box.insert("1.0", current_content)

        def save_and_import():
            new_text = text_box.get("1.0", tk.END).strip()
            if not new_text:
                messagebox.showwarning("Warning", "Editor is empty.", parent=editor)
                return
            try:
                with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                    f.write(new_text + "\n")
                editor.destroy()
                self.import_paste_commands()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}", parent=editor)

        def save_only():
            new_text = text_box.get("1.0", tk.END).strip()
            try:
                with open(PASTE_COMMANDS_PATH, "w", encoding="utf-8") as f:
                    f.write(new_text + "\n")
                messagebox.showinfo("Saved", f"Saved changes to {PASTE_COMMANDS_PATH}.", parent=editor)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}", parent=editor)

        btn_bar = ttk.Frame(editor, padding=8)
        btn_bar.pack(fill=tk.X)
        ttk.Button(btn_bar, text="Format & Import into Cheat Sheet", command=save_and_import).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Save File", command=save_only).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_bar, text="Cancel", command=editor.destroy).pack(side=tk.LEFT, padx=5)

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

            desc_lbl = ttk.Label(card, text=desc, font=("Segoe UI", 8), foreground="#555555", wraplength=230)
            desc_lbl.pack(anchor="w")

            col += 1
            if col >= max_cols:
                col = 0
                row += 1

        for c in range(max_cols):
            self.button_frame.columnconfigure(c, weight=1)

    def on_command_click(self, label, cmd_template):
        # Extract variables inside <var> or {var}
        variables = list(dict.fromkeys(re.findall(r"[<\{]([^>\}\s]+)[>\}]", cmd_template)))

        if not variables:
            # Direct execution with confirmation
            if messagebox.askyesno("Execute Command", f"Run command immediately?\n\n{cmd_template}"):
                self.execute_command(cmd_template)
            return

        # Modal dialog prompting for each detected variable
        dialog = tk.Toplevel(self.root)
        dialog.title(f"Configure: {label}")
        dialog.geometry("450x320")
        dialog.transient(self.root)
        dialog.grab_set()

        ttk.Label(dialog, text="Template:", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(10, 0))
        ttk.Label(dialog, text=cmd_template, font=("Consolas", 9), foreground="#005fb8", wraplength=420).pack(anchor="w", padx=12, pady=(0, 10))

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
                # Replace both <var> and {var} occurrences
                var_pattern = r"[<{]" + re.escape(var_name) + r"[>}]"
                final_cmd = re.sub(var_pattern, val, final_cmd)

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


def main():
    root = tk.Tk()
    app = CommandRunnerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()