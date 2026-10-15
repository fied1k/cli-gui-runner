#!/usr/bin/env python3
"""Prerequisite & Dependency Detection Engine for CLI GUI Runner.

High-performance, non-blocking scanner that verifies required tools across:
1. Native Windows PATH and local installations (with automatic PATH repair).
2. Windows Subsystem for Linux (WSL) interop (with zero window popups & batch queries).
3. Automated execution routing (auto-wrapping in WSL when native binary is absent).
"""

import glob
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

SHELL_BUILTINS = {
    "cd", "echo", "cat", "ls", "ll", "dir", "grep", "egrep", "fgrep", "awk", "sed",
    "cut", "tr", "sort", "uniq", "wc", "head", "tail", "less", "more", "tee",
    "xargs", "chmod", "chown", "mkdir", "rmdir", "cp", "mv", "rm", "touch",
    "clear", "cls", "ping", "ip", "ifconfig", "route", "df", "du", "free",
    "sudo", "doas", "time", "watch", "nohup", "export", "set", "env",
    "source", "exec", "sh", "bash", "zsh", "cmd", "powershell", "pwsh", "wsl", "exit"
}

APT_PACKAGE_MAP = {
    "bettercap": "bettercap", "nmap": "nmap", "tshark": "tshark", "wireshark": "wireshark",
    "aircrack-ng": "aircrack-ng", "airodump-ng": "aircrack-ng", "aireplay-ng": "aircrack-ng",
    "hashcat": "hashcat", "john": "john", "hydra": "hydra", "dnswalk": "dnswalk",
    "dnsrecon": "dnsrecon", "nikto": "nikto", "sqlmap": "sqlmap", "gobuster": "gobuster",
    "ffuf": "ffuf", "masscan": "masscan", "tcpdump": "tcpdump", "curl": "curl",
    "wget": "wget", "netcat": "netcat-traditional", "nc": "netcat-traditional",
    "ncat": "ncat", "socat": "socat", "kismet": "kismet", "python": "python3",
    "python3": "python3", "pip": "python3-pip", "pip3": "python3-pip"
}

WINGET_PACKAGE_MAP = {
    "nmap": "Insecure.Nmap", "wireshark": "WiresharkFoundation.Wireshark",
    "tshark": "WiresharkFoundation.Wireshark", "python": "Python.Python.3.12",
    "python3": "Python.Python.3.12", "git": "Git.Git", "curl": "cURL.cURL",
    "hashcat": "hashcat.hashcat"
}


def _run_hidden_subprocess(cmd: List[str], timeout: float = 2.5, text: bool = True):
    """Executes command with console window completely suppressed on Windows."""
    creationflags = 0
    startupinfo = None
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)
        startupinfo.wShowWindow = 0  # SW_HIDE
    return subprocess.run(
        cmd,
        capture_output=True,
        text=text,
        timeout=timeout,
        creationflags=creationflags,
        startupinfo=startupinfo
    )


class ToolPrerequisite:
    """Represents a prerequisite tool required by commands."""

    def __init__(self, name: str, command_count: int = 1):
        self.name = name.lower()
        self.command_count = command_count
        self.windows_path: Optional[str] = None
        self.windows_in_path: bool = False
        self.windows_found_unpathed: Optional[str] = None
        self.wsl_available: bool = False
        self.wsl_distro: Optional[str] = None
        self.wsl_path: Optional[str] = None
        self.status: str = "UNKNOWN"
        self.execution_mode: str = "native"
        self.install_cmd_wsl: Optional[str] = None
        self.install_cmd_winget: Optional[str] = None

    def __repr__(self):
        return f"<ToolPrerequisite {self.name}: {self.status} (Mode: {self.execution_mode})>"


class PrerequisiteDetector:
    """Detects required tools, scans Windows PATH and WSL, and offers PATH repair."""

    _wsl_status_cache: Optional[Tuple[bool, str]] = None
    _wsl_tool_cache: Dict[str, Optional[str]] = {}

    @classmethod
    def extract_required_tools(cls, commands: List[Tuple[str, str, str]]) -> Dict[str, int]:
        """Scans (label, template, desc) command tuples and tallies primary tool executables."""
        tool_counts: Dict[str, int] = {}
        for _, template, _ in commands:
            if not template or not template.strip():
                continue
            cmd_clean = re.sub(r"^(?:sudo|doas|nohup|time|exec|watch|env)\s+", "", template.strip(), flags=re.I)
            tokens = cmd_clean.split()
            if not tokens:
                continue

            first_tok = tokens[0].strip().strip("<>{}[]()\"'")
            base_exe = os.path.basename(first_tok).lower()
            base_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", base_exe)

            if not base_exe or base_exe in SHELL_BUILTINS or re.match(r"^[\-=+./\\]+$", base_exe):
                if len(tokens) > 1 and tokens[1].lower() not in SHELL_BUILTINS:
                    alt_exe = os.path.basename(tokens[1].strip("<>{}[]()\"'")).lower()
                    alt_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", alt_exe)
                    if alt_exe and alt_exe not in SHELL_BUILTINS and not alt_exe.startswith("-"):
                        base_exe = alt_exe
                    else:
                        continue
                else:
                    continue

            if base_exe.endswith(".py") or ".py" in cmd_clean:
                tool_counts["python"] = tool_counts.get("python", 0) + 1
                continue

            tool_counts[base_exe] = tool_counts.get(base_exe, 0) + 1
        return tool_counts

    @classmethod
    def check_wsl_status(cls, force_refresh: bool = False) -> Tuple[bool, str]:
        """Checks if WSL is installed and active without popping up any console window."""
        if cls._wsl_status_cache is not None and not force_refresh:
            return cls._wsl_status_cache

        if os.name != "nt":
            cls._wsl_status_cache = (False, "")
            return cls._wsl_status_cache

        wsl_bin = shutil.which("wsl") or shutil.which("wsl.exe")
        if not wsl_bin:
            cls._wsl_status_cache = (False, "")
            return cls._wsl_status_cache

        try:
            res = _run_hidden_subprocess(["wsl.exe", "--status"], timeout=2.0, text=False)
            output_str = ""
            for encoding in ("utf-16-le", "utf-8", "latin1"):
                try:
                    output_str = res.stdout.decode(encoding)
                    if "Default" in output_str or "Distribution" in output_str:
                        break
                except Exception:
                    continue

            distro = "Ubuntu"
            match = re.search(r"Default Distribution:\s*([^\r\n]+)", output_str, re.I)
            if match:
                distro = match.group(1).strip()
            is_working = res.returncode == 0 or "Distribution" in output_str
            cls._wsl_status_cache = (is_working, distro)
            return cls._wsl_status_cache
        except Exception:
            cls._wsl_status_cache = (False, "")
            return cls._wsl_status_cache

    @classmethod
    def batch_check_tools_in_wsl(cls, tool_names: List[str]) -> Dict[str, Optional[str]]:
        """Batches multiple tool lookups into a single hidden WSL process."""
        results = {}
        missing = [t.lower().strip() for t in tool_names if t.lower().strip() not in cls._wsl_tool_cache]
        for t in tool_names:
            clean = t.lower().strip()
            if clean in cls._wsl_tool_cache:
                results[clean] = cls._wsl_tool_cache[clean]

        if not missing:
            return results

        is_wsl, _ = cls.check_wsl_status()
        if not is_wsl:
            for t in missing:
                cls._wsl_tool_cache[t] = None
                results[t] = None
            return results

        linux_bins = [APT_PACKAGE_MAP.get(t, t) for t in missing]
        safe_bins = [b for b in linux_bins if re.match(r"^[a-zA-Z0-9_\-]+$", b)]
        if not safe_bins:
            for t in missing:
                cls._wsl_tool_cache[t] = None
                results[t] = None
            return results

        try:
            res = _run_hidden_subprocess(["wsl.exe", "-e", "which"] + safe_bins, timeout=2.5)
            found_paths = [p.strip() for p in res.stdout.splitlines() if p.strip()]
            found_map = {os.path.basename(p).lower(): p for p in found_paths}

            for orig_t in missing:
                mapped = APT_PACKAGE_MAP.get(orig_t, orig_t).lower()
                path = found_map.get(mapped)
                cls._wsl_tool_cache[orig_t] = path
                results[orig_t] = path
        except Exception:
            for t in missing:
                cls._wsl_tool_cache[t] = None
                results[t] = None

        return results

    @classmethod
    def check_tool_in_wsl(cls, tool_name: str) -> Optional[str]:
        clean_name = tool_name.lower().strip()
        if clean_name in cls._wsl_tool_cache:
            return cls._wsl_tool_cache[clean_name]
        res = cls.batch_check_tools_in_wsl([clean_name])
        return res.get(clean_name)

    @classmethod
    def find_python_installations_windows(cls) -> List[str]:
        found_paths, seen = [], set()
        for cand in [sys.executable, shutil.which("python"), shutil.which("python3"), shutil.which("py")]:
            if cand and os.path.isfile(cand):
                norm = os.path.normcase(os.path.abspath(cand))
                if norm not in seen:
                    found_paths.append(cand)
                    seen.add(norm)

        for pattern in (r"C:\Python3*", r"C:\Program Files\Python*", os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python*")):
            for pdir in glob.glob(pattern):
                exe = os.path.join(pdir, "python.exe")
                if os.path.isfile(exe):
                    norm = os.path.normcase(os.path.abspath(exe))
                    if norm not in seen:
                        found_paths.append(exe)
                        seen.add(norm)
        return found_paths

    @classmethod
    def is_directory_in_windows_path(cls, directory: str) -> bool:
        norm_target = os.path.normcase(os.path.normpath(directory))
        return any(os.path.normcase(os.path.normpath(p.strip())) == norm_target for p in os.environ.get("PATH", "").split(os.pathsep) if p.strip())

    @classmethod
    def add_directory_to_user_path(cls, directory: str) -> bool:
        if os.name != "nt":
            return False
        directory = os.path.abspath(directory)
        scripts_dir = os.path.join(directory, "Scripts") if os.path.isdir(os.path.join(directory, "Scripts")) else ""
        try:
            import winreg, ctypes
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    current_path, reg_type = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current_path, reg_type = "", winreg.REG_EXPAND_SZ

                paths = [p.strip() for p in current_path.split(";") if p.strip()]
                norm_paths = [os.path.normcase(os.path.normpath(p)) for p in paths]

                added = False
                for target in (directory, scripts_dir):
                    if target and os.path.normcase(os.path.normpath(target)) not in norm_paths:
                        paths.append(target)
                        norm_paths.append(os.path.normcase(os.path.normpath(target)))
                        added = True
                if added:
                    winreg.SetValueEx(key, "Path", 0, reg_type, ";".join(paths))

            for target in (directory, scripts_dir):
                if target and not cls.is_directory_in_windows_path(target):
                    os.environ["PATH"] = target + os.pathsep + os.environ.get("PATH", "")

            result = ctypes.c_ulong()
            ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, "Environment", 0x0002, 1000, ctypes.byref(result))
            return True
        except Exception as e:
            print(f"[PrerequisiteDetector] Error setting PATH: {e}", file=sys.stderr)
            return False

    @classmethod
    def inspect_tool(cls, tool_name: str, command_count: int = 1) -> ToolPrerequisite:
        prereq = ToolPrerequisite(tool_name, command_count)
        is_wsl, distro = cls.check_wsl_status()
        prereq.wsl_available = is_wsl
        prereq.wsl_distro = distro

        win_which = shutil.which(tool_name) or shutil.which(f"{tool_name}.exe")
        if win_which:
            prereq.windows_path = win_which
            prereq.windows_in_path = True
            prereq.status = "READY_WINDOWS"
            prereq.execution_mode = "native"
            return prereq

        if tool_name in ("python", "python3", "py"):
            py_installs = cls.find_python_installations_windows()
            if py_installs:
                prereq.windows_found_unpathed = py_installs[0]
                prereq.windows_path = py_installs[0]
                if cls.is_directory_in_windows_path(os.path.dirname(py_installs[0])):
                    prereq.windows_in_path = True
                    prereq.status = "READY_WINDOWS"
                else:
                    prereq.windows_in_path = False
                    prereq.status = "NEEDS_PATH"
                prereq.execution_mode = "native"
                return prereq

        if is_wsl:
            wsl_bin = cls.check_tool_in_wsl(tool_name)
            if wsl_bin:
                prereq.wsl_path = wsl_bin
                prereq.status = "READY_WSL"
                prereq.execution_mode = "wsl"
                return prereq

        if is_wsl:
            pkg = APT_PACKAGE_MAP.get(tool_name, tool_name)
            prereq.install_cmd_wsl = f"wsl sudo apt update && wsl sudo apt install -y {pkg}"
            prereq.status = "MISSING_BOTH"
        else:
            prereq.status = "MISSING_NO_WSL"

        if tool_name in WINGET_PACKAGE_MAP:
            prereq.install_cmd_winget = f"winget install {WINGET_PACKAGE_MAP[tool_name]}"

        prereq.execution_mode = "unresolved"
        return prereq

    @classmethod
    def check_prerequisites_for_commands(cls, commands: List[Tuple[str, str, str]]) -> List[ToolPrerequisite]:
        tool_counts = cls.extract_required_tools(commands)
        if "python" not in tool_counts:
            tool_counts["python"] = 0

        # Batch check in WSL in 1 single hidden process
        cls.batch_check_tools_in_wsl(list(tool_counts.keys()))

        results = []
        for tool_name, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            results.append(cls.inspect_tool(tool_name, count))
        return results

    @classmethod
    def resolve_command_execution(cls, cmd: str, prereq_cache: Optional[Dict[str, ToolPrerequisite]] = None) -> Tuple[str, str, str]:
        if os.name != "nt":
            return ("native", cmd, "")

        clean = re.sub(r"^(?:sudo|doas|nohup|time|exec|watch|env)\s+", "", cmd.strip(), flags=re.I)
        tokens = clean.split()
        if not tokens:
            return ("native", cmd, "")

        first_tok = tokens[0].strip().strip("<>{}[]()\"'")
        base_exe = os.path.basename(first_tok).lower()
        base_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", base_exe)

        if base_exe in SHELL_BUILTINS and len(tokens) > 1 and tokens[1].lower() not in SHELL_BUILTINS:
            alt = os.path.basename(tokens[1].strip("<>{}[]()\"'")).lower()
            alt = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", alt)
            if alt and not alt.startswith("-"):
                base_exe = alt

        prereq = (prereq_cache or {}).get(base_exe) or cls.inspect_tool(base_exe)
        if prereq.status == "READY_WINDOWS":
            return ("native", cmd, f"Tool '{base_exe}' running via Windows PATH")
        elif prereq.status == "READY_WSL":
            return ("wsl", f"wsl {cmd}", f"Tool '{base_exe}' detected in WSL ({prereq.wsl_distro}) - executing via WSL interop")
        elif prereq.status == "NEEDS_PATH":
            return ("native", cmd, f"Tool '{base_exe}' found at {prereq.windows_path} (Add to PATH for best performance)")
        else:
            return ("missing", cmd, f"Prerequisite tool '{base_exe}' is not installed on Windows or in WSL")
