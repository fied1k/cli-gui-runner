#!/usr/bin/env python3
"""Prerequisite & Dependency Detection Engine for CLI GUI Runner.

Scans cheat sheet commands to identify required executables and verifies
system availability across:
1. Native Windows PATH and local installations (with automatic PATH repair).
2. Windows Subsystem for Linux (WSL) interop and package availability.
3. Automated execution routing (auto-wrapping in WSL when native Windows binary is absent).
"""

import glob
import os
import re
import shutil
import subprocess
import sys
from typing import Dict, List, Optional, Tuple

# Common system built-ins or generic shell commands that don't need standalone tool verification
SHELL_BUILTINS = {
    "cd", "echo", "cat", "ls", "ll", "dir", "grep", "egrep", "fgrep", "awk", "sed",
    "cut", "tr", "sort", "uniq", "wc", "head", "tail", "less", "more", "tee",
    "xargs", "chmod", "chown", "mkdir", "rmdir", "cp", "mv", "rm", "touch",
    "clear", "cls", "ping", "ip", "ifconfig", "route", "df", "du", "free", "stat",
    "stat", "stat", "sudo", "doas", "time", "watch", "nohup", "export", "set", "env",
    "source", "exec", "sh", "bash", "zsh", "cmd", "powershell", "pwsh", "wsl", "exit"
}

# Package mapping for common security & networking tools in WSL (Ubuntu / Debian apt)
APT_PACKAGE_MAP = {
    "bettercap": "bettercap",
    "nmap": "nmap",
    "tshark": "tshark",
    "wireshark": "wireshark",
    "aircrack-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "airmon-ng": "aircrack-ng",
    "hashcat": "hashcat",
    "john": "john",
    "hydra": "hydra",
    "dnswalk": "dnswalk",
    "dnsrecon": "dnsrecon",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "masscan": "masscan",
    "tcpdump": "tcpdump",
    "curl": "curl",
    "wget": "wget",
    "netcat": "netcat-traditional",
    "nc": "netcat-traditional",
    "ncat": "ncat",
    "socat": "socat",
    "hping3": "hping3",
    "scapy": "python3-scapy",
    "kismet": "kismet",
    "metasploit": "metasploit-framework",
    "msfconsole": "metasploit-framework",
    "python": "python3",
    "python3": "python3",
    "pip": "python3-pip",
    "pip3": "python3-pip"
}

# Windows Winget package IDs
WINGET_PACKAGE_MAP = {
    "nmap": "Insecure.Nmap",
    "wireshark": "WiresharkFoundation.Wireshark",
    "tshark": "WiresharkFoundation.Wireshark",
    "python": "Python.Python.3.12",
    "python3": "Python.Python.3.12",
    "git": "Git.Git",
    "curl": "cURL.cURL",
    "hashcat": "hashcat.hashcat"
}


class ToolPrerequisite:
    """Represents a prerequisite tool required by commands."""

    def __init__(self, name: str, command_count: int = 1):
        self.name = name.lower()
        self.command_count = command_count

        # Windows status
        self.windows_path: Optional[str] = None
        self.windows_in_path: bool = False
        self.windows_found_unpathed: Optional[str] = None

        # WSL status
        self.wsl_available: bool = False
        self.wsl_distro: Optional[str] = None
        self.wsl_path: Optional[str] = None

        # Calculated strategy
        self.status: str = "UNKNOWN"  # READY_WINDOWS, READY_WSL, NEEDS_PATH, MISSING_BOTH, MISSING_NO_WSL
        self.execution_mode: str = "native"  # "native", "wsl", "unresolved"
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

            # Strip leading comment prefixes or variable markers
            cmd_clean = template.strip()
            # Remove environment prefixes or wrappers
            cmd_clean = re.sub(r"^(?:sudo|doas|nohup|time|exec|watch|env)\s+", "", cmd_clean, flags=re.I)

            # Match first command token
            tokens = cmd_clean.split()
            if not tokens:
                continue

            first_tok = tokens[0].strip().strip("<>{}[]()\"'")
            # If path, extract basename
            base_exe = os.path.basename(first_tok).lower()
            base_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", base_exe)

            if not base_exe or base_exe in SHELL_BUILTINS or re.match(r"^[\-=+./\\]+$", base_exe):
                # Check second token if first was a flag or shell wrapper
                if len(tokens) > 1 and tokens[1].lower() not in SHELL_BUILTINS:
                    alt_exe = os.path.basename(tokens[1].strip("<>{}[]()\"'")).lower()
                    alt_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", alt_exe)
                    if alt_exe and alt_exe not in SHELL_BUILTINS and not alt_exe.startswith("-"):
                        base_exe = alt_exe
                    else:
                        continue
                else:
                    continue

            # If it's a python script, python itself is the required tool
            if base_exe.endswith(".py") or ".py" in cmd_clean:
                tool_counts["python"] = tool_counts.get("python", 0) + 1
                continue

            tool_counts[base_exe] = tool_counts.get(base_exe, 0) + 1

        # Always include python if any caplet or python file is in commands
        return tool_counts

    @classmethod
    def check_wsl_status(cls, force_refresh: bool = False) -> Tuple[bool, str]:
        """Checks if Windows Subsystem for Linux (WSL) is installed, enabled, and responsive."""
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
            # Check wsl --status with short timeout
            res = subprocess.run(
                ["wsl.exe", "--status"],
                capture_output=True,
                text=False,
                timeout=3.0
            )
            # WSL --status returns UTF-16 LE encoded text
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
            # Fallback check: try wsl.exe -l -q
            try:
                res2 = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=2.0)
                out = res2.stdout.decode("utf-16-le", errors="ignore").strip()
                if out:
                    distro = out.splitlines()[0].strip()
                    cls._wsl_status_cache = (True, distro)
                    return cls._wsl_status_cache
            except Exception:
                pass

            cls._wsl_status_cache = (False, "")
            return cls._wsl_status_cache

    @classmethod
    def check_tool_in_wsl(cls, tool_name: str) -> Optional[str]:
        """Checks if a tool executable exists inside the default WSL environment."""
        clean_name = tool_name.lower().strip()
        if clean_name in cls._wsl_tool_cache:
            return cls._wsl_tool_cache[clean_name]

        is_wsl, _ = cls.check_wsl_status()
        if not is_wsl:
            cls._wsl_tool_cache[clean_name] = None
            return None

        # Resolve aliases in linux (e.g. python -> python3)
        linux_bin = APT_PACKAGE_MAP.get(clean_name, clean_name)
        if linux_bin == "python3-pip":
            linux_bin = "pip3"
        elif linux_bin == "python3-scapy":
            linux_bin = "scapy"

        try:
            res = subprocess.run(
                ["wsl.exe", "-e", "which", linux_bin],
                capture_output=True,
                text=True,
                timeout=3.0
            )
            if res.returncode == 0 and res.stdout.strip():
                path = res.stdout.strip().splitlines()[0]
                cls._wsl_tool_cache[clean_name] = path
                return path
        except Exception:
            pass

        cls._wsl_tool_cache[clean_name] = None
        return None

    @classmethod
    def find_python_installations_windows(cls) -> List[str]:
        """Finds Python installations on Windows, including those not currently in PATH."""
        found_paths = []
        seen = set()

        # 1. Current sys.executable
        if sys.executable and os.path.isfile(sys.executable):
            norm = os.path.normcase(os.path.abspath(sys.executable))
            found_paths.append(sys.executable)
            seen.add(norm)

        # 2. PATH lookups
        for name in ("python", "python3", "py"):
            path = shutil.which(name)
            if path and os.path.isfile(path):
                norm = os.path.normcase(os.path.abspath(path))
                if norm not in seen:
                    found_paths.append(path)
                    seen.add(norm)

        # 3. Known root directories on Windows
        candidate_patterns = [
            r"C:\Python3*",
            r"C:\Program Files\Python*",
            r"C:\Program Files (x86)\Python*",
            os.path.expandvars(r"%LOCALAPPDATA%\Programs\Python\Python*")
        ]

        for pattern in candidate_patterns:
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
        """Verifies if a specific directory exists in the active Windows PATH."""
        norm_target = os.path.normcase(os.path.normpath(directory))
        raw_path = os.environ.get("PATH", "")
        for item in raw_path.split(os.pathsep):
            if item.strip() and os.path.normcase(os.path.normpath(item.strip())) == norm_target:
                return True
        return False

    @classmethod
    def add_directory_to_user_path(cls, directory: str) -> bool:
        """Persistently appends directory to User PATH in Windows Registry and updates current process."""
        if os.name != "nt":
            return False

        directory = os.path.abspath(directory)
        scripts_dir = os.path.join(directory, "Scripts") if os.path.isdir(os.path.join(directory, "Scripts")) else ""

        try:
            import winreg
            import ctypes

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    current_path, reg_type = winreg.QueryValueEx(key, "Path")
                except FileNotFoundError:
                    current_path = ""
                    reg_type = winreg.REG_EXPAND_SZ

                paths = [p.strip() for p in current_path.split(";") if p.strip()]
                norm_paths = [os.path.normcase(os.path.normpath(p)) for p in paths]

                added = False
                for target in (directory, scripts_dir):
                    if target and os.path.normcase(os.path.normpath(target)) not in norm_paths:
                        paths.append(target)
                        norm_paths.append(os.path.normcase(os.path.normpath(target)))
                        added = True

                if added:
                    new_val = ";".join(paths)
                    winreg.SetValueEx(key, "Path", 0, reg_type, new_val)

            # Update running process environment
            for target in (directory, scripts_dir):
                if target and not cls.is_directory_in_windows_path(target):
                    os.environ["PATH"] = target + os.pathsep + os.environ.get("PATH", "")

            # Broadcast WM_SETTINGCHANGE
            HWND_BROADCAST = 0xFFFF
            WM_SETTINGCHANGE = 0x001A
            SMTO_ABORTIFHUNG = 0x0002
            result = ctypes.c_ulong()
            ctypes.windll.user32.SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                "Environment",
                SMTO_ABORTIFHUNG,
                1000,
                ctypes.byref(result)
            )
            return True
        except Exception as e:
            print(f"[PrerequisiteDetector] Error setting PATH: {e}", file=sys.stderr)
            return False

    @classmethod
    def inspect_tool(cls, tool_name: str, command_count: int = 1) -> ToolPrerequisite:
        """Evaluates tool availability on Windows, local unpathed disks, and inside WSL."""
        prereq = ToolPrerequisite(tool_name, command_count)
        is_wsl, distro = cls.check_wsl_status()
        prereq.wsl_available = is_wsl
        prereq.wsl_distro = distro

        # 1. Check Native Windows PATH
        win_which = shutil.which(tool_name) or shutil.which(f"{tool_name}.exe")
        if win_which:
            prereq.windows_path = win_which
            prereq.windows_in_path = True
            prereq.status = "READY_WINDOWS"
            prereq.execution_mode = "native"
            return prereq

        # Special check for Python on Windows
        if tool_name in ("python", "python3", "py"):
            py_installs = cls.find_python_installations_windows()
            if py_installs:
                prereq.windows_found_unpathed = py_installs[0]
                pydir = os.path.dirname(py_installs[0])
                if cls.is_directory_in_windows_path(pydir):
                    prereq.windows_path = py_installs[0]
                    prereq.windows_in_path = True
                    prereq.status = "READY_WINDOWS"
                    prereq.execution_mode = "native"
                    return prereq
                else:
                    # Python exists on disk but is not in user/system PATH
                    prereq.windows_path = py_installs[0]
                    prereq.windows_in_path = False
                    prereq.status = "NEEDS_PATH"
                    prereq.execution_mode = "native"
                    return prereq

        # 2. Check WSL Interop
        if is_wsl:
            wsl_bin = cls.check_tool_in_wsl(tool_name)
            if wsl_bin:
                prereq.wsl_path = wsl_bin
                prereq.status = "READY_WSL"
                prereq.execution_mode = "wsl"
                return prereq

        # 3. Tool is not installed on Windows or in WSL
        # Provide suggested install actions
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
        """Audits all tools needed for a given set of cheat sheet commands."""
        tool_counts = cls.extract_required_tools(commands)

        # Ensure Python is always checked as an essential runner dependency
        if "python" not in tool_counts:
            tool_counts["python"] = 0

        results = []
        for tool_name, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
            prereq = cls.inspect_tool(tool_name, count)
            results.append(prereq)

        return results

    @classmethod
    def resolve_command_execution(cls, cmd: str, prereq_cache: Optional[Dict[str, ToolPrerequisite]] = None) -> Tuple[str, str, str]:
        """
        Determines execution route for a given command.
        Returns (execution_mode, final_command_string, note).
        execution_mode: "native", "wsl", or "missing"
        """
        if os.name != "nt":
            return ("native", cmd, "")

        # Extract primary tool
        clean = re.sub(r"^(?:sudo|doas|nohup|time|exec|watch|env)\s+", "", cmd.strip(), flags=re.I)
        tokens = clean.split()
        if not tokens:
            return ("native", cmd, "")

        first_tok = tokens[0].strip().strip("<>{}[]()\"'")
        base_exe = os.path.basename(first_tok).lower()
        base_exe = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", base_exe)

        if base_exe in SHELL_BUILTINS:
            # Check second token
            if len(tokens) > 1 and tokens[1].lower() not in SHELL_BUILTINS:
                alt = os.path.basename(tokens[1].strip("<>{}[]()\"'")).lower()
                alt = re.sub(r"\.(?:exe|bat|cmd|ps1|sh)$", "", alt)
                if alt and not alt.startswith("-"):
                    base_exe = alt

        prereq = None
        if prereq_cache and base_exe in prereq_cache:
            prereq = prereq_cache[base_exe]
        else:
            prereq = cls.inspect_tool(base_exe)

        if prereq.status == "READY_WINDOWS":
            return ("native", cmd, f"Tool '{base_exe}' running via Windows PATH")
        elif prereq.status == "READY_WSL":
            # Auto-wrap in WSL
            wsl_cmd = f"wsl {cmd}"
            return ("wsl", wsl_cmd, f"Tool '{base_exe}' detected in WSL ({prereq.wsl_distro}) - executing via WSL interop")
        elif prereq.status == "NEEDS_PATH":
            return ("native", cmd, f"Tool '{base_exe}' found at {prereq.windows_path} (Add to PATH for best performance)")
        else:
            return ("missing", cmd, f"Prerequisite tool '{base_exe}' is not installed on Windows or in WSL")
