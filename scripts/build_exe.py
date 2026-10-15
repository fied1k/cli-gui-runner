#!/usr/bin/env python3
"""Build Standalone Windows Executable for CLI GUI Runner.

Compiles cli_gui_runner.py into a single, self-contained Windows executable
(CliGuiRunner.exe) with all default profiles, caplets, and assets bundled.
Copies the built executable directly into the local project root.
"""

import os
import shutil
import subprocess
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def kill_running_instances():
    """Terminate running CliGuiRunner.exe instances so files are not locked."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/f", "/im", "CliGuiRunner.exe"],
                capture_output=True,
                check=False
            )
        except Exception:
            pass


def build_standalone_exe():
    print("==> Compiling standalone Windows executable (CliGuiRunner.exe)...")
    kill_running_instances()

    # Ensure dependencies and directories
    dist_dir = os.path.join(ROOT_DIR, "dist")
    build_dir = os.path.join(ROOT_DIR, "build")

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        "--name",
        "CliGuiRunner",
        "--add-data",
        f"profiles{os.pathsep}profiles",
        "--add-data",
        f"caplets{os.pathsep}caplets",
        "--add-data",
        f"commands.txt{os.pathsep}.",
        "--add-data",
        f"bettercap.txt{os.pathsep}.",
        "cli_gui_runner.py",
    ]

    result = subprocess.run(cmd, cwd=ROOT_DIR)
    if result.returncode != 0:
        raise RuntimeError("PyInstaller compilation failed!")

    source_exe = os.path.join(dist_dir, "CliGuiRunner.exe")
    target_exe = os.path.join(ROOT_DIR, "CliGuiRunner.exe")

    kill_running_instances()

    if os.path.isfile(source_exe):
        try:
            shutil.copy2(source_exe, target_exe)
        except PermissionError:
            kill_running_instances()
            import time
            time.sleep(1)
            shutil.copy2(source_exe, target_exe)
        size_mb = os.path.getsize(target_exe) / (1024 * 1024)
        print(f"[OK] Standalone executable compiled and saved to local folder:")
        print(f"     Path: {target_exe} ({size_mb:.2f} MB)")
        return target_exe
    else:
        raise FileNotFoundError(f"Expected compiled binary not found at {source_exe}")


if __name__ == "__main__":
    build_standalone_exe()
