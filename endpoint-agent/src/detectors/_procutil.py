"""Helpers shared by the process-watching detectors.

Everything here is best-effort and wrapped in try/except: inspecting other processes
can fail on permissions, and a failure must never crash a detector.
"""
from __future__ import annotations


import hashlib
import os
import subprocess
import sys
from pathlib import Path

import psutil

# Processes legitimately allowed to touch the Chrome credential stores.
WHITELIST_PROC_NAMES = {
    "google chrome",
    "google chrome helper",
    "google chrome helper (renderer)",
    "google chrome helper (gpu)",
    "chrome",
    "chrome.exe",
    "chromium",
    "brave browser",
    "brave",
    # macOS system services that legitimately poke at preference/keychain files
    "cfprefsd",
    "mds",
    "mds_stores",
    "mdworker",
    "mdworker_shared",
    "spotlight",
    "securityd",
    "trustd",
    "backupd",
    # Windows system
    "system",
    "svchost.exe",
    "searchindexer.exe",
    "msmpeng.exe",
}

_MAX_HASH_BYTES = 50 * 1024 * 1024  # do not hash anything bigger than 50 MB


def chrome_base_dirs() -> list[Path]:
    """Root 'User Data' dirs for Chromium-family browsers, per OS."""
    home = Path.home()
    dirs: list[Path] = []
    if sys.platform == "darwin":
        appsup = home / "Library" / "Application Support"
        dirs += [
            appsup / "Google" / "Chrome",
            appsup / "Google" / "Chrome Beta",
            appsup / "BraveSoftware" / "Brave-Browser",
            appsup / "Microsoft Edge",
        ]
    elif sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        dirs += [
            local / "Google" / "Chrome" / "User Data",
            local / "BraveSoftware" / "Brave-Browser" / "User Data",
            local / "Microsoft" / "Edge" / "User Data",
        ]
    else:
        dirs += [home / ".config" / "google-chrome", home / ".config" / "chromium"]
    return [d for d in dirs if d.exists()]


def _profile_dirs(base: Path) -> list[Path]:
    profiles = []
    for child in base.iterdir() if base.exists() else []:
        if child.is_dir() and (child.name == "Default" or child.name.startswith("Profile")):
            profiles.append(child)
    return profiles


def credential_files(filename: str) -> list[Path]:
    """All paths to a given Chrome credential file (e.g. 'Cookies', 'Login Data')
    across every browser and every profile. Handles the newer Network/ subfolder."""
    out: list[Path] = []
    for base in chrome_base_dirs():
        for prof in _profile_dirs(base):
            for candidate in (prof / filename, prof / "Network" / filename):
                if candidate.exists():
                    out.append(candidate)
    return out


def processes_holding(paths: list[Path]) -> list[tuple[psutil.Process, str]]:
    """Returns (process, matched_path) for processes that currently have one of the
    given files open. Uses psutil.open_files (visible for the current user's processes)."""
    targets = {str(p.resolve()) for p in paths}
    hits: list[tuple[psutil.Process, str]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for f in proc.open_files():
                if f.path in targets or os.path.realpath(f.path) in targets:
                    hits.append((proc, f.path))
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return hits


def is_whitelisted_proc(name: str) -> bool:
    return (name or "").strip().lower() in WHITELIST_PROC_NAMES


def sha256_file(path: str) -> str | None:
    try:
        if os.path.getsize(path) > _MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def code_signature(exe: str) -> str:
    """Returns 'apple', 'developer', 'unsigned' or 'unknown' for a binary.

    macOS uses codesign. Windows/Linux return 'unknown' (cheap, avoids heavy calls);
    the alert still fires on the credential-file read itself."""
    if not exe or sys.platform != "darwin":
        return "unknown"
    try:
        r = subprocess.run(
            ["codesign", "-dv", "--verbose=2", exe],
            capture_output=True,
            text=True,
            timeout=8,
        )
        info = (r.stderr or "") + (r.stdout or "")
        if r.returncode != 0:
            return "unsigned"
        low = info.lower()
        if "authority=apple" in low or "authority=software signing" in low:
            return "apple"
        if "authority=developer id" in low:
            return "developer"
        return "developer" if "authority=" in low else "unsigned"
    except (subprocess.SubprocessError, OSError):
        return "unknown"


def proc_details(proc: psutil.Process) -> dict:
    """Best-effort snapshot of a process for an alert."""
    d = {"name": "?", "exe": "", "pid": None, "parent": "?", "sha256": None, "signature": "unknown"}
    try:
        d["pid"] = proc.pid
        d["name"] = proc.name()
    except (psutil.Error, OSError):
        pass
    try:
        d["exe"] = proc.exe() or ""
    except (psutil.Error, OSError):
        d["exe"] = ""
    try:
        parent = proc.parent()
        d["parent"] = parent.name() if parent else "?"
    except (psutil.Error, OSError):
        d["parent"] = "?"
    if d["exe"]:
        d["sha256"] = sha256_file(d["exe"])
        d["signature"] = code_signature(d["exe"])
    return d
