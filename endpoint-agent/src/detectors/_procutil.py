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

# Cache of binary path -> signature verdict, so we do not re-run codesign /
# Get-AuthenticodeSignature on every poll for the same binary.
_SIG_CACHE: dict[str, str] = {}


def signature_trusted(sig: str) -> bool:
    """A binary is trusted if it is validly signed, on either OS."""
    return sig in ("apple", "developer", "signed")


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
    """Returns 'apple', 'developer', 'signed', 'unsigned' or 'unknown' for a binary.

    macOS uses codesign; Windows uses Authenticode (Get-AuthenticodeSignature).
    Results are cached per path. 'signed' means a valid signature on Windows."""
    if not exe:
        return "unknown"
    if exe in _SIG_CACHE:
        return _SIG_CACHE[exe]
    sig = _compute_signature(exe)
    _SIG_CACHE[exe] = sig
    return sig


def _compute_signature(exe: str) -> str:
    try:
        if sys.platform == "darwin":
            r = subprocess.run(
                ["codesign", "-dv", "--verbose=2", exe],
                capture_output=True, text=True, timeout=8,
            )
            info = ((r.stderr or "") + (r.stdout or "")).lower()
            if r.returncode != 0:
                return "unsigned"
            if "authority=apple" in info or "authority=software signing" in info:
                return "apple"
            if "authority=developer id" in info:
                return "developer"
            return "developer" if "authority=" in info else "unsigned"
        if sys.platform == "win32":
            # Authenticode status: Valid / NotSigned / HashMismatch / NotTrusted / ...
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f'(Get-AuthenticodeSignature -LiteralPath "{exe}").Status'],
                capture_output=True, text=True, timeout=20,
            )
            status = (r.stdout or "").strip()
            if status == "Valid":
                return "signed"
            if status == "NotSigned":
                return "unsigned"
            return "unknown"
    except (subprocess.SubprocessError, OSError):
        return "unknown"
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
