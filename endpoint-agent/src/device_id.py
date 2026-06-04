"""Stable device identity derived from the machine serial number.

device_id = first 8 hex chars of sha256(serial). Used to differentiate two machines
that happen to share the same human label. Falls back to the hostname if the serial
cannot be read (never crashes the agent).
"""
from __future__ import annotations


import hashlib
import platform
import subprocess
import sys


def _machine_serial() -> str:
    # Must NEVER crash: a bad reading falls back to the hostname. errors="ignore" because
    # ioreg can emit non-UTF-8 bytes, and a targeted query keeps the output small and clean.
    try:
        if sys.platform == "darwin":
            out = subprocess.run(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                capture_output=True, text=True, errors="ignore", timeout=10,
            ).stdout
            for line in out.splitlines():
                if "IOPlatformSerialNumber" in line:
                    # line looks like:  "IOPlatformSerialNumber" = "C02XXXXXXXXX"
                    return line.split("=")[-1].strip().strip('"')
        elif sys.platform == "win32":
            out = subprocess.run(
                ["wmic", "bios", "get", "serialnumber"],
                capture_output=True, text=True, errors="ignore", timeout=10,
            ).stdout
            lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            if len(lines) >= 2:
                return lines[1]
    except Exception:
        pass
    return platform.node() or "unknown"


def device_id() -> str:
    serial = _machine_serial()
    return hashlib.sha256(serial.encode("utf-8", "ignore")).hexdigest()[:8]


def short_id(device_label: str) -> str:
    """A friendly identifier like 'nick-mbp-a1b2c3d4' from the label + device_id."""
    slug = "".join(c.lower() if c.isalnum() else "-" for c in device_label)
    slug = "-".join(filter(None, slug.split("-")))
    return f"{slug}-{device_id()}" if slug else device_id()
