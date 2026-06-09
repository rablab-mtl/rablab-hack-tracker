"""Detection 5: a process running from a temp/cache location, unsigned, often spawned
by an installer. This is the fake-installer infostealer pattern (fake Photoshop, fake
Brave, etc.): the .dmg/.pkg/.exe drops a child binary into /tmp or %TEMP% and runs it.
"""
from __future__ import annotations


import datetime
import sys

import psutil

from alert import Alert
from . import Detector
from . import _procutil

TEMP_HINTS = (
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/library/caches/",
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
)

INSTALLER_PARENTS = {"installer", "installer.app", "package_script_service", "msiexec.exe", "msiexec"}

# Known vendor updaters legitimately extract+run helper binaries from temp dirs (e.g. Adobe's
# ARMDCHammer, Google's updater, Microsoft AutoUpdate). If the PARENT process is one of these,
# the temp binary is an update payload, not a fake installer. Real stealers are spawned by
# launchd / Installer / a shell, not by a vendor updater.
VENDOR_UPDATER_PARENTS = (
    "com.adobe", "armdc", "adobe acrobat updater",
    "googlesoftwareupdate", "com.google", "google updater",
    "com.microsoft", "msupdate", "microsoft autoupdate",
)

# Some updaters (e.g. Microsoft AutoUpdate cloning Teams) run the helper with a plain
# parent like bash, so we also recognise known vendor-updater dirs in the BINARY PATH.
# Kept SPECIFIC on purpose: "com.apple." is excluded because the real stealer on Anna's
# Mac hid under ".com.apple.metadata...", which must keep being flagged.
VENDOR_PATH_HINTS = (
    "com.microsoft.autoupdate",
    "com.adobe.armdc",
    "com.adobe.acc",
    "googlesoftwareupdate",
    "com.google.keystone",
)


def _from_temp(exe: str) -> bool:
    low = (exe or "").lower()
    return bool(exe) and any(h in low for h in TEMP_HINTS)


def _in_applications(exe: str) -> bool:
    low = (exe or "").lower()
    if sys.platform == "darwin":
        return low.startswith("/applications/") or "/applications/" in low
    if sys.platform == "win32":
        return "\\program files" in low
    return False


class SuspiciousInstallDetector(Detector):
    name = "suspicious_install"
    interval = 15

    def run_once(self) -> list[Alert]:
        alerts: list[Alert] = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                exe = proc.exe() or ""
            except (psutil.Error, OSError):
                continue
            if not _from_temp(exe) or _in_applications(exe):
                continue
            # Inside a known vendor-updater dir -> legit update payload, skip.
            if any(h in exe.lower() for h in VENDOR_PATH_HINTS):
                continue

            sig = _procutil.code_signature(exe)
            if _procutil.signature_trusted(sig):
                continue  # validly signed binary from temp is unusual but not alone alarming

            d = _procutil.proc_details(proc)
            parent_low = (d["parent"] or "").lower()
            # Spawned by a known vendor updater -> legit update payload, not a fake installer.
            if any(h in parent_low for h in VENDOR_UPDATER_PARENTS):
                continue
            parent_is_installer = parent_low in INSTALLER_PARENTS

            details = [
                f"Processus : {d['name']} (PID {d['pid']})",
                f"Binaire : {exe}",
                f"Parent : {d['parent']}",
                "Signature : PAS signe" if sig == "unsigned" else "Signature : indeterminee",
            ]
            if d["sha256"]:
                details.append(f"SHA-256 : {d['sha256']}")
            if parent_is_installer:
                details.append("Lance par un installeur (pattern faux installer).")

            alerts.append(
                Alert(
                    icon="🚨" if parent_is_installer else "⚠️",
                    alert_type="INSTALL suspect",
                    detector=self.name,
                    time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                    headline=f"Un binaire non signe tourne depuis un dossier temporaire : {d['name']}",
                    details=details,
                    why=(
                        "Les faux installeurs (faux Photoshop, faux Brave...) deposent un binaire dans "
                        "un dossier temporaire et l'executent pour voler cookies et mots de passe."
                    ),
                    action="Si tu viens d'installer un logiciel telecharge hors store officiel, desinstalle et scanne.",
                    dedup_key=f"install:{d['sha256'] or exe}",
                )
            )
        return alerts
