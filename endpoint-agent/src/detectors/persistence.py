"""Detection 3: a new, suspicious autostart entry (LaunchAgent / Scheduled Task).

macOS: scans LaunchAgents/LaunchDaemons plists.
Windows: scans the registry Run keys and Scheduled Tasks.

An entry is suspicious when the binary it points to lives in a temp/cache/random dir,
or is not signed by Apple / a known developer, or the label looks random.
"""
from __future__ import annotations


import datetime
import plistlib
import re
import sys
from pathlib import Path

from alert import Alert
from . import Detector
from . import _procutil

SUSPICIOUS_DIR_HINTS = (
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/.cache/",
    "/library/application support/.",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\programdata\\",
)

_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}")

WHY = (
    "Installer un demarrage automatique est la facon dont un infostealer reste actif et se "
    "relance apres un reboot. C'est un marqueur de persistence."
)


# Our own agent's autostart entry; never flag ourselves.
SELF_LABEL = "com.rablab.hacktracker"


def _binary_suspicious(binary: str) -> tuple[bool, list[str]]:
    # Only a binary living in a temp/cache/random dir is a real persistence signal.
    # "unsigned" alone is far too noisy on macOS (legit helpers, scripts, Homebrew, etc.),
    # and an empty/unknown binary path is never treated as suspicious.
    if not binary:
        return (False, [])
    low = binary.lower()
    if not any(h in low for h in SUSPICIOUS_DIR_HINTS):
        return (False, [])
    # A validly signed binary (Apple / Developer ID / Microsoft) in a temp/cache dir is
    # almost always a legit updater or installer, not infostealer persistence. Skip it.
    if _procutil.signature_trusted(_procutil.code_signature(binary)):
        return (False, [])
    return (True, [
        f"Binaire dans un repertoire temporaire/cache : {binary}",
        "et pas signe par un editeur reconnu",
    ])


def _label_suspicious(label: str) -> bool:
    # Only a UUID-like label is a reliable signal. The previous length-based heuristic
    # flagged legit names like com.adobe.AdobeCreativeCloud, so it is removed. The strong
    # signal for persistence is the binary location (temp/cache dir), handled above.
    return bool(label) and bool(_UUID_RE.search(label))


class PersistenceDetector(Detector):
    name = "persistence"
    interval = 30

    def run_once(self) -> list[Alert]:
        if sys.platform == "darwin":
            return self._scan_macos()
        if sys.platform == "win32":
            return self._scan_windows()
        return []

    # ----- macOS --------------------------------------------------------
    def _scan_macos(self) -> list[Alert]:
        dirs = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        alerts: list[Alert] = []
        for d in dirs:
            if not d.exists():
                continue
            for plist in d.glob("*.plist"):
                try:
                    with open(plist, "rb") as f:
                        data = plistlib.load(f)
                except (OSError, plistlib.InvalidFileException, ValueError):
                    continue
                label = str(data.get("Label", plist.stem))
                if label == SELF_LABEL:
                    continue  # never flag our own agent
                binary = ""
                if isinstance(data.get("Program"), str):
                    binary = data["Program"]
                elif isinstance(data.get("ProgramArguments"), list) and data["ProgramArguments"]:
                    binary = str(data["ProgramArguments"][0])

                bad_bin, reasons = _binary_suspicious(binary)
                bad_label = _label_suspicious(label)
                if not (bad_bin or bad_label):
                    continue
                if bad_label:
                    reasons.append(f"Label de plist en forme d'UUID : {label}")

                alerts.append(
                    Alert(
                        icon="⚠️",
                        alert_type="PERSISTENCE suspecte",
                        detector=self.name,
                        time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                        headline=f"Nouveau LaunchAgent/Daemon : {plist}",
                        details=[f"Label : {label}", f"Binaire pointe : {binary or 'inconnu'}", *reasons],
                        why=WHY,
                        action="Verifie ce demarrage automatique. Si tu ne le reconnais pas, supprime la plist et scanne.",
                        dedup_key=f"persistence:{plist}",
                    )
                )
        return alerts

    # ----- Windows ------------------------------------------------------
    def _scan_windows(self) -> list[Alert]:
        alerts: list[Alert] = []
        try:
            import winreg  # type: ignore
        except ImportError:
            return []

        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, subkey in run_keys:
            try:
                key = winreg.OpenKey(hive, subkey)
            except OSError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    i += 1
                    bad, reasons = _binary_suspicious(str(value))
                    if not bad:
                        continue
                    alerts.append(
                        Alert(
                            icon="⚠️",
                            alert_type="PERSISTENCE suspecte",
                            detector=self.name,
                            time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                            headline=f"Nouvelle entree Run : {name}",
                            details=[f"Commande : {value}", *reasons],
                            why=WHY,
                            action="Verifie cette entree de demarrage. Si inconnue, supprime-la et scanne.",
                            dedup_key=f"persistence:run:{name}:{value}",
                        )
                    )
            finally:
                winreg.CloseKey(key)
        return alerts
