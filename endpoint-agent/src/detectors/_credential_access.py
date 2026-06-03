"""Shared logic for detections 1 and 2: a non-browser process reading a Chrome
credential store (Cookies, Login Data). This is the number-one infostealer pattern.

We list processes that currently hold the target file open and flag any that is not
on the browser/system whitelist.
"""
from __future__ import annotations


import datetime

from alert import Alert
from . import _procutil


def scan_credential_access(
    detector_name: str,
    filename: str,
    alert_type: str,
    why: str,
    action: str,
) -> list[Alert]:
    paths = _procutil.credential_files(filename)
    if not paths:
        return []

    alerts: list[Alert] = []
    for proc, matched_path in _procutil.processes_holding(paths):
        try:
            name = proc.name()
        except Exception:
            name = "?"
        if _procutil.is_whitelisted_proc(name):
            continue

        d = _procutil.proc_details(proc)
        # dedup_key on the binary hash when we have it, else the exe path.
        dedup_key = f"{detector_name}:{d['sha256'] or d['exe'] or name}"

        details = [
            f"Processus : {d['name']} (PID {d['pid']})",
            f"Binaire : {d['exe'] or 'inconnu'}",
            f"Parent : {d['parent']}",
            f"Fichier lu : {matched_path}",
            f"Signature : {_sig_label(d['signature'])}",
        ]
        if d["sha256"]:
            details.append(f"SHA-256 : {d['sha256']}")

        # Reading the credential store by a non-browser process is THE headline
        # infostealer pattern: always critical. Signature is shown in the details.
        icon = "🚨"
        alerts.append(
            Alert(
                icon=icon,
                alert_type=alert_type,
                detector=detector_name,
                time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                headline=f"Le processus {d['name']} vient de lire {filename} de Chrome.",
                details=details,
                why=why,
                action=action,
                dedup_key=dedup_key,
            )
        )
    return alerts


def _sig_label(sig: str) -> str:
    return {
        "apple": "signe Apple",
        "developer": "signe developer ID",
        "unsigned": "PAS signe (suspect)",
        "unknown": "indeterminee",
    }.get(sig, sig)
