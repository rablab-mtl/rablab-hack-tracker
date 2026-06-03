"""Detection 4: an active network connection to a known infostealer C2 address.

Compares the remote IPs of current connections against the IoC IP set downloaded
from abuse.ch (ThreatFox / URLhaus), filtered to infostealer families.
"""
from __future__ import annotations


import datetime

import psutil

from alert import Alert
from . import Detector


def _remote_endpoints() -> list[tuple[str, int | None, str | None]]:
    """Returns (remote_ip, pid, process_name) for every active outbound connection.

    Tries the system-wide call first. On macOS without root that is denied, so we fall
    back to iterating per-process connections. Note: system-wide returns 'sconn' tuples
    (which carry a pid), while per-process returns 'pconn' tuples (no pid field) - so we
    must take the pid from the process we are iterating, never from the connection."""
    out: list[tuple[str, int | None, str | None]] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                out.append((c.raddr.ip, c.pid, None))
        return out
    except (psutil.AccessDenied, PermissionError, OSError):
        pass
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            for c in proc.net_connections(kind="inet"):
                if c.raddr:
                    out.append((c.raddr.ip, proc.pid, proc.info.get("name")))
        except (psutil.Error, OSError):
            continue
    return out


class C2ConnectionsDetector(Detector):
    name = "c2_connections"
    interval = 30

    def run_once(self) -> list[Alert]:
        ioc_ips = self.ctx.db.ioc_ip_set()
        if not ioc_ips:
            return []

        alerts: list[Alert] = []
        for ip, pid, pname in _remote_endpoints():
            if not ip or ip not in ioc_ips:
                continue
            if not pname and pid:
                try:
                    pname = psutil.Process(pid).name()
                except (psutil.Error, OSError):
                    pname = "?"
            pname = pname or "?"

            alerts.append(
                Alert(
                    icon="🚨",
                    alert_type="COMMUNICATION malveillante",
                    detector=self.name,
                    time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                    headline=f"Le processus {pname} (PID {pid}) communique avec {ip}.",
                    details=[
                        f"IP distante : {ip}",
                        f"Processus : {pname} (PID {pid})",
                        "Listee comme serveur de commande d'un infostealer (source : abuse.ch).",
                    ],
                    why=(
                        "Une connexion vers un serveur de commande connu signifie que ce poste est "
                        "infecte et exfiltre probablement des donnees (dont les sessions Google Ads)."
                    ),
                    action="Debranche ce poste du reseau et lance le scan antivirus. Previens l'equipe securite.",
                    dedup_key=f"c2:{ip}",
                )
            )
        return alerts
