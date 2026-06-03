"""Detection 4: an active network connection to a known infostealer C2 address.

Compares the remote IPs of current connections against the IoC IP set downloaded
from abuse.ch (ThreatFox / URLhaus), filtered to infostealer families.
"""
from __future__ import annotations


import datetime

import psutil

from alert import Alert
from . import Detector


def _connections() -> list:
    """All inet connections, with a fallback when system-wide access is denied."""
    try:
        return psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError, OSError):
        pass
    # Fallback: only the current user's own processes (no elevated privileges needed).
    conns = []
    for proc in psutil.process_iter():
        try:
            for c in proc.net_connections(kind="inet"):
                c = c._replace(pid=proc.pid) if c.pid is None else c
                conns.append(c)
        except (psutil.Error, OSError):
            continue
    return conns


class C2ConnectionsDetector(Detector):
    name = "c2_connections"
    interval = 30

    def run_once(self) -> list[Alert]:
        ioc_ips = self.ctx.db.ioc_ip_set()
        if not ioc_ips:
            return []

        alerts: list[Alert] = []
        for conn in _connections():
            raddr = getattr(conn, "raddr", None)
            if not raddr:
                continue
            ip = raddr.ip if hasattr(raddr, "ip") else (raddr[0] if raddr else None)
            if not ip or ip not in ioc_ips:
                continue

            pname, pid = "?", getattr(conn, "pid", None)
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except (psutil.Error, OSError):
                    pname = "?"

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
                    action="Debranche ce poste du reseau et lance le scan antivirus. Previens Julien.",
                    dedup_key=f"c2:{ip}",
                )
            )
        return alerts
