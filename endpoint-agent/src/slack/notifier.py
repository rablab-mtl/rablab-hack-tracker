"""Builds and sends Slack messages for the endpoint agent.

The webhook URL is read from runtime config (fetched from the worker, rotatable by Julien).
Whitelist links are minted by the worker (only it can sign them); if the worker is
unreachable, the alert is still sent, just without the link.
"""
from __future__ import annotations


import datetime

import requests

from alert import Alert


class Notifier:
    def __init__(
        self,
        webhook_url: str,
        worker_url: str,
        agent_token: str,
        device_label: str,
        email: str,
        device_noun: str,
        short_id: str,
        os_platform: str,
    ):
        self.webhook_url = webhook_url
        self.worker_url = worker_url.rstrip("/")
        self.agent_token = agent_token
        self.device_label = device_label
        self.email = email
        self.device_noun = device_noun
        self.short_id = short_id
        self.os_platform = os_platform

    # ----- low level ----------------------------------------------------
    def _post(self, text: str) -> bool:
        if not self.webhook_url:
            return False
        try:
            r = requests.post(self.webhook_url, json={"text": text}, timeout=15)
            return r.ok
        except requests.RequestException:
            return False

    def _header(self) -> str:
        return f"{self.device_noun} de {self.device_label} ({self.email})"

    def _whitelist_url(self, dedup_key: str, label: str) -> str | None:
        """Ask the worker for a signed whitelist link. Best effort."""
        try:
            r = requests.post(
                f"{self.worker_url}/endpoint-alert",
                json={"device_id": self.short_id, "pattern": dedup_key, "label": label},
                headers={"X-Agent-Token": self.agent_token},
                timeout=15,
            )
            if r.ok:
                return r.json().get("whitelist_url")
        except requests.RequestException:
            pass
        return None

    # ----- alerts -------------------------------------------------------
    def build_alert_text(self, alert: Alert, whitelist_url: str | None) -> str:
        lines = [
            f"{alert.icon} {alert.alert_type} - {self._header()}",
            f"{alert.time_hms} - {alert.headline}",
            "",
            "Details :",
        ]
        lines += [f"- {d}" for d in alert.details]
        lines += [
            "",
            "Pourquoi c'est en lien avec le hack Google Ads :",
            alert.why,
            "",
            f"→ Action : {alert.action}",
        ]
        if whitelist_url:
            lines.append(f"→ C'etait toi / faux positif ? Clique pour whitelister : {whitelist_url}")
        return "\n".join(lines)

    def send_alert(self, alert: Alert) -> bool:
        label = f"{alert.alert_type} sur {self.device_noun} de {self.device_label} : {alert.headline}"
        wl = self._whitelist_url(alert.dedup_key, label)
        return self._post(self.build_alert_text(alert, wl))

    # ----- lifecycle messages ------------------------------------------
    def send_install(self) -> bool:
        now = datetime.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
        text = (
            "✅ [INSTALL] Nouveau device enregistre\n"
            f"Device : {self.device_noun} de {self.device_label} ({self.email})\n"
            f"Identifiant : {self.short_id}\n"
            f"OS : {self.os_platform}\n"
            f"Heure d'install : {now}\n\n"
            "L'agent enverra un heartbeat chaque matin a 9h dans ce canal.\n"
            "Les alertes critiques apparaitront avec 🚨 ou ⚠️."
        )
        return self._post(text)

    def send_heartbeat(self, alerts_24h: int) -> bool:
        text = (
            f"✅ [HEARTBEAT] {self.device_noun} de {self.device_label} ({self.email}) "
            f"- actif, {alerts_24h} alerte(s) sur 24h."
        )
        return self._post(text)

    def send_uninstall(self) -> bool:
        now = datetime.datetime.now().astimezone().strftime("%H:%M %Z")
        text = (
            f"👋 [UNINSTALL] {self.device_noun} de {self.device_label} ({self.email}) "
            f"- agent desinstalle a {now}."
        )
        return self._post(text)

    def send_killswitch(self) -> bool:
        text = (
            f"🛑 [KILL_SWITCH] {self.device_noun} de {self.device_label} ({self.email}) "
            "- auto-desinstallation suite a kill switch admin."
        )
        return self._post(text)
