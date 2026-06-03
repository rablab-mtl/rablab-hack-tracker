"""Heartbeat handling.

Two channels:
  - Worker push (every ~10 min): keeps the /status dashboard fresh and lets Julien see
    which devices are alive without spamming Slack.
  - Daily Slack heartbeat at 09:00 America/Toronto: a single reassuring line per device.
"""
from __future__ import annotations


import datetime

import requests

try:
    from zoneinfo import ZoneInfo

    EASTERN = ZoneInfo("America/Toronto")
except Exception:  # zoneinfo data missing on some minimal installs
    EASTERN = None


class Heartbeat:
    def __init__(self, worker_url: str, agent_token: str, device_payload: dict, notifier, db):
        self.worker_url = worker_url.rstrip("/")
        self.agent_token = agent_token
        self.device_payload = device_payload
        self.notifier = notifier
        self.db = db
        self._last_slack_date: datetime.date | None = None

    def push_worker(self, status: str = "active") -> bool:
        payload = dict(self.device_payload)
        payload["status"] = status
        payload["alerts_24h"] = self.db.alerts_last_24h()
        try:
            r = requests.post(
                f"{self.worker_url}/heartbeat",
                json=payload,
                headers={"X-Agent-Token": self.agent_token},
                timeout=15,
            )
            return r.ok
        except requests.RequestException:
            return False

    def _now_eastern(self) -> datetime.datetime:
        if EASTERN:
            return datetime.datetime.now(EASTERN)
        return datetime.datetime.now()

    def maybe_send_daily_slack(self) -> None:
        now = self._now_eastern()
        today = now.date()
        if self._last_slack_date == today:
            return
        if now.hour >= 9:
            if self.notifier.send_heartbeat(self.db.alerts_last_24h()):
                self._last_slack_date = today
