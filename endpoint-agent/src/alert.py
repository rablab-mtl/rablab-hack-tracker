"""Shared data types passed between detectors, the notifier and the agent loop."""
from __future__ import annotations


from dataclasses import dataclass, field


@dataclass
class Alert:
    """One detection ready to be turned into a Slack message.

    dedup_key uniquely identifies the suspicious thing (a binary hash, an extension id,
    an IP, a plist path...). It drives both local dedup and the click-to-whitelist link.
    """

    icon: str  # 🚨 or ⚠️ or 🔵
    alert_type: str  # e.g. "INFOSTEALER probable"
    detector: str  # detector name, for history/dedup namespace
    time_hms: str  # HH:MM:SS
    headline: str  # short event sentence
    details: list[str]
    why: str  # link to the Google Ads hack
    action: str  # what to do
    dedup_key: str


@dataclass
class DetectorContext:
    """Everything a detector needs, injected by the agent so detectors stay testable."""

    db: object  # storage.db.Database
    learning_mode: bool = False  # first 24h: alerts go out as 🔵, no panic
    extra: dict = field(default_factory=dict)
