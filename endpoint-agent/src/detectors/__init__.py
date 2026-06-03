"""Detector framework.

Each detector exposes:
  - name      : short id, used for dedup namespace and logs
  - interval  : seconds between run_once() calls (the agent schedules each detector)
  - run_once(): returns a list[Alert] of NEW findings (raw; the agent applies dedup,
                whitelist and learning-mode centrally)

Detectors must never raise out of run_once(); the agent wraps every call in try/except,
but defensive code inside keeps one bad reading from blanking a whole cycle.
"""
from __future__ import annotations


from alert import Alert, DetectorContext


class Detector:
    name = "base"
    interval = 60

    def __init__(self, ctx: DetectorContext):
        self.ctx = ctx

    def run_once(self) -> list[Alert]:
        return []
