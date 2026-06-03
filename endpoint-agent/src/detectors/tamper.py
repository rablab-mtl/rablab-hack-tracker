"""Detection 7: the agent's own code changed unexpectedly.

We hash every .py file under src/ at install (stored in .expected_hash) and compare on
each run. A mismatch that is not a legitimate update means someone modified the agent,
which is itself suspicious.
"""
from __future__ import annotations


import datetime
import hashlib
from pathlib import Path

import config
from alert import Alert
from . import Detector


def _src_root() -> Path:
    # this file is src/detectors/tamper.py -> src/
    return Path(__file__).resolve().parents[1]


def compute_source_hash() -> str:
    h = hashlib.sha256()
    root = _src_root()
    for py in sorted(root.rglob("*.py")):
        try:
            h.update(py.relative_to(root).as_posix().encode())
            h.update(py.read_bytes())
        except OSError:
            continue
    return h.hexdigest()


def ensure_expected_hash() -> None:
    """Called once at startup: record the current hash if none exists yet."""
    p = config.expected_hash_path()
    if not p.exists():
        config._write_private(p, compute_source_hash())


class TamperDetector(Detector):
    name = "tamper"
    interval = 3600

    def run_once(self) -> list[Alert]:
        p = config.expected_hash_path()
        if not p.exists():
            ensure_expected_hash()
            return []
        try:
            expected = p.read_text(encoding="utf-8").strip()
        except OSError:
            return []
        current = compute_source_hash()
        if current == expected:
            return []
        return [
            Alert(
                icon="🚨",
                alert_type="AGENT MODIFIE",
                detector=self.name,
                time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
                headline="Le code de l'agent rablab-hack-tracker a ete modifie.",
                details=[
                    f"Hash attendu : {expected[:16]}...",
                    f"Hash actuel : {current[:16]}...",
                ],
                why=(
                    "Si personne n'a mis a jour l'agent volontairement, une modification de son code "
                    "peut signifier qu'un malware a tente de le neutraliser ou de le detourner."
                ),
                action="Confirme aupres de l'admin qu'une mise a jour legitime a eu lieu. Sinon, reinstalle l'agent proprement.",
                dedup_key=f"tamper:{current}",
            )
        ]
