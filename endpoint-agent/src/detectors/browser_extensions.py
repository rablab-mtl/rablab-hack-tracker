"""Detection 6: a recently installed Chrome extension with sensitive permissions,
especially one not served from the official Chrome Web Store update URL.
Cookie-stealing extensions are a common, quiet infostealer vector.
"""
from __future__ import annotations


import datetime
import json
import time
from pathlib import Path

from alert import Alert
from . import Detector
from . import _procutil

SENSITIVE_PERMS = {"cookies", "webRequest", "<all_urls>", "tabs", "proxy", "webRequestBlocking"}
OFFICIAL_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
RECENT_DAYS = 60


def _read_manifest(ext_dir: Path) -> tuple[dict, Path] | None:
    # ext_dir/<version>/manifest.json ; pick the most recent version folder.
    versions = [p for p in ext_dir.iterdir() if p.is_dir()] if ext_dir.exists() else []
    versions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for v in versions:
        mf = v / "manifest.json"
        if mf.exists():
            try:
                return json.loads(mf.read_text(encoding="utf-8", errors="ignore")), mf
            except (OSError, json.JSONDecodeError):
                continue
    return None


def _all_permissions(manifest: dict) -> set[str]:
    perms = set()
    for key in ("permissions", "optional_permissions", "host_permissions"):
        val = manifest.get(key)
        if isinstance(val, list):
            perms.update(str(x) for x in val)
    return perms


class BrowserExtensionsDetector(Detector):
    name = "browser_extensions"
    interval = 300  # extensions change rarely; check every 5 min

    def run_once(self) -> list[Alert]:
        alerts: list[Alert] = []
        cutoff = time.time() - RECENT_DAYS * 86400
        for base in _procutil.chrome_base_dirs():
            for prof in base.iterdir() if base.exists() else []:
                ext_root = prof / "Extensions"
                if not ext_root.exists():
                    continue
                for ext_dir in ext_root.iterdir():
                    if not ext_dir.is_dir():
                        continue
                    alert = self._check_extension(ext_dir, cutoff)
                    if alert:
                        alerts.append(alert)
        return alerts

    def _check_extension(self, ext_dir: Path, cutoff: float) -> Alert | None:
        ext_id = ext_dir.name
        try:
            recent = ext_dir.stat().st_mtime >= cutoff
        except OSError:
            recent = False

        parsed = _read_manifest(ext_dir)
        if not parsed:
            return None
        manifest, _mf = parsed
        perms = _all_permissions(manifest)
        sensitive = perms & SENSITIVE_PERMS
        if not sensitive:
            return None

        update_url = str(manifest.get("update_url", ""))
        off_store = bool(update_url) and update_url != OFFICIAL_UPDATE_URL

        # Alert when it is recent OR served from outside the official store.
        if not (recent or off_store):
            return None

        name = str(manifest.get("name", ext_id))
        details = [
            f"Extension : {name} (id : {ext_id})",
            f"Permissions sensibles : {', '.join(sorted(sensitive))}",
            f"Update URL : {update_url or '(absente)'}"
            + ("" if not off_store else " (hors Chrome Web Store)"),
        ]
        if recent:
            details.append("Installee recemment (< 60 jours).")

        return Alert(
            icon="🚨" if off_store else "⚠️",
            alert_type="EXTENSION suspecte",
            detector=self.name,
            time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
            headline=f"Extension Chrome a permissions sensibles : {name}",
            details=details,
            why=(
                "Une extension qui peut lire les cookies et toutes les pages peut voler les sessions "
                "Google Ads directement depuis le navigateur, sans toucher au disque."
            ),
            action="Verifie cette extension. Si tu ne la reconnais pas, desinstalle-la depuis chrome://extensions.",
            dedup_key=f"extension:{ext_id}",
        )
