"""Detection 6: a browser extension that can steal cookies AND is served from outside
the official Chrome Web Store (sideloaded / external update server).

The strong, low-noise signal is "off-store + sensitive permission". Extensions from the
Web Store (update_url on clients2.google.com) are reviewed by Google and are NOT flagged,
even if they legitimately use cookies/tabs (MozBar, HubSpot, wallets, etc.). Cookie-stealer
extensions are almost always sideloaded with their own update server.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from urllib.parse import urlparse

from alert import Alert
from . import Detector
from . import _procutil

# Permissions that let an extension read sessions / all pages. 'tabs' is intentionally
# excluded: it is extremely common and low-risk on its own.
SENSITIVE_PERMS = {"cookies", "<all_urls>", "webRequest", "webRequestBlocking", "proxy"}

# Any scheme on this host is the official Chrome Web Store updater.
STORE_HOST = "clients2.google.com"


def _read_manifest(ext_dir: Path) -> tuple[dict, Path] | None:
    versions = [p for p in ext_dir.iterdir() if p.is_dir()] if ext_dir.exists() else []
    versions.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for v in versions:
        mf = v / "manifest.json"
        if mf.exists():
            try:
                return json.loads(mf.read_text(encoding="utf-8", errors="ignore")), v
            except (OSError, json.JSONDecodeError):
                continue
    return None


def _all_permissions(manifest: dict) -> set[str]:
    perms: set[str] = set()
    for key in ("permissions", "optional_permissions", "host_permissions"):
        val = manifest.get(key)
        if isinstance(val, list):
            perms.update(str(x) for x in val)
    return perms


def _is_store(update_url: str) -> bool:
    """True if the extension updates from the official Web Store (any scheme)."""
    if not update_url:
        return False
    try:
        return (urlparse(update_url).hostname or "").lower() == STORE_HOST
    except ValueError:
        return False


def _resolve_name(manifest: dict, version_dir: Path) -> str:
    """Resolve __MSG_xxx__ i18n placeholders to the real localized name."""
    name = str(manifest.get("name", ""))
    if not name.startswith("__MSG_"):
        return name or version_dir.parent.name
    key = name[len("__MSG_") :].rstrip("_")
    locale = str(manifest.get("default_locale", "en"))
    for loc in (locale, "en", "en_US"):
        msg = version_dir / "_locales" / loc / "messages.json"
        if msg.exists():
            try:
                data = json.loads(msg.read_text(encoding="utf-8", errors="ignore"))
                # message keys are case-insensitive in Chrome
                for k, v in data.items():
                    if k.lower() == key.lower() and isinstance(v, dict) and "message" in v:
                        return str(v["message"])
            except (OSError, json.JSONDecodeError):
                continue
    return version_dir.parent.name  # fall back to the extension id


class BrowserExtensionsDetector(Detector):
    name = "browser_extensions"
    interval = 300

    def run_once(self) -> list[Alert]:
        alerts: list[Alert] = []
        for base in _procutil.chrome_base_dirs():
            for prof in base.iterdir() if base.exists() else []:
                ext_root = prof / "Extensions"
                if not ext_root.exists():
                    continue
                for ext_dir in ext_root.iterdir():
                    if not ext_dir.is_dir():
                        continue
                    alert = self._check_extension(ext_dir)
                    if alert:
                        alerts.append(alert)
        return alerts

    def _check_extension(self, ext_dir: Path) -> Alert | None:
        ext_id = ext_dir.name
        parsed = _read_manifest(ext_dir)
        if not parsed:
            return None
        manifest, version_dir = parsed

        sensitive = _all_permissions(manifest) & SENSITIVE_PERMS
        if not sensitive:
            return None

        update_url = str(manifest.get("update_url", ""))
        # Only flag extensions served from OUTSIDE the official Web Store. Store extensions
        # (and those with no external updater) are not the cookie-stealer pattern.
        if not update_url or _is_store(update_url):
            return None

        name = _resolve_name(manifest, version_dir)
        return Alert(
            icon="🚨",
            alert_type="EXTENSION suspecte",
            detector=self.name,
            time_hms=datetime.datetime.now().strftime("%H:%M:%S"),
            headline=f"Extension HORS Chrome Web Store avec acces aux cookies : {name}",
            details=[
                f"Extension : {name} (id : {ext_id})",
                f"Permissions sensibles : {', '.join(sorted(sensitive))}",
                f"Update URL : {update_url} (serveur externe, PAS le Chrome Web Store)",
            ],
            why=(
                "Une extension installee hors du Chrome Web Store et capable de lire les cookies "
                "peut voler les sessions Google Ads directement dans le navigateur. C'est un "
                "vecteur classique d'infostealer."
            ),
            action="Verifie cette extension dans chrome://extensions. Si tu ne l'as pas installee volontairement, desinstalle-la et scanne.",
            dedup_key=f"extension:{ext_id}",
        )
