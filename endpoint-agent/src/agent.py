"""rablab-hack-tracker endpoint agent: main loop and CLI.

Subcommands:
  run        start the monitoring loop (used by the LaunchAgent / Scheduled Task)
  install    finalize install: fetch config, record source hash, send install Slack message
  status     print the local agent status
  logs       print the local log file path and tail

Design notes:
  - Detectors run on independent schedules; each run_once() is wrapped in try/except so
    one failing detector never stops the others (brief requirement).
  - Dedup, whitelist and learning-mode are applied centrally here, not in detectors.
  - There is NO code auto-update. agent_version_min from the worker is advisory only.
  - The kill switch only triggers a local uninstall; it never runs remote code.
"""
from __future__ import annotations


import logging
import subprocess
import sys
import time
from pathlib import Path

import config
from alert import DetectorContext
from device_id import short_id
from heartbeat import Heartbeat
from ioc.feed_updater import update_iocs
from slack.notifier import Notifier
from storage.db import Database

from detectors import tamper
from detectors.browser_extensions import BrowserExtensionsDetector
from detectors.c2_connections import C2ConnectionsDetector
from detectors.cookies_access import CookiesAccessDetector
from detectors.passwords_access import PasswordsAccessDetector
from detectors.persistence import PersistenceDetector
from detectors.suspicious_install import SuspiciousInstallDetector
from detectors.tamper import TamperDetector

# These signal active credential theft; they are never downgraded by learning mode.
CRITICAL_DETECTORS = {"cookies_access", "passwords_access", "c2_connections", "tamper"}
LEARNING_WINDOW_SECONDS = 24 * 3600

IOC_REFRESH_SECONDS = 4 * 3600
WORKER_HEARTBEAT_SECONDS = 600


def _setup_logging() -> logging.Logger:
    logger = logging.getLogger("rablab-hack-tracker")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        config.config_dir().mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(config.log_path(), encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
        try:
            import os

            if sys.platform != "win32":
                os.chmod(config.log_path(), 0o600)
        except OSError:
            pass
    return logger


def refresh_config(db: Database, sid: str, logger: logging.Logger, attempts: int = 3) -> dict:
    """Fetch /agent-config from the worker, cache it, sync whitelist. Returns runtime dict.
    Retries a few times so a transient network blip does not lose the webhook, and falls
    back to the cached runtime.json only if every attempt fails."""
    import time as _time

    import requests

    url = f"{config.worker_url()}/agent-config?device_id={sid}"
    for i in range(max(1, attempts)):
        try:
            r = requests.get(url, headers={"X-Agent-Token": config.AGENT_SHARED_TOKEN}, timeout=15)
            if r.ok:
                remote = r.json()
                runtime = config.load_runtime_config()
                runtime.update(remote)
                config.save_runtime_config(runtime)
                # Sync server-side whitelist into local DB (permanent silencing).
                db.sync_whitelist(remote.get("whitelisted_patterns", []) or [])
                return runtime
            logger.info(f"config refresh HTTP {r.status_code} (attempt {i + 1})")
        except (requests.RequestException, ValueError) as e:
            logger.info(f"config refresh failed (attempt {i + 1}): {e}")
        if i < attempts - 1:
            _time.sleep(3)
    logger.info("config refresh: all attempts failed, using cached runtime")
    return config.load_runtime_config()


def build_notifier(runtime: dict, label: str, email: str, sid: str, osp: str) -> Notifier:
    return Notifier(
        webhook_url=runtime.get("webhook_url", ""),
        worker_url=config.worker_url(),
        agent_token=config.AGENT_SHARED_TOKEN,
        device_label=label,
        email=email,
        device_noun=config.device_noun(),
        short_id=sid,
        os_platform=osp,
    )


def do_kill_switch(notifier: Notifier, logger: logging.Logger) -> None:
    logger.info("Kill switch active; sending Slack notice and self-uninstalling.")
    notifier.send_killswitch()
    script = config_uninstall_script()
    if script and script.exists():
        try:
            if sys.platform == "win32":
                subprocess.Popen(
                    ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(script), "-KillSwitch"]
                )
            else:
                subprocess.Popen(["bash", str(script), "--kill-switch"])
        except OSError as e:
            logger.info(f"uninstall script failed to launch: {e}")


def config_uninstall_script() -> Path | None:
    root = Path(__file__).resolve().parents[1]  # endpoint-agent/
    name = "uninstall-windows.ps1" if sys.platform == "win32" else "uninstall-macos.sh"
    return root / name


def handle_alert(alert, db: Database, notifier: Notifier, learning: bool, logger: logging.Logger) -> None:
    if db.is_whitelisted(alert.dedup_key):
        return
    if db.seen_before(alert.detector, alert.dedup_key):
        return  # already alerted once for this exact pattern

    if learning and alert.detector not in CRITICAL_DETECTORS:
        alert.icon = "🔵"
        alert.alert_type = f"[CALIBRATION] {alert.alert_type}"

    if notifier.send_alert(alert):
        db.record_alert(alert.detector, alert.icon, alert.headline)
        logger.info(f"alert sent: {alert.detector} {alert.dedup_key}")
    else:
        logger.info(f"alert send FAILED (will retry next occurrence): {alert.detector}")


def run_loop() -> int:
    logger = _setup_logging()
    local = config.load_local_config()
    if not local.get("email") or not local.get("device_label"):
        logger.info("Agent not installed (missing config). Run install first.")
        print("Agent non configure. Lance d'abord l'installation.")
        return 1

    label = local["device_label"]
    email = local["email"]
    sid = short_id(label)
    osp = config.os_platform_string()
    install_ts = float(local.get("install_ts", time.time()))

    db = Database(config.db_path())
    tamper.ensure_expected_hash()

    runtime = refresh_config(db, sid, logger)
    notifier = build_notifier(runtime, label, email, sid, osp)

    if runtime.get("kill_switch"):
        do_kill_switch(notifier, logger)
        return 0

    # Initial IoC load (best effort; detector simply finds nothing if it fails).
    try:
        n = update_iocs(db, runtime.get("ioc_feeds"))
        logger.info(f"IoC set loaded: {n} indicators")
    except Exception as e:
        logger.info(f"initial IoC load failed: {e}")

    ctx = DetectorContext(db=db)
    detector_classes = [
        CookiesAccessDetector,
        PasswordsAccessDetector,
        PersistenceDetector,
        C2ConnectionsDetector,
        SuspiciousInstallDetector,
        BrowserExtensionsDetector,
        TamperDetector,
    ]
    detectors = [cls(ctx) for cls in detector_classes]

    device_payload = {
        "device_id": sid,
        "device_label": label,
        "email": email,
        "os_platform": osp,
        "agent_version": config.AGENT_VERSION,
    }
    hb = Heartbeat(config.worker_url(), config.AGENT_SHARED_TOKEN, device_payload, notifier, db)

    now = time.monotonic()
    next_run = {d.name: now for d in detectors}
    next_ioc = now + IOC_REFRESH_SECONDS
    next_cfg = now + float(runtime.get("config_refresh_interval_seconds", 3600))
    next_hb = now  # push a heartbeat right away so the dashboard lights up

    logger.info(f"Agent started: {label} ({email}) {sid} {osp}")
    hb.push_worker()

    while True:
        now = time.monotonic()
        learning = (time.time() - install_ts) < LEARNING_WINDOW_SECONDS

        for d in detectors:
            if now < next_run[d.name]:
                continue
            next_run[d.name] = now + d.interval
            try:
                for alert in d.run_once():
                    handle_alert(alert, db, notifier, learning, logger)
            except Exception as e:  # one detector must never kill the loop
                logger.info(f"detector {d.name} raised: {e}")

        if now >= next_ioc:
            next_ioc = now + IOC_REFRESH_SECONDS
            try:
                update_iocs(db, runtime.get("ioc_feeds"))
            except Exception as e:
                logger.info(f"IoC refresh failed: {e}")

        if now >= next_cfg:
            runtime = refresh_config(db, sid, logger)
            next_cfg = now + float(runtime.get("config_refresh_interval_seconds", 3600))
            notifier.webhook_url = runtime.get("webhook_url", notifier.webhook_url)
            if runtime.get("kill_switch"):
                do_kill_switch(notifier, logger)
                return 0

        if now >= next_hb:
            next_hb = now + WORKER_HEARTBEAT_SECONDS
            hb.push_worker()
        hb.maybe_send_daily_slack()

        time.sleep(2)


def cmd_install() -> int:
    """Finalize install: record source hash, fetch config, send the install Slack message."""
    logger = _setup_logging()
    local = config.load_local_config()
    if not local.get("email") or not local.get("device_label"):
        print("Config locale manquante (email / device_label).")
        return 1
    if "install_ts" not in local:
        local["install_ts"] = time.time()
        config.save_local_config(local)

    label, email = local["device_label"], local["email"]
    sid = short_id(label)
    osp = config.os_platform_string()
    db = Database(config.db_path())
    tamper.ensure_expected_hash()
    runtime = refresh_config(db, sid, logger)
    notifier = build_notifier(runtime, label, email, sid, osp)

    if not runtime.get("webhook_url"):
        print("Avertissement : aucun webhook recu du worker. Verifie l'URL du worker et le token.")
    ok = notifier.send_install()
    # Also light up the dashboard immediately.
    Heartbeat(config.worker_url(), config.AGENT_SHARED_TOKEN,
              {"device_id": sid, "device_label": label, "email": email,
               "os_platform": osp, "agent_version": config.AGENT_VERSION},
              notifier, db).push_worker()
    print("Message d'install envoye." if ok else "Message d'install NON envoye (webhook indisponible).")
    return 0


def cmd_notify_uninstall() -> int:
    """Called by the uninstall script: send the 👋 Slack message and mark the device gone."""
    logger = _setup_logging()
    local = config.load_local_config()
    if not local.get("email"):
        return 0
    label, email = local.get("device_label", "?"), local["email"]
    sid = short_id(label)
    osp = config.os_platform_string()
    db = Database(config.db_path())
    runtime = config.load_runtime_config()
    notifier = build_notifier(runtime, label, email, sid, osp)
    notifier.send_uninstall()
    Heartbeat(
        config.worker_url(),
        config.AGENT_SHARED_TOKEN,
        {"device_id": sid, "device_label": label, "email": email,
         "os_platform": osp, "agent_version": config.AGENT_VERSION},
        notifier,
        db,
    ).push_worker(status="uninstalled")
    return 0


def cmd_status() -> int:
    local = config.load_local_config()
    if not local.get("email"):
        print("rablab-hack-tracker n'est pas configure sur ce poste.")
        return 1
    db = Database(config.db_path())
    label = local.get("device_label", "?")
    sid = short_id(label)
    print("✅ rablab-hack-tracker")
    print(f"Device : {config.device_noun()} de {label} ({local.get('email')})")
    print(f"Identifiant : {sid}")
    print(f"OS : {config.os_platform_string()}")
    print(f"Alertes envoyees dans les 24h : {db.alerts_last_24h()}")
    print(f"IoC charges : {db.ioc_count()}")
    print(f"Logs : {config.log_path()}")
    return 0


def cmd_logs() -> int:
    p = config.log_path()
    if not p.exists():
        print("Aucun log pour l'instant.")
        return 0
    print(f"Log : {p}\n")
    try:
        lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        print("\n".join(lines[-50:]))
    except OSError as e:
        print(f"Impossible de lire le log : {e}")
    return 0


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "run"
    if cmd == "run":
        return run_loop()
    if cmd == "install":
        return cmd_install()
    if cmd == "status":
        return cmd_status()
    if cmd == "logs":
        return cmd_logs()
    if cmd == "notify-uninstall":
        return cmd_notify_uninstall()
    print(f"Commande inconnue : {cmd}")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
