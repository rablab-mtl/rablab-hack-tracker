"""Configuration and runtime state for the endpoint agent.

Two layers:
  - Local install config (email, device label, worker url): written once at install,
    stored in the config dir as config.json.
  - Runtime config (Slack webhook, kill switch, ioc feeds, whitelist): fetched from the
    worker /agent-config endpoint at startup and refreshed hourly, cached in runtime.json.

The only "token" baked into this public repo is AGENT_SHARED_TOKEN. It is an anti-bot
filter on the worker config endpoint, not a real secret (see brief, "Securite des endpoints").
The Slack webhook is NEVER stored in the repo; it is fetched from the worker at runtime.
"""
from __future__ import annotations


import json
import os
import platform
import sys
from pathlib import Path

AGENT_VERSION = "1.0.0"

# Public worker URL (not a secret). Overridable via config.json "worker_url".
DEFAULT_WORKER_URL = "https://rablab-gads-monitor.rablab.workers.dev"

# Anti-bot token shared by all agents, also a Cloudflare secret on the worker side.
AGENT_SHARED_TOKEN = "MvLIAQnTY3No6VOneRtwhUhgi2t4rgCB"


def config_dir() -> Path:
    """Per-OS config directory, chmod 600 on the files inside."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "rablab-hack-tracker"
    # macOS and Linux: ~/.config/rablab-hack-tracker
    return Path.home() / ".config" / "rablab-hack-tracker"


def config_path() -> Path:
    return config_dir() / "config.json"


def runtime_path() -> Path:
    return config_dir() / "runtime.json"


def db_path() -> Path:
    return config_dir() / "tracker.db"


def log_path() -> Path:
    return config_dir() / "agent.log"


def expected_hash_path() -> Path:
    return config_dir() / ".expected_hash"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if sys.platform != "win32":
        os.chmod(path, 0o600)


def load_local_config() -> dict:
    p = config_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_local_config(cfg: dict) -> None:
    _write_private(config_path(), json.dumps(cfg, indent=2))


def load_runtime_config() -> dict:
    p = runtime_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_runtime_config(cfg: dict) -> None:
    _write_private(runtime_path(), json.dumps(cfg, indent=2))


def worker_url() -> str:
    return load_local_config().get("worker_url", DEFAULT_WORKER_URL).rstrip("/")


def os_platform_string() -> str:
    """Human readable OS string for alert headers, e.g. 'macOS 14.5 (arm64)'."""
    arch = platform.machine()
    if sys.platform == "darwin":
        mac_ver = platform.mac_ver()[0] or "?"
        return f"macOS {mac_ver} ({arch})"
    if sys.platform == "win32":
        return f"Windows {platform.release()} ({arch})"
    return f"{platform.system()} {platform.release()} ({arch})"


def device_noun() -> str:
    """'Mac', 'Windows' or 'Device' for the alert header label."""
    if sys.platform == "darwin":
        return "Mac"
    if sys.platform == "win32":
        return "Windows"
    return "Device"
