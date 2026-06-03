"""Downloads infostealer indicators of compromise (IoCs) from abuse.ch.

We keep two kinds of IoC:
  - ip      : C2 IP addresses. The c2 detector matches active connections against these.
  - domain  : malicious hostnames (kept for reference; IP matching is what fires alerts).

ThreatFox rows are filtered to the infostealer families relevant to this incident.
URLhaus' plain text dump has no tags, so its live malicious hosts are kept as-is
(any corporate machine contacting a confirmed-malicious host is worth flagging).
"""
from __future__ import annotations


import csv
import io
import ipaddress
from urllib.parse import urlparse

import requests

STEALER_KEYWORDS = [
    "stealer",
    "amos",
    "atomic",
    "cthulhu",
    "lumma",
    "redline",
    "vidar",
    "banshee",
    "raccoon",
    "rhadamanthys",
    "stealc",
]

DEFAULT_FEEDS = [
    "https://urlhaus.abuse.ch/downloads/text/",
    "https://threatfox.abuse.ch/export/csv/recent/",
]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _host_from_url(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    try:
        host = urlparse(line if "://" in line else "http://" + line).hostname
        return host
    except ValueError:
        return None


def _parse_threatfox_csv(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    # ThreatFox CSV lines are quoted and prefixed with comment lines starting with '#'.
    rows = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    reader = csv.reader(io.StringIO("\n".join(rows)), skipinitialspace=True)
    for fields in reader:
        if len(fields) < 4:
            continue
        blob = " ".join(fields).lower()
        if not any(k in blob for k in STEALER_KEYWORDS):
            continue
        # Column 2 is ioc_value, column 3 is ioc_type in the standard export.
        ioc_value = fields[2].strip()
        ioc_type = fields[3].strip().lower()
        if ioc_type.startswith("ip"):
            ip = ioc_value.split(":")[0]
            if _is_ip(ip):
                out.append((ip, "ip"))
        elif "domain" in ioc_type or "url" in ioc_type:
            host = _host_from_url(ioc_value) or ioc_value
            if host:
                out.append((host, "ip" if _is_ip(host) else "domain"))
    return out


def _parse_text_feed(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        host = _host_from_url(line)
        if host:
            out.append((host, "ip" if _is_ip(host) else "domain"))
    return out


def fetch_feed(url: str) -> list[tuple[str, str]]:
    resp = requests.get(url, timeout=30, headers={"User-Agent": "rablab-hack-tracker/1.0"})
    resp.raise_for_status()
    text = resp.text
    if "threatfox" in url:
        return _parse_threatfox_csv(text)
    return _parse_text_feed(text)


def update_iocs(db, feeds: list[str]) -> int:
    """Refresh the whole IoC set. Returns the number of indicators stored.

    Robust: a single failing feed does not wipe the existing set.
    """
    collected: dict[str, str] = {}
    any_success = False
    for url in feeds or DEFAULT_FEEDS:
        try:
            for value, kind in fetch_feed(url):
                # Prefer 'ip' kind when the same value appears as both.
                if value not in collected or kind == "ip":
                    collected[value] = kind
            any_success = True
        except (requests.RequestException, ValueError):
            continue
    if not any_success:
        return db.ioc_count()
    db.replace_iocs([(v, k) for v, k in collected.items()])
    return len(collected)
