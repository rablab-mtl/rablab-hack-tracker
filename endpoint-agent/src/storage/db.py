"""Local SQLite persistence.

Holds:
  - seen:      dedup of (detector, pattern) so we alert once, then stay silent
  - iocs:      C2 domains / IPs downloaded from abuse.ch
  - alerts:    history of alerts sent (for the 24h counter and status command)
  - whitelist: patterns the user marked as false positives (never alert again)

All access is single-process and short-lived; we open a connection per operation
to keep things robust across the agent's long-running threads.
"""
from __future__ import annotations


import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


class Database:
    def __init__(self, path: Path):
        self.path = str(path)
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as c:
            c.executescript(
                """
                CREATE TABLE IF NOT EXISTS seen (
                    detector TEXT NOT NULL,
                    pattern  TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    PRIMARY KEY (detector, pattern)
                );
                CREATE TABLE IF NOT EXISTS iocs (
                    value TEXT PRIMARY KEY,
                    kind  TEXT NOT NULL,
                    updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    ts REAL NOT NULL,
                    detector TEXT NOT NULL,
                    icon TEXT NOT NULL,
                    headline TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS whitelist (
                    pattern TEXT PRIMARY KEY,
                    added REAL NOT NULL
                );
                """
            )

    # ----- dedup --------------------------------------------------------
    def seen_before(self, detector: str, pattern: str) -> bool:
        """Returns True if this (detector, pattern) was already alerted; else records it."""
        with self._conn() as c:
            row = c.execute(
                "SELECT 1 FROM seen WHERE detector=? AND pattern=?", (detector, pattern)
            ).fetchone()
            if row:
                return True
            c.execute(
                "INSERT INTO seen (detector, pattern, first_seen) VALUES (?,?,?)",
                (detector, pattern, time.time()),
            )
            return False

    # ----- whitelist ----------------------------------------------------
    def is_whitelisted(self, pattern: str) -> bool:
        with self._conn() as c:
            return (
                c.execute("SELECT 1 FROM whitelist WHERE pattern=?", (pattern,)).fetchone()
                is not None
            )

    def add_whitelist(self, pattern: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT OR IGNORE INTO whitelist (pattern, added) VALUES (?,?)",
                (pattern, time.time()),
            )

    def sync_whitelist(self, patterns: list[str]) -> None:
        """Merge in patterns whitelisted server-side (from /agent-config)."""
        for p in patterns:
            self.add_whitelist(p)

    def set_whitelist(self, patterns: list[str]) -> None:
        """Replace the local whitelist with exactly the server-side list, so a pattern
        removed from the whitelist (un-whitelisted by the admin) starts alerting again."""
        with self._conn() as c:
            c.execute("DELETE FROM whitelist")
            c.executemany(
                "INSERT OR IGNORE INTO whitelist (pattern, added) VALUES (?,?)",
                [(p, time.time()) for p in patterns],
            )

    # ----- iocs ---------------------------------------------------------
    def replace_iocs(self, items: list[tuple[str, str]]) -> None:
        """items = list of (value, kind). Replaces the whole IoC set."""
        now = time.time()
        with self._conn() as c:
            c.execute("DELETE FROM iocs")
            c.executemany(
                "INSERT OR REPLACE INTO iocs (value, kind, updated) VALUES (?,?,?)",
                [(v, k, now) for v, k in items],
            )

    def ioc_set(self) -> set[str]:
        with self._conn() as c:
            return {r[0] for r in c.execute("SELECT value FROM iocs").fetchall()}

    def ioc_ip_set(self) -> set[str]:
        with self._conn() as c:
            return {
                r[0] for r in c.execute("SELECT value FROM iocs WHERE kind='ip'").fetchall()
            }

    def ioc_count(self) -> int:
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]

    # ----- alerts -------------------------------------------------------
    def record_alert(self, detector: str, icon: str, headline: str) -> None:
        with self._conn() as c:
            c.execute(
                "INSERT INTO alerts (ts, detector, icon, headline) VALUES (?,?,?,?)",
                (time.time(), detector, icon, headline),
            )

    def alerts_last_24h(self) -> int:
        cutoff = time.time() - 24 * 3600
        with self._conn() as c:
            return c.execute("SELECT COUNT(*) FROM alerts WHERE ts>=?", (cutoff,)).fetchone()[0]
