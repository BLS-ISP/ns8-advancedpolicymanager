"""SQLite3 WAL connection manager with foreign keys enforced."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.config import Settings
from app.db.schema import apply_migrations
from app.db.seed import seed_demo_data_if_empty


class DatabaseManager:
    """Manages SQLite WAL connections, migrations, and optional mock demo seeding."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._init_lock = threading.Lock()
        self._initialized = False

    @property
    def db_path(self) -> Path:
        return self.settings.resolve_data_dir() / "apm.db"

    def _open_raw_connection(self, isolation_level: str | None = "") -> sqlite3.Connection:
        data_dir = self.settings.resolve_data_dir()
        data_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            isolation_level=isolation_level,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def ensure_initialized(self) -> None:
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            conn = self._open_raw_connection()
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                apply_migrations(conn)
                if self.settings.ldap_mode == "mock" and self.settings.apm_seed_demo:
                    seed_demo_data_if_empty(conn)
            finally:
                conn.close()
            self._initialized = True

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        self.ensure_initialized()
        conn = self._open_raw_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        self.ensure_initialized()
        conn = self._open_raw_connection(isolation_level=None if immediate else "")
        try:
            if immediate:
                conn.execute("BEGIN IMMEDIATE;")
            yield conn
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            raise
        finally:
            conn.close()
