"""SQLite schema migrations and cluster revision helpers."""

from __future__ import annotations

import sqlite3

from app.errors import utc_now_iso

SCHEMA_VERSION = 1

DDL_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS system_state (
        key TEXT PRIMARY KEY,
        int_value INTEGER NOT NULL DEFAULT 0,
        text_value TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS policies (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        is_enabled INTEGER NOT NULL DEFAULT 1,
        revision INTEGER NOT NULL DEFAULT 1,
        rules_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS device_groups (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        description TEXT NOT NULL DEFAULT '',
        tags_json TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS assignments (
        id TEXT PRIMARY KEY,
        policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
        priority INTEGER NOT NULL,
        is_enabled INTEGER NOT NULL DEFAULT 1,
        target_user_type TEXT NOT NULL,
        target_user_ref TEXT,
        target_device_type TEXT NOT NULL,
        target_device_ref TEXT,
        os_filter_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_assignments_priority
    ON assignments(priority ASC, created_at ASC);
    """,
    """
    CREATE TABLE IF NOT EXISTS enrollment_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_prefix TEXT NOT NULL,
        default_device_group_id TEXT REFERENCES device_groups(id) ON DELETE SET NULL,
        expires_at TEXT NOT NULL,
        max_uses INTEGER NOT NULL,
        use_count INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        hostname TEXT NOT NULL,
        os_family TEXT NOT NULL,
        os_version TEXT NOT NULL DEFAULT '',
        arch TEXT NOT NULL DEFAULT 'x86_64',
        agent_version TEXT NOT NULL DEFAULT '1.0.0',
        machine_id TEXT,
        current_user TEXT,
        device_token_hash TEXT UNIQUE,
        applied_revision INTEGER NOT NULL DEFAULT 0,
        compliance_status TEXT NOT NULL DEFAULT 'COMPLIANT',
        compliance_items_json TEXT NOT NULL DEFAULT '[]',
        last_seen_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS device_group_memberships (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        device_group_id TEXT NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
        PRIMARY KEY (device_id, device_group_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS compliance_events (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
        device_hostname TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL
    );
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_compliance_events_timestamp
    ON compliance_events(timestamp DESC);
    """,
    """
    CREATE TABLE IF NOT EXISTS idempotency_records (
        idempotency_key TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        request_hash TEXT NOT NULL,
        state TEXT NOT NULL,
        status_code INTEGER,
        response_json TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (idempotency_key, endpoint),
        UNIQUE (idempotency_key, endpoint)
    );
    """,
]


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Create tables, indexes, and initial system state idempotently."""
    for ddl in DDL_STATEMENTS:
        conn.execute(ddl)

    conn.execute(
        "INSERT OR IGNORE INTO system_state (key, int_value, text_value) VALUES ('cluster_revision', 1, NULL)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
        (SCHEMA_VERSION, utc_now_iso()),
    )
    conn.commit()


def get_cluster_revision(conn: sqlite3.Connection) -> int:
    row = conn.execute(
        "SELECT int_value FROM system_state WHERE key = 'cluster_revision'"
    ).fetchone()
    return int(row["int_value"]) if row else 1


def bump_cluster_revision(conn: sqlite3.Connection) -> int:
    conn.execute(
        "UPDATE system_state SET int_value = int_value + 1 WHERE key = 'cluster_revision'"
    )
    return get_cluster_revision(conn)
