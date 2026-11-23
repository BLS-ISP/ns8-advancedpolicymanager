"""Atomic Idempotency-Key guard backed by SQLite UNIQUE(idempotency_key, endpoint)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import TYPE_CHECKING, Any, Callable

from fastapi.responses import JSONResponse

from app.errors import ApiError, utc_now_iso

if TYPE_CHECKING:
    from app.db.connection import DatabaseManager


def compute_request_hash(payload: Any) -> str:
    """Compute canonical SHA-256 digest of a JSON-serializable request payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def run_idempotent(
    *,
    db: "DatabaseManager",
    idempotency_key: str | None,
    endpoint: str,
    payload_for_hash: Any,
    action: Callable[[], tuple[int, dict[str, Any]]],
) -> JSONResponse:
    """Execute `action` atomically under `(idempotency_key, endpoint)` idempotency semantics."""
    if idempotency_key is None or not idempotency_key.strip():
        status_code, response_body = action()
        return JSONResponse(status_code=status_code, content=response_body)

    clean_key = idempotency_key.strip()
    if len(clean_key) > 256:
        raise ApiError(422, "VALIDATION_ERROR", "Idempotency-Key darf maximal 256 Zeichen lang sein")

    req_hash = compute_request_hash(payload_for_hash)

    with db.transaction(immediate=True) as conn:
        try:
            conn.execute(
                """
                INSERT INTO idempotency_records
                    (idempotency_key, endpoint, request_hash, state, status_code, response_json, created_at)
                VALUES (?, ?, ?, 'IN_PROGRESS', NULL, NULL, ?)
                """,
                (clean_key, endpoint, req_hash, utc_now_iso()),
            )
        except sqlite3.IntegrityError:
            existing = conn.execute(
                """
                SELECT request_hash, state, status_code, response_json
                FROM idempotency_records
                WHERE idempotency_key = ? AND endpoint = ?
                """,
                (clean_key, endpoint),
            ).fetchone()
            if existing is None:
                raise ApiError(409, "IDEMPOTENCY_IN_PROGRESS", "Parallele Anfrage aktiv")

            if existing["request_hash"] != req_hash:
                raise ApiError(
                    422,
                    "IDEMPOTENCY_KEY_REUSED",
                    "Idempotency-Key wurde bereits mit einem anderen Request-Body verwendet",
                )

            if existing["state"] == "IN_PROGRESS":
                raise ApiError(
                    409,
                    "IDEMPOTENCY_IN_PROGRESS",
                    "Ein paralleler Request mit diesem Idempotency-Key wird bereits verarbeitet",
                )

            cached_body = json.loads(existing["response_json"])
            return JSONResponse(
                status_code=int(existing["status_code"]),
                content=cached_body,
            )

    try:
        status_code, response_body = action()
    except Exception:
        with db.transaction(immediate=True) as cleanup_conn:
            cleanup_conn.execute(
                """
                DELETE FROM idempotency_records
                WHERE idempotency_key = ? AND endpoint = ? AND state = 'IN_PROGRESS'
                """,
                (clean_key, endpoint),
            )
        raise

    serialized = json.dumps(response_body, ensure_ascii=False)
    with db.transaction(immediate=True) as finish_conn:
        finish_conn.execute(
            """
            UPDATE idempotency_records
            SET state = 'COMPLETED', status_code = ?, response_json = ?
            WHERE idempotency_key = ? AND endpoint = ?
            """,
            (status_code, serialized, clean_key, endpoint),
        )

    return JSONResponse(status_code=status_code, content=response_body)
