"""Consistent error handling and pagination utilities per contract Section 2."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any


class ApiError(Exception):
    """Structured API exception producing { "error": { "code", "message", "details" } }."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with Z suffix."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_paginated_response(
    items: list[Any],
    page: int,
    page_size: int,
    total_items: int,
) -> dict[str, Any]:
    """Build standard paginated response matching Section 2 of the API contract."""
    safe_page = max(1, page)
    safe_page_size = max(1, page_size)
    total_pages = max(1, math.ceil(total_items / safe_page_size))
    return {
        "data": items,
        "pagination": {
            "page": safe_page,
            "pageSize": safe_page_size,
            "totalItems": total_items,
            "totalPages": total_pages,
        },
    }
