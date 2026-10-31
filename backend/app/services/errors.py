"""Typed application errors that map cleanly onto HTTP responses."""

from __future__ import annotations

from typing import Any


class IngestError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        **extra: Any,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.extra = extra

    def as_detail(self) -> dict[str, Any]:
        detail = {"code": self.code, "message": self.message}
        detail.update(self.extra)
        return detail
