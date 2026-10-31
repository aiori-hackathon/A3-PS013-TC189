"""Agent enrollment and bearer-token authentication."""

from __future__ import annotations

import hashlib
import hmac
import secrets

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.constants import AgentStatus
from app.database import get_db
from app.models import Agent

AGENT_TOKEN_PREFIX = "ct_agent_"
_AGENT_TOKEN_BYTES = 32


def generate_agent_token() -> str:
    return f"{AGENT_TOKEN_PREFIX}{secrets.token_urlsafe(_AGENT_TOKEN_BYTES)}"


def hash_agent_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_prefix(token: str) -> str:
    return token[:12]


def require_enrollment_token(
    x_enrollment_token: str | None = Header(default=None, alias="X-Enrollment-Token"),
    settings: Settings = Depends(get_settings),
) -> None:
    configured = settings.agent_enrollment_token
    if not configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "agent_registration_disabled",
                "message": (
                    "Agent registration is disabled because AGENT_ENROLLMENT_TOKEN "
                    "is not configured on the server."
                ),
            },
        )
    if not x_enrollment_token or not hmac.compare_digest(
        x_enrollment_token.encode("utf-8"), configured.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "invalid_enrollment_token",
                "message": "Enrollment token is missing or invalid.",
            },
        )


def get_current_agent(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_db),
) -> Agent:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "missing_agent_token", "message": "Bearer agent token is required."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    scheme, _, token = authorization.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token.startswith(AGENT_TOKEN_PREFIX) or len(token) < 20:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_agent_token", "message": "Agent token is malformed."},
            headers={"WWW-Authenticate": "Bearer"},
        )

    agent = session.scalar(select(Agent).where(Agent.token_hash == hash_agent_token(token)))
    if agent is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_agent_token", "message": "Agent token is not recognized."},
            headers={"WWW-Authenticate": "Bearer"},
        )
    if agent.status is AgentStatus.DISABLED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "agent_disabled", "message": "This agent has been disabled."},
        )
    return agent
