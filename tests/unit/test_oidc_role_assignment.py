import json

import pytest

from tracecat.auth.models import UserRole
from tracecat.auth.oidc import OIDCRoleAssignmentError, assign_role_from_oidc_token


@pytest.mark.anyio
async def test_oidc_role_match(monkeypatch):
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", json.dumps({"tracecat-admins": "ADMIN"}))
    token = {"sub": "1", "email": "a@example.com", "aud": "client", "groups": ["tracecat-admins"]}
    role = assign_role_from_oidc_token(token)
    assert role == UserRole.ADMIN


@pytest.mark.anyio
async def test_oidc_default_role(monkeypatch):
    monkeypatch.delenv("OIDC_GROUP_ROLE_MAP", raising=False)
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "BASIC")
    token = {"sub": "1", "email": "a@example.com", "aud": "client", "groups": ["none"]}
    role = assign_role_from_oidc_token(token)
    assert role == UserRole.BASIC


@pytest.mark.anyio
async def test_oidc_strict_mode(monkeypatch):
    monkeypatch.delenv("OIDC_GROUP_ROLE_MAP", raising=False)
    monkeypatch.delenv("OIDC_DEFAULT_ROLE", raising=False)
    monkeypatch.setenv("OIDC_STRICT_MODE", "true")
    token = {"sub": "1", "email": "a@example.com", "aud": "client", "groups": []}
    with pytest.raises(OIDCRoleAssignmentError):
        assign_role_from_oidc_token(token)
