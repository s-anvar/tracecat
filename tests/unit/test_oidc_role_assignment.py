import json

import pytest

from tracecat.auth.models import UserRole
from tracecat.auth.oidc import OIDCGroupRoleError, determine_oidc_role


@pytest.mark.anyio
async def test_role_from_group(monkeypatch):
    token = {
        "sub": "1",
        "email": "a@b.com",
        "aud": "client",
        "groups": ["admins", "users"],
    }
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", json.dumps({"admins": "ADMIN"}))
    assert determine_oidc_role(token) == UserRole.ADMIN


@pytest.mark.anyio
async def test_role_from_default(monkeypatch):
    token = {"sub": "1", "email": "a@b.com", "aud": "client", "groups": ["nogroup"]}
    monkeypatch.delenv("OIDC_GROUP_ROLE_MAP", raising=False)
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "BASIC")
    assert determine_oidc_role(token) == UserRole.BASIC


@pytest.mark.anyio
async def test_role_no_match(monkeypatch):
    token = {"sub": "1", "email": "a@b.com", "aud": "client", "groups": ["nogroup"]}
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", json.dumps({"admins": "ADMIN"}))
    monkeypatch.delenv("OIDC_DEFAULT_ROLE", raising=False)
    with pytest.raises(OIDCGroupRoleError):
        determine_oidc_role(token)


@pytest.mark.anyio
async def test_role_group_case_insensitive(monkeypatch):
    token = {
        "sub": "1",
        "email": "a@b.com",
        "aud": "client",
        "groups": ["TraceCat Admins"],
    }
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", json.dumps({"tracecat admins": "ADMIN"}))
    assert determine_oidc_role(token) == UserRole.ADMIN


@pytest.mark.anyio
async def test_role_group_whitespace(monkeypatch):
    token = {"sub": "1", "email": "a@b.com", "aud": "client", "groups": ["  admins  "]}
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", json.dumps({"admins": "ADMIN"}))
    assert determine_oidc_role(token) == UserRole.ADMIN
