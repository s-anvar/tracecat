import importlib
import os

import pytest

from tracecat.auth.models import UserRole
from tracecat.auth import users as users_module
import tracecat.config as config


def reload_modules():
    importlib.reload(config)
    importlib.reload(users_module)


def test_role_highest_privilege(monkeypatch):
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", '{"admins":"admin","users":"basic"}')
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "basic")
    reload_modules()
    assert users_module.resolve_oidc_role(["users", "admins"]) == UserRole.ADMIN


def test_fallback_default_role(monkeypatch):
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", '{"editors":"basic"}')
    monkeypatch.setenv("OIDC_DEFAULT_ROLE", "basic")
    reload_modules()
    assert users_module.resolve_oidc_role(["unknown"]) == UserRole.BASIC


def test_no_default_role(monkeypatch):
    monkeypatch.setenv("OIDC_GROUP_ROLE_MAP", '{"editors":"basic"}')
    monkeypatch.delenv("OIDC_DEFAULT_ROLE", raising=False)
    reload_modules()
    assert users_module.resolve_oidc_role(["unknown"]) is None
