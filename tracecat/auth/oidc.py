from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from tracecat.auth.models import UserRole
from tracecat.logger import logger

__all__ = ["OIDCGroupRoleError", "determine_oidc_role"]


class OIDCGroupRoleError(Exception):
    """Raised when a role cannot be resolved from the OIDC token."""


_ALLOWED_ROLES = {"ADMIN": UserRole.ADMIN, "BASIC": UserRole.BASIC}


def _parse_groups(groups_claim: Any) -> list[str]:
    if groups_claim is None:
        return []
    if isinstance(groups_claim, str):
        return [groups_claim]
    if isinstance(groups_claim, list | tuple | set):
        return [str(g) for g in groups_claim]
    return []


def determine_oidc_role(id_token: Mapping[str, Any]) -> UserRole:
    """Determine a user's role based on the OIDC ``id_token`` groups claim."""

    groups = _parse_groups(id_token.get("groups"))
    sub = id_token.get("sub")
    email = id_token.get("email")
    client_id = id_token.get("aud")

    raw_map = os.getenv("OIDC_GROUP_ROLE_MAP", "{}")
    try:
        group_map = json.loads(raw_map) if raw_map else {}
    except json.JSONDecodeError:
        logger.error(
            "Invalid OIDC_GROUP_ROLE_MAP JSON", sub=sub, client_id=client_id
        )
        group_map = {}

    for group in groups:
        role_name = group_map.get(group)
        if role_name:
            role_enum = _ALLOWED_ROLES.get(str(role_name).upper())
            if role_enum:
                logger.info(
                    "OIDC role assigned from group",
                    sub=sub,
                    email=email,
                    assigned_role=role_enum.value,
                    matched_group=group,
                    client_id=client_id,
                )
                return role_enum

    default_role = os.getenv("OIDC_DEFAULT_ROLE")
    role_enum = _ALLOWED_ROLES.get((default_role or "").upper())
    if role_enum:
        logger.info(
            "OIDC role assigned from default",
            sub=sub,
            email=email,
            assigned_role=role_enum.value,
            matched_group=None,
            client_id=client_id,
        )
        return role_enum

    logger.error(
        "OIDC role assignment failed",
        sub=sub,
        groups=groups,
        reason="no_matching_groups",
        client_id=client_id,
    )
    raise OIDCGroupRoleError("No matching OIDC group and no valid default role")
