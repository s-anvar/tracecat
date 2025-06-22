import json
import os

from loguru import logger

from tracecat.auth.models import UserRole


class OIDCRoleAssignmentError(Exception):
    """Raised when OIDC role assignment fails in strict mode."""


def assign_role_from_oidc_token(token: dict) -> UserRole | None:
    """Return user role based on OIDC group claims.

    Args:
        token: Decoded OIDC ID token.

    Returns:
        The assigned ``UserRole`` if one was determined, otherwise ``None``.

    Raises:
        OIDCRoleAssignmentError: If strict mode is enabled and no role could be
            assigned.
    """

    groups_claim = token.get("groups") or []
    if isinstance(groups_claim, str):
        groups = [groups_claim]
    else:
        groups = list(groups_claim)

    group_role_map_raw = os.environ.get("OIDC_GROUP_ROLE_MAP") or "{}"
    try:
        group_role_map = json.loads(group_role_map_raw)
    except json.JSONDecodeError:
        logger.error(
            "Invalid OIDC_GROUP_ROLE_MAP", raw=group_role_map_raw
        )
        group_role_map = {}

    for group in groups:
        mapped_role = group_role_map.get(group)
        if mapped_role in {"ADMIN", "BASIC"}:
            logger.info(
                "OIDC group matched",
                event="oidc_role_assigned",
                sub=token.get("sub"),
                email=token.get("email"),
                client_id=token.get("aud"),
                assigned_role=mapped_role,
                matched_group=group,
            )
            return UserRole(mapped_role.lower())

    default_role = os.environ.get("OIDC_DEFAULT_ROLE")
    if default_role in {"ADMIN", "BASIC"}:
        logger.info(
            "OIDC default role applied",
            event="oidc_default_role",
            sub=token.get("sub"),
            email=token.get("email"),
            client_id=token.get("aud"),
            assigned_role=default_role,
        )
        return UserRole(default_role.lower())

    strict_mode = os.environ.get("OIDC_STRICT_MODE", "false").lower() == "true"
    if strict_mode:
        logger.error(
            "OIDC role assignment failed",
            event="oidc_role_assignment_failed",
            sub=token.get("sub"),
            groups=groups,
            client_id=token.get("aud"),
            reason="no_match",
        )
        raise OIDCRoleAssignmentError("No matching role from OIDC groups")

    logger.info(
        "OIDC role assignment skipped",
        event="oidc_role_assignment_skipped",
        sub=token.get("sub"),
        groups=groups,
        client_id=token.get("aud"),
        reason="no_match",
    )
    return None
