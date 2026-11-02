from __future__ import annotations
from typing import Any, Iterable, Optional, Set

# Guest and external user targeting (Conditions.Users "GuestsOrExternalUsers").
#
# roadrecon stores the condition in policyDetail as an include or exclude block:
#   {"GuestsOrExternalUsers": {"GuestOrExternalUserTypes": "InternalGuest, B2bCollaborationGuest, ...",
#                              "ExternalTenants": ["<tenant id>", ...]}}
# ExternalTenants is missing when the policy covers all external tenants.
# Older policies use a plain "GuestsOrExternalUsers" or "Guests" value in the Users list instead.
#
# Entra assigns one external user type per sign-in. Offline we only have the user object in
# roadrecon.db, so this module classifies a user from userType and the "#EXT#" marker in the UPN:
#
#   userType Guest  + #EXT# in UPN -> b2bCollaborationGuest  (external account, guest)
#   userType Guest  + no #EXT#     -> internalGuest          (local account, guest)
#   userType Member + #EXT# in UPN -> b2bCollaborationMember (external account, member)
#   userType Member + no #EXT#     -> not external
#
# What cannot be determined offline:
#   - b2bDirectConnectUser and serviceProvider: these users have no user object in the resource
#     tenant (Teams shared channels, GDAP/partner admins), so a user looked up in roadrecon.db
#     never has these types. A policy that only targets them never matches a DB user.
#   - otherExternalUser: Entra's catch-all for external users that fit no other category. It cannot
#     be told apart from the types above with the data roadrecon collects, so this module never
#     assigns it. A policy that only targets otherExternalUser does not match.
#   - The user's home tenant is not in roadrecon.db. When a block lists specific ExternalTenants,
#     a type match is reported as uncertain (signal-dependent) instead of a definitive match.

INTERNAL_GUEST = "internalguest"
B2B_COLLABORATION_GUEST = "b2bcollaborationguest"
B2B_COLLABORATION_MEMBER = "b2bcollaborationmember"
B2B_DIRECT_CONNECT_USER = "b2bdirectconnectuser"
OTHER_EXTERNAL_USER = "otherexternaluser"
SERVICE_PROVIDER = "serviceprovider"

ALL_EXTERNAL_TYPES = {
    INTERNAL_GUEST,
    B2B_COLLABORATION_GUEST,
    B2B_COLLABORATION_MEMBER,
    B2B_DIRECT_CONNECT_USER,
    OTHER_EXTERNAL_USER,
    SERVICE_PROVIDER,
}

# Types this module can assign to a user from roadrecon.db.
DETERMINABLE_TYPES = {INTERNAL_GUEST, B2B_COLLABORATION_GUEST, B2B_COLLABORATION_MEMBER}

# Types that never have a user object in the resource tenant.
NOT_IN_DIRECTORY_TYPES = {B2B_DIRECT_CONNECT_USER, SERVICE_PROVIDER}

# Types that exist in the directory but cannot be identified offline.
UNDETERMINABLE_TYPES = {OTHER_EXTERNAL_USER}

# Legacy values in a Users include/exclude list that mean "all guest and external users".
LEGACY_USER_VALUES = {"guests", "guestsorexternalusers"}

DISPLAY_NAMES = {
    INTERNAL_GUEST: "internalGuest",
    B2B_COLLABORATION_GUEST: "b2bCollaborationGuest",
    B2B_COLLABORATION_MEMBER: "b2bCollaborationMember",
    B2B_DIRECT_CONNECT_USER: "b2bDirectConnectUser",
    OTHER_EXTERNAL_USER: "otherExternalUser",
    SERVICE_PROVIDER: "serviceProvider",
}

MATCH = "match"
UNCERTAIN = "uncertain"


def classify_external_user(user: Any) -> Optional[str]:
    """Return the external user type for a roadrecon User, or None for an internal member."""
    user_type = str(getattr(user, "userType", "") or "").strip().lower()
    upn = str(getattr(user, "userPrincipalName", "") or "").lower()
    external_account = "#ext#" in upn

    if user_type == "guest":
        return B2B_COLLABORATION_GUEST if external_account else INTERNAL_GUEST
    if external_account:
        return B2B_COLLABORATION_MEMBER
    return None


def is_legacy_value(value: Any) -> bool:
    return str(value).strip().lower() in LEGACY_USER_VALUES


def _parse_types(raw: Any) -> Set[str]:
    if raw is None:
        return set()
    if isinstance(raw, str):
        items: Iterable[Any] = raw.split(",")
    elif isinstance(raw, (list, tuple, set)):
        items = raw
    else:
        items = [raw]
    return {str(x).strip().lower() for x in items if str(x).strip()}


def _tenants_enumerated(raw: Any) -> bool:
    """True when the block is limited to specific external tenants."""
    if raw is None:
        return False
    if isinstance(raw, dict):
        kind = str(raw.get("membershipKind") or raw.get("MembershipKind") or "").lower()
        if kind == "all":
            return False
        members = raw.get("members") or raw.get("Members") or []
        return bool(members)
    if isinstance(raw, str):
        return raw.strip().lower() not in ("", "all")
    if isinstance(raw, (list, tuple, set)):
        vals = [str(x).strip().lower() for x in raw if str(x).strip()]
        return bool(vals) and "all" not in vals
    return False


def match_external_block(spec: Any, ext_type: Optional[str]) -> Optional[str]:
    """Match a GuestsOrExternalUsers block against a user's external type.

    Returns MATCH, UNCERTAIN (type matches but the block is limited to specific external tenants),
    or None (no match).
    """
    if ext_type is None or not isinstance(spec, dict):
        return None

    types = _parse_types(spec.get("GuestOrExternalUserTypes", spec.get("guestOrExternalUserTypes")))
    if ext_type not in types:
        return None

    tenants = spec.get("ExternalTenants", spec.get("externalTenants"))
    if _tenants_enumerated(tenants):
        return UNCERTAIN
    return MATCH


def display_type(ext_type: Optional[str]) -> str:
    return DISPLAY_NAMES.get(ext_type or "", ext_type or "")


def describe_block(spec: Any) -> str:
    """Short human-readable form of a GuestsOrExternalUsers block."""
    if not isinstance(spec, dict):
        return str(spec)
    types = _parse_types(spec.get("GuestOrExternalUserTypes", spec.get("guestOrExternalUserTypes")))
    names = [DISPLAY_NAMES.get(t, t) for t in sorted(types)] or ["(no types)"]
    text = ", ".join(names)
    tenants = spec.get("ExternalTenants", spec.get("externalTenants"))
    if _tenants_enumerated(tenants):
        count = len(tenants.get("members") or tenants.get("Members") or []) if isinstance(tenants, dict) else (
            len(tenants) if isinstance(tenants, (list, tuple, set)) else 1
        )
        text += f" (from {count} specific external tenant{'s' if count != 1 else ''})"
    return text
