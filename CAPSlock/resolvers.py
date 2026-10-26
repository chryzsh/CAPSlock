from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional, Set
from CAPSlock.models import UserContext, NameResolver
from roadtools.roadlib.metadef.database import User, Group, DirectoryRole, Application, ServicePrincipal, Policy, lnk_group_member_group


def get_user_by_upn(session, upn: str) -> Optional[User]:
    return session.query(User).filter(User.userPrincipalName == upn).one_or_none()


def build_user_context(session, user: User) -> UserContext:
    groups = (
        session.query(Group)
        .join(Group.memberUsers)
        .filter(User.objectId == user.objectId)
        .all()
    )
    group_ids = expand_group_ids(session, {g.objectId for g in groups if getattr(g, "objectId", None)})

    roles = (
        session.query(DirectoryRole)
        .join(DirectoryRole.memberUsers)
        .filter(User.objectId == user.objectId)
        .all()
    )
    roles += roles_via_groups(session, group_ids)

    role_object_ids = {r.objectId for r in roles if getattr(r, "objectId", None)}

    role_template_ids = set()
    for r in roles:
        tid = getattr(r, "roleTemplateId", None)
        if tid:
            role_template_ids.add(tid)

    return UserContext(
        user=user,
        object_id=user.objectId,
        groups=group_ids,
        role_object_ids=role_object_ids,
        role_template_ids=role_template_ids,
        assumed_groups=set(),
        assumed_roles=set(),
    )


def expand_group_ids(session, group_ids: Set[str]) -> Set[str]:
    # Conditional Access uses transitive membership, so walk up group nesting.
    result = set(group_ids)
    frontier = set(group_ids)
    while frontier:
        parents = (
            session.query(lnk_group_member_group.c.Group)
            .filter(lnk_group_member_group.c.childGroup.in_(frontier))
            .all()
        )
        frontier = {p for (p,) in parents if p and p not in result}
        result |= frontier
    return result


def roles_via_groups(session, group_ids: Set[str]) -> list:
    # Directory roles assigned to role-assignable groups the user is in.
    if not group_ids:
        return []
    return (
        session.query(DirectoryRole)
        .join(DirectoryRole.memberGroups)
        .filter(Group.objectId.in_(group_ids))
        .all()
    )


def build_name_resolver(session) -> NameResolver:
    groups = session.query(Group.objectId, Group.displayName).all()
    roles = session.query(
        DirectoryRole.objectId,
        DirectoryRole.displayName,
        DirectoryRole.roleTemplateId
    ).all()

    group_names_by_id = {gid: name for gid, name in groups if gid and name}
    role_names_by_object_id = {oid: name for oid, name, tid in roles if oid and name}
    role_names_by_template_id = {tid: name for oid, name, tid in roles if tid and name}

    users = session.query(User.objectId, User.userPrincipalName, User.displayName).all()
    user_names_by_id = {}
    for oid, upn, dname in users:
        if oid:
            user_names_by_id[oid] = upn or dname or "(unknown)"

    apps = session.query(Application.objectId, Application.appId, Application.displayName).all()
    app_names_by_id = {}
    for oid, aid, dname in apps:
        if dname:
            if oid:
                app_names_by_id[oid] = dname
            if aid:
                app_names_by_id[aid] = dname

    sps = session.query(ServicePrincipal.objectId, ServicePrincipal.appId, ServicePrincipal.displayName).all()
    for oid, aid, dname in sps:
        if dname:
            if oid and oid not in app_names_by_id:
                app_names_by_id[oid] = dname
            if aid and aid not in app_names_by_id:
                app_names_by_id[aid] = dname

    import json as _json
    locations = session.query(Policy).filter(Policy.policyType == 6).all()
    location_names_by_id = {}
    for loc in locations:
        if loc.displayName:
            if loc.policyIdentifier:
                location_names_by_id[loc.policyIdentifier] = loc.displayName
            if loc.objectId and loc.objectId not in location_names_by_id:
                location_names_by_id[loc.objectId] = loc.displayName
        if loc.policyDetail:
            for raw in loc.policyDetail:
                try:
                    detail = _json.loads(raw)
                    knp = detail.get("KnownNetworkPolicies")
                    if knp and knp.get("NetworkId") and knp.get("NetworkName"):
                        location_names_by_id[knp["NetworkId"]] = knp["NetworkName"].strip()
                except Exception:
                    pass

    return NameResolver(
        group_names_by_id=group_names_by_id,
        role_names_by_template_id=role_names_by_template_id,
        role_names_by_object_id=role_names_by_object_id,
        user_names_by_id=user_names_by_id,
        app_names_by_id=app_names_by_id,
        location_names_by_id=location_names_by_id,
    )


def friendly_ids(resolver: Optional[NameResolver], ids: list[str], kind: str) -> list[str]:
    if resolver is None:
        return ids

    if kind == "group":
        return [resolver.group_name(x) for x in ids]
    if kind == "role":
        return [resolver.role_name(x) for x in ids]
    if kind == "user":
        return [resolver.user_name(x) for x in ids]
    if kind == "app":
        return [resolver.app_name(x) for x in ids]
    if kind == "location":
        return [resolver.location_name(x) for x in ids]
    return ids