from __future__ import annotations
from typing import Any, Dict, List, Optional, Set, Tuple

# CAPSlock takes client app types as Graph names (clientAppTypes). roadrecon
# stores Entra's internal names in Conditions.ClientTypes. Some Graph names
# cover several internal names.
GRAPH_CLIENT_APPS: Tuple[str, ...] = (
    "browser",
    "mobileAppsAndDesktopClients",
    "exchangeActiveSync",
    "other",
)

INTERNAL_CLIENT_TYPES: Dict[str, Tuple[str, ...]] = {
    "browser": ("Browser",),
    "mobileAppsAndDesktopClients": ("Native",),
    "exchangeActiveSync": ("EasSupported", "EasUnsupported"),
    "other": ("LegacyImap", "LegacyMapi", "LegacyOffice", "LegacyPop", "LegacySmtp", "OtherLegacy"),
}

# Lowercased stored or scenario value -> (Graph name, internal names it covers).
_ALIASES: Dict[str, Tuple[str, Tuple[str, ...]]] = {"all": ("all", ())}
for _graph, _internal in INTERNAL_CLIENT_TYPES.items():
    _ALIASES[_graph.lower()] = (_graph, _internal)
    for _name in _internal:
        _ALIASES[_name.lower()] = (_graph, (_name,))
# Graph also has easSupported (EAS clients on supported platforms only).
_ALIASES["eassupported"] = ("exchangeActiveSync", ("EasSupported",))


def normalize_client_app(value: Any) -> Optional[str]:
    """Return the Graph name for a Graph or internal client app value, "all",
    or None if the value is not recognized."""
    if value is None:
        return None
    hit = _ALIASES.get(str(value).strip().lower())
    return hit[0] if hit else None


def _covered(values: List[Any]) -> Tuple[Dict[str, Set[str]], bool, List[str]]:
    """Map a list of stored values to {Graph name: internal names covered},
    an "all" flag, and the values that were not recognized."""
    covered: Dict[str, Set[str]] = {}
    has_all = False
    unknown: List[str] = []
    for v in values:
        if v is None or not str(v).strip():
            continue
        hit = _ALIASES.get(str(v).strip().lower())
        if hit is None:
            unknown.append(str(v))
            continue
        graph, internal = hit
        if graph == "all":
            has_all = True
            continue
        covered.setdefault(graph, set()).update(internal)
    return covered, has_all, unknown


def raw_client_app_values(cond: Dict[str, Any]) -> Tuple[List[Any], List[Any]]:
    """Return the include and exclude values as stored. Reads the roadrecon
    ClientTypes blocks and the Graph-style ClientAppTypes list."""
    inc: List[Any] = []
    exc: List[Any] = []

    graph_style = cond.get("ClientAppTypes") or []
    if isinstance(graph_style, str):
        graph_style = [graph_style]
    inc.extend(graph_style)

    ct = cond.get("ClientTypes") or {}
    for blk in (ct.get("Include") or []):
        inc.extend(blk.get("ClientTypes") or [])
    for blk in (ct.get("Exclude") or []):
        exc.extend(blk.get("ClientTypes") or [])

    return inc, exc


def describe_client_app_values(values: List[Any]) -> List[str]:
    """Human-readable list: Graph names, with the stored names in brackets
    when they differ. Unrecognized values are kept and marked."""
    covered, has_all, unknown = _covered(values)
    out: List[str] = []
    if has_all:
        out.append("All")
    for graph in GRAPH_CLIENT_APPS:
        if graph not in covered:
            continue
        internal = INTERNAL_CLIENT_TYPES[graph]
        stored = [str(v) for v in values if normalize_client_app(v) == graph]
        if all(str(v).strip().lower() == graph.lower() for v in stored):
            out.append(graph)
        elif covered[graph] >= set(internal):
            out.append(f"{graph} ({', '.join(internal)})")
        else:
            part = [n for n in internal if n in covered[graph]]
            out.append(f"{graph} (only {', '.join(part)})")
    for v in unknown:
        out.append(f"{v} (unrecognized)")
    return out


def eval_client_app(cond: Dict[str, Any], scenario_value: Optional[str]) -> Tuple[bool, bool, str]:
    """Evaluate the client app condition. Returns (matched, runtime_dependent, reason).

    Unrecognized values are never dropped. CAPSlock cannot tell whether an
    unrecognized stored value covers the scenario client app, so:
      - an unrecognized include value that could be the only match makes the
        result signal-dependent instead of "did not match";
      - an unrecognized exclude value makes a match signal-dependent, since
        the scenario client app may be excluded;
      - an unrecognized scenario value makes the result signal-dependent.
    A Graph name such as "other" covers several internal names. If a policy
    lists only some of them, a scenario with that Graph name may or may not
    be covered, so that is signal-dependent too.
    """
    inc_raw, exc_raw = raw_client_app_values(cond)
    inc, inc_all, inc_unknown = _covered(inc_raw)
    exc, exc_all, exc_unknown = _covered(exc_raw)

    if not inc and not inc_all and not inc_unknown and not exc and not exc_all and not exc_unknown:
        return True, False, "ClientApp: no client app type condition present"

    if scenario_value is None:
        return True, True, "ClientApp: scenario client_app not provided"

    got = normalize_client_app(scenario_value)
    if got is None or got == "all":
        return True, True, f"ClientApp: scenario client_app not recognized ({scenario_value})"

    full = set(INTERNAL_CLIENT_TYPES[got])
    notes: List[str] = []

    # Exclusions first.
    if exc_all:
        return False, False, "ClientApp: excludes All"
    if got in exc:
        if exc[got] >= full:
            return False, False, f"ClientApp: excluded ({got})"
        notes.append(f"policy excludes only {', '.join(sorted(exc[got]))} of {got}")
    if exc_unknown:
        notes.append(f"policy excludes unrecognized client type(s) {', '.join(exc_unknown)}")

    # Inclusions. Only excludes present means all client apps are included.
    if not inc and not inc_all and not inc_unknown:
        included, how = True, "not excluded (implicit All)"
    elif inc_all:
        included, how = True, "includes All"
    elif got in inc and inc[got] >= full:
        included, how = True, f"matched ({got})"
    elif got in inc:
        included, how = True, f"matched ({got})"
        notes.append(f"policy includes only {', '.join(sorted(inc[got]))} of {got}")
    elif inc_unknown:
        included, how = True, f"not in known include values ({got})"
        notes.append(f"policy includes unrecognized client type(s) {', '.join(inc_unknown)}")
    else:
        included, how = False, f"did not match ({got})"

    if not included:
        return False, False, f"ClientApp: {how}"
    if notes:
        return True, True, f"ClientApp: {how}; " + "; ".join(notes)
    return True, False, f"ClientApp: {how}"
