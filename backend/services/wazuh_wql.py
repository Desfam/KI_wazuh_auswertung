"""
wazuh_wql.py
============
Wazuh Query Language (WQL) builder and parser.

WQL is used in the `q=` query parameter of most Wazuh API list endpoints.
It supports the syntax:

    field=value        exact match
    field!=value       not equal
    field~value        contains
    field<value        less than
    field>value        greater than
    expr;expr          AND
    expr,expr          OR

Official docs: https://documentation.wazuh.com/current/user-manual/api/queries.html

Example:
    build_wql({"status": "active", "os_platform": "windows"})
    # → "status=active;os.platform=windows"
"""
from __future__ import annotations

from typing import Optional

# Maps our human-friendly filter keys → Wazuh WQL field names
_FIELD_MAP: dict[str, str] = {
    "status":              "status",
    "os_platform":         "os.platform",
    "os_name":             "os.name",
    "group":               "group",
    "name":                "name",
    "name_contains":       "name",       # handled with ~ operator
    "ip":                  "ip",
    "version":             "version",
    "manager":             "manager",
    "node_name":           "node_name",
    "last_keep_alive_after": "lastKeepAlive",
}

# For these keys we use the ~ (contains) operator instead of =
_CONTAINS_KEYS = {"name_contains"}
# For these keys we use > (greater than) instead of =
_GT_KEYS = {"last_keep_alive_after"}


def build_wql(filters: dict[str, str | None]) -> str:
    """
    Convert a dict of filter key→value pairs into a WQL q= string.

    Ignores keys with None / empty-string values.

    Examples:
        build_wql({"status": "active"})
        # → "status=active"

        build_wql({"status": "active", "os_platform": "windows"})
        # → "status=active;os.platform=windows"

        build_wql({"name_contains": "web"})
        # → "name~web"

        build_wql({"last_keep_alive_after": "2024-01-01T00:00:00Z"})
        # → "lastKeepAlive>2024-01-01T00:00:00Z"

        build_wql({})
        # → ""
    """
    clauses: list[str] = []

    for key, value in filters.items():
        if value is None or value == "":
            continue

        field = _FIELD_MAP.get(key)
        if field is None:
            # Pass through unknown keys as-is (allows raw WQL field names)
            field = key

        if key in _CONTAINS_KEYS:
            op = "~"
        elif key in _GT_KEYS:
            op = ">"
        else:
            op = "="

        # Escape semicolons and commas in values to avoid WQL injection
        safe_value = str(value).replace(";", "\\;").replace(",", "\\,")
        clauses.append(f"{field}{op}{safe_value}")

    return ";".join(clauses)


def parse_wql(q: str) -> dict[str, str]:
    """
    Parse a WQL q= string back into a dict of {field: value}.

    Only handles AND (;) chains with = operator for round-trip support.
    Complex expressions (OR, ~, <, >) are returned under the "_raw" key.

    Examples:
        parse_wql("status=active;os.platform=windows")
        # → {"status": "active", "os.platform": "windows"}

        parse_wql("name~web")
        # → {"_raw": "name~web"}
    """
    if not q or not q.strip():
        return {}

    result: dict[str, str] = {}

    # Split on unescaped semicolons (AND)
    parts = _split_unescaped(q, ";")

    for part in parts:
        part = part.strip()
        if "=" in part and "~" not in part and "<" not in part and ">" not in part and "!=" not in part:
            field, _, value = part.partition("=")
            result[field.strip()] = value.strip()
        else:
            result["_raw"] = result.get("_raw", "") + ("," if "_raw" in result else "") + part

    return result


def validate_wql(q: str) -> tuple[bool, str]:
    """
    Basic syntactic validation of a WQL expression.

    Returns (is_valid, message).
    """
    if not q:
        return True, "Empty (no filter)"

    parts = _split_unescaped(q, ";")
    for part in parts:
        part_or = _split_unescaped(part, ",")
        for clause in part_or:
            if not any(op in clause for op in ("=", "~", "<", ">")):
                return False, f"Clause '{clause}' has no valid operator (=, ~, <, >)"
            if clause.startswith(("=", "~", "<", ">", "!")):
                return False, f"Clause '{clause}' starts with operator — missing field name"

    return True, "Valid"


# ── helpers ───────────────────────────────────────────────────────────────────

def _split_unescaped(s: str, sep: str) -> list[str]:
    """Split string on unescaped separator characters."""
    parts = []
    current = []
    escaped = False

    for ch in s:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
            current.append(ch)
        elif ch == sep:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)

    if current:
        parts.append("".join(current))

    return parts
