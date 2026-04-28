from __future__ import annotations

import re
from typing import Any


# ── Patterns that are ALWAYS suspicious regardless of profile ─────────────────
_ALWAYS_SUSPICIOUS_RE = re.compile(
    r"-enc\b|-encodedcommand|iex\s*\(|invoke-expression|downloadstring|downloadfile"
    r"|rundll32\s+javascript|mimikatz|sekurlsa|lsass|vssadmin\s+delete"
    r"|schtasks\s+/create|net\s+user\s+/add|net\s+localgroup\s+administrators"
    r"|reg\s+add.+\\run\b|wscript\.shell|powershell\s+-w\s+hidden"
    r"|powershell\s+-windowstyle\s+hidden|amsi|shellcode|inject",
    re.IGNORECASE,
)

# Windows event IDs that are routine on sysadmin hosts at high volume
_SYSADMIN_NORMAL_EIDS = frozenset({
    "4624", "4634", "4647", "4648", "4672", "4673", "4674",
    "4688", "4689", "5156", "5157", "7040",
})


def score_group(group: dict[str, Any]) -> dict[str, Any]:
    event_id = group.get("event_id") or ""
    count = group.get("count", 0)
    host = (group.get("host") or "").lower()
    description = (group.get("rule_description") or "").lower()
    sample = group.get("sample", {})
    platform = group.get("platform")

    score = 20
    suspicious = False
    reason_bits: list[str] = []

    if platform == "windows":
        if event_id == "1102":
            score = 90
            suspicious = True
            reason_bits.append("Audit log was cleared")
        elif event_id == "7045":
            score = 78 if count <= 2 else 86
            suspicious = True
            reason_bits.append("New Windows service installation")
        elif event_id == "4728" or event_id == "4732":
            score = 82
            suspicious = True
            reason_bits.append("Privileged group membership changed")
        elif event_id == "4720":
            score = 70
            suspicious = True
            reason_bits.append("New user account created")
        elif event_id == "4688":
            score = 58 if count < 5 else 72
            suspicious = count >= 3
            reason_bits.append("Process creation burst")
        elif event_id == "4625":
            if count >= 20:
                score = 84
                suspicious = True
                reason_bits.append("Repeated failed logons on one host")
            elif count >= 5:
                score = 60
                suspicious = True
                reason_bits.append("Cluster of failed logons")
            else:
                score = 35
                reason_bits.append("Single or low-volume failed logons")

    if platform == "linux":
        searchable = " ".join(
            [
                description,
                str(sample.get("decoder") or ""),
                str(sample.get("linux_type") or ""),
                " ".join(sample.get("groups") or []),
            ]
        ).lower()
        if "sudo" in searchable and "useradd" in searchable:
            score = 88
            suspicious = True
            reason_bits.append("Privilege use near account creation")
        elif "useradd" in searchable or "usermod" in searchable or "groupadd" in searchable:
            score = 76
            suspicious = True
            reason_bits.append("Linux account management activity")
        elif "cron" in searchable:
            score = 64
            suspicious = count >= 2
            reason_bits.append("Cron-related activity")
        elif "sshd" in searchable or "authentication_failed" in searchable or "invalid_login" in searchable or "pam" in searchable:
            score = 82 if count >= 10 else 58
            suspicious = count >= 3
            reason_bits.append("Authentication anomalies on Linux")

    if "domain controller" in host or "dc" == host:
        score += 5
        reason_bits.append("Host naming suggests higher value target")

    score = max(0, min(score, 100))
    confidence = min(95, max(45, 45 + count * 3))
    severity = severity_from_score(score)
    return {
        "local_score": score,
        "local_severity": severity,
        "confidence": confidence,
        "suspicious": suspicious or score >= 60,
        "local_reason": "; ".join(reason_bits) if reason_bits else "Matched relevant security pattern",
    }


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def apply_profile_modifiers(result: dict[str, Any], profile_name: str | None) -> dict[str, Any]:
    """Adjust a ``score_group`` result based on the host profile.

    This is the second-pass modifier used by the analysis engine.  The goal
    is profilbasiertes Denken: a sysadmin host with many process-creation /
    admin-logon events should NOT produce HIGH risk unless suspicious behaviour
    is actually present.

    Args:
        result: Dict returned by ``score_group()``.
        profile_name: The ``HostProfile.name`` for this host, or ``None``.

    Returns:
        A copy of *result* with adjusted ``local_score``, ``local_severity``,
        ``suspicious``, and ``local_reason``.
    """
    if not profile_name:
        return result

    profile_lower = profile_name.lower()
    if "sysadmin" not in profile_lower:
        return result

    score: int = result.get("local_score", 0)
    reason: str = result.get("local_reason", "")
    event_id: str = str(result.get("event_id") or "")
    description: str = str(result.get("rule_description") or "").lower()
    sample: dict[str, Any] = result.get("sample") or {}
    # Build a combined text blob for hard-suspicious pattern matching
    cmd = str(sample.get("CommandLine") or sample.get("command_line") or "")
    searchable = f"{description} {cmd}".lower()

    # Hard-suspicious → amplify, never suppress
    if _ALWAYS_SUSPICIOUS_RE.search(searchable):
        new_score = min(score + 15, 100)
        new_reason = reason + "; [SysAdmin-Profil: Angriffsmuster erkannt – Risiko erhöht]"
        out = dict(result)
        out["local_score"] = new_score
        out["local_severity"] = severity_from_score(new_score)
        out["suspicious"] = True
        out["local_reason"] = new_reason
        return out

    # Normal sysadmin event (login / process / admin) → suppress
    is_normal_eid = event_id in _SYSADMIN_NORMAL_EIDS
    if is_normal_eid:
        # HARD RULE: normal event type, no hard-suspicious content → cap at low
        new_score = min(score, 30)
        new_reason = (
            reason
            + f"; [SysAdmin-Profil: Event {event_id} ist für Admin-Host normal – Score auf LOW gedeckelt]"
        )
        out = dict(result)
        out["local_score"] = new_score
        out["local_severity"] = severity_from_score(new_score)
        out["suspicious"] = new_score >= 60
        out["local_reason"] = new_reason
        return out

    # Unknown event on sysadmin host — apply a moderate cap
    new_score = min(score, 55)
    if new_score < score:
        out = dict(result)
        out["local_score"] = new_score
        out["local_severity"] = severity_from_score(new_score)
        out["suspicious"] = new_score >= 60
        out["local_reason"] = reason + "; [SysAdmin-Profil: Score auf MEDIUM gedeckelt]"
        return out

    return result
