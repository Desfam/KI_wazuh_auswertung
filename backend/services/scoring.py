from __future__ import annotations

from typing import Any


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
