from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

try:
    from services.ai_prompts import build_structured_finding_prompt
except Exception:
    # Keep the script standalone when deployed remotely without the full backend package.
    def build_structured_finding_prompt(finding: dict[str, Any]) -> str:
        return (
            "You are a SOC analyst. Return valid JSON only with keys suspicious, severity, reason, recommended_checks. "
            "Severity must be one of critical, high, medium, low. "
            f"Finding: {json.dumps(finding)}"
        )

WINDOWS_EVENT_IDS = {
    # Auth / Logon
    "4624",  # successful logon
    "4625",  # failed logon
    "4634",  # logoff
    "4647",  # user initiated logoff
    "4648",  # logon with explicit credentials
    "4672",  # special privileges assigned
    "4673",  # privileged service called
    "4674",  # privileged operation attempted
    "4771",  # kerberos pre-auth failed
    "4776",  # NTLM auth
    "4768",  # kerberos TGT requested
    "4769",  # kerberos service ticket requested
    "4778",  # session reconnected
    "4779",  # session disconnected
    "4800",  # workstation locked
    "4801",  # workstation unlocked

    # Process / Execution
    "4688",  # process creation
    "4689",  # process ended
    "4697",  # service installed (security log, if enabled)

    # Account / Group changes
    "4720",  # user created
    "4722",  # user enabled
    "4723",  # password change attempt
    "4724",  # password reset attempt
    "4725",  # user disabled
    "4726",  # user deleted
    "4727",  # security global group created
    "4728",  # member added to global security group
    "4729",  # member removed from global security group
    "4731",  # local group created
    "4732",  # member added to local security group
    "4733",  # member removed from local security group
    "4735",  # local group changed
    "4737",  # global group changed
    "4740",  # account locked out
    "4741",  # computer account created
    "4742",  # computer account changed
    "4743",  # computer account deleted
    "4767",  # account unlocked

    # Audit / Logs / Policy
    "4719",  # system audit policy changed
    "4902",  # per-user audit policy changed
    "1102",  # audit log cleared

    # Services / System
    "7040",  # service start type changed
    "7045",  # service installed
    "7034",  # service terminated unexpectedly
    "7035",  # service control sent
    "7036",  # service entered state
    "7038",  # service logon failure
    "7041",  # service account invalid / service start problem

    # Scheduled Tasks / Persistence
    "4698",  # scheduled task created
    "4699",  # scheduled task deleted
    "4700",  # scheduled task enabled
    "4701",  # scheduled task disabled
    "4702",  # scheduled task updated

    # Object / Registry / File
    "4656",  # handle requested
    "4657",  # registry value modified
    "4663",  # object access
    "4660",  # object deleted

    # Defender / PowerShell / AppLocker / Script
    "4103",  # PowerShell module logging
    "4104",  # PowerShell script block logging
    "8001",  # AppLocker
    "8002",  # AppLocker
    "8003",  # AppLocker
    "8004",  # AppLocker

    # Windows Error / Crash / WER
    "1000",  # application error
    "1001",  # windows error reporting
}
LINUX_GROUP_KEYWORDS = {
    # General
    "linux",
    "syslog",

    # Authentication
    "sshd",
    "authentication_failed",
    "invalid_login",
    "pam",
    "login",
    "sudo",
    "su",

    # User / group management
    "useradd",
    "usermod",
    "userdel",
    "groupadd",
    "groupdel",
    "passwd",

    # Persistence / scheduling
    "cron",
    "crond",
    "systemd",
    "service",
    "systemctl",

    # Networking / remote access
    "ssh",
    "telnet",
    "ftp",
    "vsftpd",

    # Privilege / escalation
    "wheel",
    "rootcheck",
    "auditd",

    # Package / changes
    "apt",
    "dpkg",
    "yum",
    "dnf",
    "rpm",

    # Web / exposure
    "nginx",
    "apache",
    "httpd",

    # Containers / infra
    "docker",
    "containerd",
    "podman",

    # File integrity / malware-ish indicators
    "fim",
    "ossec",
    "wazuh",
}
BENIGN_WINDOWS_PATTERNS = {
    ("4625", "local service", "5", "svchost.exe"),
    ("4625", "system", "5", "svchost.exe"),
    ("7036", "", "", ""),      # service state changes oft harmlos
    ("7035", "", "", ""),      # service control messages oft harmlos
    ("4634", "", "", ""),      # logoff
    ("4647", "", "", ""),      # user initiated logoff
    ("4800", "", "", ""),      # lock
    ("4801", "", "", ""),      # unlock
    ("1001", "", "", ""),      # WER oft kein Security-Fall
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run grouped Wazuh analysis on the VM and optionally call Ollama.")
    parser.add_argument("--indexer-url", required=True)
    parser.add_argument("--indexer-user", required=True)
    parser.add_argument("--indexer-pass", required=True)
    parser.add_argument("--index-pattern", default="wazuh-alerts-*")
    parser.add_argument("--ollama-url", required=True)
    parser.add_argument("--ollama-model", default="llama3.1:8b")
    parser.add_argument("--lookback-hours", type=int, default=24)
    parser.add_argument("--size", type=int, default=3000)
    parser.add_argument("--output-txt", default="/tmp/ai_wazuh_24h_report.txt")
    parser.add_argument("--output-json", default="/tmp/ai_wazuh_24h_report.json")
    parser.add_argument("--host-filter", default=None)
    parser.add_argument("--event-ids", default=None, help="Comma-separated Windows event IDs override")
    parser.add_argument("--min-rule-level", type=int, default=0)
    parser.add_argument("--max-findings", type=int, default=200)
    parser.add_argument("--max-events-per-host", type=int, default=0)
    parser.add_argument("--only-windows", action="store_true")
    parser.add_argument("--only-linux", action="store_true")
    parser.add_argument("--include-noise", action="store_true")
    parser.add_argument("--skip-ai", action="store_true")
    parser.add_argument("--stdout-only", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    return parser.parse_args()


def resolve_windows_event_ids(args: argparse.Namespace) -> set[str]:
    if not args.event_ids:
        return WINDOWS_EVENT_IDS
    parsed = {
        token.strip()
        for token in str(args.event_ids).split(",")
        if token.strip()
    }
    return parsed or WINDOWS_EVENT_IDS


def fetch_alerts(args: argparse.Namespace) -> list[dict[str, Any]]:
    query: dict[str, Any] = {
        "size": args.size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{args.lookback_hours}h",
                                "lte": "now",
                            }
                        }
                    }
                ]
            }
        },
    }
    if args.host_filter:
        query["query"]["bool"]["filter"].append(
            {"wildcard": {"agent.name.keyword": f"*{args.host_filter}*"}}
        )

    response = requests.post(
        f"{args.indexer_url.rstrip('/')}/{args.index_pattern}/_search",
        auth=(args.indexer_user, args.indexer_pass),
        json=query,
        verify=not args.insecure,
        timeout=120,
    )
    response.raise_for_status()
    return response.json().get("hits", {}).get("hits", [])


def pick(source: dict[str, Any], *paths: str) -> Any:
    for path in paths:
        current: Any = source
        found = True
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                found = False
                break
        if found and current not in (None, ""):
            return current
    return None


def normalize(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source", {})
    groups = pick(source, "rule.groups") or []
    if isinstance(groups, str):
        groups = [groups]
    event_id = pick(source, "data.win.system.eventID", "data.win.system.eventId", "win.system.eventID")
    platform = detect_platform(source, groups, pick(source, "decoder.name"), event_id)
    return {
        "timestamp": pick(source, "@timestamp", "timestamp"),
        "host": pick(source, "agent.name", "agent.hostname", "host.name", "manager.name") or "unknown-host",
        "platform": platform,
        "event_id": str(event_id) if event_id is not None else None,
        "rule_id": str(pick(source, "rule.id") or "") or None,
        "rule_description": str(pick(source, "rule.description") or "") or None,
        "rule_level": int(pick(source, "rule.level") or 0),
        "groups": groups,
        "decoder": pick(source, "decoder.name"),
        "location": pick(source, "location") or "unknown-location",
        "target_user": pick(source, "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName", "data.srcuser", "data.user"),
        "logon_type": str(pick(source, "data.win.eventdata.logonType") or "") or None,
        "process": pick(source, "data.win.eventdata.processName", "data.process.name"),
        "linux_type": pick(source, "data.program", "syslog.program", "data.audit.exe", "decoder.name"),
        "raw": source,
    }


def detect_platform(source: dict[str, Any], groups: list[str], decoder: Any, event_id: Any) -> str:
    groups_joined = " ".join(str(item).lower() for item in groups)
    decoder_text = str(decoder or "").lower()
    if event_id or "windows" in groups_joined or decoder_text == "windows_eventchannel":
        return "windows"
    if any(keyword in groups_joined for keyword in ("linux", "syslog", "sshd", "pam", "audit")):
        return "linux"
    if "sshd" in decoder_text or "pam" in decoder_text:
        return "linux"
    return "other"


def is_relevant(alert: dict[str, Any], include_noise: bool, windows_event_ids: set[str], min_rule_level: int) -> bool:
    if int(alert.get("rule_level") or 0) < int(min_rule_level or 0):
        return False

    if include_noise:
        return alert["platform"] in {"windows", "linux"}

    if alert["platform"] == "windows":
        if alert.get("event_id") not in windows_event_ids:
            return False
        signature = (
            (alert.get("event_id") or "").lower(),
            (alert.get("target_user") or "").lower(),
            (alert.get("logon_type") or "").lower(),
            (str(alert.get("process") or "")).lower(),
        )
        return signature not in BENIGN_WINDOWS_PATTERNS

    if alert["platform"] == "linux":
        searchable = " ".join(
            [
                *(alert.get("groups") or []),
                str(alert.get("decoder") or ""),
                str(alert.get("rule_description") or ""),
                str(alert.get("location") or ""),
                str(alert.get("linux_type") or ""),
            ]
        ).lower()
        return any(keyword in searchable for keyword in LINUX_GROUP_KEYWORDS)

    return False


def build_group_key(alert: dict[str, Any]) -> str:
    if alert["platform"] == "windows":
        return "|".join(
            [
                alert.get("host") or "unknown-host",
                alert.get("event_id") or "unknown-event",
                alert.get("rule_id") or "unknown-rule",
                alert.get("target_user") or "unknown-user",
                alert.get("logon_type") or "unknown-logon",
                str(alert.get("process") or "unknown-process"),
            ]
        )

    return "|".join(
        [
            alert.get("host") or "unknown-host",
            alert.get("rule_id") or "unknown-rule",
            ",".join(alert.get("groups") or []),
            alert.get("location") or "unknown-location",
        ]
    )


def group_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for alert in alerts:
        buckets[build_group_key(alert)].append(alert)

    grouped: list[dict[str, Any]] = []
    for group_key, items in buckets.items():
        first = items[0]
        timestamps = [item.get("timestamp") for item in items if item.get("timestamp")]
        grouped.append(
            {
                "group_key": group_key,
                "host": first["host"],
                "platform": first["platform"],
                "event_id": first.get("event_id"),
                "rule_id": first.get("rule_id"),
                "rule_description": first.get("rule_description"),
                "rule_level": first.get("rule_level", 0),
                "count": len(items),
                "first_seen": min(timestamps) if timestamps else None,
                "last_seen": max(timestamps) if timestamps else None,
                "sample": first,
            }
        )
    return sorted(grouped, key=lambda item: (item["count"], item.get("rule_level", 0)), reverse=True)


def score_group(group: dict[str, Any]) -> dict[str, Any]:
    event_id = group.get("event_id") or ""
    count = int(group.get("count", 0))
    platform = group.get("platform")
    sample = group.get("sample", {})
    description = str(group.get("rule_description") or "").lower()
    score = 20
    suspicious = False
    reasons: list[str] = []

    if platform == "windows":
        if event_id == "1102":
            score = 90
            suspicious = True
            reasons.append("Audit log cleared")
        elif event_id == "7045":
            score = 80 if count < 3 else 88
            suspicious = True
            reasons.append("Service installation")
        elif event_id in {"4728", "4732"}:
            score = 82
            suspicious = True
            reasons.append("Privileged group membership changed")
        elif event_id == "4720":
            score = 74
            suspicious = True
            reasons.append("New user account created")
        elif event_id == "4688":
            score = 55 if count < 5 else 70
            suspicious = count >= 3
            reasons.append("Process creation cluster")
        elif event_id == "4625":
            if count >= 20:
                score = 84
                suspicious = True
                reasons.append("High-volume failed logons")
            elif count >= 5:
                score = 60
                suspicious = True
                reasons.append("Repeated failed logons")
            else:
                score = 35
                reasons.append("Single or low-volume failed logon")

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
            reasons.append("Privilege use near account creation")
        elif "useradd" in searchable or "usermod" in searchable or "groupadd" in searchable:
            score = 75
            suspicious = True
            reasons.append("Linux account management activity")
        elif "cron" in searchable:
            score = 62
            suspicious = count >= 2
            reasons.append("Cron-related activity")
        elif "sshd" in searchable or "authentication_failed" in searchable or "invalid_login" in searchable or "pam" in searchable:
            score = 80 if count >= 10 else 58
            suspicious = count >= 3
            reasons.append("Linux authentication anomaly")

    score = max(0, min(100, score))
    confidence = min(95, max(45, 45 + count * 3))
    return {
        "local_score": score,
        "local_severity": severity_from_score(score),
        "confidence": confidence,
        "suspicious": suspicious or score >= 60,
        "reason": "; ".join(reasons) if reasons else "Relevant grouped security activity",
    }


def severity_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def ask_ollama(args: argparse.Namespace, finding: dict[str, Any]) -> dict[str, Any]:
    finding_payload = {
        "host": finding["host"],
        "platform": finding["platform"],
        "event_id": finding.get("event_id"),
        "rule_id": finding.get("rule_id"),
        "count": finding["count"],
        "local_score": finding["local_score"],
        "local_severity": finding["local_severity"],
        "rule_description": finding.get("rule_description"),
        "group_key": finding["group_key"],
    }
    prompt = build_structured_finding_prompt(finding_payload)
    response = requests.post(
        args.ollama_url,
        json={
            "model": args.ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        },
        timeout=300,
    )
    response.raise_for_status()
    content = response.json().get("response", "{}")
    parsed = json.loads(content)
    return {
        "suspicious": bool(parsed.get("suspicious", finding["suspicious"])),
        "ai_severity": str(parsed.get("severity", finding["local_severity"])).lower(),
        "reason": str(parsed.get("reason", finding["reason"])),
        "recommended_checks": [str(item) for item in parsed.get("recommended_checks", [])],
    }


def fallback_checks(platform: str) -> list[str]:
    if platform == "windows":
        return [
            "Review adjacent Windows Security events for the same host and user",
            "Validate whether the activity matches an approved admin action",
            "Inspect related logon and process creation activity in the same time window",
        ]
    return [
        "Review auth logs or journalctl around the same time window",
        "Check whether the account action matches an approved change",
        "Inspect related sudo, SSH, and cron activity on the host",
    ]


def build_findings(args: argparse.Namespace, grouped: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for group in grouped:
        finding = {
            **group,
            **score_group(group),
            "ai_severity": None,
            "recommended_checks": [],
        }
        if args.only_windows and finding["platform"] != "windows":
            continue
        if args.only_linux and finding["platform"] != "linux":
            continue
        if not args.skip_ai:
            try:
                finding.update(ask_ollama(args, finding))
            except Exception as exc:
                finding["ai_severity"] = finding["local_severity"]
                finding["reason"] = f"AI request failed: {exc}"
                finding["recommended_checks"] = fallback_checks(finding["platform"])
        else:
            finding["ai_severity"] = finding["local_severity"]
            finding["recommended_checks"] = fallback_checks(finding["platform"])

        findings.append({
            key: value
            for key, value in finding.items()
            if key != "sample"
        })
    return findings


def build_report_text(top_hosts: list[tuple[str, int]], findings: list[dict[str, Any]], args: argparse.Namespace) -> str:
    lines = [
        "=== WAZUH AI 24H REPORT ===",
        "",
        f"Generated at: {datetime.now(timezone.utc).replace(microsecond=0).isoformat()}",
        f"Lookback hours: {args.lookback_hours}",
        f"Mode: {'windows-only' if args.only_windows else 'linux-only' if args.only_linux else 'mixed'}",
        "",
        "Top hosts by relevant alerts:",
    ]
    for host, count in top_hosts:
        lines.append(f"- {host}: {count}")
    lines.append("")
    lines.append("Top findings:")
    for finding in findings[:80]:
        lines.append(
            f"- Host={finding['host']} | Platform={finding['platform']} | Count={finding['count']} | "
            f"Event={finding.get('event_id') or finding.get('rule_id') or 'n/a'} | "
            f"Severity={finding.get('ai_severity') or finding['local_severity']} | Reason={finding['reason']}"
        )
    return "\n".join(lines)


def main() -> None:
    args = parse_args()
    selected_windows_event_ids = resolve_windows_event_ids(args)
    hits = fetch_alerts(args)
    normalized = [normalize(hit) for hit in hits]
    relevant = [
        item for item in normalized
        if is_relevant(
            item,
            include_noise=args.include_noise,
            windows_event_ids=selected_windows_event_ids,
            min_rule_level=args.min_rule_level,
        )
    ]

    if args.max_events_per_host and args.max_events_per_host > 0:
        per_host_counter: dict[str, int] = defaultdict(int)
        limited_relevant: list[dict[str, Any]] = []
        for item in relevant:
            host = str(item.get("host") or "unknown-host")
            if per_host_counter[host] >= args.max_events_per_host:
                continue
            per_host_counter[host] += 1
            limited_relevant.append(item)
        relevant = limited_relevant

    grouped = group_alerts(relevant)
    findings = build_findings(args, grouped)
    if args.max_findings and args.max_findings > 0:
        findings = findings[: args.max_findings]

    top_hosts_counter = Counter(item["host"] for item in relevant)
    top_hosts = top_hosts_counter.most_common()
    report_text = build_report_text(top_hosts, findings, args)

    report_json = {
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "lookback_hours": args.lookback_hours,
        "total_alerts": len(hits),
        "relevant_alerts": len(relevant),
        "top_hosts": dict(top_hosts),
        "findings": findings,
    }

    if args.stdout_only:
        print("===REPORT_TEXT_BEGIN===")
        print(report_text)
        print("===REPORT_TEXT_END===")
        print("===REPORT_JSON_BEGIN===")
        print(json.dumps(report_json, indent=2, ensure_ascii=False))
        print("===REPORT_JSON_END===")
        return

    output_txt = Path(args.output_txt)
    output_json = Path(args.output_json)
    output_txt.write_text(report_text, encoding="utf-8")
    output_json.write_text(json.dumps(report_json, indent=2, ensure_ascii=False), encoding="utf-8")

    print(report_text)
    print(f"\nReport TXT: {output_txt}")
    print(f"Report JSON: {output_json}")


if __name__ == "__main__":
    main()