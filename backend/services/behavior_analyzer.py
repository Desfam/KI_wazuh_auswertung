"""Behavior-level analysis for known and new entities.

This is SEPARATE from entity-level detection (new_process, new_service etc.).
It answers: "Is this entity executing suspiciously, even if it's in the baseline?"

Principle:
    Baseline says: svchost.exe → known
    Event says:    svchost.exe -enc aW1wb3J0IG1hbHdhcmU=
    → Baseline: ✅ known   |   Behavior: 🔴 ALERT

Key insight: Baseline is context, not a whitelist.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


# ── Suspicious command-line rules ─────────────────────────────────────────────
# Each tuple: (compiled_pattern, human_readable_label, score_delta)

_CMD_RULES: list[tuple[re.Pattern[str], str, int]] = [
    # Encoded commands / obfuscation
    (re.compile(r'-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{20,}', re.I),
     "encoded command (-enc)", 45),
    (re.compile(r'(?:FromBase64String|base64_decode|base64 -d)', re.I),
     "base64 decode in command", 30),

    # PowerShell stealth flags
    (re.compile(r'-nop(?:rofile)?\b', re.I), "PowerShell -noprofile", 15),
    (re.compile(r'-(?:w|windowstyle)\s+hid(?:den)?', re.I), "hidden window style", 20),
    (re.compile(r'-exec(?:utionpolicy)?\s+(?:bypass|unrestricted)', re.I),
     "execution policy bypass", 25),

    # Remote execution / downloads
    (re.compile(r'\bIEX\b|\bInvoke-Expression\b', re.I), "Invoke-Expression (IEX)", 35),
    (re.compile(r'\bDownloadString\b|\bDownloadFile\b', re.I), "WebClient download", 40),
    (re.compile(r'\bNew-Object\s+.*Net\.WebClient\b', re.I), "WebClient instantiation", 35),
    (re.compile(r'(?:wget|curl)\s+https?://', re.I), "network download command", 30),
    (re.compile(r'Invoke-(?:WebRequest|RestMethod)\b', re.I), "PowerShell web request", 30),

    # LOLBins
    (re.compile(r'\bcertutil\b.*-(?:decode|urlcache|encode)', re.I), "certutil LOLBin", 35),
    (re.compile(r'\b(?:mshta|cmstp|regsvr32|installutil|runscripthelper)\.exe\b', re.I),
     "LOLBin execution", 30),
    (re.compile(r'\bwmic\b.*process\b.*call\b', re.I), "WMIC process call", 25),
    (re.compile(r'\bat\.exe\b', re.I), "legacy AT scheduler", 20),

    # Credential / LSASS attacks
    (re.compile(r'\b(?:mimikatz|sekurlsa|lsadump|kerberoast)\b', re.I),
     "credential dumping tool", 70),
    (re.compile(r'(?:taskkill|procdump)\b.*\blsass\b', re.I), "LSASS targeting", 65),

    # Defense evasion
    (re.compile(r'\bvssadmin\b.*delete\b', re.I), "VSS shadow copy deletion", 55),
    (re.compile(r'\bbcdedit\b', re.I), "boot config modification", 40),
    (re.compile(r'\bwbadmin\b.*delete\b', re.I), "backup deletion", 50),

    # Persistence / lateral movement
    (re.compile(r'\bschtasks\b.*(?:/create|/change)', re.I), "scheduled task creation", 25),
    (re.compile(r'\breg(?:\.exe)?\s+(?:add|delete|export)\b', re.I),
     "registry modification", 20),
    (re.compile(r'\bnet(?:\.exe)?\s+(?:user|localgroup|group)\b', re.I),
     "account enumeration", 20),
    (re.compile(r'\bnet(?:\.exe)?\s+use\b', re.I), "net use (lateral)", 20),

    # Reconnaissance
    (re.compile(r'\bwhoami(?:\.exe)?\b', re.I), "whoami execution", 15),
    (re.compile(r'\b(?:ipconfig|ifconfig)\b.*all\b', re.I), "network config dump", 10),
    (re.compile(r'\bnetstat\b', re.I), "network state enumeration", 10),
    (re.compile(r'\barp\b\s+-a\b', re.I), "ARP table enumeration", 10),

    # Shell chaining
    (re.compile(r'cmd(?:\.exe)?\s+/[cC]\s+', re.I), "cmd /c execution", 15),
]


# ── Unexpected parent process rules ───────────────────────────────────────────
# Maps process_basename → set of legitimate parents (basename, lowercase).
# If the actual parent is not in the expected set → anomaly.

_EXPECTED_PARENTS: dict[str, frozenset[str]] = {
    "svchost.exe":   frozenset({"services.exe"}),
    "lsass.exe":     frozenset({"wininit.exe"}),
    "smss.exe":      frozenset({"system", ""}),
    "csrss.exe":     frozenset({"smss.exe"}),
    "wininit.exe":   frozenset({"smss.exe"}),
    "winlogon.exe":  frozenset({"smss.exe"}),
    "services.exe":  frozenset({"wininit.exe"}),
    "spoolsv.exe":   frozenset({"services.exe"}),
    "taskhostw.exe": frozenset({"services.exe", "svchost.exe"}),
    "explorer.exe":  frozenset({"userinit.exe"}),
    "lsm.exe":       frozenset({"wininit.exe"}),
}

_PARENT_ANOMALY_SCORE = 35


# ── Result type ───────────────────────────────────────────────────────────────

@dataclass
class BehaviorResult:
    flags: list[str] = field(default_factory=list)
    score_delta: int = 0
    is_suspicious: bool = False


# ── Main analysis function ────────────────────────────────────────────────────

def analyze_behavior(
    process: str | None,
    command_line: str | None,
    parent_process: str | None,
) -> BehaviorResult:
    """
    Analyze the execution context of a single event.

    Returns BehaviorResult with:
      - flags: list of human-readable anomaly labels
      - score_delta: amount to add to the base risk score (0-60 cap)
      - is_suspicious: True if any flags were raised
    """
    result = BehaviorResult()

    # Normalize inputs
    proc_lower   = (process or "").lower().split("\\")[-1].strip()
    cmd          = command_line or ""
    parent_lower = (parent_process or "").lower().split("\\")[-1].strip()

    # 1. Scan command-line patterns
    for pattern, label, delta in _CMD_RULES:
        if cmd and pattern.search(cmd):
            result.flags.append(label)
            result.score_delta += delta

    # 2. Check unexpected parent process (only for processes with known parents)
    if proc_lower in _EXPECTED_PARENTS and parent_lower:
        expected = _EXPECTED_PARENTS[proc_lower]
        if parent_lower not in expected:
            result.flags.append(f"unexpected parent: {parent_lower} → {proc_lower}")
            result.score_delta += _PARENT_ANOMALY_SCORE

    # Deduplicate flags, cap score delta to avoid inflation
    result.flags = list(dict.fromkeys(result.flags))
    result.score_delta = min(result.score_delta, 60)
    result.is_suspicious = bool(result.flags)

    return result
