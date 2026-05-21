"""
Windows Event ID Knowledge Base
================================
Structured analyst context for the most security-relevant Windows Event IDs.
Used to enrich Event Map inspector popups and API responses.

Each entry contains:
  title               — Short human-readable event name
  summary             — One-sentence description (aligns with SNIPEN_EVENT_ID_EXPLANATIONS)
  why_it_matters      — Analyst context: what this event indicates
  benign_causes       — Common harmless explanations
  suspicious_causes   — Indicators that warrant investigation
  recommended_checks  — Concrete next steps for an analyst
  related_events      — Event IDs that provide additional context
  category            — Event category for grouping/filtering
  default_severity    — Baseline severity when no Wazuh rule overrides it
"""

from __future__ import annotations

from typing import TypedDict


class EventKnowledgeEntry(TypedDict):
    title: str
    summary: str
    why_it_matters: str
    benign_causes: list[str]
    suspicious_causes: list[str]
    recommended_checks: list[str]
    related_events: list[str]
    category: str
    default_severity: str


EVENT_ID_KNOWLEDGE: dict[str, EventKnowledgeEntry] = {
    "4624": {
        "title": "Successful Logon",
        "summary": "An account was successfully logged on.",
        "why_it_matters": (
            "Alone it is normal, but combined with failed logons (4625), unusual source IPs, "
            "off-hours timing, or privilege escalation it can indicate compromised credentials "
            "or lateral movement."
        ),
        "benign_causes": [
            "Regular user workstation login",
            "Service account starting a scheduled task",
            "Remote desktop session by IT staff",
            "Application using stored credentials",
        ],
        "suspicious_causes": [
            "Logon from unusual IP or workstation",
            "Logon at unusual hours",
            "Logon immediately after multiple 4625 failures",
            "Logon type 3 (network) from an external IP",
            "Lateral movement via pass-the-hash",
        ],
        "recommended_checks": [
            "Check Logon Type (2=interactive, 3=network, 10=remote interactive)",
            "Compare source workstation and IP to known assets",
            "Look for preceding 4625 failures for the same account",
            "Check for 4672 (special privileges) in the same session",
            "Verify logon time against normal working hours",
        ],
        "related_events": ["4625", "4634", "4648", "4672", "4776", "4771"],
        "category": "authentication",
        "default_severity": "info",
    },
    "4625": {
        "title": "Failed Logon",
        "summary": "An account failed to log on.",
        "why_it_matters": (
            "Repeated failed logons can indicate stale credentials in services or scheduled tasks, "
            "but also password spraying, brute-force attempts, or lateral movement with stolen credentials."
        ),
        "benign_causes": [
            "User typed the wrong password",
            "Old password stored in a service, scheduled task, or mapped drive",
            "Disabled or expired account still used by an application",
            "Cached credentials not yet updated after a password change",
        ],
        "suspicious_causes": [
            "Many failures against many different accounts → Password Spray",
            "Many failures against one account → Brute Force",
            "Failures from an external or unusual IP",
            "Failures followed by a successful 4624",
            "Failures targeting admin accounts",
        ],
        "recommended_checks": [
            "Is there a successful 4624 shortly after these failures?",
            "Check source IP and workstation name",
            "Are multiple accounts failing from the same source? (spray)",
            "Check Sub Status: 0xC000006A = bad password, 0xC0000064 = unknown user",
            "Look for Account Lockout (4740) for affected accounts",
        ],
        "related_events": ["4624", "4648", "4740", "4771", "4776", "4672"],
        "category": "authentication",
        "default_severity": "medium",
    },
    "4634": {
        "title": "Logoff",
        "summary": "An account was logged off.",
        "why_it_matters": (
            "Usually benign. Very short session durations — logon followed immediately by logoff — "
            "can indicate automated access, in-and-out lateral movement, or scripted enumeration."
        ),
        "benign_causes": [
            "Normal user logging out",
            "Session timeout",
            "Network logon ending after completing a task",
        ],
        "suspicious_causes": [
            "Very short session after a logon — possible automated enumeration",
            "Logoff immediately after privilege escalation",
            "Multiple logon/logoff cycles from the same account in a short time",
        ],
        "recommended_checks": [
            "Calculate session duration — check for unusually short sessions",
            "Correlate with the preceding 4624 to determine logon type",
            "Check if sensitive operations occurred during the session",
        ],
        "related_events": ["4624", "4647", "4672"],
        "category": "authentication",
        "default_severity": "info",
    },
    "4648": {
        "title": "Explicit Credential Logon",
        "summary": "A logon was attempted using explicit credentials (RunAs, net use, etc.).",
        "why_it_matters": (
            "This event fires when a process uses credentials other than the currently logged-in user. "
            "Lateral movement tools like PsExec and Mimikatz frequently trigger 4648 events."
        ),
        "benign_causes": [
            "Administrator using RunAs to elevate a process",
            "Scheduled task running under a different service account",
            "Mapping a network drive with alternate credentials",
        ],
        "suspicious_causes": [
            "PsExec or similar tools using explicit credentials",
            "Mimikatz pass-the-ticket or pass-the-hash",
            "Scripted lateral movement using stored credentials",
            "4648 targeting Domain Admin or SYSTEM accounts",
        ],
        "recommended_checks": [
            "What process triggered the logon?",
            "What account was targeted? (privileged = high priority)",
            "Does the source machine normally make these calls?",
            "Correlate with 4624 on the target machine",
        ],
        "related_events": ["4624", "4625", "4672", "4688"],
        "category": "authentication",
        "default_severity": "medium",
    },
    "4672": {
        "title": "Special Privileges Assigned",
        "summary": "Special privileges were assigned to a new logon session.",
        "why_it_matters": (
            "These privileges allow bypassing security boundaries. Attackers use them for "
            "credential dumping, token manipulation, and lateral movement. 4672 + 4624 = admin session."
        ),
        "benign_causes": [
            "Administrator logging in — always generates 4672",
            "Service running under a privileged account (SYSTEM, LocalService)",
            "IT support escalating a session via RunAs",
        ],
        "suspicious_causes": [
            "SeDebugPrivilege assigned to a non-admin account",
            "SeTcbPrivilege on a user account",
            "4672 for a non-admin account at unusual hours",
            "Immediately followed by credential dumping or token manipulation",
        ],
        "recommended_checks": [
            "Which account received the privileges? (should be an admin)",
            "Which specific privileges? (SeDebugPrivilege = high risk)",
            "Correlate with preceding 4624 — what logon type was it?",
            "Is this session expected for this account and time?",
        ],
        "related_events": ["4624", "4648", "4673", "4674", "4688"],
        "category": "privilege",
        "default_severity": "medium",
    },
    "4688": {
        "title": "Process Created",
        "summary": "A new process has been created.",
        "why_it_matters": (
            "Malicious activity — ransomware, credential dumpers, C2 beacons, lateral movement tools — "
            "all appear here. Command line and parent process are the most critical fields."
        ),
        "benign_causes": [
            "Normal application launch by a user",
            "Windows system process spawning child processes",
            "Antivirus or monitoring agent starting a scan",
        ],
        "suspicious_causes": [
            "cmd.exe or powershell.exe spawned by a browser or Office process",
            "Encoded PowerShell commands (-EncodedCommand)",
            "Process running from TEMP, AppData, or unusual paths",
            "LOLBins: certutil, mshta, wscript, rundll32 with unusual arguments",
        ],
        "recommended_checks": [
            "Check the parent process — is it expected to spawn this child?",
            "Review the command line",
            "Check executable path — system processes belong in C:\\Windows\\System32",
            "Cross-reference process hash against threat intelligence",
            "Look for network connections from the new process",
        ],
        "related_events": ["4689", "4624", "4648", "5156", "7045"],
        "category": "process",
        "default_severity": "low",
    },
    "4697": {
        "title": "Service Installed",
        "summary": "A service was installed on this system.",
        "why_it_matters": (
            "Service installation is a common persistence technique. Attackers install malicious services "
            "to survive reboots. Legitimate software rarely installs services without prior notice."
        ),
        "benign_causes": [
            "Software installation (antivirus, monitoring agents, drivers)",
            "Windows Update installing a new component",
            "IT-managed deployment via SCCM, Intune, or similar",
        ],
        "suspicious_causes": [
            "Service installed from TEMP, Downloads, or user-writable paths",
            "Service with a random or obfuscated name",
            "Service installed using PsExec or remote tools",
            "Cobalt Strike or Metasploit service-based lateral movement",
        ],
        "recommended_checks": [
            "Check the service binary path — is it signed and in an expected location?",
            "Who installed the service?",
            "Is the service name meaningful or obfuscated?",
            "Correlate with 4688 events (which process created the service?)",
        ],
        "related_events": ["4688", "4624", "7045", "4698"],
        "category": "service",
        "default_severity": "high",
    },
    "4698": {
        "title": "Scheduled Task Created",
        "summary": "A scheduled task was created.",
        "why_it_matters": (
            "Scheduled tasks are a popular persistence and lateral movement mechanism. "
            "Attackers create tasks to execute payloads on a schedule or at logon."
        ),
        "benign_causes": [
            "Software installer creating a maintenance or update task",
            "IT automation creating deployment tasks",
        ],
        "suspicious_causes": [
            "Task created by a non-admin account",
            "Task action runs from TEMP, AppData, or unusual paths",
            "Task runs encoded PowerShell or VBScript",
            "Task created via remote service (lateral movement)",
        ],
        "recommended_checks": [
            "Who created the task?",
            "What does the task action execute?",
            "When is the task scheduled to run?",
            "Correlate with 4688 — which process created the task?",
        ],
        "related_events": ["4702", "4699", "4688", "4624"],
        "category": "service",
        "default_severity": "high",
    },
    "4702": {
        "title": "Scheduled Task Updated",
        "summary": "A scheduled task was updated.",
        "why_it_matters": (
            "Attackers may update existing legitimate tasks to add malicious payloads, "
            "making detection harder than creating new tasks."
        ),
        "benign_causes": [
            "Software patching or updating a maintenance task",
            "IT team modifying automation tasks",
        ],
        "suspicious_causes": [
            "Action path changed to a non-standard executable",
            "Arguments include encoded commands",
            "Task modified by an account that did not create it",
        ],
        "recommended_checks": [
            "What changed in the task definition?",
            "Who modified the task?",
            "Does the new action still look legitimate?",
        ],
        "related_events": ["4698", "4699", "4688"],
        "category": "service",
        "default_severity": "medium",
    },
    "4719": {
        "title": "Audit Policy Changed",
        "summary": "System audit policy was changed.",
        "why_it_matters": (
            "Attackers modify audit policy to disable logging before carrying out attacks. "
            "Any unexpected audit policy change is a serious red flag."
        ),
        "benign_causes": [
            "Group Policy applying a new audit configuration",
            "IT security team adjusting audit settings",
        ],
        "suspicious_causes": [
            "Audit policy disabled for logon, process, or object access categories",
            "Change made by a non-privileged or unexpected account",
            "Change immediately before or after a suspicious event cluster",
        ],
        "recommended_checks": [
            "Which category was changed and in which direction?",
            "Who made the change?",
            "Does this correlate with a Group Policy update?",
            "Check for 1102 (log clear) around the same time",
        ],
        "related_events": ["1102", "4906", "4907", "4912"],
        "category": "audit-policy",
        "default_severity": "high",
    },
    "4720": {
        "title": "User Account Created",
        "summary": "A new user account was created.",
        "why_it_matters": (
            "Attackers create new accounts for persistence. Unexpected account creation is "
            "always a high-priority alert."
        ),
        "benign_causes": [
            "HR onboarding process creating accounts",
            "IT automation provisioning service accounts",
        ],
        "suspicious_causes": [
            "Account created by a non-standard admin tool or script",
            "Account name resembles a system or service account",
            "Account created during off-hours without change request",
            "Account immediately added to an admin group",
        ],
        "recommended_checks": [
            "Who created the account?",
            "Does the name follow naming conventions?",
            "Was the account immediately added to a privileged group?",
            "Cross-reference with HR/IT change records",
        ],
        "related_events": ["4722", "4728", "4732", "4724", "4726"],
        "category": "account-management",
        "default_severity": "high",
    },
    "4722": {
        "title": "User Account Enabled",
        "summary": "A user account was enabled.",
        "why_it_matters": (
            "Re-enabling a disabled account — especially a dormant one — is a common persistence tactic. "
            "Dormant accounts often have no current monitoring."
        ),
        "benign_causes": [
            "Employee returning from leave",
            "IT re-enabling a service account for a deployment",
        ],
        "suspicious_causes": [
            "Long-inactive account suddenly re-enabled",
            "Account enabled without a corresponding IT ticket",
        ],
        "recommended_checks": [
            "How long was the account disabled?",
            "Who enabled it and was this expected?",
            "Was there a logon attempt (4624) shortly after enabling?",
        ],
        "related_events": ["4725", "4726", "4624", "4672"],
        "category": "account-management",
        "default_severity": "medium",
    },
    "4725": {
        "title": "User Account Disabled",
        "summary": "A user account was disabled.",
        "why_it_matters": (
            "Unexpected account disabling can be part of a DoS attack or cover tracks after an attack. "
            "Privileged account disabling can lock out admins."
        ),
        "benign_causes": [
            "Employee offboarding",
            "Inactive account cleanup",
        ],
        "suspicious_causes": [
            "Admin account disabled by a non-admin",
            "Multiple accounts disabled in rapid succession",
        ],
        "recommended_checks": [
            "Which account was disabled?",
            "Who performed the action?",
            "Are multiple accounts being targeted?",
        ],
        "related_events": ["4722", "4726", "4740"],
        "category": "account-management",
        "default_severity": "medium",
    },
    "4726": {
        "title": "User Account Deleted",
        "summary": "A user account was deleted.",
        "why_it_matters": (
            "Account deletion after an intrusion is a common cleanup step to remove evidence "
            "of a created backdoor account."
        ),
        "benign_causes": [
            "Employee offboarding completing final account cleanup",
            "IT removing stale or test accounts",
        ],
        "suspicious_causes": [
            "Account deleted shortly after being created (cleanup after attack)",
            "Privileged account deleted unexpectedly",
        ],
        "recommended_checks": [
            "Was this account recently created? (check 4720)",
            "Who deleted the account?",
            "Were there any logons using this account before deletion?",
        ],
        "related_events": ["4720", "4722", "4724"],
        "category": "account-management",
        "default_severity": "high",
    },
    "4728": {
        "title": "Added to Global Security Group",
        "summary": "A member was added to a security-enabled global group.",
        "why_it_matters": (
            "Adding accounts to privileged groups like Domain Admins is a critical privilege escalation indicator."
        ),
        "benign_causes": [
            "IT provisioning a new employee with appropriate access",
            "Service account getting required group membership",
        ],
        "suspicious_causes": [
            "Account added to Domain Admins, Enterprise Admins, or Backup Operators",
            "Addition by an account without HR/IT approval",
        ],
        "recommended_checks": [
            "Which group was the account added to?",
            "Who performed the addition?",
            "Is the added account a user, service, or recently created?",
        ],
        "related_events": ["4732", "4729", "4720", "4672"],
        "category": "group-management",
        "default_severity": "high",
    },
    "4732": {
        "title": "Added to Local Security Group",
        "summary": "A member was added to a security-enabled local group (e.g., local Administrators).",
        "why_it_matters": (
            "Adding an account to the local Administrators group is a quick and common privilege escalation technique."
        ),
        "benign_causes": [
            "IT support adding a user to local Admins for troubleshooting",
            "Software installer requiring local admin",
        ],
        "suspicious_causes": [
            "User account added to local Administrators unexpectedly",
            "Same account added to local Admins on multiple machines",
        ],
        "recommended_checks": [
            "Which local group? (Administrators = critical)",
            "Which account was added?",
            "Who performed the change?",
        ],
        "related_events": ["4733", "4728", "4624", "4672"],
        "category": "group-management",
        "default_severity": "high",
    },
    "4738": {
        "title": "User Account Changed",
        "summary": "A user account was changed (properties modified).",
        "why_it_matters": (
            "Account changes can include enabling password-not-required or changing account type — "
            "techniques used to prepare an account for misuse."
        ),
        "benign_causes": [
            "IT updating account properties",
            "Password reset by helpdesk",
        ],
        "suspicious_causes": [
            '"Password Not Required" flag set',
            '"Password Does Not Expire" set on a sensitive account',
            "Changes to a privileged account without a ticket",
        ],
        "recommended_checks": [
            "What field was changed? (check UserAccountControl flags)",
            "Who made the change?",
            "Was this a privileged or service account?",
        ],
        "related_events": ["4720", "4722", "4724", "4781"],
        "category": "account-management",
        "default_severity": "medium",
    },
    "4740": {
        "title": "Account Locked Out",
        "summary": "A user account was locked out due to too many failed authentication attempts.",
        "why_it_matters": (
            "Widespread lockouts across many accounts are a strong indicator of a password spray attack. "
            "Single account lockouts are often benign but worth investigating."
        ),
        "benign_causes": [
            "User forgot their password",
            "Old password cached in a service, task, or mobile device",
        ],
        "suspicious_causes": [
            "Multiple accounts locked out simultaneously → Password Spray",
            "Lockouts from an unusual workstation or IP",
            "Lockouts targeting admin accounts",
        ],
        "recommended_checks": [
            "Is this one account or many? Many = spray attack",
            "Find the source via 4625 events",
            "Check for 4624 after the lockout",
            "Identify where the stale credential is stored",
        ],
        "related_events": ["4625", "4767", "4624", "4771"],
        "category": "authentication",
        "default_severity": "medium",
    },
    "4768": {
        "title": "Kerberos TGT Requested",
        "summary": "A Kerberos authentication ticket (TGT) was requested.",
        "why_it_matters": (
            "Normal at logon but also the target of AS-REP Roasting. Unusual requests for non-existent "
            "accounts or without pre-authentication indicate reconnaissance or exploitation."
        ),
        "benign_causes": [
            "Normal user logon requesting a ticket",
            "Service account authenticating to the domain",
        ],
        "suspicious_causes": [
            "Failure code 0x6 (account does not exist) → username enumeration",
            "Bulk 0x18 failures → password spray",
            "AS-REP Roasting: TGT for accounts with pre-auth disabled",
        ],
        "recommended_checks": [
            "Check the Result Code — 0x0 = success, others = failure",
            "Is the requesting account valid and expected?",
            "Bulk failures against different accounts?",
        ],
        "related_events": ["4769", "4771", "4625", "4776"],
        "category": "kerberos",
        "default_severity": "low",
    },
    "4769": {
        "title": "Kerberos Service Ticket Requested",
        "summary": "A Kerberos service ticket (TGS) was requested.",
        "why_it_matters": (
            "Kerberoasting requests service tickets for SPNs to crack offline. "
            "High volumes of TGS requests, especially for service accounts, indicate this attack."
        ),
        "benign_causes": [
            "Normal access to network services (file shares, SQL, Exchange)",
            "Application authenticating to a backend service",
        ],
        "suspicious_causes": [
            "Bulk TGS requests for many different SPNs → Kerberoasting",
            "Requests using RC4 encryption (0x17) instead of AES",
            "Ticket requested by a user who does not normally access that service",
        ],
        "recommended_checks": [
            "How many TGS requests from this account in this window?",
            "Encryption type? RC4 (0x17) is suspicious",
            "Which services were targeted?",
        ],
        "related_events": ["4768", "4771", "4770"],
        "category": "kerberos",
        "default_severity": "medium",
    },
    "4771": {
        "title": "Kerberos Pre-Auth Failed",
        "summary": "Kerberos pre-authentication failed.",
        "why_it_matters": (
            "Bulk failures for many accounts indicate password spraying. "
            "Single account failures indicate targeted brute force."
        ),
        "benign_causes": [
            "User mistyped password during Kerberos logon",
            "Stale cached Kerberos credentials in an application",
        ],
        "suspicious_causes": [
            "Many accounts failing in a short window → Password Spray",
            "Single account failing many times → Brute Force",
            "Failure from external IP",
        ],
        "recommended_checks": [
            "Failure code 0x18 = wrong password; 0x6 = user not found",
            "Volume — single account or many?",
            "Source IP and workstation",
        ],
        "related_events": ["4768", "4625", "4740", "4776"],
        "category": "kerberos",
        "default_severity": "medium",
    },
    "4776": {
        "title": "NTLM Credential Validation",
        "summary": "The domain controller attempted to validate NTLM credentials.",
        "why_it_matters": (
            "NTLM is weaker than Kerberos and a target for pass-the-hash, NTLM relay, and credential stuffing. "
            "Bulk NTLM failures indicate spraying or relay attacks."
        ),
        "benign_causes": [
            "Applications and older services still using NTLM",
            "Workgroup machines authenticating to a DC",
        ],
        "suspicious_causes": [
            "Bulk NTLM failures for many accounts → Password Spray",
            "NTLM from a domain machine when Kerberos should be used → Pass-the-Hash",
            "NTLM relay attack",
        ],
        "recommended_checks": [
            "Error code 0xC000006A = bad password; 0xC0000064 = no such user",
            "Source workstation — expected machine?",
            "Volume — single account or many?",
        ],
        "related_events": ["4625", "4624", "4771", "4768"],
        "category": "kerberos",
        "default_severity": "medium",
    },
    "4781": {
        "title": "Account Renamed",
        "summary": "An account name was changed.",
        "why_it_matters": (
            "Renaming privileged accounts hides malicious accounts or confuses defenders. "
            "Attackers may rename a new backdoor account to appear legitimate."
        ),
        "benign_causes": [
            "IT renaming the built-in Administrator account for hardening",
            "Employee name change requiring account update",
        ],
        "suspicious_causes": [
            "Built-in account renamed to something obscure",
            "Newly created account renamed to resemble a system account",
        ],
        "recommended_checks": [
            "What was the old and new name?",
            "Was this the built-in Administrator (SID ending in -500)?",
            "Who performed the rename?",
        ],
        "related_events": ["4720", "4738", "4728"],
        "category": "account-management",
        "default_severity": "medium",
    },
    "4798": {
        "title": "Local Group Membership Enumerated",
        "summary": "A user's local group membership was enumerated.",
        "why_it_matters": (
            "Enumerating local group memberships is standard AD reconnaissance. "
            "BloodHound and net.exe trigger this to map privilege paths."
        ),
        "benign_causes": [
            "IT admin checking local group members",
            "Security tools performing compliance scans",
        ],
        "suspicious_causes": [
            "Enumeration by a non-admin user account",
            "Rapid enumeration of many accounts",
            "BloodHound or other AD recon tools",
        ],
        "recommended_checks": [
            "Who is querying? Standard users should not do this",
            "Single query or bulk enumeration?",
            "Timing — correlates with other reconnaissance?",
        ],
        "related_events": ["4799", "4728", "4732", "4624"],
        "category": "account-management",
        "default_severity": "medium",
    },
    "5140": {
        "title": "Network Share Accessed",
        "summary": "A network share object was accessed.",
        "why_it_matters": (
            "Ransomware and data exfiltration heavily target network shares. "
            "ADMIN$, IPC$, and C$ access from a workstation is a primary lateral movement indicator."
        ),
        "benign_causes": [
            "Users accessing file shares for work",
            "Backup agents accessing file shares",
            "IT management via admin shares",
        ],
        "suspicious_causes": [
            "Access to ADMIN$, C$, or IPC$ from a workstation",
            "Mass enumeration of shares across many hosts",
            "Ransomware spreading to network shares",
        ],
        "recommended_checks": [
            "Which share? (ADMIN$, C$, IPC$ = critical)",
            "Source account and machine — expected access?",
            "Single access or bulk across many machines?",
        ],
        "related_events": ["5145", "4624", "4648", "4688"],
        "category": "object-access",
        "default_severity": "medium",
    },
    "5145": {
        "title": "Network Share Access Check",
        "summary": "A network share access check was performed.",
        "why_it_matters": (
            "High volumes of 5145 events can indicate share enumeration, ransomware spreading, "
            "or unauthorized data access."
        ),
        "benign_causes": [
            "Normal file access through a mapped drive",
            "Backup agent scanning share contents",
        ],
        "suspicious_causes": [
            "Bulk access checks against many files → ransomware or exfiltration",
            "Many access-denied events → unauthorized probing",
        ],
        "recommended_checks": [
            "Volume — how many access checks in the window?",
            "Which share and path?",
            "Access granted or denied?",
        ],
        "related_events": ["5140", "4624", "4688"],
        "category": "object-access",
        "default_severity": "low",
    },
    "5156": {
        "title": "WFP Allowed Connection",
        "summary": "The Windows Filtering Platform allowed a network connection.",
        "why_it_matters": (
            "Malware beaconing to C2, lateral movement over SMB, and data exfiltration appear here. "
            "Unexpected outbound connections from servers are critical indicators."
        ),
        "benign_causes": [
            "Normal application outbound connections",
            "Windows Update, telemetry, or sync services",
        ],
        "suspicious_causes": [
            "Outbound connections from cmd.exe or powershell.exe to external IPs",
            "Connections on unusual C2 ports (4444, 8080, 8443)",
            "Lateral movement connections on port 445",
        ],
        "recommended_checks": [
            "Which process is making the connection?",
            "Destination IP — internal, external, or known-bad?",
            "Destination port — standard for the application?",
        ],
        "related_events": ["5157", "4688", "4624"],
        "category": "network",
        "default_severity": "low",
    },
    "5157": {
        "title": "WFP Blocked Connection",
        "summary": "The Windows Filtering Platform blocked a network connection.",
        "why_it_matters": (
            "Blocked connections reveal malware trying to reach C2 or lateral movement that was prevented. "
            "A spike in blocked connections from a single host is a strong compromise indicator."
        ),
        "benign_causes": [
            "Application trying to connect to an unavailable server",
            "Firewall rule change blocking previously allowed traffic",
        ],
        "suspicious_causes": [
            "Malware beacon blocked by endpoint firewall",
            "Lateral movement attempt blocked",
            "Bulk blocked connections from one host → compromised machine trying to spread",
        ],
        "recommended_checks": [
            "Source process — what is trying to connect?",
            "Destination IP and port",
            "Pattern of attempts or single event?",
        ],
        "related_events": ["5156", "4688"],
        "category": "network",
        "default_severity": "medium",
    },
    "5379": {
        "title": "Credential Manager Read",
        "summary": "Credential Manager credentials were read.",
        "why_it_matters": (
            "Credential Manager stores saved passwords for RDP, websites, and applications. "
            "Mimikatz and similar tools read these to escalate or move laterally."
        ),
        "benign_causes": [
            "User or application using saved credentials",
            "Windows automatic sign-in using saved credentials",
        ],
        "suspicious_causes": [
            "Credential read by cmd.exe or powershell.exe",
            "Credential read followed by logon to a new system",
            "Mimikatz or similar tool",
        ],
        "recommended_checks": [
            "Which process read the credentials?",
            "Which credential was accessed?",
            "Is there a subsequent 4624 or 4648 from a new location?",
        ],
        "related_events": ["4648", "4624", "4672"],
        "category": "credential",
        "default_severity": "high",
    },
    "7045": {
        "title": "New Service Installed",
        "summary": "A new service was installed on the system.",
        "why_it_matters": (
            "Service installation is one of the most reliable indicators of malware persistence. "
            "PsExec, Cobalt Strike, and many ransomware families install services."
        ),
        "benign_causes": [
            "Software installer creating a required service",
            "Windows Update installing a driver",
            "IT deployment tool",
        ],
        "suspicious_causes": [
            "Service with a random or short name",
            "Service binary in TEMP, Downloads, or non-standard paths",
            "Service created via PsExec remotely",
            "Cobalt Strike or Metasploit service names",
        ],
        "recommended_checks": [
            "Service binary path — signed? Standard location?",
            "Service name — meaningful or random?",
            "Who installed it?",
            "Check file hash against threat intelligence",
        ],
        "related_events": ["4697", "4688", "4624", "4648"],
        "category": "service",
        "default_severity": "high",
    },
    "1102": {
        "title": "Audit Log Cleared",
        "summary": "The Windows Security audit log was cleared.",
        "why_it_matters": (
            "Clearing the security log is the most obvious sign of an attacker covering their tracks. "
            "In a well-managed environment this should almost never happen without documentation."
        ),
        "benign_causes": [
            "Authorized security audit by IT/security team",
            "Log management system (should use archiving instead)",
        ],
        "suspicious_causes": [
            "Log cleared after a period of suspicious activity",
            "Log cleared by an account that is not a SIEM/log management account",
            "Log cleared multiple times",
        ],
        "recommended_checks": [
            "Who cleared the log?",
            "What events happened immediately before the clear (preserved in SIEM)?",
            "Is this a recurring pattern?",
            "Treat as a critical incident until proven benign",
        ],
        "related_events": ["517", "4719", "4907"],
        "category": "audit-policy",
        "default_severity": "critical",
    },
}


def get_event_knowledge(event_id: str) -> EventKnowledgeEntry | None:
    """Return full analyst knowledge for an event ID, or None if not in the knowledge base."""
    return EVENT_ID_KNOWLEDGE.get(event_id)


def get_event_summary(event_id: str, fallback: str | None = None) -> str:
    """Return a plain-text summary for an event ID with graceful fallbacks."""
    entry = EVENT_ID_KNOWLEDGE.get(event_id)
    if entry:
        return entry["summary"]
    if fallback:
        return fallback
    return "No explanation available for this Event ID. Use the Wazuh rule description and raw event data for analysis."
