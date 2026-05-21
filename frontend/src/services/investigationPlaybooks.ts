/**
 * Investigation Playbooks — Wazuh AI Analyzer (Frontend mirror)
 * ==============================================================
 * Defensive analysis playbooks that bridge the gap between
 * "what happened?" (EventKnowledge) and "what should I do next?".
 *
 * SAFETY CONTRACT (Phase 1)
 * -------------------------
 * - No playbook may auto-execute any action.
 * - Dangerous actions are listed solely for UI gating / reference.
 * - All script references are disabled until Script Library Phase 2.
 * - Use: The-Art-of-Hacking/h4cker as inspiration only — no offensive tools.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

export type PlaybookPlatform = 'windows' | 'linux' | 'both' | 'network';
export type PlaybookSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface InvestigationPlaybook {
  playbook_id: string;
  title: string;
  category: string;
  platform: PlaybookPlatform;
  severity_scope: PlaybookSeverity[];
  description: string;
  trigger_conditions: string[];
  related_event_ids: string[];
  related_event_keys: string[];
  related_categories: string[];
  related_mitre_techniques: string[];
  recommended_checks: string[];
  /** Read-only script IDs — no execution in Phase 1 */
  recommended_readonly_scripts: string[];
  /** Listed for gating only — all disabled in Phase 1 */
  dangerous_actions: string[];
  blocked_actions_reason: string;
  false_positive_notes: string[];
  baseline_notes: string[];
  escalation_conditions: string[];
  references: string[];
}

// ─── Script catalogue (Phase 1 — display only) ───────────────────────────────

export const SCRIPT_LABELS: Record<string, string> = {
  // Windows
  collect_windows_event_context:       'Collect Event Context',
  collect_windows_processes:           'Collect Processes',
  collect_windows_services:            'Collect Services',
  collect_windows_scheduled_tasks:     'Collect Scheduled Tasks',
  collect_windows_local_admins:        'Collect Local Admins',
  collect_windows_defender_status:     'Defender Status',
  collect_windows_network_connections: 'Network Connections',
  collect_windows_firewall_rules:      'Firewall Rules',
  // Linux
  collect_linux_auth_context:          'Collect Auth Logs',
  collect_linux_recent_logins:         'Recent Logins',
  collect_linux_sudo_activity:         'sudo Activity',
  collect_linux_processes:             'Collect Processes',
  collect_linux_services:              'Collect Services',
  collect_linux_cron_jobs:             'Cron Jobs',
  collect_linux_systemd_units:         'systemd Units',
  collect_linux_listening_ports:       'Listening Ports',
  collect_linux_package_history:       'Package History',
  collect_linux_sensitive_files:       'Sensitive Files',
  collect_linux_firewall_status:       'Firewall Status',
  // Network
  check_dns_resolution:                'DNS Check',
  check_ip_reputation_placeholder:     'IP Reputation (placeholder)',
  check_open_ports_readonly:           'Open Ports (read-only)',
  check_tls_certificate:               'TLS Certificate',
};

// ─── Playbook data ────────────────────────────────────────────────────────────

export const INVESTIGATION_PLAYBOOKS: InvestigationPlaybook[] = [
  // ── 1. Windows Failed Logon ──────────────────────────────────────────────
  {
    playbook_id: 'windows_failed_logon_triage',
    title: 'Windows Failed Logon Triage',
    category: 'authentication',
    platform: 'windows',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'Investigate failed Windows logon attempts. Repeated failures may indicate brute force, credential stuffing, or a misconfigured service. A successful logon after failures may indicate a compromised account.',
    trigger_conditions: [
      'Event ID 4625 (Failed Logon)',
      'Event ID 4771 (Kerberos pre-auth failed)',
      'Event ID 4776 (NTLM credential validation failed)',
      'Event ID 4740 (Account locked out)',
    ],
    related_event_ids: ['4625', '4771', '4776', '4740', '4624'],
    related_event_keys: [],
    related_categories: ['authentication', 'kerberos', 'credential'],
    related_mitre_techniques: ['T1110', 'T1110.001', 'T1110.003', 'T1078'],
    recommended_checks: [
      'Count failures per source IP and per target account',
      'Check if account was locked (4740)',
      'Check for successful logon (4624) after failures — possible compromise',
      'Identify logon type: interactive (2), network (3), remote (10)',
      'Check if source workstation is a known asset',
      'Check time-of-day — off-hours failures are higher risk',
      'Check SubStatus code in 4625 for exact failure reason',
      'Review Wazuh active response — was source IP blocked?',
    ],
    recommended_readonly_scripts: [
      'collect_windows_event_context',
      'collect_windows_network_connections',
      'collect_windows_local_admins',
    ],
    dangerous_actions: ['block_ip', 'disable_account', 'reset_password'],
    blocked_actions_reason:
      'Account and IP actions are disabled in Phase 1. Confirm host identity and escalate to IT policy owner before any blocking.',
    false_positive_notes: [
      'Service accounts with cached wrong passwords after a password change',
      'Users locking themselves out on another device',
      'Scheduled tasks running under old credentials',
    ],
    baseline_notes: [
      'Establish normal failure rate per host/user before alerting',
      'Build a list of known service account sources',
    ],
    escalation_conditions: [
      'Successful logon follows a burst of failures for the same account',
      'Source IP belongs to an external or unknown network',
      'Account locked out repeatedly',
      'Logon type 3 (network) from a non-domain source',
    ],
    references: [
      'MITRE ATT&CK T1110 — Brute Force',
      'Windows Security Event ID 4625',
    ],
  },

  // ── 2. Windows Successful Logon After Failures ───────────────────────────
  {
    playbook_id: 'windows_successful_logon_after_failures',
    title: 'Windows Successful Logon After Failures',
    category: 'authentication',
    platform: 'windows',
    severity_scope: ['high', 'critical'],
    description:
      'A successful logon (4624 or 4672) occurred after one or more failed logon attempts. This pattern may indicate credential compromise following a brute force or password spray.',
    trigger_conditions: [
      'Event ID 4624 following multiple 4625 for the same account',
      'Event ID 4672 (Special Privileges) in the same session',
      'Short time delta between failures and success',
    ],
    related_event_ids: ['4624', '4625', '4672', '4771', '4776'],
    related_event_keys: [],
    related_categories: ['authentication', 'privilege'],
    related_mitre_techniques: ['T1078', 'T1110'],
    recommended_checks: [
      'Check time delta between last failure and success',
      'Verify source IP and workstation against known assets',
      'Check if 4672 (special privileges) was issued in the same logon session',
      'Look for subsequent activity: file access, lateral movement, privilege use',
      'Check if the account is privileged or a service account',
    ],
    recommended_readonly_scripts: [
      'collect_windows_event_context',
      'collect_windows_local_admins',
      'collect_windows_network_connections',
    ],
    dangerous_actions: ['disable_account', 'kill_session', 'reset_password', 'block_ip'],
    blocked_actions_reason: 'Account and session actions require IT policy approval and confirmed host identity.',
    false_positive_notes: [
      'User mistyped password on previous attempt — perfectly normal',
      'Application retry logic after brief network interruption',
    ],
    baseline_notes: ['Track failures-before-success ratio per account over time'],
    escalation_conditions: [
      '4672 (Special Privileges) immediately after successful logon',
      'Source IP is unknown or external',
      'Account is a domain administrator or service account',
      'Further lateral movement events (4624 type 3) on other hosts',
    ],
    references: [
      'MITRE ATT&CK T1078 — Valid Accounts',
      'Windows Security Event ID 4624 / 4672',
    ],
  },

  // ── 3. Windows Privileged Logon ──────────────────────────────────────────
  {
    playbook_id: 'windows_privileged_logon_triage',
    title: 'Windows Privileged Logon Triage',
    category: 'privilege',
    platform: 'windows',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'Special privileges were assigned to a new logon session (4672). Unexpected privileged logons may indicate privilege abuse or lateral movement.',
    trigger_conditions: [
      'Event ID 4672 (Special Privileges Assigned to New Logon)',
      'Event ID 4624 from unusual source for a privileged account',
    ],
    related_event_ids: ['4672', '4624', '4634'],
    related_event_keys: [],
    related_categories: ['privilege', 'authentication'],
    related_mitre_techniques: ['T1078', 'T1078.002', 'T1134'],
    recommended_checks: [
      'Identify which privileges were assigned (SeDebugPrivilege, SeBackupPrivilege, etc.)',
      'Verify the account is expected to hold those privileges',
      'Check source workstation and IP',
      'Check time of day against baseline',
      'Look for subsequent sensitive object access events (4663, 4656)',
    ],
    recommended_readonly_scripts: ['collect_windows_local_admins', 'collect_windows_event_context'],
    dangerous_actions: ['disable_account', 'revoke_privileges'],
    blocked_actions_reason: 'Privilege changes require IT policy owner and change management approval.',
    false_positive_notes: [
      'Admin accounts generate 4672 on every logon — expected for domain admins',
      'Service accounts with necessary SeServiceLogonRight',
    ],
    baseline_notes: ['Whitelist known admin account + host combinations'],
    escalation_conditions: [
      'Non-admin account receives SeDebugPrivilege or SeImpersonatePrivilege',
      'Privileged logon at unusual hours from unusual host',
    ],
    references: ['MITRE ATT&CK T1078.002', 'Windows Security Event ID 4672'],
  },

  // ── 4. Windows Process Execution ─────────────────────────────────────────
  {
    playbook_id: 'windows_process_execution_triage',
    title: 'Windows Process Execution Triage',
    category: 'process',
    platform: 'windows',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'A new process was created (4688 or Sysmon). Suspicious parent-child relationships, encoded command lines, or executables in temp directories are common malware indicators.',
    trigger_conditions: [
      'Event ID 4688 (New Process Created)',
      'Sysmon Event ID 1 (Process Create)',
      'Unusual parent process (e.g. Word spawning cmd.exe)',
      'Base64/encoded command line arguments',
      'Executable in %TEMP%, %APPDATA%, C:\\Users\\Public',
    ],
    related_event_ids: ['4688', 'Sysmon-1', 'Sysmon-7', 'Sysmon-10'],
    related_event_keys: [],
    related_categories: ['process'],
    related_mitre_techniques: ['T1059', 'T1059.001', 'T1059.003', 'T1204', 'T1055', 'T1036'],
    recommended_checks: [
      'Identify parent-child process relationship',
      'Check if executable path is expected for this process name',
      'Decode any Base64 or obfuscated command line arguments',
      'Check if process was spawned by an Office application or browser',
      'Review network connections made by the process (Sysmon-3)',
      'Check if process wrote to suspicious directories',
    ],
    recommended_readonly_scripts: [
      'collect_windows_processes',
      'collect_windows_event_context',
      'collect_windows_network_connections',
    ],
    dangerous_actions: ['kill_process', 'delete_file', 'quarantine_host'],
    blocked_actions_reason: 'Process termination and file deletion require confirmed malicious intent and host policy approval.',
    false_positive_notes: [
      'Legitimate software updates may spawn cmd.exe or PowerShell',
      'IT tooling (RMM, AV, deployment) often runs from unusual paths',
    ],
    baseline_notes: ['Build process baseline per host role (workstation/server/DC)'],
    escalation_conditions: [
      'PowerShell or cmd spawned by Office application',
      'Process running from %TEMP% or hidden directory',
      'Encoded or obfuscated command line',
      'Process connects to external IP immediately after launch',
    ],
    references: [
      'MITRE ATT&CK T1059 — Command and Scripting Interpreter',
      'MITRE ATT&CK T1055 — Process Injection',
    ],
  },

  // ── 5. Windows Service Installed ─────────────────────────────────────────
  {
    playbook_id: 'windows_service_installed_triage',
    title: 'Windows Service Installed Triage',
    category: 'service',
    platform: 'windows',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'A new Windows service was installed or a service configuration was changed. Attackers commonly install services for persistence, privilege escalation, or lateral movement.',
    trigger_conditions: [
      'Event ID 4697 (Service Was Installed)',
      'Event ID 7045 (New Service Installed)',
      'Event ID 7040 (Start Type Changed)',
      'Event ID 7036 (Service State Changed)',
    ],
    related_event_ids: ['4697', '7045', '7040', '7036'],
    related_event_keys: [],
    related_categories: ['service', 'persistence'],
    related_mitre_techniques: ['T1543.003', 'T1569.002'],
    recommended_checks: [
      'Check service executable path — is it in a trusted location?',
      'Check service account — running as SYSTEM is higher risk',
      'Compare service name against known software baseline',
      'Check who installed the service (user context from 4697)',
      'Check if service was installed with AUTO_START on unusual binary',
    ],
    recommended_readonly_scripts: [
      'collect_windows_services',
      'collect_windows_event_context',
      'collect_windows_processes',
    ],
    dangerous_actions: ['stop_service', 'delete_service', 'quarantine_host'],
    blocked_actions_reason: 'Service changes require confirmed malicious classification and change approval.',
    false_positive_notes: [
      'Software installers and update agents create services',
      'AV/EDR products create services during installation',
      'RMM agent installation creates services',
    ],
    baseline_notes: ['Maintain a baseline of approved services per host role'],
    escalation_conditions: [
      'Service binary in %TEMP%, %APPDATA%, or user-writable directory',
      'Service running as SYSTEM with an unknown executable',
      'Service installed outside a known change window',
    ],
    references: ['MITRE ATT&CK T1543.003 — Create or Modify System Process: Windows Service'],
  },

  // ── 6. Windows Scheduled Task ────────────────────────────────────────────
  {
    playbook_id: 'windows_scheduled_task_triage',
    title: 'Windows Scheduled Task Triage',
    category: 'persistence',
    platform: 'windows',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'A scheduled task was created, modified or deleted. Scheduled tasks are a common persistence mechanism used by both legitimate software and attackers.',
    trigger_conditions: [
      'Event ID 4698 (Scheduled Task Created)',
      'Event ID 4702 (Scheduled Task Updated)',
      'Event ID 4699 (Scheduled Task Deleted)',
      'Event ID 4700 (Scheduled Task Enabled)',
      'Event ID 4701 (Scheduled Task Disabled)',
    ],
    related_event_ids: ['4698', '4702', '4699', '4700', '4701'],
    related_event_keys: [],
    related_categories: ['persistence', 'process'],
    related_mitre_techniques: ['T1053.005'],
    recommended_checks: [
      'Inspect task XML — what action does it run?',
      'Check task creator (user account) from event log',
      'Check if the executable path is expected',
      'Check task trigger — at logon, daily, on event?',
      'Verify if the task matches known software',
    ],
    recommended_readonly_scripts: ['collect_windows_scheduled_tasks', 'collect_windows_event_context'],
    dangerous_actions: ['delete_scheduled_task', 'disable_scheduled_task'],
    blocked_actions_reason: 'Task modifications require confirmed malicious classification.',
    false_positive_notes: [
      'Software installers (browsers, AV, backup) create tasks',
      'Windows itself creates maintenance tasks',
    ],
    baseline_notes: ['Baseline scheduled tasks by host role — flag new unknown tasks'],
    escalation_conditions: [
      'Task runs an encoded PowerShell command',
      'Task created by a non-admin or unexpected user',
      'Task executable is in a temp or user-writable directory',
    ],
    references: ['MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task'],
  },

  // ── 7. Windows Audit Log Cleared ─────────────────────────────────────────
  {
    playbook_id: 'windows_audit_log_cleared_triage',
    title: 'Windows Audit Log Cleared Triage',
    category: 'audit-policy',
    platform: 'windows',
    severity_scope: ['high', 'critical'],
    description:
      'The Windows Security or System audit log was cleared. Log clearing is a common attacker technique to remove forensic evidence and should almost never happen outside planned maintenance.',
    trigger_conditions: [
      'Event ID 1102 (Audit Log was Cleared)',
      'Event ID 4719 (System Audit Policy was Changed)',
    ],
    related_event_ids: ['1102', '4719'],
    related_event_keys: [],
    related_categories: ['audit-policy', 'defense-evasion'],
    related_mitre_techniques: ['T1070.001', 'T1562.002'],
    recommended_checks: [
      'Identify who cleared the log — check account name in the event',
      'Check if a change request exists for this host and time',
      'Review forwarded logs in SIEM — may still have pre-clear events',
      'Check remote session activity before log clear',
    ],
    recommended_readonly_scripts: ['collect_windows_event_context', 'collect_windows_local_admins'],
    dangerous_actions: ['isolate_host', 'quarantine_host'],
    blocked_actions_reason: 'Isolation requires incident declaration and management approval.',
    false_positive_notes: ['Planned log maintenance by IT admin with a documented change record'],
    baseline_notes: ['Log clearing should be near-zero in normal operations'],
    escalation_conditions: [
      'Log cleared by a non-admin or unexpected account',
      'Log cleared immediately after suspicious activity',
      'Multiple logs cleared in a short window',
    ],
    references: [
      'MITRE ATT&CK T1070.001 — Indicator Removal: Clear Windows Event Logs',
      'Windows Security Event ID 1102',
    ],
  },

  // ── 8. Windows Firewall / WFP ────────────────────────────────────────────
  {
    playbook_id: 'windows_firewall_or_wfp_triage',
    title: 'Windows Firewall / WFP Rule Change Triage',
    category: 'network',
    platform: 'windows',
    severity_scope: ['medium', 'high'],
    description:
      'A Windows Firewall rule was added, modified or deleted, or WFP allowed/blocked a connection. Rule changes by unknown processes may indicate defence weakening for C2 or lateral movement.',
    trigger_conditions: [
      'Event ID 5156 (WFP allowed a connection)',
      'Event ID 5157 (WFP blocked a connection)',
      'Event ID 4946/4947/4948 (Firewall rule added/modified/deleted)',
      'Event ID 5024/5025 (Firewall service started/stopped)',
    ],
    related_event_ids: ['5156', '5157', '4946', '4947', '4948', '4950', '5024', '5025'],
    related_event_keys: [],
    related_categories: ['network', 'defense-evasion'],
    related_mitre_techniques: ['T1562.004', 'T1071'],
    recommended_checks: [
      'Identify process making the firewall change or connection',
      'Check rule name, direction (inbound/outbound) and port',
      'Check destination IP — is it known/trusted?',
      'Check if Firewall service was stopped (5025)',
      'Correlate with new service or process execution events',
    ],
    recommended_readonly_scripts: [
      'collect_windows_firewall_rules',
      'collect_windows_network_connections',
      'collect_windows_event_context',
    ],
    dangerous_actions: ['modify_firewall', 'isolate_host'],
    blocked_actions_reason: 'Firewall changes require network team approval.',
    false_positive_notes: [
      'Software installers routinely add firewall exceptions',
      'RMM and AV agents add rules during installation',
    ],
    baseline_notes: ['Snapshot firewall rule set per host after clean install'],
    escalation_conditions: [
      'Firewall service stopped (5025)',
      'Inbound rule added for all ports (0–65535)',
      'Rule added immediately after a new process or service install',
    ],
    references: ['MITRE ATT&CK T1562.004 — Disable or Modify System Firewall'],
  },

  // ── 9. Linux SSH Brute Force ──────────────────────────────────────────────
  {
    playbook_id: 'linux_ssh_bruteforce_triage',
    title: 'Linux SSH Brute Force Triage',
    category: 'authentication',
    platform: 'linux',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'Multiple failed SSH authentication attempts were detected from the same source IP or for the same target user. May indicate brute force or credential stuffing against SSH.',
    trigger_conditions: [
      'linux.ssh.login_failure — multiple events in short time',
      'Same source IP with many different usernames (spray)',
      'Invalid user attempts for non-existent accounts',
    ],
    related_event_ids: ['5760'],
    related_event_keys: ['linux.ssh.login_failure'],
    related_categories: ['authentication'],
    related_mitre_techniques: ['T1110', 'T1110.001', 'T1110.003'],
    recommended_checks: [
      'Count failures per source IP over last hour and day',
      'Check if any failure was followed by a successful SSH login',
      'Check target usernames — are they real accounts?',
      'Check if source IP has hit other hosts',
      'Check Fail2Ban / Wazuh active response — was IP blocked?',
      'Verify SSH port — non-standard ports may indicate exposed service',
    ],
    recommended_readonly_scripts: [
      'collect_linux_auth_context',
      'collect_linux_recent_logins',
      'collect_linux_firewall_status',
    ],
    dangerous_actions: ['block_ip', 'disable_account', 'modify_firewall'],
    blocked_actions_reason: 'IP blocking and account changes require host identity confirmation and IT policy approval.',
    false_positive_notes: [
      'Automated monitoring tools with misconfigured credentials',
      'Scanning tools (Shodan, etc.) probing publicly visible hosts',
    ],
    baseline_notes: [
      'Note normal SSH failure rate for internet-facing hosts',
      'Disable SSH password auth and enforce key-only where possible',
    ],
    escalation_conditions: [
      'Successful SSH login follows failures from same source IP',
      'Failures target root or admin accounts',
      'Failure rate exceeds 100 attempts per minute',
      'Source IP matches a known threat intelligence indicator',
    ],
    references: [
      'MITRE ATT&CK T1110 — Brute Force',
      'CIS Benchmark — SSH hardening',
    ],
  },

  // ── 10. Linux Successful SSH Login ───────────────────────────────────────
  {
    playbook_id: 'linux_successful_ssh_login_triage',
    title: 'Linux Successful SSH Login Triage',
    category: 'authentication',
    platform: 'linux',
    severity_scope: ['low', 'medium', 'high'],
    description:
      'A successful SSH authentication was observed. Combined with prior failures, unusual source IPs, or off-hours timing it may indicate compromised credentials or initial access.',
    trigger_conditions: [
      'linux.ssh.login_success',
      'Successful SSH login following failures from the same IP',
      'Login from unusual or external source IP',
    ],
    related_event_ids: [],
    related_event_keys: ['linux.ssh.login_success', 'linux.ssh.login_failure'],
    related_categories: ['authentication'],
    related_mitre_techniques: ['T1078', 'T1021.004'],
    recommended_checks: [
      'Check if a burst of failures preceded this success from the same IP',
      'Check source IP against known admin/developer IP ranges',
      'Review subsequent commands / sudo activity after login',
      'Review authorized_keys for unexpected public keys',
    ],
    recommended_readonly_scripts: [
      'collect_linux_auth_context',
      'collect_linux_recent_logins',
      'collect_linux_sudo_activity',
      'collect_linux_sensitive_files',
    ],
    dangerous_actions: ['kill_session', 'disable_account', 'block_ip'],
    blocked_actions_reason: 'Session and account actions require host identity confirmation.',
    false_positive_notes: ['Normal developer or admin login from authorised IP'],
    baseline_notes: ['Baseline normal login sources per user'],
    escalation_conditions: [
      'Login from external IP not in known-good list',
      'Followed by sudo or root activity',
      'Login follows recent brute force pattern',
      'Authorized_keys file modified recently',
    ],
    references: [
      'MITRE ATT&CK T1021.004 — Remote Services: SSH',
      'MITRE ATT&CK T1078 — Valid Accounts',
    ],
  },

  // ── 11. Linux sudo Privilege ─────────────────────────────────────────────
  {
    playbook_id: 'linux_sudo_privilege_triage',
    title: 'Linux sudo Privilege Triage',
    category: 'privilege',
    platform: 'linux',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'A user executed a command via sudo or a sudo failure was observed. Unexpected sudo usage, root commands after SSH login, or sudo failures may indicate privilege escalation attempts.',
    trigger_conditions: [
      'linux.sudo.command — sudo command executed',
      'linux.sudo.command_failure — sudo denied',
      'sudo executed immediately after SSH login',
    ],
    related_event_ids: [],
    related_event_keys: ['linux.sudo.command', 'linux.sudo.command_failure'],
    related_categories: ['privilege'],
    related_mitre_techniques: ['T1078.003', 'T1548.003'],
    recommended_checks: [
      'Identify the exact command run via sudo',
      'Check if the user is in the sudoers allowlist for this command',
      'Check if the command modifies sudoers, passwd, or shadow',
      'Check for sudo -l (listing sudo rights) — reconnaissance indicator',
      'Cross-reference with SSH login events before this sudo use',
    ],
    recommended_readonly_scripts: [
      'collect_linux_sudo_activity',
      'collect_linux_auth_context',
      'collect_linux_sensitive_files',
    ],
    dangerous_actions: ['disable_account', 'remove_sudo_access', 'kill_session'],
    blocked_actions_reason: 'Account changes require host identity confirmation and IT policy approval.',
    false_positive_notes: [
      'Developers and admins legitimately using sudo for routine tasks',
      'Automated deployment scripts using sudo for package installs',
    ],
    baseline_notes: ['Document expected sudo commands per role (developer, ops, DBA)'],
    escalation_conditions: [
      'sudo used to modify /etc/sudoers, /etc/passwd, /etc/shadow',
      'sudo used to write to /root/.ssh/authorized_keys',
      'sudo used to add a new user with UID 0',
    ],
    references: ['MITRE ATT&CK T1548.003 — Abuse Elevation Control Mechanism: Sudo'],
  },

  // ── 12. Linux FIM Sensitive File Change ──────────────────────────────────
  {
    playbook_id: 'linux_fim_sensitive_file_change',
    title: 'Linux FIM Sensitive File Change',
    category: 'file-integrity',
    platform: 'linux',
    severity_scope: ['high', 'critical'],
    description:
      'Wazuh FIM detected a modification to a sensitive system file. Changes to sudoers, passwd, shadow, authorized_keys, systemd units or crontab without an approved change record are high-priority findings.',
    trigger_conditions: [
      'linux.fim.sudoers_modified — /etc/sudoers or /etc/sudoers.d/*',
      'linux.fim.passwd_modified — /etc/passwd',
      'linux.fim.shadow_modified — /etc/shadow',
      'linux.fim.ssh_authorized_keys_modified — ~/.ssh/authorized_keys',
      'linux.fim.systemd_unit_modified — /etc/systemd/**',
      'linux.fim.crontab_modified',
    ],
    related_event_ids: [],
    related_event_keys: [
      'linux.fim.file_modified',
      'linux.fim.sudoers_modified',
      'linux.fim.passwd_modified',
      'linux.fim.shadow_modified',
      'linux.fim.ssh_authorized_keys_modified',
      'linux.fim.systemd_unit_modified',
      'linux.fim.crontab_modified',
    ],
    related_categories: ['file-integrity'],
    related_mitre_techniques: ['T1098', 'T1548.003', 'T1543.002', 'T1053.003'],
    recommended_checks: [
      'Identify which file was modified and the exact change',
      'Check which user/process made the change (Wazuh audit context)',
      'Verify against approved change management record',
      'Check sudo and SSH activity around the timestamp',
      'For authorized_keys: check if new key was added',
      'For sudoers: check if NOPASSWD or new user entry was added',
    ],
    recommended_readonly_scripts: [
      'collect_linux_sensitive_files',
      'collect_linux_sudo_activity',
      'collect_linux_auth_context',
      'collect_linux_systemd_units',
      'collect_linux_cron_jobs',
    ],
    dangerous_actions: ['restore_file', 'reboot_host', 'quarantine_host'],
    blocked_actions_reason: 'File restoration and host actions require confirmed malicious classification and host identity.',
    false_positive_notes: [
      'Package manager modifying /etc/passwd, /etc/shadow, /etc/group',
      'Admin adding an authorised SSH key for a new team member',
      'Ansible/Chef/Puppet configuration management making approved changes',
    ],
    baseline_notes: ['Track which automation tools normally touch sensitive paths'],
    escalation_conditions: [
      'authorized_keys modified by non-admin user or during off-hours',
      'sudoers modified to add NOPASSWD or new user',
      'New systemd unit enabled immediately after SSH login',
    ],
    references: [
      'MITRE ATT&CK T1098 — Account Manipulation',
      'Wazuh FIM documentation',
    ],
  },

  // ── 13. Linux systemd Persistence ────────────────────────────────────────
  {
    playbook_id: 'linux_systemd_persistence_triage',
    title: 'Linux systemd Persistence Triage',
    category: 'persistence',
    platform: 'linux',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'A new systemd service, timer or unit was created or modified. Attackers use systemd units for persistence after initial access.',
    trigger_conditions: [
      'linux.systemd.service_enabled',
      'linux.systemd.unit_created',
      'linux.systemd.unit_modified',
      'linux.systemd.timer_created',
    ],
    related_event_ids: [],
    related_event_keys: [
      'linux.systemd.service_enabled',
      'linux.systemd.unit_created',
      'linux.systemd.unit_modified',
      'linux.systemd.timer_created',
    ],
    related_categories: ['persistence'],
    related_mitre_techniques: ['T1543.002'],
    recommended_checks: [
      'Read the unit file — what ExecStart command does it run?',
      'Verify the binary referenced in ExecStart exists and is trusted',
      'Check if the unit was enabled for auto-start',
      'Compare against package manager: did a software install create this?',
    ],
    recommended_readonly_scripts: [
      'collect_linux_systemd_units',
      'collect_linux_processes',
      'collect_linux_sudo_activity',
    ],
    dangerous_actions: ['disable_service', 'delete_unit_file', 'reboot_host'],
    blocked_actions_reason: 'Unit changes require confirmed malicious classification and change approval.',
    false_positive_notes: [
      'Package installs create units for daemons',
      'Application management tools (Docker, k8s) create units',
    ],
    baseline_notes: ['Snapshot clean systemd unit list after OS install and provisioning'],
    escalation_conditions: [
      'Unit file references executable in /tmp or user home directory',
      'Unit created immediately after SSH login',
      'Unit runs encoded or obfuscated command',
    ],
    references: ['MITRE ATT&CK T1543.002 — Create or Modify System Process: Systemd Service'],
  },

  // ── 14. Linux Cron Persistence ───────────────────────────────────────────
  {
    playbook_id: 'linux_cron_persistence_triage',
    title: 'Linux Cron Job Persistence Triage',
    category: 'persistence',
    platform: 'linux',
    severity_scope: ['medium', 'high'],
    description:
      'A cron job was created, modified or deleted. Cron is a common persistence mechanism on Linux — unexpected entries in /etc/cron* or user crontabs should be investigated.',
    trigger_conditions: [
      'linux.cron.job_created',
      'linux.cron.job_modified',
      'linux.cron.job_deleted',
      'linux.cron.execution of an unexpected command',
    ],
    related_event_ids: [],
    related_event_keys: [
      'linux.cron.execution',
      'linux.cron.job_created',
      'linux.cron.job_modified',
      'linux.cron.job_deleted',
    ],
    related_categories: ['persistence'],
    related_mitre_techniques: ['T1053.003'],
    recommended_checks: [
      'Read the cron entry — what command does it run?',
      'Identify which user owns the crontab entry',
      'Check for wget/curl/bash -i patterns in cron command',
      'Review /etc/cron.d, /etc/cron.daily, /etc/cron.hourly',
    ],
    recommended_readonly_scripts: [
      'collect_linux_cron_jobs',
      'collect_linux_sudo_activity',
      'collect_linux_auth_context',
    ],
    dangerous_actions: ['delete_cron_entry', 'kill_process'],
    blocked_actions_reason: 'Cron modifications require confirmed malicious classification.',
    false_positive_notes: [
      'Package management creates cron entries in /etc/cron.daily',
      'Backup and monitoring tools schedule cron jobs',
    ],
    baseline_notes: ['Baseline expected cron entries for each host role'],
    escalation_conditions: [
      'Cron entry runs a command from /tmp or a user-writable directory',
      'Cron entry uses wget/curl to download and execute',
      'Cron entry created immediately after SSH login or sudo session',
    ],
    references: ['MITRE ATT&CK T1053.003 — Scheduled Task/Job: Cron'],
  },

  // ── 15. Linux Package Change ──────────────────────────────────────────────
  {
    playbook_id: 'linux_package_change_triage',
    title: 'Linux Package Change Triage',
    category: 'system',
    platform: 'linux',
    severity_scope: ['low', 'medium', 'high'],
    description:
      'A software package was installed or removed. Unexpected installs can indicate privilege escalation, tooling installation, or an attacker expanding capability.',
    trigger_conditions: [
      'linux.package.installed',
      'linux.package.removed',
      'Unusual package name (ncat, netcat, nmap, socat)',
    ],
    related_event_ids: [],
    related_event_keys: ['linux.package.installed', 'linux.package.removed'],
    related_categories: ['system'],
    related_mitre_techniques: ['T1072', 'T1588.001'],
    recommended_checks: [
      'Identify the package name and version',
      'Check if the package is expected for this host role',
      'Check who installed it — user context from apt/yum/dpkg logs',
      'Verify the package source — official repo or unknown source?',
    ],
    recommended_readonly_scripts: ['collect_linux_package_history', 'collect_linux_sudo_activity'],
    dangerous_actions: ['remove_package'],
    blocked_actions_reason: 'Package removal requires confirmed malicious classification and change approval.',
    false_positive_notes: ['Automated update processes', 'Ansible/Chef/Puppet provisioning'],
    baseline_notes: ['Maintain an approved package list per host role'],
    escalation_conditions: [
      'Network scanning or exploitation tool installed (nmap, hydra, metasploit)',
      'Package installed outside maintenance window by unexpected user',
      'Security baseline package removed (e.g. auditd, fail2ban)',
    ],
    references: ['MITRE ATT&CK T1072 — Software Deployment Tools'],
  },

  // ── 16. Linux Firewall Block ──────────────────────────────────────────────
  {
    playbook_id: 'linux_firewall_block_triage',
    title: 'Linux Firewall Block Triage',
    category: 'network',
    platform: 'linux',
    severity_scope: ['low', 'medium', 'high'],
    description:
      'The host firewall (UFW, iptables, nftables) blocked or recorded a connection. High block volumes indicate scanning; outbound blocks may indicate C2 attempts.',
    trigger_conditions: [
      'linux.firewall.ufw_block',
      'linux.firewall.iptables_changed',
      'linux.firewall.nftables_changed',
    ],
    related_event_ids: [],
    related_event_keys: [
      'linux.firewall.ufw_block',
      'linux.firewall.iptables_changed',
      'linux.firewall.nftables_changed',
    ],
    related_categories: ['network'],
    related_mitre_techniques: ['T1046', 'T1071'],
    recommended_checks: [
      'Identify source IP, destination port and protocol',
      'Count blocks from same IP over last hour',
      'For iptables/nftables changes: identify who changed the rules',
      'Check if the rule change weakened the firewall',
    ],
    recommended_readonly_scripts: [
      'collect_linux_firewall_status',
      'collect_linux_listening_ports',
      'collect_linux_auth_context',
    ],
    dangerous_actions: ['modify_firewall', 'block_ip'],
    blocked_actions_reason: 'Firewall changes require network team approval.',
    false_positive_notes: ['Port scanners and internet crawlers produce high block volumes on public IPs'],
    baseline_notes: ['Establish normal block volume for internet-facing hosts'],
    escalation_conditions: [
      'Firewall rule deleted that was blocking a sensitive port',
      'Outbound block to external IP on port 443/4444/8443 — possible C2',
    ],
    references: ['UFW documentation', 'MITRE ATT&CK T1046 — Network Service Discovery'],
  },

  // ── 17. Linux Kernel Instability ─────────────────────────────────────────
  {
    playbook_id: 'linux_kernel_instability_triage',
    title: 'Linux Kernel Instability Triage',
    category: 'system-health',
    platform: 'linux',
    severity_scope: ['high', 'critical'],
    description:
      'A kernel oops, panic, OOM kill, segfault, or unexpected module load was detected. May indicate hardware failure, kernel exploits, or rootkit activity.',
    trigger_conditions: [
      'linux.kernel.oops',
      'linux.kernel.panic',
      'linux.kernel.oom_killer',
      'linux.kernel.seg_fault',
      'linux.kernel.module_loaded — unexpected module',
    ],
    related_event_ids: [],
    related_event_keys: [
      'linux.kernel.oops',
      'linux.kernel.panic',
      'linux.kernel.oom_killer',
      'linux.kernel.seg_fault',
      'linux.kernel.module_loaded',
    ],
    related_categories: ['system-health'],
    related_mitre_techniques: ['T1014', 'T1599'],
    recommended_checks: [
      'Read the full kernel log message for the call trace',
      'Check which kernel module is referenced',
      'For OOM kills: check which process was killed and memory pressure',
      'For module_loaded: identify the module name and path',
    ],
    recommended_readonly_scripts: [
      'collect_linux_processes',
      'collect_linux_services',
      'collect_linux_sudo_activity',
    ],
    dangerous_actions: ['reboot_host', 'unload_module'],
    blocked_actions_reason: 'Kernel actions require IT admin approval and platform stability assessment.',
    false_positive_notes: [
      'OOM kills under legitimate high-memory workloads',
      'Kernel oops from known hardware compatibility issues',
    ],
    baseline_notes: ['Note approved kernel modules for each host type'],
    escalation_conditions: [
      'Unknown kernel module loaded from /tmp or non-standard path',
      'Repeated kernel panics — possible hardware failure or active exploit',
    ],
    references: ['MITRE ATT&CK T1014 — Rootkit', 'Linux kernel oops documentation'],
  },

  // ── 18. DNS / Suspicious DNS ──────────────────────────────────────────────
  {
    playbook_id: 'dns_resolution_or_suspicious_dns_triage',
    title: 'DNS Resolution / Suspicious DNS Triage',
    category: 'network',
    platform: 'both',
    severity_scope: ['medium', 'high', 'critical'],
    description:
      'Suspicious DNS activity detected — NXDOMAIN responses, unusual query volumes, or queries to newly registered / low-reputation domains. May indicate C2 beaconing, DNS tunnelling, or data exfiltration.',
    trigger_conditions: [
      'Windows Event ID 1014 (DNS resolution timeout)',
      'Sysmon Event ID 22 (DNS Query)',
      'High volume of NXDOMAIN responses from single host',
      'DNS query to unusual TLD or DGA-like domain',
    ],
    related_event_ids: ['1014', 'Sysmon-22'],
    related_event_keys: [],
    related_categories: ['network'],
    related_mitre_techniques: ['T1071.004', 'T1568', 'T1568.002'],
    recommended_checks: [
      'Identify the queried domain name',
      'Check domain age and registrar (newly registered = higher risk)',
      'Identify which process made the DNS query',
      'Check query frequency — DGA/beaconing generates regular high volumes',
      'For Sysmon-22: check parent process of the resolver',
    ],
    recommended_readonly_scripts: [
      'check_dns_resolution',
      'check_ip_reputation_placeholder',
      'collect_windows_network_connections',
      'collect_linux_processes',
    ],
    dangerous_actions: ['block_domain', 'block_ip', 'modify_firewall'],
    blocked_actions_reason: 'DNS/firewall blocking requires network team review and threat confirmation.',
    false_positive_notes: [
      'CDN domains use many sub-domains that may look unusual',
      'Event ID 1014 can fire in normal network timeouts — check frequency',
    ],
    baseline_notes: ['Baseline top DNS query destinations per host/user role'],
    escalation_conditions: [
      'Same long random-looking subdomain queried repeatedly — DGA or tunnelling',
      'Process making DNS queries is not a browser or known application',
      'Query to a domain registered in last 30 days',
    ],
    references: [
      'MITRE ATT&CK T1071.004 — Application Layer Protocol: DNS',
      'MITRE ATT&CK T1568.002 — Dynamic Resolution: DGA',
    ],
  },
];

// ─── Index structures ─────────────────────────────────────────────────────────

const _byEventId:  Map<string, InvestigationPlaybook[]> = new Map();
const _byEventKey: Map<string, InvestigationPlaybook[]> = new Map();
const _byCategory: Map<string, InvestigationPlaybook[]> = new Map();
const _byId:       Map<string, InvestigationPlaybook>   = new Map();

for (const p of INVESTIGATION_PLAYBOOKS) {
  _byId.set(p.playbook_id, p);
  for (const eid  of p.related_event_ids)  { const l = _byEventId.get(eid)   ?? []; l.push(p); _byEventId.set(eid, l); }
  for (const key  of p.related_event_keys) { const l = _byEventKey.get(key)  ?? []; l.push(p); _byEventKey.set(key, l); }
  for (const cat  of p.related_categories) { const l = _byCategory.get(cat)  ?? []; l.push(p); _byCategory.set(cat, l); }
}

// ─── Resolver API ─────────────────────────────────────────────────────────────

export function getPlaybook(id: string): InvestigationPlaybook | undefined {
  return _byId.get(id);
}

export function getPlaybooksForEventId(eventId: string): InvestigationPlaybook[] {
  return _byEventId.get(String(eventId)) ?? [];
}

export function getPlaybooksForLinuxKey(key: string): InvestigationPlaybook[] {
  return _byEventKey.get(key) ?? [];
}

export function getPlaybooksForCategory(
  category: string,
  platform?: PlaybookPlatform,
): InvestigationPlaybook[] {
  const all = _byCategory.get(category) ?? [];
  if (!platform) return all;
  return all.filter((p) => p.platform === platform || p.platform === 'both');
}

/**
 * Resolve the best-matching playbooks for a given event cluster.
 *
 * eventIds:   Windows/Sysmon event IDs from the cluster
 * linuxKeys:  Linux event keys from the cluster
 * categories: Wazuh/KB categories from the cluster
 * platform:   'windows' | 'linux' | undefined
 *
 * Returns playbooks ordered: exact event/key match first, category match second.
 * Deduplicates by playbook_id.
 */
export function resolvePlaybooks(opts: {
  eventIds?: string[];
  linuxKeys?: string[];
  categories?: string[];
  platform?: PlaybookPlatform;
}): InvestigationPlaybook[] {
  const seen = new Set<string>();
  const results: InvestigationPlaybook[] = [];

  const add = (p: InvestigationPlaybook) => {
    if (!seen.has(p.playbook_id)) { seen.add(p.playbook_id); results.push(p); }
  };

  for (const eid of opts.eventIds  ?? []) getPlaybooksForEventId(eid).forEach(add);
  for (const key of opts.linuxKeys  ?? []) getPlaybooksForLinuxKey(key).forEach(add);
  for (const cat of opts.categories ?? []) getPlaybooksForCategory(cat, opts.platform).forEach(add);

  return results;
}
