/**
 * Windows Event ID Knowledge Base
 * Covers the most security-relevant Event IDs with analyst context.
 * Used by the Event Map inspector to explain events in plain language.
 */

export interface EventKnowledge {
  title: string;
  summary: string;
  whyItMatters: string;
  benignCauses: string[];
  suspiciousCauses: string[];
  recommendedChecks: string[];
  relatedEvents: string[];
  category:
    | 'authentication'
    | 'privilege'
    | 'process'
    | 'account-management'
    | 'audit-policy'
    | 'network'
    | 'service'
    | 'object-access'
    | 'credential'
    | 'kerberos'
    | 'group-management';
  defaultSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export const EVENT_KNOWLEDGE: Record<string, EventKnowledge> = {
  '4624': {
    title: 'Successful Logon',
    summary: 'An account was successfully logged on to this machine.',
    whyItMatters:
      'Alone it is normal, but in combination with failed logons (4625), unusual source IPs, off-hours timing, or privilege escalation events it can indicate compromised credentials or lateral movement.',
    benignCauses: [
      'Regular user workstation login',
      'Service account starting a scheduled task',
      'Remote desktop session by IT staff',
      'Application using stored credentials',
    ],
    suspiciousCauses: [
      'Logon from unusual IP or workstation',
      'Logon at unusual hours',
      'Logon immediately after multiple 4625 failures',
      'Logon type 3 (network) from external IP',
      'Lateral movement with pass-the-hash',
    ],
    recommendedChecks: [
      'Check Logon Type (2=interactive, 3=network, 10=remote interactive)',
      'Compare source workstation and IP to known assets',
      'Look for preceding 4625 failures for the same account',
      'Check for 4672 (special privileges) in the same session',
      'Verify logon time against normal working hours',
    ],
    relatedEvents: ['4625', '4634', '4648', '4672', '4776', '4771'],
    category: 'authentication',
    defaultSeverity: 'info',
  },

  '4625': {
    title: 'Failed Logon',
    summary: 'An account failed to log on.',
    whyItMatters:
      'Repeated failed logons can indicate stale credentials in services or scheduled tasks, but also password spraying, brute-force attempts, or lateral movement with stolen credentials.',
    benignCauses: [
      'User typed the wrong password',
      'Old password stored in a service, scheduled task, or mapped drive',
      'Disabled or expired account still used by an application',
      'Cached credentials not yet updated after a password change',
    ],
    suspiciousCauses: [
      'Many failures against many different accounts → Password Spray',
      'Many failures against one account → Brute Force',
      'Failures from an external or unusual IP',
      'Failures followed by a successful 4624',
      'Failures targeting admin accounts',
    ],
    recommendedChecks: [
      'Is there a successful 4624 shortly after these failures?',
      'Check source IP and workstation name',
      'Are multiple accounts failing from the same source? (spray)',
      'Check Account Lockout (4740) for the affected accounts',
      'Check Sub Status code: 0xC000006A = bad password, 0xC0000064 = unknown user',
    ],
    relatedEvents: ['4624', '4648', '4740', '4771', '4776', '4672'],
    category: 'authentication',
    defaultSeverity: 'medium',
  },

  '4634': {
    title: 'Logoff',
    summary: 'An account was logged off.',
    whyItMatters:
      'Usually benign, but very short session durations (logon followed immediately by logoff) can indicate automated access, in-and-out lateral movement, or service account activity.',
    benignCauses: [
      'Normal user logging out',
      'Session timeout',
      'Network logon ending after completing a task',
    ],
    suspiciousCauses: [
      'Very short session after a logon — possible automated enumeration',
      'Logoff immediately after privilege escalation',
      'Multiple logon/logoff cycles from the same account',
    ],
    recommendedChecks: [
      'Calculate session duration — check for unusually short sessions',
      'Correlate with the preceding 4624 to determine logon type',
      'Check if sensitive operations occurred during the session',
    ],
    relatedEvents: ['4624', '4647', '4672'],
    category: 'authentication',
    defaultSeverity: 'info',
  },

  '4648': {
    title: 'Explicit Credential Logon',
    summary: 'A logon was attempted using explicit credentials (RunAs, net use, etc.).',
    whyItMatters:
      'This event fires when a process uses credentials other than the currently logged-in user. Lateral movement tools like PsExec and Mimikatz frequently trigger 4648 events.',
    benignCauses: [
      'Administrator using RunAs to elevate a process',
      'Scheduled task running under a different service account',
      'Mapping a network drive with alternate credentials',
    ],
    suspiciousCauses: [
      'PsExec or similar tools using explicit credentials',
      'Mimikatz pass-the-ticket or pass-the-hash',
      'Scripted lateral movement using stored credentials',
      '4648 targeting Domain Admin or SYSTEM accounts',
    ],
    recommendedChecks: [
      'What process triggered the logon? (check process name)',
      'What account was targeted? (privileged = high priority)',
      'Does the source machine normally make these calls?',
      'Correlate with 4624 on the target machine',
    ],
    relatedEvents: ['4624', '4625', '4672', '4688'],
    category: 'authentication',
    defaultSeverity: 'medium',
  },

  '4672': {
    title: 'Special Privileges Assigned',
    summary: 'Special privileges (e.g., SeDebugPrivilege, SeTcbPrivilege) were assigned to a new logon session.',
    whyItMatters:
      'These privileges allow the account to bypass security boundaries. Attackers actively seek these privileges for credential dumping, token manipulation, and lateral movement. 4672 + 4624 together = admin-level session.',
    benignCauses: [
      'Administrator logging in — always generates 4672',
      'Service running under a privileged account (SYSTEM, LocalService)',
      'IT support escalating a session via RunAs',
    ],
    suspiciousCauses: [
      'SeDebugPrivilege assigned to a non-admin account',
      'SeTcbPrivilege (acts as part of OS) on a user account',
      '4672 for a non-admin account at unusual hours',
      'Immediately followed by credential dumping or token manipulation',
    ],
    recommendedChecks: [
      'Which account received the privileges? (Should be an admin account)',
      'Which specific privileges were assigned? (SeDebugPrivilege = high risk)',
      'Correlate with preceding 4624 — what logon type was it?',
      'Check if the session is expected for this account and time',
    ],
    relatedEvents: ['4624', '4648', '4673', '4674', '4688'],
    category: 'privilege',
    defaultSeverity: 'medium',
  },

  '4688': {
    title: 'Process Created',
    summary: 'A new process has been created.',
    whyItMatters:
      'Every process start is logged. Malicious activity — ransomware, credential dumpers, C2 beacons, lateral movement tools — all appear here. The command line and parent process are the most important fields.',
    benignCauses: [
      'Normal application launch by a user',
      'Windows system process spawning child processes',
      'Antivirus or monitoring agent starting a scan',
      'Scheduled task or service starting a process',
    ],
    suspiciousCauses: [
      'cmd.exe or powershell.exe spawned by a browser or Office process',
      'Encoded PowerShell commands (-EncodedCommand)',
      'Process running from TEMP, AppData, or unusual paths',
      'LOLBins: certutil, mshta, wscript, rundll32, regsvr32 with unusual args',
      'Process with no parent or spawned by a service unexpectedly',
    ],
    recommendedChecks: [
      'Check the parent process — is it expected to spawn this child?',
      'Review the command line (requires "Include command line" audit policy)',
      'Check the executable path — system processes should be in C:\\Windows\\System32',
      'Cross-reference process hash against threat intelligence',
      'Look for network connections from the new process',
    ],
    relatedEvents: ['4689', '4624', '4648', '5156', '7045'],
    category: 'process',
    defaultSeverity: 'low',
  },

  '4697': {
    title: 'Service Installed',
    summary: 'A service was installed on this system.',
    whyItMatters:
      'Service installation is a common persistence technique. Attackers install malicious services to survive reboots. Legitimate software rarely installs services without prior notice.',
    benignCauses: [
      'Software installation (antivirus, monitoring agents, drivers)',
      'Windows Update installing a new component',
      'IT-managed deployment via SCCM, Intune, or similar',
    ],
    suspiciousCauses: [
      'Service installed from TEMP, Downloads, or user-writable paths',
      'Service with a random or obfuscated name',
      'Service installed using PsExec or remote tools',
      'Service with a description that does not match its binary',
      'Cobalt Strike or Metasploit service-based lateral movement',
    ],
    recommendedChecks: [
      'Check the service binary path — is it signed and in an expected location?',
      'Who installed the service? Check the account in the event',
      'Is the service name meaningful or obfuscated?',
      'Does the installation time correlate with any scheduled maintenance?',
      'Look for 4688 events around the same time (which process created the service?)',
    ],
    relatedEvents: ['4688', '4624', '7045', '4698'],
    category: 'service',
    defaultSeverity: 'high',
  },

  '4698': {
    title: 'Scheduled Task Created',
    summary: 'A scheduled task was created.',
    whyItMatters:
      'Scheduled tasks are a popular persistence and lateral movement mechanism. Attackers frequently create tasks to execute payloads on a schedule or at logon.',
    benignCauses: [
      'Software installer creating a maintenance or update task',
      'IT automation creating deployment tasks',
      'Antivirus creating scheduled scan tasks',
    ],
    suspiciousCauses: [
      'Task created by a non-admin account',
      'Task action runs from TEMP, AppData, or unusual paths',
      'Task runs an encoded PowerShell or VBScript',
      'Task created via remote service (lateral movement)',
      'Task name mimicking a system task',
    ],
    recommendedChecks: [
      'Who created the task? (check the Creator field)',
      'What does the task action execute? (binary path and arguments)',
      'When is the task scheduled to run?',
      'Correlate with 4688 to find what process created the task',
      'Check for 4624/4648 from the same account around the same time',
    ],
    relatedEvents: ['4702', '4699', '4688', '4624'],
    category: 'service',
    defaultSeverity: 'high',
  },

  '4702': {
    title: 'Scheduled Task Updated',
    summary: 'A scheduled task was updated.',
    whyItMatters:
      'Attackers may update existing legitimate tasks to add malicious payloads, making detection harder than creating new tasks. Look for changes to the task action or schedule.',
    benignCauses: [
      'Software patching or updating a maintenance task',
      'IT team modifying automation tasks',
      'Windows updating its own tasks during updates',
    ],
    suspiciousCauses: [
      'Action path changed to a non-standard executable',
      'Arguments added that include encoded commands',
      'Task modified by an account that did not create it',
      'Task trigger changed to run more frequently',
    ],
    recommendedChecks: [
      'What changed? Compare old vs. new task XML if possible',
      'Who modified the task? Expected account?',
      'Does the new action still look legitimate?',
    ],
    relatedEvents: ['4698', '4699', '4688'],
    category: 'service',
    defaultSeverity: 'medium',
  },

  '4719': {
    title: 'Audit Policy Changed',
    summary: 'System audit policy was changed.',
    whyItMatters:
      'Attackers modify audit policy to blind defenders — disabling logging for specific activities before carrying out attacks. Any unexpected audit policy change is a serious red flag.',
    benignCauses: [
      'Group Policy applying a new audit configuration',
      'IT security team adjusting audit settings',
      'System hardening scripts modifying policy',
    ],
    suspiciousCauses: [
      'Audit policy disabled for logon, process, or object access categories',
      'Change made by a non-privileged or unexpected account',
      'Change immediately before or after a suspicious event cluster',
      'Change during off-hours without a change ticket',
    ],
    recommendedChecks: [
      'Which policy category was changed and in which direction?',
      'Who made the change? Was it an expected admin account?',
      'Does this correlate with a Group Policy update?',
      'Check for 1102 (log clear) around the same time',
    ],
    relatedEvents: ['1102', '4906', '4907', '4912'],
    category: 'audit-policy',
    defaultSeverity: 'high',
  },

  '4720': {
    title: 'User Account Created',
    summary: 'A new user account was created.',
    whyItMatters:
      'Attackers create new accounts for persistence — either for direct access or as a backup in case their primary account is disabled. Unexpected account creation is always a high-priority alert.',
    benignCauses: [
      'HR onboarding process creating accounts via Active Directory',
      'IT automation provisioning service accounts',
      'New employee workstation setup',
    ],
    suspiciousCauses: [
      'Account created by a non-standard admin tool or script',
      'Account name resembles a system or service account',
      'Account created during off-hours without change request',
      'Account created on a workstation (local account) unexpectedly',
      'Account immediately added to an admin group',
    ],
    recommendedChecks: [
      'Who created the account? (check Creator field)',
      'What is the account name — does it follow naming conventions?',
      'Was the account immediately added to a privileged group?',
      'Cross-reference with HR/IT change records',
    ],
    relatedEvents: ['4722', '4728', '4732', '4724', '4726'],
    category: 'account-management',
    defaultSeverity: 'high',
  },

  '4722': {
    title: 'User Account Enabled',
    summary: 'A user account was enabled.',
    whyItMatters:
      'Re-enabling a disabled account — especially a legacy or forgotten one — is a common attack tactic for persistence. Attackers often use dormant accounts that have no current monitoring.',
    benignCauses: [
      'Employee returning from leave and account being reactivated',
      'IT re-enabling a service account for a deployment',
    ],
    suspiciousCauses: [
      'Long-inactive account suddenly re-enabled',
      'Account enabled without a corresponding IT ticket',
      'Account with old/known credentials re-enabled',
    ],
    recommendedChecks: [
      'How long was the account disabled?',
      'Who enabled it and was this expected?',
      'Was there a logon attempt (4624) shortly after enabling?',
    ],
    relatedEvents: ['4725', '4726', '4624', '4672'],
    category: 'account-management',
    defaultSeverity: 'medium',
  },

  '4725': {
    title: 'User Account Disabled',
    summary: 'A user account was disabled.',
    whyItMatters:
      'While often administrative, unexpected account disabling can be part of a denial-of-service attack or cover track after an attack. Privileged account disabling can lock out admins.',
    benignCauses: [
      'Employee offboarding process',
      'Inactive account cleanup by IT',
      'Account lockout policy disabling after failures',
    ],
    suspiciousCauses: [
      'Admin account disabled by a non-admin',
      'Multiple accounts disabled in rapid succession',
      'Account disabled immediately before suspicious activity',
    ],
    recommendedChecks: [
      'Which account was disabled?',
      'Who performed the action?',
      'Are multiple accounts being targeted?',
    ],
    relatedEvents: ['4722', '4726', '4740'],
    category: 'account-management',
    defaultSeverity: 'medium',
  },

  '4726': {
    title: 'User Account Deleted',
    summary: 'A user account was deleted.',
    whyItMatters:
      'Account deletion after an intrusion is a common cleanup step to remove evidence of a created backdoor account. Unexpected deletions warrant immediate investigation.',
    benignCauses: [
      'Employee offboarding completing the final account cleanup',
      'IT removing stale or test accounts',
    ],
    suspiciousCauses: [
      'Account deleted shortly after being created (cleanup after attack)',
      'Privileged account deleted unexpectedly',
      'Account deleted without a corresponding HR/IT ticket',
    ],
    recommendedChecks: [
      'Was this account recently created? (check 4720)',
      'Who deleted the account?',
      'Were there any logons using this account before deletion?',
    ],
    relatedEvents: ['4720', '4722', '4724'],
    category: 'account-management',
    defaultSeverity: 'high',
  },

  '4728': {
    title: 'Member Added to Global Security Group',
    summary: 'A member was added to a security-enabled global group.',
    whyItMatters:
      'Adding accounts to security groups — especially privileged ones like Domain Admins or Backup Operators — is a critical privilege escalation indicator.',
    benignCauses: [
      'IT provisioning a new employee with appropriate access',
      'Service account getting required group membership',
    ],
    suspiciousCauses: [
      'Account added to Domain Admins, Enterprise Admins, or Backup Operators',
      'Addition by an account without HR/IT approval',
      'User account suddenly getting privileged group membership',
    ],
    recommendedChecks: [
      'Which group was the account added to?',
      'Who performed the addition?',
      'Is the added account a user, service, or recently created account?',
      'Cross-reference with change management records',
    ],
    relatedEvents: ['4732', '4729', '4633', '4720', '4672'],
    category: 'group-management',
    defaultSeverity: 'high',
  },

  '4732': {
    title: 'Member Added to Local Security Group',
    summary: 'A member was added to a security-enabled local group (e.g., local Administrators).',
    whyItMatters:
      'Adding an account to the local Administrators group on a workstation or server is a quick and common privilege escalation technique.',
    benignCauses: [
      'IT support adding a user to local Admins for troubleshooting',
      'Software installer requiring local admin during setup',
    ],
    suspiciousCauses: [
      'User account added to local Administrators group',
      'Addition by a non-admin or non-IT account',
      'Same account added to local Admins on multiple machines',
    ],
    recommendedChecks: [
      'Which local group? (Administrators = critical)',
      'Which account was added?',
      'Who performed the change?',
      'Is this the only machine or a mass change across the environment?',
    ],
    relatedEvents: ['4733', '4728', '4624', '4672'],
    category: 'group-management',
    defaultSeverity: 'high',
  },

  '4738': {
    title: 'User Account Changed',
    summary: 'A user account was changed (properties modified).',
    whyItMatters:
      'Account changes can include enabling password-not-required, setting a new password, or changing the account type — all of which are techniques used to prepare an account for misuse.',
    benignCauses: [
      'IT updating account properties (phone number, description, etc.)',
      'Password reset by helpdesk',
      'Account policy changes by an admin',
    ],
    suspiciousCauses: [
      '"Password Not Required" flag set',
      '"Password Does Not Expire" flag set on a sensitive account',
      'User Type Changed flag — account type switched',
      'Changes to a privileged or service account without a ticket',
    ],
    recommendedChecks: [
      'What field was changed? (look for UserAccountControl flag changes)',
      'Who made the change?',
      'Was this a privileged account (Domain Admin, service account)?',
    ],
    relatedEvents: ['4720', '4722', '4724', '4781'],
    category: 'account-management',
    defaultSeverity: 'medium',
  },

  '4740': {
    title: 'User Account Locked Out',
    summary: 'A user account was locked out due to too many failed authentication attempts.',
    whyItMatters:
      'Account lockouts are direct evidence of either forgotten passwords/stale credentials or an active brute-force/password-spray attack. Widespread lockouts across many accounts are a critical indicator of an attack.',
    benignCauses: [
      'User forgot their password and exceeded retry limit',
      'Old password cached in a service, scheduled task, or mobile device',
      'Remote session with expired credentials',
    ],
    suspiciousCauses: [
      'Multiple accounts locked out simultaneously → Password Spray',
      'Lockouts originating from an unusual workstation or IP',
      'Lockouts targeting service or admin accounts',
    ],
    recommendedChecks: [
      'Is this one account or many? Many accounts = spray attack',
      'Find the source via 4625 events — what is the originating workstation?',
      'Check for 4624 after the lockout — was the account eventually accessed?',
      'Identify where the stale credential is stored if benign',
    ],
    relatedEvents: ['4625', '4767', '4624', '4771'],
    category: 'authentication',
    defaultSeverity: 'medium',
  },

  '4768': {
    title: 'Kerberos TGT Requested',
    summary: 'A Kerberos authentication ticket (TGT) was requested.',
    whyItMatters:
      'TGT requests are normal at logon but are also the target of Kerberoasting and AS-REP Roasting attacks. Unusual TGT requests for non-existent accounts or without pre-authentication indicate reconnaissance or exploitation.',
    benignCauses: [
      'Normal user logon requesting a ticket',
      'Service account authenticating to the domain',
    ],
    suspiciousCauses: [
      'Failure code 0x6 (account does not exist) → username enumeration',
      'Failure code 0x18 (bad password) in bulk → password spray',
      'AS-REP Roasting: TGT for accounts with Kerberos pre-auth disabled',
      'Golden Ticket: TGT requested with forged credentials',
    ],
    recommendedChecks: [
      'Check the Result Code — 0x0 is success, anything else is a failure',
      'Is the account requesting a valid, expected account?',
      'Is the client address an expected workstation?',
      'Are there bulk failures against different accounts? (enumeration/spray)',
    ],
    relatedEvents: ['4769', '4771', '4625', '4776'],
    category: 'kerberos',
    defaultSeverity: 'low',
  },

  '4769': {
    title: 'Kerberos Service Ticket Requested',
    summary: 'A Kerberos service ticket (TGS) was requested.',
    whyItMatters:
      'Kerberoasting attacks request service tickets for Service Principal Names (SPNs) to extract and crack offline. Unusually high volumes of TGS requests, especially for service accounts, indicate this attack.',
    benignCauses: [
      'Normal access to network services (file shares, SQL, Exchange)',
      'Application authenticating to a backend service',
    ],
    suspiciousCauses: [
      'Bulk TGS requests for many different SPNs in a short time → Kerberoasting',
      'Requests using RC4 encryption (0x17) instead of AES → weaker tickets, easier to crack',
      'Ticket requested by a user who does not normally access that service',
    ],
    recommendedChecks: [
      'How many TGS requests from this account in this window?',
      'What encryption type? RC4 (0x17) is suspicious in modern environments',
      'Which services were targeted — are they service accounts with weak passwords?',
      'Correlate with 4624 on the same source machine',
    ],
    relatedEvents: ['4768', '4771', '4770'],
    category: 'kerberos',
    defaultSeverity: 'medium',
  },

  '4771': {
    title: 'Kerberos Pre-Authentication Failed',
    summary: 'Kerberos pre-authentication failed — the wrong password was used for a Kerberos logon.',
    whyItMatters:
      'Similar to 4625 but specific to Kerberos. Bulk failures for many accounts indicate password spraying. Failures against specific accounts indicate targeted brute force or password testing.',
    benignCauses: [
      'User mistyped password during Kerberos logon',
      'Stale cached Kerberos credentials in an application',
    ],
    suspiciousCauses: [
      'Many accounts failing in a short window → Password Spray',
      'Single account failing many times → Brute Force',
      'Failure code 0x18 (wrong password) from external IP',
    ],
    recommendedChecks: [
      'Failure code 0x18 = wrong password (targeted), 0x6 = user not found (enumeration)',
      'Volume and pattern — single account or many accounts?',
      'Source IP and workstation',
      'Check for successful 4768 or 4624 after the failures',
    ],
    relatedEvents: ['4768', '4625', '4740', '4776'],
    category: 'kerberos',
    defaultSeverity: 'medium',
  },

  '4776': {
    title: 'NTLM Credential Validation',
    summary: 'The domain controller attempted to validate NTLM credentials for an account.',
    whyItMatters:
      'NTLM authentication is weaker than Kerberos and a common target for pass-the-hash, relay attacks (NTLM relay), and credential stuffing. Failed bulk NTLM validations indicate spraying or pass-the-hash attempts.',
    benignCauses: [
      'Applications and older services still using NTLM authentication',
      'Workgroup machines authenticating to a DC',
      'Legacy systems that cannot use Kerberos',
    ],
    suspiciousCauses: [
      'Bulk NTLM failures for many accounts → Password Spray',
      'NTLM from a domain machine when Kerberos should be used → Pass-the-Hash',
      'NTLM relay attack setting up a man-in-the-middle',
    ],
    recommendedChecks: [
      'Error code 0xC000006A = bad password; 0xC0000064 = no such user',
      'Source workstation — does it match expected machines?',
      'Volume of failures — single account or many?',
      'Consider whether NTLM should be restricted in your environment',
    ],
    relatedEvents: ['4625', '4624', '4771', '4768'],
    category: 'kerberos',
    defaultSeverity: 'medium',
  },

  '4781': {
    title: 'Account Renamed',
    summary: 'An account name was changed.',
    whyItMatters:
      'Renaming accounts — especially privileged accounts like Administrator — is a common technique to hide malicious accounts or confuse defenders. Attackers may also rename a newly created backdoor account to appear legitimate.',
    benignCauses: [
      'IT renaming the built-in Administrator account for security hardening',
      'Employee name change requiring account update',
    ],
    suspiciousCauses: [
      'Built-in account renamed to something non-obvious (hiding privileges)',
      'Newly created account renamed to resemble a system account',
      'Rename performed by a non-standard admin account',
    ],
    recommendedChecks: [
      'What was the old name and new name?',
      'Was this the built-in Administrator (SID ending in -500)?',
      'Who performed the rename?',
      'Is the new name plausible or suspicious?',
    ],
    relatedEvents: ['4720', '4738', '4728'],
    category: 'account-management',
    defaultSeverity: 'medium',
  },

  '4798': {
    title: 'Local Group Membership Enumerated',
    summary: "A user's local group membership was enumerated.",
    whyItMatters:
      'Enumerating local group memberships is a standard reconnaissance step. Tools like BloodHound and net.exe trigger this event to map privilege paths before escalation.',
    benignCauses: [
      'IT admin checking local group members via management tools',
      'Security tools performing compliance scans',
    ],
    suspiciousCauses: [
      'Enumeration by a non-admin user account',
      'Rapid enumeration of many accounts or groups',
      'Enumeration from a workstation that does not usually perform admin tasks',
      'BloodHound or other AD reconnaissance tools',
    ],
    recommendedChecks: [
      'Who is querying? Standard user accounts should not do this',
      'Is this a single query or bulk enumeration?',
      'Does the timing correlate with other reconnaissance events?',
      'Check for LDAP queries and 4799 events from the same source',
    ],
    relatedEvents: ['4799', '4728', '4732', '4624'],
    category: 'account-management',
    defaultSeverity: 'medium',
  },

  '5140': {
    title: 'Network Share Accessed',
    summary: 'A network share object was accessed.',
    whyItMatters:
      'Ransomware and data exfiltration attacks heavily target network shares. Accessing ADMIN$, IPC$, or C$ shares remotely is a primary indicator of lateral movement.',
    benignCauses: [
      'Users accessing file shares for work',
      'Backup agents accessing file shares',
      'IT management via admin shares (ADMIN$, C$)',
    ],
    suspiciousCauses: [
      'Access to ADMIN$, C$, or IPC$ from a workstation → lateral movement',
      'Mass enumeration of shares across many hosts',
      'Access to shares containing sensitive data by a non-authorized account',
      'Ransomware spreading to network shares',
    ],
    recommendedChecks: [
      'Which share was accessed? (ADMIN$, C$, IPC$ are critical)',
      'Source account and machine — is this expected access?',
      'Is this a single access or bulk access across many machines?',
      'Correlate with 4688 for spawned processes (e.g., PsExec)',
    ],
    relatedEvents: ['5145', '4624', '4648', '4688'],
    category: 'object-access',
    defaultSeverity: 'medium',
  },

  '5145': {
    title: 'Network Share Access Check',
    summary: 'A network share access check was performed — whether access was granted or denied.',
    whyItMatters:
      'This is a more granular version of 5140. High volumes of 5145 events can indicate share enumeration, ransomware spreading across the network, or DLP bypass attempts.',
    benignCauses: [
      'Normal file access through a mapped drive',
      'Backup agent scanning share contents',
    ],
    suspiciousCauses: [
      'Bulk access checks against many files → ransomware or exfiltration',
      'Access denied events in volume → unauthorized user probing shares',
      'Access from a machine that does not normally connect to these shares',
    ],
    recommendedChecks: [
      'Volume — how many access checks in the window?',
      'Which share and path — sensitive data location?',
      'Access granted or denied?',
      'Source machine and account',
    ],
    relatedEvents: ['5140', '4624', '4688'],
    category: 'object-access',
    defaultSeverity: 'low',
  },

  '5156': {
    title: 'WFP Allowed Connection',
    summary: 'The Windows Filtering Platform (WFP) allowed a network connection.',
    whyItMatters:
      'Malware beaconing to C2 servers, lateral movement over SMB/RPC, and data exfiltration all appear as allowed connections. Unexpected outbound connections from servers or processes that should not be network-active are critical indicators.',
    benignCauses: [
      'Normal application making outbound connections',
      'Windows Update, telemetry, or sync services',
      'Antivirus cloud lookups',
    ],
    suspiciousCauses: [
      'Outbound connections from cmd.exe, powershell.exe, or svchost.exe to external IPs',
      'Connections on unusual ports (non-standard C2: 4444, 8080, 8443)',
      'Lateral movement connections on SMB port 445',
      'Process that should not be network-active making connections',
    ],
    recommendedChecks: [
      'Which process is making the connection?',
      'Destination IP — is it internal, external, or in a known-bad list?',
      'Destination port — is it standard for the application?',
      'Correlate with 4688 to find when the process was created',
    ],
    relatedEvents: ['5157', '4688', '4624'],
    category: 'network',
    defaultSeverity: 'low',
  },

  '5157': {
    title: 'WFP Blocked Connection',
    summary: 'The Windows Filtering Platform (WFP) blocked a network connection.',
    whyItMatters:
      'Blocked connections can reveal malware attempting to reach C2 servers, or lateral movement that was prevented by the firewall. A spike in blocked connections from a single host is a strong indicator of compromise.',
    benignCauses: [
      'Application misconfiguration trying to connect to an unavailable server',
      'Firewall rule change that now blocks previously allowed traffic',
    ],
    suspiciousCauses: [
      'Malware beacon blocked by endpoint firewall',
      'Lateral movement attempt blocked by host-based firewall',
      'Bulk blocked connections from one host → compromised machine trying to spread',
    ],
    recommendedChecks: [
      'Source process — what is trying to connect?',
      'Destination IP and port — known malicious? Unusual?',
      'Is this one event or a pattern of attempts?',
      'Correlate with 4688 to identify the process origin',
    ],
    relatedEvents: ['5156', '4688'],
    category: 'network',
    defaultSeverity: 'medium',
  },

  '5379': {
    title: 'Credential Manager Read',
    summary: 'Credential Manager credentials were read.',
    whyItMatters:
      'Credential Manager stores saved passwords for RDP, websites, and applications. Malware and credential dumpers like Mimikatz read these credentials to escalate or move laterally.',
    benignCauses: [
      'User or application using saved credentials from Credential Manager',
      'Windows automatic sign-in using saved credentials',
    ],
    suspiciousCauses: [
      'Credential read by a process that should not access credentials (cmd, powershell)',
      'Credential read followed by logon to a new system',
      'Mimikatz or similar tool extracting stored credentials',
    ],
    recommendedChecks: [
      'Which process read the credentials?',
      'Which credential was accessed (which target)?',
      'Is there a subsequent 4624 or 4648 from a new location?',
    ],
    relatedEvents: ['4648', '4624', '4672'],
    category: 'credential',
    defaultSeverity: 'high',
  },

  '7045': {
    title: 'New Service Installed',
    summary: 'A new service was installed on the system (from the System event log).',
    whyItMatters:
      'Service installation from the Application/System log (7045) is one of the most reliable indicators of malware persistence and lateral movement. PsExec, Cobalt Strike, and many ransomware families install services.',
    benignCauses: [
      'Software installer creating a required service',
      'Windows Update installing a driver service',
      'IT deployment tool deploying a service',
    ],
    suspiciousCauses: [
      'Service with a random or short name',
      'Service binary in TEMP, Downloads, or non-standard paths',
      'Service created via PsExec from a remote host',
      'Service running as SYSTEM without an obvious need',
      'Cobalt Strike or Metasploit service names (often random)',
    ],
    recommendedChecks: [
      'Service binary path — signed? In a standard location?',
      'Service name — meaningful or random characters?',
      'Who installed it? From which account?',
      'Check the file hash against threat intelligence',
      'Look for 4688 and 4624 events around the same time',
    ],
    relatedEvents: ['4697', '4688', '4624', '4648'],
    category: 'service',
    defaultSeverity: 'high',
  },

  '1102': {
    title: 'Audit Log Cleared',
    summary: 'The Windows Security audit log was cleared.',
    whyItMatters:
      'Clearing the security log is the single most obvious sign of an attacker trying to cover their tracks. In a well-managed environment, this should almost never happen without a documented reason.',
    benignCauses: [
      'Authorized security audit by IT/security team',
      'Log management system clearing old logs (should use archiving instead)',
    ],
    suspiciousCauses: [
      'Log cleared after a period of suspicious activity',
      'Log cleared by an account that is not a SIEM or log management account',
      'Log cleared multiple times',
      'Combined with 517 (legacy: log cleared) on older systems',
    ],
    recommendedChecks: [
      'Who cleared the log? Which account?',
      'What events happened immediately before the clear (preserved in SIEM)?',
      'Is this a recurring pattern or a one-time event?',
      'Treat as a critical incident until proven benign',
    ],
    relatedEvents: ['517', '4719', '4907'],
    category: 'audit-policy',
    defaultSeverity: 'critical',
  },
};

/**
 * Returns full knowledge for an Event ID, or undefined if not in the knowledge base.
 */
export function getEventKnowledge(eventId: string | undefined): EventKnowledge | undefined {
  if (!eventId) return undefined;
  return EVENT_KNOWLEDGE[eventId];
}

/**
 * Returns a plain-text summary for an Event ID.
 * Falls back through: knowledge base → provided fallback → generic message.
 */
export function getEventSummary(eventId: string | undefined, fallback?: string): string {
  if (eventId && EVENT_KNOWLEDGE[eventId]) {
    return EVENT_KNOWLEDGE[eventId].summary;
  }
  return fallback ?? 'No explanation available for this Event ID. Use the Wazuh rule description and raw event data for analysis.';
}

/**
 * Category display labels for the inspector UI.
 */
export const CATEGORY_LABELS: Record<EventKnowledge['category'], string> = {
  authentication: 'Authentication',
  privilege: 'Privilege Use',
  process: 'Process Tracking',
  'account-management': 'Account Management',
  'audit-policy': 'Audit Policy',
  network: 'Network',
  service: 'Service / Persistence',
  'object-access': 'Object Access',
  credential: 'Credential Access',
  kerberos: 'Kerberos',
  'group-management': 'Group Management',
};
