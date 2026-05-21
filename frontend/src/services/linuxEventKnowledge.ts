/**
 * Linux Event Knowledge Base  v0.1
 * ==================================
 * TypeScript mirror of backend/knowledge/linux_event_knowledge.py.
 *
 * Events are identified by semantic keys in the format:
 *   linux.<subsystem>.<event_type>
 *
 * v0.1 covers
 * -----------
 *  SSH authentication (sshd)
 *  sudo privilege escalation
 *  Local login (PAM / login)
 *  Cron job execution
 *  Package management (apt / dpkg / yum / dnf)
 *  Kernel oops / panic
 *  UFW / firewall blocks
 *  Wazuh FIM file modifications
 *
 * TODO v0.2
 * ---------
 *  auditd EXECVE / USER_LOGIN
 *  systemd unit lifecycle events
 *  authorized_keys modified
 *  sudoers / passwd / shadow modified (via auditd)
 *  cron job created / modified / deleted
 *  kernel module loaded / unloaded
 *  OOM killer / segfault
 *  iptables / nftables rule changes
 *  new listening port detected
 */

export type LinuxEventCategory =
  | 'authentication'
  | 'privilege'
  | 'persistence'
  | 'system'
  | 'system-health'
  | 'network'
  | 'file-integrity'
  | 'unknown';

export type KnowledgeLevel = 'deep' | 'pattern' | 'basic' | 'generic' | 'unknown';

export interface LinuxEventKnowledge {
  /** Canonical key, e.g. "linux.ssh.login_failure" */
  key: string;
  /** Log source path or subsystem */
  source: string | null;
  /** Process / program name */
  program: string | null;
  /** Short human-readable event title */
  title: string;
  category: LinuxEventCategory;
  /** Baseline severity when no Wazuh rule overrides it */
  defaultSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** One-sentence description */
  summary: string;
  whatTriggersIt: string[];
  examplePatterns: string[];
  importantFields: string[];
  fieldInterpretation: Record<string, string>;
  commonBenignCauses: string[];
  suspiciousCauses: string[];
  highSignalPatterns: string[];
  relatedEvents: string[];
  recommendedChecks: string[];
  escalationConditions: string[];
  baselineConditions: string[];
  falsePositiveNotes: string[];
  references: string[];
  knowledgeLevel: KnowledgeLevel;
}

// ---------------------------------------------------------------------------
// Legacy key normaliser
// ---------------------------------------------------------------------------
const LEGACY_KEY_MAP: Record<string, string> = {
  ssh_failed_login:      'linux.ssh.login_failure',
  ssh_successful_login:  'linux.ssh.login_success',
  console_login_success: 'linux.local.login_success',
  sudo_command:          'linux.sudo.command',
  sudo_failed:           'linux.sudo.command_failure',
  cron_job:              'linux.cron.execution',
  package_installed:     'linux.package.installed',
  package_removed:       'linux.package.removed',
  kernel_oops:           'linux.kernel.oops',
  kernel_panic:          'linux.kernel.panic',
  ufw_block:             'linux.firewall.ufw_block',
  fim_modified:          'linux.fim.file_modified',
};

// ---------------------------------------------------------------------------
// Sensitive FIM paths — used by the resolver to escalate severity
// ---------------------------------------------------------------------------
export const SENSITIVE_FIM_PATHS: readonly string[] = [
  '/etc/passwd',
  '/etc/shadow',
  '/etc/sudoers',
  '/etc/sudoers.d/',
  '/etc/ssh/authorized_keys',
  '/root/.ssh/authorized_keys',
  '/home/',
  '/etc/systemd/system/',
  '/etc/cron.d/',
  '/etc/crontab',
  '/var/spool/cron/',
];

// ---------------------------------------------------------------------------
// Knowledge base
// ---------------------------------------------------------------------------
export const LINUX_EVENT_KNOWLEDGE: Record<string, LinuxEventKnowledge> = {

  'linux.ssh.login_failure': {
    key: 'linux.ssh.login_failure',
    source: '/var/log/auth.log',
    program: 'sshd',
    title: 'SSH Failed Login',
    category: 'authentication',
    defaultSeverity: 'medium',
    summary: 'An SSH login attempt failed due to bad credentials, an invalid username, or a key mismatch.',
    whatTriggersIt: [
      'User typed wrong password',
      'SSH key not accepted by server',
      'Login attempt for a non-existent username',
      'Login attempt for a disabled or locked account',
      'Brute-force or password-spray automation',
    ],
    examplePatterns: [
      'Failed password for root from 1.2.3.4 port 45182 ssh2',
      'Failed password for invalid user admin from 5.6.7.8 port 12345 ssh2',
      'Invalid user test from 9.10.11.12 port 22222',
    ],
    importantFields: ['user', 'src_ip', 'src_port', 'auth_method'],
    fieldInterpretation: {
      user: "'root', 'admin', 'guest' are high-signal if this host uses key-only auth",
      src_ip: 'Source IP of the attacker or misconfigured client',
      src_port: 'Ephemeral port from the client — changes each attempt',
      auth_method: 'password / publickey / gssapi — password attempts are higher risk',
    },
    commonBenignCauses: [
      'Developer mistyped their password',
      'Old SSH key on a laptop that no longer matches',
      'Automated monitoring or backup script with stale credentials',
      'Legitimate user connecting to wrong server',
    ],
    suspiciousCauses: [
      'Rapid succession of failures from the same IP (brute-force)',
      'Failures from multiple IPs targeting the same username (spray)',
      "Failures for 'root' when root login is disabled",
      'Failures for generic usernames: admin, pi, ubuntu, test',
      'Failure followed immediately by success from same IP',
      'Failures from known-bad ASN or Tor exit node',
    ],
    highSignalPatterns: [
      '10+ failures in < 60 seconds from same source IP',
      "Failures for 'root' when PermitRootLogin=no",
      'Failure then success from same IP within 5 minutes',
      'Failures sweeping username list: admin, root, guest, ubuntu, pi',
      'Failures from IP with prior block or known-bad reputation',
    ],
    relatedEvents: [
      'linux.ssh.login_success',
      'linux.local.login_success',
      'linux.firewall.ufw_block',
    ],
    recommendedChecks: [
      'Count failure frequency per source IP in the last 1h',
      'Check if failures are followed by a successful login (same IP or user)',
      'Look up source IP in threat intelligence (Shodan, AbuseIPDB)',
      'Review /etc/ssh/sshd_config: PermitRootLogin, PasswordAuthentication',
      'Check if the target user account is valid and active',
      'Review fail2ban / ufw logs to see if IP was already blocked',
    ],
    escalationConditions: [
      'Failed login immediately followed by successful login from same IP',
      'More than 20 failures per minute from same source',
      'Target username is a privileged service account',
      'Source IP is an internal host (lateral movement indicator)',
    ],
    baselineConditions: [
      '1–5 isolated failures per day per user with no subsequent success',
      'Failures from known developer IPs with a legacy key',
    ],
    falsePositiveNotes: [
      'CI/CD pipelines may retry SSH connections and trigger false alarms',
      'Ansible/Puppet with rotating keys may cause transient failures',
    ],
    references: [
      'https://man.openbsd.org/sshd_config.5',
      'https://attack.mitre.org/techniques/T1110/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.ssh.login_success': {
    key: 'linux.ssh.login_success',
    source: '/var/log/auth.log',
    program: 'sshd',
    title: 'SSH Successful Login',
    category: 'authentication',
    defaultSeverity: 'info',
    summary: 'An SSH login was accepted using password or public key authentication.',
    whatTriggersIt: [
      'Valid credentials (password or key) accepted by sshd',
      'Successful PAM authentication chain completion',
    ],
    examplePatterns: [
      'Accepted password for colin from 192.168.1.10 port 55234 ssh2',
      'Accepted publickey for deploy from 10.0.0.5 port 41122 ssh2: RSA SHA256:...',
    ],
    importantFields: ['user', 'src_ip', 'src_port', 'auth_method', 'key_fingerprint'],
    fieldInterpretation: {
      user: 'Authenticated username',
      src_ip: 'Source IP — compare to known baselines',
      auth_method: "'publickey' is generally safer than 'password'",
      key_fingerprint: 'For key auth — track fingerprints to detect new/unknown keys',
    },
    commonBenignCauses: [
      'Developer SSH-ing into server for routine work',
      'Automated deployment via CI/CD pipeline',
      'Monitoring agent connecting for health checks',
      'IT administrator remote session',
    ],
    suspiciousCauses: [
      'Login immediately after multiple failed login attempts',
      'Login from unusual geographic location or new IP',
      'Login from an internal host that should not access this server',
      'Login at unusual hours (late night / weekend for non-ops accounts)',
      'Login with password auth when only key auth should be configured',
      'Login for a service account that should never be interactive',
    ],
    highSignalPatterns: [
      'Success after 5+ failures from same source (brute-force succeeded)',
      'First-time login from new country or IP block',
      "Login for 'root' when direct root login should be disabled",
      'Login for a locked or disabled account',
    ],
    relatedEvents: [
      'linux.ssh.login_failure',
      'linux.sudo.command',
      'linux.local.login_success',
    ],
    recommendedChecks: [
      'Check if this IP/user combination has logged in before',
      'Review commands run after login (audit log / bash history)',
      'Check for sudo escalation events in the same session',
      'Verify auth_method: password login should alert if only keys are approved',
      'Review /var/log/auth.log for session open/close times',
    ],
    escalationConditions: [
      'Login preceded by 5+ failed attempts from same IP',
      'Login for root account directly',
      'Login from external IP followed by sudo escalation',
      'Login at off-hours for non-ops account',
    ],
    baselineConditions: [
      'Known developer IP, business hours, publickey auth',
      'Automated pipeline service account with fixed key fingerprint',
    ],
    falsePositiveNotes: [
      'Jump-host or bastion logins will show unusual source IPs — maintain allowlist',
    ],
    references: [
      'https://man.openbsd.org/sshd_config.5',
      'https://attack.mitre.org/techniques/T1078/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.local.login_success': {
    key: 'linux.local.login_success',
    source: '/var/log/auth.log',
    program: 'login',
    title: 'Local Console Login',
    category: 'authentication',
    defaultSeverity: 'low',
    summary: 'A user successfully logged in via local console or TTY.',
    whatTriggersIt: [
      'User logged in at physical console',
      'PAM-based authentication success for a local login session',
      'Virtual console (VTY) login on a server',
    ],
    examplePatterns: [
      'pam_unix(login:session): session opened for user colin by (uid=0)',
      'LOGIN on tty1 BY colin',
    ],
    importantFields: ['user', 'tty', 'uid'],
    fieldInterpretation: {
      user: 'Authenticated username',
      tty: 'Terminal device — tty1–tty6 are physical consoles',
      uid: 'UID of the login process — uid=0 means root authorised the session',
    },
    commonBenignCauses: [
      'IT admin working at physical console',
      'Server room access for maintenance',
      'Virtual KVM session during incident response',
    ],
    suspiciousCauses: [
      'Console login on a server that should never have direct logins',
      'Console login by non-admin user on a sensitive server',
      'Login at unusual hours, especially after a network incident',
    ],
    highSignalPatterns: [
      'Console login on a cloud VM (physical access to hypervisor indicated)',
      'Console login by root directly',
      'Console login immediately after failed SSH attempts',
    ],
    relatedEvents: ['linux.ssh.login_success', 'linux.sudo.command'],
    recommendedChecks: [
      'Confirm physical access authorisation',
      'Check if server has a physical console access policy',
      'Review subsequent commands in the session',
      'Check for any configuration changes made during the session',
    ],
    escalationConditions: [
      'Console login on cloud/virtual server',
      'Console login by root',
      'Console login by unknown user account',
    ],
    baselineConditions: ['Known admin account, documented maintenance window'],
    falsePositiveNotes: [
      'Headless servers in data centres rarely generate these — treat all as high priority',
    ],
    references: [
      'https://linux.die.net/man/8/login',
      'https://attack.mitre.org/techniques/T1078/003/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.sudo.command': {
    key: 'linux.sudo.command',
    source: '/var/log/auth.log',
    program: 'sudo',
    title: 'sudo Command Executed',
    category: 'privilege',
    defaultSeverity: 'medium',
    summary: 'A user successfully executed a command with elevated privileges using sudo.',
    whatTriggersIt: [
      'User ran a command prefixed with sudo',
      'sudo validated user password and sudoers permissions',
      'sudo session opened and command executed as target user (usually root)',
    ],
    examplePatterns: [
      'colin : TTY=pts/0 ; PWD=/home/colin ; USER=root ; COMMAND=/usr/bin/apt update',
      'deploy : TTY=pts/1 ; PWD=/opt/app ; USER=root ; COMMAND=/bin/systemctl restart nginx',
    ],
    importantFields: ['user', 'tty', 'pwd', 'target_user', 'command'],
    fieldInterpretation: {
      user: 'The user who ran sudo',
      tty: 'Terminal — pts/* means SSH session, tty* means console',
      pwd: 'Working directory when sudo was invoked',
      target_user: 'Target user (usually root)',
      command: 'Full command path and arguments — most important field',
    },
    commonBenignCauses: [
      'Administrator installing or updating packages',
      'Developer restarting a service for testing',
      'IT ops running a maintenance script',
      'Automated deployment pipeline using sudo for privilege',
    ],
    suspiciousCauses: [
      'sudo to spawn a shell: sudo bash, sudo su, sudo -i',
      'sudo of persistence tools: crontab, at, systemctl enable',
      'sudo to modify sensitive files: /etc/passwd, /etc/sudoers, authorized_keys',
      'sudo of network tools with unusual destinations: curl, wget, nc, ncat',
      'sudo by a user who should not have sudo rights',
      'sudo after SSH login from unusual source IP',
      'sudo to run interpreter: sudo python, sudo perl, sudo ruby',
    ],
    highSignalPatterns: [
      'COMMAND contains /bin/bash or /bin/sh (shell escalation)',
      'COMMAND contains chmod 777 on sensitive files',
      'COMMAND contains wget or curl piped to shell',
      'COMMAND modifies /etc/passwd, /etc/shadow, or /etc/sudoers',
      'COMMAND adds entry to crontab or /etc/cron.d/',
      'PWD is a temp directory (/tmp, /dev/shm)',
    ],
    relatedEvents: [
      'linux.sudo.command_failure',
      'linux.ssh.login_success',
      'linux.fim.file_modified',
      'linux.package.installed',
    ],
    recommendedChecks: [
      'Review full COMMAND field — especially arguments',
      'Check if PWD indicates unusual working directory (/tmp, /dev/shm)',
      'Verify user is authorised for this sudo command in /etc/sudoers',
      'Check if this command is part of a known deployment workflow',
      'Look for subsequent FIM events on sensitive files',
      'Review sudoers configuration for NOPASSWD entries',
    ],
    escalationConditions: [
      'COMMAND spawns an interactive shell (bash, sh, su)',
      'COMMAND modifies sudoers or PAM configuration',
      'COMMAND installs/removes systemd services',
      'User invokes sudo from /tmp or /dev/shm directory',
    ],
    baselineConditions: [
      'Known deployment user running expected service restart commands',
      'Admin running apt upgrade during maintenance window',
    ],
    falsePositiveNotes: [
      'Configuration management tools (Ansible, Puppet, Chef) generate many sudo events',
      'Package managers triggered by automated patch management create baseline volume',
    ],
    references: [
      'https://man.archlinux.org/man/sudo.8',
      'https://attack.mitre.org/techniques/T1548/003/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.sudo.command_failure': {
    key: 'linux.sudo.command_failure',
    source: '/var/log/auth.log',
    program: 'sudo',
    title: 'sudo Failed / Unauthorised',
    category: 'privilege',
    defaultSeverity: 'high',
    summary:
      'A sudo attempt was denied — wrong password, not in sudoers, or PAM authentication failure.',
    whatTriggersIt: [
      'User not listed in /etc/sudoers',
      'User entered wrong password for sudo',
      'Maximum sudo authentication attempts exceeded',
      'PAM policy blocked the sudo attempt',
    ],
    examplePatterns: [
      'colin : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/colin ; USER=root ; COMMAND=/usr/bin/id',
      'pam_unix(sudo:auth): authentication failure; logname=colin uid=1001 ...',
      '3 incorrect password attempts',
    ],
    importantFields: ['user', 'tty', 'command', 'reason'],
    fieldInterpretation: {
      user: 'User who attempted sudo',
      tty: 'Terminal source',
      command: 'Command that was attempted — important for intent analysis',
      reason: 'user NOT in sudoers / authentication failure / 3 incorrect password attempts',
    },
    commonBenignCauses: [
      "New employee forgot their account doesn't have sudo rights yet",
      'Developer trying a command on the wrong server',
      'Script misconfigured to use sudo on a non-privileged host',
    ],
    suspiciousCauses: [
      'Repeated sudo failures followed by a successful one (password guessing)',
      'Attempt to run high-risk command (bash, chmod, crontab) without authorisation',
      'Sudo failure from a user who has never attempted sudo before',
      'Multiple failures for different commands in rapid succession (probing)',
    ],
    highSignalPatterns: [
      'User NOT in sudoers + attempted COMMAND=/bin/bash',
      'Multiple sudo failures in the same session',
      "Sudo failure by a user who just SSH'd in from an unknown IP",
      'Failure for a command that would allow privilege escalation',
    ],
    relatedEvents: [
      'linux.sudo.command',
      'linux.ssh.login_success',
      'linux.ssh.login_failure',
    ],
    recommendedChecks: [
      'Verify user sudo authorisation in /etc/sudoers and /etc/sudoers.d/',
      'Check if user recently had sudo rights that were revoked',
      'Review full session context — what happened before and after',
      'Alert on repeated failures or unauthorised command attempts',
    ],
    escalationConditions: [
      '3+ sudo failures in same session',
      'Sudo failure for a shell command (bash, sh, su)',
      'Sudo failure by a user who should not have logged in at all',
    ],
    baselineConditions: ['Single failure by a new employee who forgot their rights'],
    falsePositiveNotes: [
      'Misconfigured automation scripts may trigger sudo failures in CI/CD',
    ],
    references: [
      'https://man.archlinux.org/man/sudo.8',
      'https://attack.mitre.org/techniques/T1548/003/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.cron.execution': {
    key: 'linux.cron.execution',
    source: '/var/log/syslog',
    program: 'cron',
    title: 'Cron Job Executed',
    category: 'persistence',
    defaultSeverity: 'info',
    summary: 'A scheduled cron job ran on the system.',
    whatTriggersIt: [
      'Cron daemon executed a scheduled task at the configured time',
      'User crontab entry triggered',
      'System cron job from /etc/cron.d/, /etc/crontab, or /etc/cron.*/ ran',
    ],
    examplePatterns: [
      'CRON[12345]: (root) CMD (/usr/bin/certbot renew --quiet)',
      'CRON[99887]: (colin) CMD (cd /home/colin && ./backup.sh > /dev/null 2>&1)',
    ],
    importantFields: ['user', 'command', 'cron_pid'],
    fieldInterpretation: {
      user: 'User under whose identity the cron job runs',
      command: 'The command or script executed — key for intent analysis',
      cron_pid: 'PID of the cron invocation',
    },
    commonBenignCauses: [
      'System maintenance tasks: log rotation, certificate renewal, backup',
      'Application health checks and cleanup jobs',
      'Developer personal crontab entries',
    ],
    suspiciousCauses: [
      'Cron job running a script from /tmp or /dev/shm',
      'Cron job running as root with a path not in system cron baseline',
      'New cron entry that appeared after an SSH login from an unknown IP',
      'Cron job that downloads and executes from an external URL',
      'Cron job for a user that should not have system-level cron access',
    ],
    highSignalPatterns: [
      'CMD contains /tmp/ or /dev/shm/ path',
      'CMD contains curl | bash or wget | sh patterns',
      'New root cron job not in deployment baseline',
      'Cron job for a non-service user on a server (lateral movement persistence)',
    ],
    relatedEvents: [
      'linux.sudo.command',
      'linux.fim.file_modified',
      'linux.package.installed',
    ],
    recommendedChecks: [
      'Review the command being executed and its source path',
      'Compare against known cron baseline for this host',
      'Check if the cron entry was recently added (FIM event on /etc/cron.d/)',
      'Verify script content at the execution path',
      'Look for network activity during or after cron execution',
    ],
    escalationConditions: [
      'CMD executes from /tmp or /dev/shm',
      'CMD contains network download-and-execute pattern',
      'New root cron job created after SSH login from unknown IP',
    ],
    baselineConditions: [
      'Standard system tasks: logrotate, certbot, backup scripts at expected times',
    ],
    falsePositiveNotes: [
      'Ansible-managed hosts will have many expected cron entries',
      'Monitoring tools (Datadog, Prometheus) may install cron-based checks',
    ],
    references: [
      'https://man7.org/linux/man-pages/man5/crontab.5.html',
      'https://attack.mitre.org/techniques/T1053/003/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.package.installed': {
    key: 'linux.package.installed',
    source: '/var/log/dpkg.log',
    program: 'dpkg',
    title: 'Package Installed',
    category: 'system',
    defaultSeverity: 'low',
    summary: 'A software package was installed or upgraded on the system.',
    whatTriggersIt: [
      'apt install / apt upgrade command',
      'dpkg -i package.deb direct installation',
      'Automated unattended-upgrades',
      'Ansible / Puppet / Chef package management',
    ],
    examplePatterns: [
      'install openssh-server:amd64 <none> 1:8.4p1-5',
      'Commandline: apt install nmap',
      'status installed curl:amd64 7.74.0-1.3+deb11u7',
    ],
    importantFields: ['package_name', 'version', 'action', 'user'],
    fieldInterpretation: {
      package_name: 'Installed package — network tools, compilers, RATs are high-signal',
      version: 'Package version installed',
      action: 'install / upgrade / reinstall',
      user: 'Who triggered the installation (correlate with sudo event)',
    },
    commonBenignCauses: [
      'System administrator installing required software',
      'Automated security patch via unattended-upgrades',
      'Developer installing dev tools on a workstation',
      'CI/CD pipeline installing build dependencies',
    ],
    suspiciousCauses: [
      'Installation of network scanning tools: nmap, masscan, zmap',
      'Installation of offensive tools: metasploit, sqlmap, hydra',
      'Installation of remote access tools: netcat, socat, ngrok',
      'Installation of tunnelling tools: chisel, frp, gost',
      'Package installation outside maintenance windows on production',
      'Package installed immediately after SSH login from unknown IP',
    ],
    highSignalPatterns: [
      'nmap, masscan, hydra, metasploit installed on production server',
      'netcat, ncat, socat installed with no prior baseline',
      'Package installed at 3 AM outside change window',
      'Package installed via direct dpkg -i (bypasses apt logging)',
      'Python, perl, ruby interpreter added to server with no development role',
    ],
    relatedEvents: [
      'linux.sudo.command',
      'linux.package.removed',
      'linux.fim.file_modified',
    ],
    recommendedChecks: [
      'Check package name against known offensive tools list',
      'Verify if this was part of an authorised change',
      'Look for preceding sudo events that authorised the installation',
      'Check for subsequent network activity (C2 communications)',
      'Review /var/log/dpkg.log and /var/log/apt/history.log for full context',
    ],
    escalationConditions: [
      'Offensive / reconnaissance tool installed on production server',
      'Package installed outside change management window',
      'Installation immediately after anomalous login',
    ],
    baselineConditions: [
      'Known package in unattended-upgrades security update set',
      'Deployment pipeline install of documented dependency',
    ],
    falsePositiveNotes: [
      'Ansible roles install many packages as part of configuration management',
      'Automated security updates may fire outside business hours',
    ],
    references: [
      'https://man7.org/linux/man-pages/man1/dpkg.1.html',
      'https://attack.mitre.org/techniques/T1072/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.package.removed': {
    key: 'linux.package.removed',
    source: '/var/log/dpkg.log',
    program: 'dpkg',
    title: 'Package Removed',
    category: 'system',
    defaultSeverity: 'low',
    summary: 'A software package was removed or purged from the system.',
    whatTriggersIt: [
      'apt remove / apt purge command',
      'dpkg --remove or --purge',
      'Automated cleanup',
    ],
    examplePatterns: [
      'remove nmap:amd64 7.80+dfsg1-2build1 <none>',
      'purge auditd:amd64 1:2.8.5-3ubuntu3 <none>',
    ],
    importantFields: ['package_name', 'version', 'action'],
    fieldInterpretation: {
      package_name: 'Removed package — security tools being removed is especially suspicious',
      version: 'Version that was removed',
      action: 'remove (leaves config) or purge (removes config too)',
    },
    commonBenignCauses: [
      'System cleanup removing unused packages',
      'Replacing one package version with another',
      'Security hardening removing unnecessary software',
    ],
    suspiciousCauses: [
      'Removal of security monitoring tools: auditd, wazuh-agent, ossec',
      'Removal of logging tools: rsyslog, syslog-ng',
      'Removal of intrusion detection tools',
      'Package removal immediately after malware/tool installation',
      'Covering tracks by removing command-line tools used for attack',
    ],
    highSignalPatterns: [
      'auditd, wazuh-agent, or ossec-hids removed',
      'rsyslog or syslog-ng removed (disabling logging)',
      'Removal immediately after install of the same tool (clean-up after use)',
    ],
    relatedEvents: [
      'linux.package.installed',
      'linux.sudo.command',
      'linux.fim.file_modified',
    ],
    recommendedChecks: [
      'Check if a security monitoring tool was removed',
      'Look for preceding install event for the same package',
      'Verify authorisation for the removal',
      'Check if logging continuity was maintained after removal',
    ],
    escalationConditions: [
      'auditd, wazuh-agent, or syslog removed',
      'Removal without corresponding change ticket',
      'Removal followed by suspicious network activity',
    ],
    baselineConditions: ['Package cleanup as part of documented decommission'],
    falsePositiveNotes: [
      'Package cleanup during OS upgrades may generate many removal events',
    ],
    references: [
      'https://man7.org/linux/man-pages/man1/dpkg.1.html',
      'https://attack.mitre.org/techniques/T1562/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.kernel.oops': {
    key: 'linux.kernel.oops',
    source: '/var/log/kern.log',
    program: 'kernel',
    title: 'Kernel Oops',
    category: 'system-health',
    defaultSeverity: 'high',
    summary:
      'The Linux kernel encountered a non-fatal error (oops) — a BUG condition or invalid memory access.',
    whatTriggersIt: [
      'Kernel encountered a NULL pointer dereference',
      'Out-of-bounds memory access in kernel or module',
      'Bug in a kernel module driver',
      'Hardware-induced memory error',
    ],
    examplePatterns: [
      'BUG: unable to handle page fault for address 0x0000000000000000',
      'Oops: general protection fault, maybe for address 0x18',
      'kernel BUG at mm/slab.c:123!',
    ],
    importantFields: ['fault_type', 'address', 'call_trace', 'module'],
    fieldInterpretation: {
      fault_type: 'Type of fault: page fault, GPF, BUG, etc.',
      address: 'Memory address that caused the fault',
      call_trace: 'Kernel stack trace — identifies the faulty code path',
      module: 'Kernel module involved if applicable',
    },
    commonBenignCauses: [
      'Buggy third-party kernel module (graphics, storage, network driver)',
      'Incompatible kernel version with a driver',
      'Hardware memory error (bad RAM)',
    ],
    suspiciousCauses: [
      'Kernel oops after loading an unsigned or unknown module',
      'Oops in network or USB subsystem after connecting unknown device',
      'Repeated oops targeting the same subsystem (potential exploit attempt)',
      'Oops after memory pressure from an unusual process',
    ],
    highSignalPatterns: [
      'Kernel oops immediately after new module loaded',
      'Repeated oops on same address (exploit attempt)',
      'Oops in security-critical subsystem: SELinux, seccomp, capabilities',
    ],
    relatedEvents: ['linux.kernel.panic'],
    recommendedChecks: [
      'Check call_trace for the faulty module or subsystem',
      'Review recently loaded kernel modules (lsmod)',
      'Check dmesg for preceding errors',
      'Verify kernel and module versions match',
      'Schedule hardware memory test if hardware error suspected',
    ],
    escalationConditions: [
      'Oops in security module (SELinux, AppArmor, seccomp)',
      'Oops targeting kernel exploit-known address patterns',
      'Multiple oops in short timeframe',
    ],
    baselineConditions: [
      'Single oops in known buggy driver version already patched in next update',
    ],
    falsePositiveNotes: [
      'Some cloud VMs with paravirtualised drivers may generate occasional oops',
    ],
    references: [
      'https://www.kernel.org/doc/html/latest/admin-guide/bug-hunting.html',
      'https://attack.mitre.org/techniques/T1068/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.kernel.panic': {
    key: 'linux.kernel.panic',
    source: '/var/log/kern.log',
    program: 'kernel',
    title: 'Kernel Panic',
    category: 'system-health',
    defaultSeverity: 'critical',
    summary: 'The Linux kernel encountered an unrecoverable fatal error and halted.',
    whatTriggersIt: [
      'Unrecoverable kernel error (kernel BUG + not syncing)',
      'Init process crash or failure to mount root filesystem',
      'Hardware failure (bad CPU, RAM, or disk)',
      'Kernel module causing unrecoverable crash',
      'Forced panic via sysrq or kernel module',
    ],
    examplePatterns: [
      'Kernel panic - not syncing: VFS: Unable to mount root fs',
      'Kernel panic - not syncing: Fatal exception in interrupt',
      'Kernel panic - not syncing: Out of memory and no killable processes...',
    ],
    importantFields: ['panic_reason', 'call_trace'],
    fieldInterpretation: {
      panic_reason: "The reason for the panic — 'not syncing' message indicates fatal",
      call_trace: 'Stack trace at point of panic',
    },
    commonBenignCauses: [
      'Hardware failure: failing RAM or disk',
      'Kernel upgrade with incompatible modules',
      'Storage failure preventing root filesystem access',
    ],
    suspiciousCauses: [
      'Kernel panic after loading unknown/suspicious module',
      'Repeated panics in short timeframe (DoS or exploit attempt)',
      'Panic after process with unusual memory behaviour ran',
    ],
    highSignalPatterns: [
      'Kernel panic after suspicious module load',
      'Multiple panics in 24h on same host',
      'Panic immediately following exploit-like process activity',
    ],
    relatedEvents: ['linux.kernel.oops'],
    recommendedChecks: [
      'Review kdump or crash dump if configured',
      'Check hardware health: SMART for disk, memtest for RAM',
      'Review dmesg output before panic for leading indicators',
      'Check recently installed kernel modules',
      'Verify kernel version integrity',
    ],
    escalationConditions: [
      'Multiple panics in same day',
      'Panic preceded by suspicious process activity',
      'Panic on a security-critical host',
    ],
    baselineConditions: ['Single panic during kernel/module upgrade (expected)'],
    falsePositiveNotes: ['Kernel panics are always serious — no routine false positives'],
    references: [
      'https://www.kernel.org/doc/html/latest/admin-guide/sysrq.html',
      'https://attack.mitre.org/techniques/T1499/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.firewall.ufw_block': {
    key: 'linux.firewall.ufw_block',
    source: '/var/log/ufw.log',
    program: 'kernel',
    title: 'UFW Blocked Packet',
    category: 'network',
    defaultSeverity: 'low',
    summary: 'UFW (Uncomplicated Firewall) blocked an inbound or outbound packet.',
    whatTriggersIt: [
      'Inbound connection attempt to a port not in the UFW allow rules',
      'Outbound connection blocked by UFW policy',
      'Port scan hitting closed/filtered ports',
    ],
    examplePatterns: [
      '[UFW BLOCK] IN=eth0 OUT= SRC=77.72.85.26 DST=157.230.26.180 PROTO=TCP SPT=42772 DPT=3194',
      '[UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.100 DST=192.168.1.1 PROTO=UDP SPT=68 DPT=67',
    ],
    importantFields: ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'interface'],
    fieldInterpretation: {
      src_ip: 'Source IP of blocked packet — external vs internal matters',
      dst_ip: "Destination IP — should be this host's IP",
      src_port: 'SPT= field — client ephemeral port',
      dst_port: 'DPT= field — targeted service port',
      protocol: 'PROTO= TCP / UDP / ICMP',
      interface: 'IN= network interface that received the packet',
    },
    commonBenignCauses: [
      'Internet noise: random port scans from bots',
      'Misconfigured service trying to connect to wrong port',
      'Network discovery tools in legitimate monitoring',
      'IoT device with hardcoded connection target',
    ],
    suspiciousCauses: [
      'Systematic port sweep from single IP (reconnaissance)',
      'Blocks targeting privileged ports: 22, 3306, 5432, 6379, 27017',
      'Blocks from internal IP (lateral movement attempt)',
      'High volume of blocks from single IP in short time',
      'Blocks on known C2 ports: 4444, 8080, 1337, 31337',
    ],
    highSignalPatterns: [
      'DPT=22 blocks from external IP (SSH brute-force blocked)',
      'DPT=3306 or DPT=5432 blocks (database exposure attempt)',
      'Blocks from internal host that should not be scanning (lateral movement)',
      'Rapid sequential DPT changes from same SRC (port scan)',
    ],
    relatedEvents: ['linux.ssh.login_failure', 'linux.ssh.login_success'],
    recommendedChecks: [
      'Check DPT (destination port) — is this a sensitive service port?',
      'Look up SRC IP in threat intelligence',
      'Check if this IP has matching SSH failure events',
      'Review block frequency: isolated vs sustained attack',
      'Verify UFW rules cover all expected service ports',
    ],
    escalationConditions: [
      'Block targeting DB ports (3306, 5432, 6379) from external IP',
      'Sustained sweep from single IP over > 5 minutes',
      'Block from internal host IP (lateral movement indicator)',
    ],
    baselineConditions: ['Random internet noise on common ports: 22, 80, 443, 8080'],
    falsePositiveNotes: [
      'Very high volume of UFW blocks is normal for internet-facing servers',
    ],
    references: [
      'https://manpages.ubuntu.com/manpages/focal/man8/ufw.8.html',
      'https://attack.mitre.org/techniques/T1046/',
    ],
    knowledgeLevel: 'deep',
  },

  'linux.fim.file_modified': {
    key: 'linux.fim.file_modified',
    source: 'wazuh-syscheck',
    program: 'wazuh-agent',
    title: 'FIM: File Modified',
    category: 'file-integrity',
    defaultSeverity: 'medium',
    summary: 'Wazuh File Integrity Monitoring detected a modification to a monitored file.',
    whatTriggersIt: [
      'File content changed (hash mismatch vs baseline)',
      'File permissions or ownership changed',
      'File attributes (atime, mtime, inode) changed',
      'New file created in a monitored directory',
    ],
    examplePatterns: [
      "File '/etc/sudoers' has been modified",
      "File '/etc/passwd' checksum changed",
      "Integrity checksum changed for '/etc/ssh/sshd_config'",
    ],
    importantFields: ['file_path', 'old_hash', 'new_hash', 'permissions', 'owner', 'group'],
    fieldInterpretation: {
      file_path: 'Path of the changed file — sensitive paths need immediate review',
      old_hash: 'SHA256 hash before change — baseline value',
      new_hash: 'SHA256 hash after change — compare against known-good',
      permissions: 'File permission change — world-writable is a red flag',
      owner: 'File owner change — uid 0 ownership on unexpected files',
      group: 'Group change — adding to privileged group',
    },
    commonBenignCauses: [
      'Legitimate package update modified system binaries',
      'Configuration change by admin',
      'Log rotation modifying log files',
      'Application updating its own config on startup',
    ],
    suspiciousCauses: [
      'Modification to /etc/passwd, /etc/shadow, /etc/sudoers',
      'Modification to /etc/ssh/sshd_config or authorized_keys',
      'New entry in /etc/cron.d/ or /var/spool/cron/',
      'Binary modification in /usr/bin/ or /usr/sbin/ (rootkit)',
      'New file in /etc/systemd/system/ (persistence)',
      'Modification outside package management or change window',
    ],
    highSignalPatterns: [
      'Modified: /etc/passwd or /etc/shadow (credential tampering)',
      'Modified: /etc/sudoers or /etc/sudoers.d/ (privilege escalation)',
      'Modified: /root/.ssh/authorized_keys or /home/*/.ssh/authorized_keys',
      'Modified: /etc/systemd/system/*.service (persistence)',
      'Modified: /etc/crontab or /etc/cron.d/* (persistence)',
      'Modified: /usr/bin/* or /usr/lib/* with no package change event',
    ],
    relatedEvents: [
      'linux.sudo.command',
      'linux.package.installed',
      'linux.ssh.login_success',
      'linux.cron.execution',
    ],
    recommendedChecks: [
      'Review the file path — is it in a sensitive location?',
      'Compare old vs new hash against known-good version',
      'Check for a preceding package update or admin login that authorised this',
      'If /etc/passwd or /etc/sudoers: review new entries immediately',
      'If authorized_keys: check the new key fingerprint',
      'If systemd unit or cron: review the service/task content',
    ],
    escalationConditions: [
      'Any change to /etc/passwd, /etc/shadow, /etc/sudoers',
      'New authorized_keys entry without accompanying user provisioning event',
      'New systemd unit or cron entry without change ticket',
      'Binary modified without package event (potential rootkit)',
    ],
    baselineConditions: [
      'Change coincides with documented apt upgrade or config management run',
      'Log file rotation in /var/log/',
    ],
    falsePositiveNotes: [
      'Package upgrades trigger many FIM events on /usr/bin/, /usr/lib/ — correlate with dpkg log',
      'Configuration management runs (Ansible) generate expected changes',
    ],
    references: [
      'https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html',
      'https://attack.mitre.org/techniques/T1565/',
    ],
    knowledgeLevel: 'deep',
  },
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/**
 * Normalise a legacy flat key or a namespaced key to the canonical form.
 *
 * @example
 * normalizeLinuxEventKey('ssh_failed_login')       // 'linux.ssh.login_failure'
 * normalizeLinuxEventKey('linux.ssh.login_failure') // 'linux.ssh.login_failure'
 */
export function normalizeLinuxEventKey(key: string): string {
  return LEGACY_KEY_MAP[key] ?? key;
}

/**
 * Return the full knowledge entry for a key, or undefined.
 * Accepts both legacy flat keys and namespaced keys.
 */
export function getLinuxEventKnowledge(key: string): LinuxEventKnowledge | undefined {
  return LINUX_EVENT_KNOWLEDGE[normalizeLinuxEventKey(key)];
}

/** Return the one-line summary for a key, or an empty string. */
export function getLinuxEventSummary(key: string): string {
  return getLinuxEventKnowledge(key)?.summary ?? '';
}

/** Return the recommendedChecks array for a key, or an empty array. */
export function getLinuxRecommendedChecks(key: string): string[] {
  return getLinuxEventKnowledge(key)?.recommendedChecks ?? [];
}

/** Return the relatedEvents array for a key, or an empty array. */
export function getLinuxRelatedEvents(key: string): string[] {
  return getLinuxEventKnowledge(key)?.relatedEvents ?? [];
}
