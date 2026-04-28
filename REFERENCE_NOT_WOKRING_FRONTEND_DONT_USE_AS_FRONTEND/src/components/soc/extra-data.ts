import type { Severity } from "./data";

// ── Baseline ─────────────────────────────────────────────────────────────────

export type DevState = "normal" | "unusual" | "abnormal";
export type DevKind = "process" | "user" | "service_name" | "network";

export interface BaselineProfile {
  id: string;
  name: string;
  hosts: number;
}

export interface BaselineItem {
  name: string;
  kind: DevKind;
  freq: string;
  lastSeen: string;
  score: number;
  state: DevState;
  host: string;
  type: string;
  detected: string;
  reason: string;
  confidence: number;
  details: Record<string, unknown>;
}

export const baselineProfiles: BaselineProfile[] = [
  { id: "customer_service", name: "Kundenservice", hosts: 14 },
  { id: "finance", name: "Finance", hosts: 8 },
  { id: "it_ops", name: "IT Operations", hosts: 5 },
];

export const baselineNormal: BaselineItem[] = [
  {
    name: "explorer.exe",
    kind: "process",
    freq: "high",
    lastSeen: "2m ago",
    score: 5,
    state: "normal",
    host: "KS_01_003",
    type: "known_process",
    detected: "2026-04-18T08:00:00+00:00",
    reason: "Standard Windows explorer process",
    confidence: 98,
    details: { count: 1, first_seen: "2026-04-18T08:00:00+00:00" },
  },
  {
    name: "chrome.exe",
    kind: "process",
    freq: "high",
    lastSeen: "1m ago",
    score: 5,
    state: "normal",
    host: "KS_01_003",
    type: "known_process",
    detected: "2026-04-18T08:00:00+00:00",
    reason: "Standard browser process",
    confidence: 97,
    details: { count: 3, first_seen: "2026-04-18T08:00:00+00:00" },
  },
  {
    name: "NT AUTHORITY\\SYSTEM",
    kind: "user",
    freq: "high",
    lastSeen: "1m ago",
    score: 5,
    state: "normal",
    host: "KS_01_003",
    type: "known_user",
    detected: "2026-04-18T08:00:00+00:00",
    reason: "System account – expected",
    confidence: 99,
    details: { count: 200, first_seen: "2026-04-18T08:00:00+00:00" },
  },
];

export const baselineDeviations: BaselineItem[] = [
  // ── Services (UNUSUAL) ───────────────────────────────────────────────────
  {
    name: "application",
    kind: "service_name",
    freq: "1866×",
    lastSeen: "2026-04-20T13:53:50+00:00",
    score: 65,
    state: "unusual",
    host: "KS_01_003",
    type: "new_service",
    detected: "2026-04-20T13:53:50+00:00",
    reason: "New service_name: application",
    confidence: 65,
    details: { count: 1866, first_seen: "2026-04-20T13:53:50+00:00" },
  },
  {
    name: "security",
    kind: "service_name",
    freq: "1741×",
    lastSeen: "2026-04-20T13:53:50+00:00",
    score: 65,
    state: "unusual",
    host: "KS_01_003",
    type: "new_service",
    detected: "2026-04-20T13:53:50+00:00",
    reason: "New service_name: security",
    confidence: 65,
    details: { count: 1741, first_seen: "2026-04-20T13:53:50+00:00" },
  },
  {
    name: "system",
    kind: "service_name",
    freq: "1522×",
    lastSeen: "2026-04-20T13:53:50+00:00",
    score: 65,
    state: "unusual",
    host: "KS_01_003",
    type: "new_service",
    detected: "2026-04-20T13:53:50+00:00",
    reason: "New service_name: system",
    confidence: 65,
    details: { count: 1522, first_seen: "2026-04-20T13:53:50+00:00" },
  },
  // ── Processes (UNUSUAL) ──────────────────────────────────────────────────
  {
    name: "c:\\windows\\system32\\lsass.exe",
    kind: "process",
    freq: "41×",
    lastSeen: "2026-04-20T14:00:00+00:00",
    score: 55,
    state: "unusual",
    host: "KS_01_003",
    type: "new_process",
    detected: "2026-04-20T14:00:00+00:00",
    reason: "New process not in baseline: lsass.exe",
    confidence: 60,
    details: { count: 41, first_seen: "2026-04-20T14:00:00+00:00" },
  },
  {
    name: "c:\\windows\\system32\\svchost.exe",
    kind: "process",
    freq: "61×",
    lastSeen: "2026-04-20T14:00:00+00:00",
    score: 50,
    state: "unusual",
    host: "KS_01_003",
    type: "new_process",
    detected: "2026-04-20T14:00:00+00:00",
    reason: "New process not in baseline: svchost.exe",
    confidence: 55,
    details: { count: 61, first_seen: "2026-04-20T14:00:00+00:00" },
  },
  {
    name: "c:\\windows\\system32\\winlogon.exe",
    kind: "process",
    freq: "22×",
    lastSeen: "2026-04-20T14:00:00+00:00",
    score: 50,
    state: "unusual",
    host: "KS_01_003",
    type: "new_process",
    detected: "2026-04-20T14:00:00+00:00",
    reason: "New process not in baseline: winlogon.exe",
    confidence: 55,
    details: { count: 22, first_seen: "2026-04-20T14:00:00+00:00" },
  },
  // ── Users (NORMAL deviation – newly seen, low risk) ──────────────────────
  {
    name: "ksuser",
    kind: "user",
    freq: "23×",
    lastSeen: "2026-04-20T14:01:00+00:00",
    score: 40,
    state: "normal",
    host: "KS_01_003",
    type: "new_user",
    detected: "2026-04-20T14:01:00+00:00",
    reason: "New user logon: ksuser",
    confidence: 40,
    details: { count: 23, first_seen: "2026-04-20T14:01:00+00:00" },
  },
  {
    name: "KS_01_003$",
    kind: "user",
    freq: "18×",
    lastSeen: "2026-04-20T14:01:00+00:00",
    score: 40,
    state: "normal",
    host: "KS_01_003",
    type: "new_user",
    detected: "2026-04-20T14:01:00+00:00",
    reason: "New user logon: KS_01_003$",
    confidence: 40,
    details: { count: 18, first_seen: "2026-04-20T14:01:00+00:00" },
  },
  {
    name: "KSUSER",
    kind: "user",
    freq: "12×",
    lastSeen: "2026-04-20T14:01:00+00:00",
    score: 40,
    state: "normal",
    host: "KS_01_003",
    type: "new_user",
    detected: "2026-04-20T14:01:00+00:00",
    reason: "New user logon: KSUSER",
    confidence: 40,
    details: { count: 12, first_seen: "2026-04-20T14:01:00+00:00" },
  },
  {
    name: "aznord",
    kind: "user",
    freq: "5×",
    lastSeen: "2026-04-20T14:01:00+00:00",
    score: 40,
    state: "normal",
    host: "KS_01_003",
    type: "new_user",
    detected: "2026-04-20T14:01:00+00:00",
    reason: "New user logon: aznord",
    confidence: 40,
    details: { count: 5, first_seen: "2026-04-20T14:01:00+00:00" },
  },
  {
    name: "aznord@arzw.local",
    kind: "user",
    freq: "3×",
    lastSeen: "2026-04-20T14:01:00+00:00",
    score: 40,
    state: "normal",
    host: "KS_01_003",
    type: "new_user",
    detected: "2026-04-20T14:01:00+00:00",
    reason: "New user logon: aznord@arzw.local",
    confidence: 40,
    details: { count: 3, first_seen: "2026-04-20T14:01:00+00:00" },
  },
];

// ── Investigation ─────────────────────────────────────────────────────────────

export type EventType = "process" | "network" | "auth" | "service" | "file" | "registry";

export interface InvEvent {
  ts: string;
  eid: string;
  type: EventType;
  severity: Severity;
  text: string;
  host: string;
  user?: string;
  process?: string;
  data: Record<string, string>;
}

export const investigationEvents: InvEvent[] = [
  {
    ts: "13:53:50",
    eid: "7045",
    type: "service",
    severity: "HIGH",
    text: "New service installed: application",
    host: "KS_01_003",
    user: "SYSTEM",
    data: {
      service_name: "application",
      service_type: "20",
      start_type: "2",
      image_path: "C:\\Windows\\System32\\svchost.exe",
    },
  },
  {
    ts: "13:53:51",
    eid: "7045",
    type: "service",
    severity: "HIGH",
    text: "New service installed: security",
    host: "KS_01_003",
    user: "SYSTEM",
    data: {
      service_name: "security",
      service_type: "20",
      start_type: "2",
      image_path: "C:\\Windows\\System32\\svchost.exe",
    },
  },
  {
    ts: "13:53:52",
    eid: "7045",
    type: "service",
    severity: "HIGH",
    text: "New service installed: system",
    host: "KS_01_003",
    user: "SYSTEM",
    data: {
      service_name: "system",
      service_type: "20",
      start_type: "2",
      image_path: "C:\\Windows\\System32\\svchost.exe",
    },
  },
  {
    ts: "14:00:12",
    eid: "4624",
    type: "auth",
    severity: "MEDIUM",
    text: "Successful logon – ksuser (type 3)",
    host: "KS_01_003",
    user: "ksuser",
    data: {
      logon_type:   "3",
      src_ip:       "172.21.4.38",
      workstation:  "KS_01_003",
    },
  },
  {
    ts: "14:00:14",
    eid: "4624",
    type: "auth",
    severity: "MEDIUM",
    text: "Successful logon – aznord (type 3)",
    host: "KS_01_003",
    user: "aznord",
    data: {
      logon_type:   "3",
      src_ip:       "172.21.4.38",
      workstation:  "KS_01_003",
    },
  },
  {
    ts: "14:00:20",
    eid: "4625",
    type: "auth",
    severity: "HIGH",
    text: "Failed logon attempt – aznord@arzw.local",
    host: "KS_01_003",
    user: "aznord@arzw.local",
    data: {
      logon_type:   "3",
      src_ip:       "172.21.4.38",
      failure_reason: "0xC000006D",
    },
  },
  {
    ts: "14:00:25",
    eid: "4672",
    type: "auth",
    severity: "MEDIUM",
    text: "Special privileges assigned – KSUSER",
    host: "KS_01_003",
    user: "KSUSER",
    data: {
      privileges: "SeDebugPrivilege, SeImpersonatePrivilege",
    },
  },
  {
    ts: "14:00:30",
    eid: "4688",
    type: "process",
    severity: "HIGH",
    text: "Process created: lsass.exe",
    host: "KS_01_003",
    user: "SYSTEM",
    process: "C:\\Windows\\System32\\lsass.exe",
    data: {
      image_path:    "C:\\Windows\\System32\\lsass.exe",
      parent_image:  "C:\\Windows\\System32\\wininit.exe",
      command_line:  "C:\\Windows\\system32\\lsass.exe",
    },
  },
  {
    ts: "14:00:32",
    eid: "4688",
    type: "process",
    severity: "MEDIUM",
    text: "Process created: svchost.exe",
    host: "KS_01_003",
    user: "SYSTEM",
    process: "C:\\Windows\\System32\\svchost.exe",
    data: {
      image_path:    "C:\\Windows\\System32\\svchost.exe",
      parent_image:  "C:\\Windows\\System32\\services.exe",
      command_line:  "C:\\Windows\\system32\\svchost.exe -k netsvcs",
    },
  },
  {
    ts: "14:01:05",
    eid: "3",
    type: "network",
    severity: "MEDIUM",
    text: "Network connection to 172.21.4.38:445",
    host: "KS_01_003",
    user: "SYSTEM",
    process: "C:\\Windows\\System32\\lsass.exe",
    data: {
      dst_ip:    "172.21.4.38",
      dst_port:  "445",
      protocol:  "tcp",
      src_ip:    "127.0.0.1",
    },
  },
  {
    ts: "14:02:10",
    eid: "7031",
    type: "service",
    severity: "CRITICAL",
    text: "Service terminated unexpectedly: application",
    host: "KS_01_003",
    data: {
      service_name:  "application",
      exit_code:     "1067",
      restart_count: "1",
    },
  },
  {
    ts: "14:03:00",
    eid: "1001",
    type: "service",
    severity: "HIGH",
    text: "Windows Error Reporting – application crash",
    host: "KS_01_003",
    data: {
      fault_bucket:    "1234567890",
      event_name:      "APPCRASH",
      faulting_module: "ntdll.dll",
    },
  },
  // Additional hosts for investigation pivot tests
  {
    ts: "09:42:09",
    eid: "4688",
    type: "process",
    severity: "CRITICAL",
    text: "powershell.exe spawned by svchost.exe",
    host: "BANK_12_01",
    user: "NT AUTHORITY\\SYSTEM",
    process: "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    data: {
      image_path:    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      parent_image:  "C:\\Windows\\System32\\svchost.exe",
      command_line:  "powershell.exe -nop -w hidden -enc JABF...",
    },
  },
  {
    ts: "09:42:11",
    eid: "7045",
    type: "service",
    severity: "CRITICAL",
    text: "New service registered: WinUpdSvc",
    host: "BANK_12_01",
    user: "NT AUTHORITY\\SYSTEM",
    data: {
      service_name: "WinUpdSvc",
      image_path:   "C:\\ProgramData\\svc_upd.exe",
    },
  },
  {
    ts: "09:38:02",
    eid: "10",
    type: "process",
    severity: "CRITICAL",
    text: "ProcessAccess on lsass.exe – 0x1010",
    host: "RZ_MANU2",
    user: "DOMAIN\\j.weber",
    process: "rundll32.exe",
    data: {
      target_image:  "C:\\Windows\\System32\\lsass.exe",
      granted_access: "0x1010",
      source_image:   "C:\\Windows\\System32\\rundll32.exe",
    },
  },
  {
    ts: "09:33:47",
    eid: "4624",
    type: "auth",
    severity: "HIGH",
    text: "Successful logon after 23 failures – admin.svc",
    host: "DC01",
    user: "DOMAIN\\admin.svc",
    data: {
      logon_type: "3",
      src_ip:     "10.20.4.11",
      auth_package: "NTLM",
    },
  },
  {
    ts: "09:26:10",
    eid: "3",
    type: "network",
    severity: "HIGH",
    text: "TLS connection to 185.244.25.74:443 (C2 TI match)",
    host: "WS-FIN-204",
    user: "DOMAIN\\m.koehler",
    process: "chrome.exe",
    data: {
      dst_ip:   "185.244.25.74",
      dst_port: "443",
      protocol: "tcp",
      ti_feed:  "apt-ops-2025",
    },
  },
];

// ── Hosts ─────────────────────────────────────────────────────────────────────

export type HostStatus = "ONLINE" | "OFFLINE" | "ISOLATED" | "STALE";

export interface Host {
  name: string;
  ip: string;
  os: string;
  status: HostStatus;
  risk: number;
  lastSeen: string;
  alerts: number;
  tags: string[];
  profile: string;
}

export const hosts: Host[] = [
  {
    name: "KS_01_003",
    ip: "172.21.4.38",
    os: "Windows 10 22H2",
    status: "ONLINE",
    risk: 100,
    lastSeen: "1m ago",
    alerts: 250,
    tags: ["customer_service", "high-risk", "fullscan"],
    profile: "Kundenservice",
  },
  {
    name: "BANK_12_01",
    ip: "10.10.12.1",
    os: "Windows Server 2022",
    status: "ONLINE",
    risk: 88,
    lastSeen: "2m ago",
    alerts: 487,
    tags: ["finance", "critical", "server"],
    profile: "Finance",
  },
  {
    name: "RZ_MANU2",
    ip: "10.20.2.42",
    os: "Windows Server 2019",
    status: "ISOLATED",
    risk: 92,
    lastSeen: "5m ago",
    alerts: 1003,
    tags: ["manufacturing", "isolated", "incident"],
    profile: "Production",
  },
  {
    name: "DC01",
    ip: "10.0.0.1",
    os: "Windows Server 2022",
    status: "ONLINE",
    risk: 71,
    lastSeen: "1m ago",
    alerts: 214,
    tags: ["domain-controller", "critical"],
    profile: "IT Operations",
  },
  {
    name: "WS-FIN-204",
    ip: "10.10.4.204",
    os: "Windows 11 23H2",
    status: "ONLINE",
    risk: 64,
    lastSeen: "3m ago",
    alerts: 96,
    tags: ["finance", "workstation"],
    profile: "Finance",
  },
  {
    name: "WS-DEV-09",
    ip: "10.30.0.9",
    os: "Windows 11 23H2",
    status: "ONLINE",
    risk: 38,
    lastSeen: "10m ago",
    alerts: 41,
    tags: ["dev", "workstation"],
    profile: "Development",
  },
  {
    name: "SRV-FILE-01",
    ip: "10.0.1.10",
    os: "Windows Server 2019",
    status: "STALE",
    risk: 25,
    lastSeen: "2h ago",
    alerts: 12,
    tags: ["file-server", "stale"],
    profile: "IT Operations",
  },
  {
    name: "SRV-PRINT-02",
    ip: "10.0.1.12",
    os: "Windows Server 2016",
    status: "OFFLINE",
    risk: 10,
    lastSeen: "1d ago",
    alerts: 0,
    tags: ["print", "offline"],
    profile: "IT Operations",
  },
  {
    name: "WS-HR-101",
    ip: "10.10.1.101",
    os: "Windows 10 22H2",
    status: "ONLINE",
    risk: 20,
    lastSeen: "4m ago",
    alerts: 8,
    tags: ["hr", "workstation"],
    profile: "HR",
  },
  {
    name: "WS-HR-102",
    ip: "10.10.1.102",
    os: "Windows 10 22H2",
    status: "ONLINE",
    risk: 18,
    lastSeen: "6m ago",
    alerts: 5,
    tags: ["hr", "workstation"],
    profile: "HR",
  },
  {
    name: "WS-SALES-07",
    ip: "10.10.3.7",
    os: "Windows 11 22H2",
    status: "ONLINE",
    risk: 15,
    lastSeen: "8m ago",
    alerts: 3,
    tags: ["sales", "workstation"],
    profile: "Vertrieb",
  },
  {
    name: "WS-SALES-08",
    ip: "10.10.3.8",
    os: "Windows 11 22H2",
    status: "STALE",
    risk: 12,
    lastSeen: "45m ago",
    alerts: 2,
    tags: ["sales", "workstation"],
    profile: "Vertrieb",
  },
];
