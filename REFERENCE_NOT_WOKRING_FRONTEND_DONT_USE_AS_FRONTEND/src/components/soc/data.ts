export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "CONTAINED" | "CLOSED";

export interface Incident {
  id: string;
  severity: Severity;
  title: string;
  host: string;
  eventId: string;
  source: string;
  user?: string;
  process?: string;
  time: string; // relative
  ts: string; // absolute
  status: IncidentStatus;
  mitre: string[];
  tags: string[];
  description: string;
  related: { ts: string; eid: string; text: string }[];
  timeline: { ts: string; type: "detect" | "enrich" | "action"; text: string }[];
}

export const incidents: Incident[] = [
  {
    id: "INC-10481",
    severity: "CRITICAL",
    title: "New Windows Service Created (suspicious binary)",
    host: "BANK_12_01",
    eventId: "7045",
    source: "Windows/System",
    user: "NT AUTHORITY\\SYSTEM",
    process: "C:\\ProgramData\\svc_upd.exe",
    time: "2 min ago",
    ts: "2025-04-17 09:42:11",
    status: "OPEN",
    mitre: ["T1543.003", "T1059.001"],
    tags: ["persistence", "unsigned-binary", "rare-path"],
    description: "Service 'WinUpdSvc' created from unsigned binary in ProgramData.",
    related: [
      { ts: "09:42:09", eid: "4688", text: "powershell.exe spawned by svchost.exe" },
      { ts: "09:42:10", eid: "4697", text: "Service installed: WinUpdSvc" },
      { ts: "09:42:11", eid: "7045", text: "New service WinUpdSvc registered" },
      { ts: "09:42:14", eid: "4624", text: "Logon type 5 — service start" },
    ],
    timeline: [
      { ts: "09:42:11", type: "detect", text: "Rule SOC-WIN-7045-RAREPATH triggered" },
      { ts: "09:42:13", type: "enrich", text: "Binary hash unknown to VT (0/72)" },
      { ts: "09:42:15", type: "enrich", text: "Host risk score 87 — top in fleet" },
    ],
  },
  {
    id: "INC-10480",
    severity: "CRITICAL",
    title: "LSASS memory access by non-system process",
    host: "RZ_MANU2",
    eventId: "10",
    source: "Sysmon",
    user: "DOMAIN\\j.weber",
    process: "rundll32.exe",
    time: "6 min ago",
    ts: "2025-04-17 09:38:02",
    status: "INVESTIGATING",
    mitre: ["T1003.001"],
    tags: ["credential-access", "lsass", "rundll32"],
    description: "rundll32 opened LSASS with PROCESS_VM_READ.",
    related: [
      { ts: "09:38:00", eid: "4688", text: "rundll32.exe started by explorer.exe" },
      { ts: "09:38:02", eid: "10", text: "ProcessAccess on lsass.exe granted 0x1010" },
    ],
    timeline: [
      { ts: "09:38:02", type: "detect", text: "Rule SOC-CRED-LSASS-READ triggered" },
      { ts: "09:38:30", type: "action", text: "Analyst opened investigation" },
    ],
  },
  {
    id: "INC-10479",
    severity: "HIGH",
    title: "Multiple failed logons followed by success",
    host: "DC01",
    eventId: "4625/4624",
    source: "Windows/Security",
    user: "DOMAIN\\admin.svc",
    time: "11 min ago",
    ts: "2025-04-17 09:33:47",
    status: "OPEN",
    mitre: ["T1110.001"],
    tags: ["brute-force", "domain-controller", "service-account"],
    description: "23 failed NTLM logons in 40s, then 1 successful from 10.20.4.11.",
    related: [
      { ts: "09:33:05", eid: "4625", text: "Failed logon × 23 (NTLM)" },
      { ts: "09:33:47", eid: "4624", text: "Successful logon — type 3" },
    ],
    timeline: [
      { ts: "09:33:47", type: "detect", text: "Rule SOC-AUTH-BRUTE-SUCCESS triggered" },
    ],
  },
  {
    id: "INC-10478",
    severity: "HIGH",
    title: "Outbound connection to known C2 infrastructure",
    host: "WS-FIN-204",
    eventId: "3",
    source: "Sysmon",
    user: "DOMAIN\\m.koehler",
    process: "chrome.exe",
    time: "18 min ago",
    ts: "2025-04-17 09:26:10",
    status: "OPEN",
    mitre: ["T1071.001"],
    tags: ["c2", "network", "ti-match"],
    description: "TLS connection to 185.244.x.x — TI feed: APT-LIKE-OPS.",
    related: [
      { ts: "09:26:10", eid: "3", text: "Network connect 185.244.25.74:443" },
    ],
    timeline: [
      { ts: "09:26:10", type: "detect", text: "TI match — feed 'apt-ops-2025'" },
    ],
  },
  {
    id: "INC-10477",
    severity: "MEDIUM",
    title: "Scheduled task created with hidden window",
    host: "BANK_12_01",
    eventId: "4698",
    source: "Windows/Security",
    time: "27 min ago",
    ts: "2025-04-17 09:17:55",
    status: "OPEN",
    mitre: ["T1053.005"],
    tags: ["persistence", "scheduled-task"],
    description: "schtasks /create with /F and -WindowStyle Hidden.",
    related: [],
    timeline: [{ ts: "09:17:55", type: "detect", text: "Rule SOC-PERSIST-TASK triggered" }],
  },
  {
    id: "INC-10476",
    severity: "LOW",
    title: "Local user added to Administrators",
    host: "WS-DEV-09",
    eventId: "4732",
    source: "Windows/Security",
    time: "44 min ago",
    ts: "2025-04-17 09:00:12",
    status: "CONTAINED",
    mitre: ["T1098"],
    tags: ["account", "privilege"],
    description: "User 'tmpadm' added to local Administrators by IT script.",
    related: [],
    timeline: [{ ts: "09:00:12", type: "detect", text: "Rule SOC-ACC-ADMIN-ADD triggered" }],
  },
  {
    id: "INC-10475",
    severity: "INFO",
    title: "Defender signature update completed",
    host: "FLEET",
    eventId: "2000",
    source: "Defender",
    time: "1 h ago",
    ts: "2025-04-17 08:39:00",
    status: "CLOSED",
    mitre: [],
    tags: ["maintenance"],
    description: "Signatures updated to 1.413.221.0 on 412 hosts.",
    related: [],
    timeline: [],
  },
];

export const topHosts = [
  { host: "RZ_MANU2", alerts: 1003, risk: 92 },
  { host: "BANK_12_01", alerts: 487, risk: 88 },
  { host: "DC01", alerts: 214, risk: 71 },
  { host: "WS-FIN-204", alerts: 96, risk: 64 },
  { host: "WS-DEV-09", alerts: 41, risk: 38 },
];

export const recentActivity = [
  { ts: "09:42", text: "Service installed — BANK_12_01", kind: "service" as const },
  { ts: "09:38", text: "LSASS access — RZ_MANU2", kind: "cred" as const },
  { ts: "09:33", text: "Brute-force success — DC01", kind: "auth" as const },
  { ts: "09:26", text: "C2 beacon — WS-FIN-204", kind: "net" as const },
  { ts: "09:17", text: "Scheduled task — BANK_12_01", kind: "persist" as const },
  { ts: "09:00", text: "Admin add — WS-DEV-09", kind: "account" as const },
];
