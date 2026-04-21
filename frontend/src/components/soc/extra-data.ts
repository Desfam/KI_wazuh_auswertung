// Static demo/reference data for the SOC redesign pages.
// Used by the Badges component and as fallback data in pages.

export type HostStatus = "ONLINE" | "OFFLINE" | "ISOLATED" | "STALE";

export interface Host {
  name: string;
  os: string;
  risk: number;
  status: HostStatus;
  lastSeen: string;
  alerts: number;
  tags: string[];
  ip: string;
}

export const hosts: Host[] = [
  { name: "RZ_MANU2", os: "Win Server 2022", risk: 92, status: "ONLINE", lastSeen: "12s", alerts: 1003, tags: ["datacenter", "prod", "domain-joined"], ip: "10.20.4.11" },
  { name: "BANK_12_01", os: "Win Server 2019", risk: 88, status: "ONLINE", lastSeen: "4s", alerts: 487, tags: ["finance", "prod"], ip: "10.20.4.18" },
  { name: "DC01", os: "Win Server 2022", risk: 71, status: "ONLINE", lastSeen: "2s", alerts: 214, tags: ["dc", "tier-0"], ip: "10.20.1.10" },
  { name: "WS-FIN-204", os: "Win 11 23H2", risk: 64, status: "ONLINE", lastSeen: "9s", alerts: 96, tags: ["workstation", "finance"], ip: "10.30.7.204" },
  { name: "WS-DEV-09", os: "Win 11 23H2", risk: 38, status: "ISOLATED", lastSeen: "3m", alerts: 41, tags: ["workstation", "dev"], ip: "10.30.9.9" },
  { name: "FILE_SRV_03", os: "Win Server 2019", risk: 22, status: "ONLINE", lastSeen: "1s", alerts: 12, tags: ["file", "prod"], ip: "10.20.2.30" },
  { name: "JUMP_BOX_01", os: "Ubuntu 22.04", risk: 18, status: "ONLINE", lastSeen: "6s", alerts: 5, tags: ["linux", "jump"], ip: "10.20.0.5" },
  { name: "WS-HR-77", os: "Win 11 22H2", risk: 12, status: "OFFLINE", lastSeen: "2h", alerts: 0, tags: ["workstation", "hr"], ip: "10.30.5.77" },
  { name: "BUILD_AGENT_4", os: "Ubuntu 22.04", risk: 9, status: "STALE", lastSeen: "1d", alerts: 0, tags: ["linux", "ci"], ip: "10.40.1.4" },
];

export type EventType = "process" | "network" | "auth" | "service" | "file" | "registry";

export interface InvEvent {
  ts: string;
  eid: string;
  type: EventType;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  host: string;
  user?: string;
  process?: string;
  text: string;
  data: Record<string, string>;
}

export const investigationEvents: InvEvent[] = [
  { ts: "09:42:14", eid: "4624", type: "auth", severity: "INFO", host: "BANK_12_01", user: "SYSTEM", text: "Logon type 5 — service start", data: { LogonType: "5", LogonId: "0x3e7", Source: "127.0.0.1" } },
  { ts: "09:42:11", eid: "7045", type: "service", severity: "CRITICAL", host: "BANK_12_01", user: "SYSTEM", process: "services.exe", text: "New service WinUpdSvc registered", data: { ServiceName: "WinUpdSvc", ImagePath: "C:\\ProgramData\\svc_upd.exe", StartType: "auto", AccountName: "LocalSystem" } },
  { ts: "09:42:10", eid: "4697", type: "service", severity: "HIGH", host: "BANK_12_01", text: "Service installed: WinUpdSvc", data: { Subject: "SYSTEM", ServiceFileName: "C:\\ProgramData\\svc_upd.exe" } },
  { ts: "09:42:09", eid: "4688", type: "process", severity: "HIGH", host: "BANK_12_01", user: "SYSTEM", process: "powershell.exe", text: "powershell.exe spawned by svchost.exe", data: { ParentImage: "C:\\Windows\\System32\\svchost.exe", CommandLine: "powershell -nop -w hidden -enc JABz..." } },
  { ts: "09:38:02", eid: "10", type: "process", severity: "CRITICAL", host: "RZ_MANU2", user: "j.weber", process: "rundll32.exe", text: "ProcessAccess on lsass.exe granted 0x1010", data: { TargetImage: "C:\\Windows\\System32\\lsass.exe", GrantedAccess: "0x1010", CallTrace: "C:\\Windows\\..." } },
  { ts: "09:38:00", eid: "4688", type: "process", severity: "MEDIUM", host: "RZ_MANU2", user: "j.weber", process: "rundll32.exe", text: "rundll32.exe started by explorer.exe", data: { ParentImage: "explorer.exe", CommandLine: "rundll32.exe comsvcs.dll MiniDump 612 dump.bin full" } },
  { ts: "09:33:47", eid: "4624", type: "auth", severity: "HIGH", host: "DC01", user: "admin.svc", text: "Successful logon — type 3 (after 23 fails)", data: { LogonType: "3", IpAddress: "10.20.4.11", AuthPackage: "NTLM" } },
  { ts: "09:33:05", eid: "4625", type: "auth", severity: "MEDIUM", host: "DC01", user: "admin.svc", text: "Failed logon × 23 (NTLM)", data: { LogonType: "3", FailureReason: "Bad password", IpAddress: "10.20.4.11" } },
  { ts: "09:26:10", eid: "3", type: "network", severity: "HIGH", host: "WS-FIN-204", user: "m.koehler", process: "chrome.exe", text: "Network connect 185.244.25.74:443 (TI: APT-LIKE-OPS)", data: { DestIp: "185.244.25.74", DestPort: "443", Protocol: "tcp", TIFeed: "apt-ops-2025" } },
  { ts: "09:17:55", eid: "4698", type: "service", severity: "MEDIUM", host: "BANK_12_01", text: "Scheduled task created with hidden window", data: { TaskName: "\\Microsoft\\Windows\\UpdSync", Command: "powershell -WindowStyle Hidden -F C:\\u.ps1" } },
  { ts: "09:00:12", eid: "4732", type: "auth", severity: "LOW", host: "WS-DEV-09", text: "Local user added to Administrators", data: { TargetAccount: "tmpadm", Group: "Administrators", Subject: "IT-SCRIPT" } },
];

export interface Finding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  reason: string;
  category: string;
}

export const scanFindings: Finding[] = [
  { id: "F-01", title: "Unsigned binary running as service", severity: "CRITICAL", reason: "C:\\ProgramData\\svc_upd.exe — no Authenticode, VT 0/72", category: "persistence" },
  { id: "F-02", title: "Powershell with -enc base64 payload", severity: "HIGH", reason: "spawned by svchost · hidden window · 4.2KB payload", category: "execution" },
  { id: "F-03", title: "Scheduled task with hidden window", severity: "HIGH", reason: "TaskName \\Microsoft\\Windows\\UpdSync", category: "persistence" },
  { id: "F-04", title: "Outbound to rare ASN AS-49505", severity: "MEDIUM", reason: "first seen in fleet · TI hit 'apt-ops-2025'", category: "c2" },
  { id: "F-05", title: "WMI subscription on root\\subscription", severity: "MEDIUM", reason: "EventConsumer 'BVTConsumer' — uncommon", category: "persistence" },
  { id: "F-06", title: "Defender exclusion added", severity: "LOW", reason: "C:\\ProgramData\\ excluded 14m ago", category: "defense-evasion" },
  { id: "F-07", title: "Local admin group changed", severity: "LOW", reason: "+1 member · IT-SCRIPT initiator", category: "account" },
];

export interface Suggestion {
  check: string;
  why: string;
  tool: "investigation" | "isolate" | "script" | "baseline";
}

export const scanSuggestions: Suggestion[] = [
  { check: "Process → powershell.exe -enc payload", why: "unusual execution pattern · base64 + hidden", tool: "investigation" },
  { check: "Service → WinUpdSvc / svc_upd.exe", why: "unsigned · ProgramData · auto-start", tool: "isolate" },
  { check: "Network → 185.244.25.74:443", why: "TI feed match · first seen in fleet", tool: "investigation" },
  { check: "Task → \\Microsoft\\Windows\\UpdSync", why: "hidden window · powershell loader", tool: "script" },
  { check: "User → admin.svc auth burst", why: "23 fails → 1 success in 42s", tool: "investigation" },
  { check: "Baseline → WMI consumer BVTConsumer", why: "not present in datacenter baseline", tool: "baseline" },
];

export type DevState = "normal" | "unusual" | "abnormal";

export interface BaselineItem {
  name: string;
  kind: "process" | "user" | "service" | "ip";
  freq: string;
  lastSeen: string;
  score: number;
  state: DevState;
}

export const baselineProfiles = [
  { id: "datacenter", name: "Datacenter", hosts: 48 },
  { id: "workstation", name: "Workstation", hosts: 312 },
  { id: "server", name: "Server", hosts: 52 },
];

export const baselineNormal: BaselineItem[] = [
  { name: "svchost.exe", kind: "process", freq: "1.2M/d", lastSeen: "1s", score: 0, state: "normal" },
  { name: "lsass.exe", kind: "process", freq: "412/d", lastSeen: "2s", score: 0, state: "normal" },
  { name: "DOMAIN\\backup.svc", kind: "user", freq: "48/d", lastSeen: "14m", score: 0, state: "normal" },
  { name: "WinDefend", kind: "service", freq: "412 hosts", lastSeen: "0s", score: 0, state: "normal" },
  { name: "10.20.0.0/16", kind: "ip", freq: "constant", lastSeen: "0s", score: 0, state: "normal" },
];

export const baselineDeviations: BaselineItem[] = [
  { name: "svc_upd.exe", kind: "process", freq: "1/d", lastSeen: "2m", score: 94, state: "abnormal" },
  { name: "rundll32.exe → lsass", kind: "process", freq: "1/d", lastSeen: "6m", score: 89, state: "abnormal" },
  { name: "DOMAIN\\admin.svc (NTLM)", kind: "user", freq: "first seen", lastSeen: "11m", score: 78, state: "abnormal" },
  { name: "WinUpdSvc", kind: "service", freq: "first seen", lastSeen: "2m", score: 92, state: "abnormal" },
  { name: "185.244.25.74", kind: "ip", freq: "first seen", lastSeen: "18m", score: 81, state: "abnormal" },
  { name: "powershell.exe -enc", kind: "process", freq: "3/d", lastSeen: "2m", score: 64, state: "unusual" },
  { name: "schtasks.exe /create /F", kind: "process", freq: "5/d", lastSeen: "27m", score: 41, state: "unusual" },
  { name: "DOMAIN\\j.weber off-hours", kind: "user", freq: "rare", lastSeen: "6m", score: 38, state: "unusual" },
];
