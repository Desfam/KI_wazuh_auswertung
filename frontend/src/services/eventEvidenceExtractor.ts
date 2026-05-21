/**
 * Event Evidence Extractor
 * ========================
 * Extracts structured, typed evidence from Wazuh event data.
 *
 * Two entry points:
 *  - extractEventEvidence(event)  — full Wazuh indexer hit (_source or raw)
 *  - extractNodeEvidence(node)    — aggregated RadarEventCluster / live cluster
 *
 * Both return EventEvidence, consumed by InvestigationWorkbench and the
 * compact Wallboard badge.
 *
 * Field notes for non-obvious slots:
 *  - sudo:   user=sudoer, targetUser=USER(run-as), commandLine=COMMAND,
 *            rawMessage="TTY=pts/0 PWD=/root" (context line)
 *  - UFW:    sourceIp=SRC, destinationIp=DST, sourcePort=SPT,
 *            destinationPort=DPT, rawMessage="TCP"|"UDP" (PROTO)
 */

import type { ResolvedKnowledge } from './eventKnowledgeResolver';

// ─── Exported evidence type ───────────────────────────────────────────────────

export type EventEvidence = {
  host?: string;
  hostIp?: string;
  os?: string;
  user?: string;
  targetUser?: string;
  sourceIp?: string;
  sourcePort?: string;
  destinationIp?: string;
  destinationPort?: string;
  process?: string;
  parentProcess?: string;
  commandLine?: string;
  filePath?: string;
  fileAction?: 'added' | 'modified' | 'deleted' | 'unknown';
  oldHash?: string;
  newHash?: string;
  serviceName?: string;
  servicePath?: string;
  serviceStartType?: string;
  packageName?: string;
  packageVersion?: string;
  logonType?: string;
  status?: string;
  subStatus?: string;
  ruleId?: string;
  ruleDescription?: string;
  mitreTactics?: string[];
  mitreTechniques?: string[];
  /** For UFW: "TCP"|"UDP". For sudo: "TTY=pts/0 PWD=/root" context. Otherwise: log excerpt. */
  rawMessage?: string;
  sensitivePath?: boolean;
  sensitiveReason?: string;
  // ── Generic / Windows metadata ──
  provider?: string;
  channel?: string;
  computer?: string;
  eventRecordId?: string;
  level?: string;
  task?: string;
  opcode?: string;
  keywords?: string[];
  location?: string;
  decoder?: string;
  message?: string;
};

// ─── Action Policy ────────────────────────────────────────────────────────────

export type ActionPolicy = {
  policy: 'blocked' | 'review_required' | 'allowed';
  reason: string;
};

export interface UnifiedHost {
  tacticalLinked: boolean;
  /** 0–1 */
  confidence: number;
  wazuhOnly?: boolean;
}

export function getActionPolicyForEvent(
  evidence: EventEvidence,
  unifiedHost?: UnifiedHost,
): ActionPolicy {
  if (!evidence.host) {
    return { policy: 'blocked', reason: 'No host identity — cannot confirm target.' };
  }
  if (!evidence.hostIp) {
    return { policy: 'blocked', reason: 'Host IP unknown — identity not confirmed.' };
  }
  if (!unifiedHost) {
    return { policy: 'review_required', reason: 'Wazuh data only — Tactical RMM not linked.' };
  }
  if (unifiedHost.confidence < 0.6) {
    return {
      policy: 'blocked',
      reason: `Host mapping confidence too low (${Math.round(unifiedHost.confidence * 100)}%).`,
    };
  }
  if (!unifiedHost.tacticalLinked) {
    return { policy: 'review_required', reason: 'Wazuh data only — Tactical agent not matched.' };
  }
  if (unifiedHost.wazuhOnly) {
    return { policy: 'review_required', reason: 'Identity confirmed via Wazuh only. Manual review required.' };
  }
  return { policy: 'allowed', reason: 'Wazuh + Tactical confirmed. Action requires manual approval.' };
}

// ─── Sensitive path table ─────────────────────────────────────────────────────

const SENSITIVE_PATHS: Array<[RegExp, string]> = [
  [/\/etc\/passwd$/i,                          'Local account database'],
  [/\/etc\/shadow$/i,                          'Hashed password store'],
  [/\/etc\/sudoers(\.d\/?.*)?$/i,              'sudo authorisation rules'],
  [/\/etc\/ssh\/(authorized_keys|sshd_config)$/i, 'SSH keys / daemon config'],
  [/\/root\/\.ssh\//i,                         'Root SSH directory'],
  [/\/home\/[^/]+\/\.ssh\/authorized_keys$/i,  'User SSH authorised keys'],
  [/\/etc\/systemd\/system\//i,                'systemd service units'],
  [/\/etc\/cron\.d\//i,                        'cron job directory'],
  [/\/etc\/crontab$/i,                         'System crontab'],
  [/\/var\/spool\/cron\//i,                    'Per-user cron spools'],
  [/\/etc\/ld\.so\.preload$/i,                 'LD_PRELOAD pivot vector'],
  [/\/etc\/(environment|profile)(\.d\/.*)?$/i, 'Shell environment persistence'],
  [/\/root\//i,                                'Root home directory'],
];

function checkSensitivePath(path?: string): { sensitivePath: boolean; sensitiveReason?: string } {
  if (!path) return { sensitivePath: false };
  for (const [re, reason] of SENSITIVE_PATHS) {
    if (re.test(path)) return { sensitivePath: true, sensitiveReason: reason };
  }
  return { sensitivePath: false };
}

// ─── Syslog parsers ───────────────────────────────────────────────────────────

const SSH_FAIL_RE   = /Failed (?:password|publickey) for(?: invalid user)? (\S+) from ([\d.a-f:]+) port (\d+)(?:.*using (\w+))?/i;
const SSH_ACCEPT_RE = /Accepted (\w+(?:-\w+)*) for (\S+) from ([\d.a-f:]+) port (\d+)/i;
const SUDO_RE       = /(?:^|\s)(\S+)\s*:.*?TTY=(\S+)\s*;\s*PWD=(\S*)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)/is;
const UFW_SRC_RE    = /SRC=([\d.a-f:]+)/i;
const UFW_DST_RE    = /DST=([\d.a-f:]+)/i;
const UFW_SPT_RE    = /SPT=(\d+)/i;
const UFW_DPT_RE    = /DPT=(\d+)/i;
const UFW_PROTO_RE  = /\bPROTO=(\w+)/i;
const DPKG_I_RE     = /\binstalled\s+([^\s:]+)[^(]*\(([^)]+)\)/i;
const DPKG_R_RE     = /\bremoved\s+([^\s:]+)[^(]*\(([^)]+)\)/i;
const YUM_I_RE      = /Installed:\s+(\S+)-([^\s-]+)/i;

const LOGON_TYPES: Record<string, string> = {
  '2': '2 – Interactive',
  '3': '3 – Network',
  '4': '4 – Batch',
  '5': '5 – Service',
  '7': '7 – Unlock',
  '8': '8 – NetworkCleartext',
  '10': '10 – RemoteInteractive (RDP)',
  '11': '11 – CachedInteractive',
};

// ─── extractEventEvidence ─────────────────────────────────────────────────────

/**
 * Extract structured evidence from a full Wazuh event object.
 * Handles both Wazuh Indexer `_source` wrapper and bare event objects.
 */
export function extractEventEvidence(
  event: any,
  _knowledge?: ResolvedKnowledge,
): EventEvidence {
  if (!event) return {};

  // Unwrap _source wrapper from Indexer hits
  const ev      = event._source ?? event;
  const agent   = ev.agent    ?? {};
  const rule    = ev.rule     ?? {};
  const data    = ev.data     ?? {};
  const win     = ev.win      ?? {};
  const ed      = win.eventdata ?? win.EventData ?? {};
  const sys     = ev.syscheck ?? {};
  const decoder = ev.decoder  ?? {};
  const mitre   = rule.mitre  ?? {};
  const fullLog = (ev.full_log ?? ev.message ?? '') as string;

  const out: EventEvidence = {};

  // ── Agent / host ──
  out.host   = agent.name ?? undefined;
  out.hostIp = agent.ip   ?? undefined;
  out.os     = agent.os?.name ?? agent.os?.full ?? undefined;

  // ── Rule ──
  out.ruleId          = rule.id          ?? undefined;
  out.ruleDescription = rule.description ?? undefined;
  if (mitre.tactic)    out.mitreTactics   = toArray(mitre.tactic);
  if (mitre.technique) out.mitreTechniques = toArray(mitre.technique);

  // ── Windows EventData ──
  out.targetUser    = nonempty(ed.targetUserName ?? ed.TargetUserName ?? data.targetUserName);
  out.user          = nonempty(ed.subjectUserName ?? ed.SubjectUserName ?? data.subjectUserName
                               ?? data.srcuser ?? ev.srcuser);
  out.process       = nonempty(ed.processName ?? ed.newProcessName ?? ed.ProcessName
                               ?? ed.NewProcessName ?? data.processName
                               ?? decoder.name ?? ev.program_name);
  out.parentProcess = nonempty(ed.parentProcessName ?? ed.ParentProcessName);
  out.commandLine   = nonempty(ed.commandLine ?? ed.CommandLine);
  out.sourceIp      = nonempty(ed.ipAddress ?? ed.IpAddress ?? data.srcip ?? ev.srcip);

  // Logon type (4624 / 4625)
  const lt = ed.logonType ?? ed.LogonType ?? data.logonType;
  if (lt != null) out.logonType = LOGON_TYPES[String(lt)] ?? String(lt);

  const status    = ed.status    ?? ed.Status    ?? data.status;
  const subStatus = ed.subStatus ?? ed.SubStatus ?? data.subStatus;
  if (status != null) {
    out.status    = String(status);
    out.subStatus = subStatus != null ? String(subStatus) : undefined;
  }

  // ── Windows 7045 – new service ──
  const svcName = ed.serviceName ?? ed.ServiceName ?? data.serviceName;
  if (svcName) {
    out.serviceName      = String(svcName);
    out.servicePath      = nonempty(ed.serviceFileName ?? ed.ServiceFileName ?? data.serviceFileName);
    out.serviceStartType = nonempty(ed.startType ?? ed.StartType ?? data.startType);
    if (!out.user) out.user = nonempty(ed.accountName ?? ed.AccountName ?? data.accountName);
  }

  // ── Syscheck / FIM ──
  const sysPath = sys.path ?? sys.file ?? sys.filename;
  if (sysPath) {
    out.filePath   = String(sysPath);
    out.fileAction = normaliseFileAction(sys.event ?? sys.changed_attributes?.[0]);
    out.user       ??= nonempty(sys.uname_after ?? sys.uname_before);
    out.oldHash    = nonempty(sys.md5_before  ?? sys.sha1_before ?? sys.sha256_before);
    out.newHash    = nonempty(sys.md5_after   ?? sys.sha1_after  ?? sys.sha256_after);
    Object.assign(out, checkSensitivePath(out.filePath));
  }

  // ── Package management (dpkg/apt/rpm/yum) ──
  const dpkgI = DPKG_I_RE.exec(fullLog);
  const dpkgR = DPKG_R_RE.exec(fullLog);
  const yumI  = YUM_I_RE.exec(fullLog);
  const pkgM  = dpkgI ?? dpkgR ?? yumI;
  if (pkgM) {
    out.packageName    = pkgM[1];
    out.packageVersion = pkgM[2];
  }

  // ── SSH (syslog) ──
  if (!out.filePath && !out.serviceName && !out.packageName) {
    const failM   = SSH_FAIL_RE.exec(fullLog);
    const acceptM = SSH_ACCEPT_RE.exec(fullLog);
    if (failM) {
      out.user        ??= nonempty(failM[1]);
      out.sourceIp    ??= nonempty(failM[2]);
      out.sourcePort  ??= nonempty(failM[3]);
      if (failM[4]) out.commandLine = `auth: ${failM[4]}`;
    } else if (acceptM) {
      out.commandLine ??= `auth: ${acceptM[1]}`;
      out.user        ??= nonempty(acceptM[2]);
      out.sourceIp    ??= nonempty(acceptM[3]);
      out.sourcePort  ??= nonempty(acceptM[4]);
    }
  }

  // ── sudo ──
  const sudoM = SUDO_RE.exec(fullLog);
  if (sudoM) {
    out.user        ??= nonempty(sudoM[1]);
    out.targetUser  ??= nonempty(sudoM[4]);
    out.commandLine ??= sudoM[5].trim() || undefined;
    // Store TTY/PWD context in rawMessage for UI display
    out.rawMessage = `TTY=${sudoM[2]} PWD=${sudoM[3]}`;
  }

  // ── UFW / netfilter ──
  if (UFW_SRC_RE.test(fullLog)) {
    out.sourceIp      = UFW_SRC_RE.exec(fullLog)?.[1] ?? out.sourceIp;
    out.destinationIp = UFW_DST_RE.exec(fullLog)?.[1] ?? undefined;
    out.sourcePort    = UFW_SPT_RE.exec(fullLog)?.[1] ?? undefined;
    out.destinationPort = UFW_DPT_RE.exec(fullLog)?.[1] ?? undefined;
    // Protocol stored in rawMessage (short string like "TCP")
    out.rawMessage = UFW_PROTO_RE.exec(fullLog)?.[1] ?? undefined;
  }

  // ── Generic fallback fields from data.* ──
  out.user     ??= nonempty(data.dstuser ?? data.srcuser);
  out.sourceIp ??= nonempty(data.srcip);
  out.process  ??= nonempty(data.program_name ?? ev.program_name);

  // ── Generic Windows / Wazuh metadata ──
  const sys2 = win.system ?? win.System ?? {};
  out.provider   = nonempty(sys2.providerName ?? sys2.ProviderName ?? ed.providerName ?? data.provider_name);
  out.channel    = nonempty(sys2.channel      ?? sys2.Channel      ?? data.channel);
  out.computer   = nonempty(sys2.computer     ?? sys2.Computer     ?? data.computer ?? agent.name);
  out.eventRecordId = nonempty(sys2.eventRecordID ?? sys2.EventRecordID ?? ed.eventRecordID ?? data.eventRecordId);
  out.level      = nonempty(sys2.level        ?? sys2.Level        ?? data.level);
  out.task       = nonempty(sys2.task         ?? sys2.Task         ?? data.task);
  out.opcode     = nonempty(sys2.opcode       ?? sys2.Opcode       ?? data.opcode);
  const kw       = sys2.keywords ?? sys2.Keywords ?? data.keywords;
  if (kw) out.keywords = toArray(kw);
  out.location   = nonempty(ev.location);
  out.decoder    = nonempty(decoder.name);
  // Message: prefer Windows EventData.Message, fall back to full_log excerpt
  out.message    = nonempty(ed.Message ?? ed.message ?? data.message)
                   ?? (fullLog.length > 20 ? fullLog.slice(0, 300) : undefined);

  // ── Raw log excerpt (only if not already set by UFW/sudo) ──
  if (fullLog && !out.rawMessage) out.rawMessage = fullLog.slice(0, 400);

  return out;
}

// ─── extractNodeEvidence ─────────────────────────────────────────────────────

/** Minimal cluster shape compatible with RadarEventCluster. */
interface ClusterData {
  title: string;
  eventIds: string[];
  ruleIds: string[];
  mitreTactics: string[];
  hosts: Array<{ hostname: string; ip?: string | null; count: number }>;
  users: Array<{ name: string; count: number }>;
  processes: Array<{ name: string; count: number }>;
  sourceIps: Array<{ name: string; count: number }>;
  explanation: string;
}

/**
 * Build best-effort EventEvidence from an aggregated RadarEventCluster.
 * Used when individual raw events are not available.
 */
export function extractNodeEvidence(node: ClusterData): EventEvidence {
  const title   = node.title.toLowerCase();
  const topHost = node.hosts[0];
  const topUser = node.users[0];
  const topProc = node.processes[0];
  const topIp   = node.sourceIps[0];
  const eventId = node.eventIds[0] ?? '';

  const out: EventEvidence = {
    host:          topHost?.hostname  ?? undefined,
    hostIp:        topHost?.ip        ?? undefined,
    user:          topUser?.name      ?? undefined,
    process:       topProc?.name      ?? undefined,
    sourceIp:      topIp?.name        ?? undefined,
    ruleId:        node.ruleIds[0]    ?? undefined,
    ruleDescription: undefined,          // not available in cluster; set by callers if needed
    mitreTactics:  node.mitreTactics.length > 0 ? [...node.mitreTactics] : undefined,
  };

  // ── FIM ──
  if (title.includes('file integrity') || title.includes(' fim ') || title.startsWith('fim')) {
    out.fileAction =
      title.includes('delet') || title.includes('remov') ? 'deleted' :
      title.includes('add')   || title.includes('creat') ? 'added'   :
      title.includes('modif') || title.includes('chang') ? 'modified' : 'unknown';
    // Path not available in cluster; filePath intentionally omitted
  }

  // ── sudo ──
  if (title.includes('sudo')) {
    out.targetUser = 'root';
    // commandLine derived from top process name
    if (topProc) out.commandLine = topProc.name;
  }

  // ── SSH ──
  // user and sourceIp already set from cluster arrays

  // ── Windows logon (4624 / 4625) ──
  if (eventId === '4625' || eventId === '4624') {
    out.logonType = '3 – Network';
  }

  // ── Windows 7045 – new service ──
  if (eventId === '7045') {
    // Service name is usually in the process slot for this event type
    out.serviceName = topProc?.name ?? undefined;
  }

  // ── Package install / removal ──
  if (title.includes('package') && (title.includes('install') || title.includes('remov'))) {
    out.packageName = topProc?.name ?? undefined;
  }

  return out;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function toArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === 'string') return [v];
  return [];
}

function nonempty(v: unknown): string | undefined {
  if (v == null) return undefined;
  const s = String(v).trim();
  return s.length > 0 && s !== '-' && s !== 'N/A' ? s : undefined;
}

function normaliseFileAction(event?: string): EventEvidence['fileAction'] {
  if (!event) return 'unknown';
  const e = Array.isArray(event) ? event.join(' ').toLowerCase() : String(event).toLowerCase();
  if (e.includes('add') || e.includes('creat')) return 'added';
  if (e.includes('delet') || e.includes('remov')) return 'deleted';
  if (e.includes('modif') || e.includes('chang') || e.includes('content')
      || e.includes('perm') || e.includes('owner') || e.includes('inode')) return 'modified';
  return 'unknown';
}
