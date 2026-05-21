/**
 * Event Knowledge Resolver  (frontend)
 * =====================================
 * Top-level router that classifies a Wazuh event and returns the best
 * available analyst knowledge from either the Windows Event ID KB or
 * the Linux Event KB.
 *
 * Resolution order
 * ----------------
 * 1. Windows Event ID present → Windows KB lookup
 * 2. Linux indicators detected → Linux pattern resolver
 * 3. Wazuh rule description available → basic fallback
 * 4. Unknown fallback
 *
 * Usage
 * -----
 * ```ts
 * import { resolveEventKnowledge } from '@/services/eventKnowledgeResolver';
 *
 * const knowledge = resolveEventKnowledge(wazuhEvent);
 * console.log(knowledge.title, knowledge.defaultSeverity);
 * ```
 */

import { EVENT_KNOWLEDGE, type EventKnowledge } from './eventKnowledge';
import {
  LINUX_EVENT_KNOWLEDGE,
  SENSITIVE_FIM_PATHS,
  normalizeLinuxEventKey,
  type LinuxEventKnowledge,
  type KnowledgeLevel,
} from './linuxEventKnowledge';

// ---------------------------------------------------------------------------
// Shared response shape
// ---------------------------------------------------------------------------

export interface ResolvedKnowledge {
  /** Canonical knowledge key */
  key: string;
  /** Human-readable event title */
  title: string;
  category: string;
  defaultSeverity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** One-line description */
  summary: string;
  knowledgeLevel: KnowledgeLevel;
  /** Origin platform */
  platform: 'windows' | 'linux' | 'unknown';
  /** Full Windows KB entry when platform === 'windows' */
  windowsDetail?: EventKnowledge;
  /** Full Linux KB entry when platform === 'linux' and knowledgeLevel === 'deep' */
  linuxDetail?: LinuxEventKnowledge;
}

// ---------------------------------------------------------------------------
// Linux program / decoder lists
// ---------------------------------------------------------------------------

const LINUX_PROGRAMS = new Set([
  'sshd', 'sudo', 'su', 'login', 'cron', 'crond',
  'systemd', 'kernel', 'dmesg', 'auditd',
  'dpkg', 'apt', 'apt-get', 'yum', 'dnf', 'rpm',
  'ossec-syscheckd', 'wazuh-syscheckd',
]);

const LINUX_DECODERS = new Set([
  'sshd', 'sudo', 'pam', 'syslog', 'auditd',
  'systemd', 'kernel', 'dpkg',
]);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function safeGet(obj: unknown, ...keys: string[]): string {
  let cur: unknown = obj;
  for (const k of keys) {
    if (cur == null || typeof cur !== 'object') return '';
    cur = (cur as Record<string, unknown>)[k];
  }
  return typeof cur === 'string' ? cur : String(cur ?? '');
}

function extractWindowsEventId(event: Record<string, unknown>): string | null {
  // Wazuh normalised: data.win.system.eventID
  const v1 = safeGet(event, 'data', 'win', 'system', 'eventID');
  if (v1) return v1;
  // Fallback flat: data.id
  const v2 = safeGet(event, 'data', 'id');
  if (v2) return v2;
  return null;
}

function isLinuxEvent(event: Record<string, unknown>): boolean {
  // 1. Agent OS platform
  const platform = safeGet(event, 'agent', 'os', 'platform').toLowerCase();
  if (platform.includes('linux')) return true;
  if (platform.includes('windows')) return false;

  // 2. Decoder name
  const decoder = safeGet(event, 'decoder', 'name').toLowerCase();
  if (LINUX_DECODERS.has(decoder)) return true;

  // 3. Program name (multiple possible locations)
  const prog = (
    safeGet(event, 'program_name') ||
    safeGet(event, 'predecoder', 'program_name') ||
    safeGet(event, 'data', 'program_name')
  ).toLowerCase();
  if (LINUX_PROGRAMS.has(prog)) return true;

  return false;
}

function extractLinuxFields(event: Record<string, unknown>): {
  program: string;
  message: string;
  source: string;
  ruleDescription: string;
} {
  return {
    program:
      safeGet(event, 'program_name') ||
      safeGet(event, 'predecoder', 'program_name') ||
      safeGet(event, 'data', 'program_name'),
    message:
      safeGet(event, 'full_log') ||
      safeGet(event, 'message') ||
      safeGet(event, 'data', 'log'),
    source:
      safeGet(event, 'location') ||
      safeGet(event, 'data', 'srcip'),
    ruleDescription: safeGet(event, 'rule', 'description'),
  };
}

// ---------------------------------------------------------------------------
// Linux pattern classifier (mirrors Python resolve_linux_event_from_log)
// ---------------------------------------------------------------------------

function resolveLinuxEventFromLog(
  program: string,
  message: string,
  ruleDescription: string,
): ResolvedKnowledge {
  const prog = program.toLowerCase().trim();
  const msg = message.toLowerCase();

  const deepMatch = (key: string): ResolvedKnowledge => {
    const entry = LINUX_EVENT_KNOWLEDGE[key];
    return {
      key,
      title: entry.title,
      category: entry.category,
      defaultSeverity: entry.defaultSeverity,
      summary: entry.summary,
      knowledgeLevel: 'deep',
      platform: 'linux',
      linuxDetail: entry,
    };
  };

  // 1. SSH
  if (prog === 'sshd' || msg.includes('sshd')) {
    if (/failed password|invalid user|authentication failure/.test(msg))
      return deepMatch('linux.ssh.login_failure');
    if (/accepted password|accepted publickey|accepted keyboard/.test(msg))
      return deepMatch('linux.ssh.login_success');
  }

  // 2. sudo
  if (prog === 'sudo' || prog.startsWith('sudo')) {
    if (/not in sudoers|authentication failure|incorrect password attempts/.test(msg))
      return deepMatch('linux.sudo.command_failure');
    if (/command=/.test(msg))
      return deepMatch('linux.sudo.command');
  }

  // 3. PAM / local login
  if (['login', 'su', 'gdm', 'lightdm'].includes(prog) || msg.includes('pam_unix')) {
    if (/session opened for user/.test(msg))
      return deepMatch('linux.local.login_success');
  }

  // 4. Cron
  if (prog === 'cron' || prog === 'crond' || prog.includes('cron')) {
    if (/\bcmd\b/.test(msg))
      return deepMatch('linux.cron.execution');
  }

  // 5. Package management
  if (['dpkg', 'apt', 'apt-get', 'yum', 'dnf', 'rpm'].includes(prog)) {
    if (/\b(install|upgrade|reinstall)\b/.test(msg))
      return deepMatch('linux.package.installed');
    if (/\b(remove|purge|erase)\b/.test(msg))
      return deepMatch('linux.package.removed');
  }

  // 6. Kernel
  if (prog === 'kernel' || prog === 'dmesg') {
    if (/kernel panic|not syncing/.test(msg))
      return deepMatch('linux.kernel.panic');
    if (/\bbug\b|\boops\b|page fault|general protection/.test(msg))
      return deepMatch('linux.kernel.oops');
    if (msg.includes('ufw block'))
      return deepMatch('linux.firewall.ufw_block');
  }

  // 7. UFW (may appear as raw message without specific program)
  if (msg.includes('ufw block') || msg.includes('[ufw block]'))
    return deepMatch('linux.firewall.ufw_block');

  // 8. Wazuh FIM / syscheck
  if (
    ['ossec-syscheckd', 'wazuh-syscheckd', 'syscheck', 'wazuh fim'].includes(prog) ||
    msg.includes('syscheck') ||
    msg.includes('fim')
  ) {
    if (/modified|checksum changed|has been modified/.test(msg)) {
      const entry = { ...LINUX_EVENT_KNOWLEDGE['linux.fim.file_modified'] };
      // Sensitive path escalation
      for (const sensPath of SENSITIVE_FIM_PATHS) {
        if (message.includes(sensPath)) {
          return {
            key: 'linux.fim.file_modified',
            title: entry.title,
            category: entry.category,
            defaultSeverity: 'high',
            summary: `FIM detected modification of a sensitive path (${sensPath.replace(/\/$/, '')}): ${entry.summary}`,
            knowledgeLevel: 'deep',
            platform: 'linux',
            linuxDetail: entry,
          };
        }
      }
      return deepMatch('linux.fim.file_modified');
    }
  }

  // 9. Basic fallback — Wazuh rule description
  if (ruleDescription) {
    return {
      key: 'linux.unknown',
      title: 'Linux Event',
      category: 'unknown',
      defaultSeverity: 'info',
      summary: ruleDescription,
      knowledgeLevel: 'basic',
      platform: 'linux',
    };
  }

  // 10. Unknown fallback
  return {
    key: 'linux.unknown',
    title: 'Unknown Linux Event',
    category: 'unknown',
    defaultSeverity: 'info',
    summary: 'No matching Linux event knowledge found.',
    knowledgeLevel: 'unknown',
    platform: 'linux',
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Resolve analyst knowledge for a raw Wazuh event object.
 *
 * @param event - A Wazuh event document (plain object from the API).
 * @returns A {@link ResolvedKnowledge} response, always populated.
 */
export function resolveEventKnowledge(
  event: Record<string, unknown>,
): ResolvedKnowledge {
  if (!event || typeof event !== 'object') {
    return {
      key: 'unknown',
      title: 'Unknown Event',
      category: 'unknown',
      defaultSeverity: 'info',
      summary: 'No event data provided.',
      knowledgeLevel: 'unknown',
      platform: 'unknown',
    };
  }

  // ------------------------------------------------------------------
  // Route 1 — Windows Event ID
  // ------------------------------------------------------------------
  const winId = extractWindowsEventId(event);
  if (winId && EVENT_KNOWLEDGE[winId]) {
    const entry = EVENT_KNOWLEDGE[winId];
    return {
      key: `windows.event.${winId}`,
      title: entry.title,
      category: entry.category,
      defaultSeverity: entry.defaultSeverity,
      summary: entry.summary,
      knowledgeLevel: 'deep',
      platform: 'windows',
      windowsDetail: entry,
    };
  }

  // ------------------------------------------------------------------
  // Route 2 — Linux event
  // ------------------------------------------------------------------
  if (isLinuxEvent(event)) {
    const { program, message, ruleDescription } = extractLinuxFields(event);
    return resolveLinuxEventFromLog(program, message, ruleDescription);
  }

  // ------------------------------------------------------------------
  // Route 3 — Wazuh rule description basic fallback
  // ------------------------------------------------------------------
  const ruleDesc = safeGet(event, 'rule', 'description');
  if (ruleDesc) {
    return {
      key: 'generic',
      title: 'Wazuh Event',
      category: 'unknown',
      defaultSeverity: 'info',
      summary: ruleDesc,
      knowledgeLevel: 'generic',
      platform: 'unknown',
    };
  }

  // ------------------------------------------------------------------
  // Route 4 — Unknown
  // ------------------------------------------------------------------
  return {
    key: 'unknown',
    title: 'Unknown Event',
    category: 'unknown',
    defaultSeverity: 'info',
    summary: 'No matching event knowledge found.',
    knowledgeLevel: 'unknown',
    platform: 'unknown',
  };
}

/**
 * Convenience wrapper — look up by a known Linux event key directly,
 * bypassing event routing.
 */
export function resolveLinuxKnowledgeByKey(key: string): ResolvedKnowledge | undefined {
  const canon = normalizeLinuxEventKey(key);
  const entry = LINUX_EVENT_KNOWLEDGE[canon];
  if (!entry) return undefined;
  return {
    key: canon,
    title: entry.title,
    category: entry.category,
    defaultSeverity: entry.defaultSeverity,
    summary: entry.summary,
    knowledgeLevel: 'deep',
    platform: 'linux',
    linuxDetail: entry,
  };
}
