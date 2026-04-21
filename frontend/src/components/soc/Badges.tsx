/**
 * SOC Design System — Badges
 *
 * Adapted from __REDESIGN__/src/components/soc/Badges.tsx
 * Maps to real app severity strings (lowercase) and task statuses.
 */

export type SocSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type TaskStatus = 'new' | 'investigating' | 'resolved' | 'false_positive';

const sevLabel: Record<SocSeverity, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

const sevClass: Record<SocSeverity, string> = {
  critical: 'bg-soc-critical text-white',
  high:     'bg-soc-high text-black',
  medium:   'bg-soc-warning text-black',
  low:      'bg-soc-info text-black',
  info:     'bg-[var(--soc-muted)] text-[var(--soc-muted-fg)] border border-[var(--soc-border)]',
};

/** Normalise any severity string from the real app to SocSeverity */
export function normaliseSeverity(s: string | undefined | null): SocSeverity {
  switch ((s ?? '').toLowerCase()) {
    case 'critical': return 'critical';
    case 'high':     return 'high';
    case 'medium':   return 'medium';
    case 'low':      return 'low';
    default:         return 'info';
  }
}

export function SeverityBadge({ level }: { level: SocSeverity | string }) {
  const sev = normaliseSeverity(level);
  return (
    <span className={`soc-badge ${sevClass[sev]}`}>
      {sevLabel[sev]}
    </span>
  );
}

const statusLabel: Record<TaskStatus, string> = {
  new:            'OPEN',
  investigating:  'INVESTIGATING',
  false_positive: 'CONTAINED',
  resolved:       'CLOSED',
};

const statusClass: Record<TaskStatus, string> = {
  new:            'text-soc-critical border-soc-critical/50',
  investigating:  'text-soc-warning border-soc-warning/50',
  false_positive: 'text-soc-info border-soc-info/50',
  resolved:       'text-[var(--soc-muted-fg)] border-[var(--soc-border)]',
};

export function StatusBadge({ status }: { status: TaskStatus | string }) {
  const key = (status as TaskStatus) in statusLabel ? (status as TaskStatus) : 'new';
  return (
    <span
      className={`soc-badge bg-transparent border ${statusClass[key]}`}
    >
      {statusLabel[key]}
    </span>
  );
}

export function SocTag({ children }: { children: React.ReactNode }) {
  return (
    <span className="soc-badge bg-[var(--soc-muted)] text-[var(--soc-muted-fg)] border border-[var(--soc-border)]">
      {children}
    </span>
  );
}

/** Left-border class for an incident card based on severity */
export function incidentBorderClass(severity: string, selected: boolean): string {
  if (selected) return 'border-l-2 border-l-[var(--soc-primary)]';
  switch (normaliseSeverity(severity)) {
    case 'critical': return 'border-l-2 soc-border-l-critical';
    case 'high':     return 'border-l-2 soc-border-l-high';
    case 'medium':   return 'border-l-2 soc-border-l-warning';
    case 'low':      return 'border-l-2 soc-border-l-info';
    default:         return 'border-l-2 soc-border-l-muted';
  }
}
