/**
 * SOC Design System — IncidentCard
 *
 * Adapted from __REDESIGN__/src/components/soc/IncidentCard.tsx
 * Wired to the real GeneratedTask type from the existing app.
 */

import { Search, CheckCircle2 } from 'lucide-react';
import { SeverityBadge, StatusBadge, SocTag, incidentBorderClass } from './Badges';

export type GeneratedTask = {
  task_id: string;
  host: string;
  severity: string;
  title: string;
  details: string;
  recommended_checks: string[];
  event_id?: string | null;
  rule_id?: string | null;
  rule_description?: string | null;
  platform?: string | null;
  count?: number;
  reason?: string | null;
  local_score?: number | null;
  mitre_ids?: string[];
  status?: 'new' | 'investigating' | 'resolved' | 'false_positive';
};

interface Props {
  task: GeneratedTask;
  selected: boolean;
  onSelect: () => void;
  /** Navigate to Snipen with this host pre-filled */
  onInvestigate: (host: string) => void;
  onStatusChange: (taskId: string, status: GeneratedTask['status']) => void;
  /** Relative time string (e.g. "5 min ago") — passed in from parent */
  timeAgo?: string;
}

export function IncidentCard({ task, selected, onSelect, onInvestigate, onStatusChange, timeAgo }: Props) {
  const status = task.status ?? 'new';

  return (
    <div
      onClick={onSelect}
      className={[
        'cursor-pointer px-3 py-2 hover:bg-[var(--soc-row-hover)] transition-colors',
        incidentBorderClass(task.severity, selected),
        selected ? 'bg-[var(--soc-row-hover)]' : '',
      ].join(' ')}
    >
      {/* Row 1: badges + time */}
      <div className="flex items-center gap-2">
        <SeverityBadge level={task.severity} />
        <StatusBadge status={status} />
        <span className="font-mono text-[10.5px] text-[var(--soc-muted-fg)]">
          {task.rule_id ?? task.event_id ?? '—'}
        </span>
        {timeAgo && (
          <span className="ml-auto font-mono text-[10.5px] text-[var(--soc-muted-fg)]">{timeAgo}</span>
        )}
      </div>

      {/* Row 2: title */}
      <div className="mt-1 text-[12.5px] font-medium leading-snug text-[var(--soc-foreground)]">
        {task.title}
      </div>

      {/* Row 3: meta */}
      <div className="mt-1 flex flex-wrap items-center gap-3 font-mono text-[11px] text-[var(--soc-muted-fg)]">
        <span>
          <span className="text-[var(--soc-foreground)]/70">host</span>{' '}
          {task.host}
        </span>
        {task.event_id && (
          <span>
            <span className="text-[var(--soc-foreground)]/70">eid</span>{' '}
            {task.event_id}
          </span>
        )}
        {task.platform && (
          <span>
            <span className="text-[var(--soc-foreground)]/70">plat</span>{' '}
            {task.platform}
          </span>
        )}
        {task.local_score != null && (
          <span>
            <span className="text-[var(--soc-foreground)]/70">risk</span>{' '}
            <span
              className={
                task.local_score >= 8
                  ? 'text-soc-critical'
                  : task.local_score >= 5
                    ? 'text-soc-warning'
                    : 'text-soc-success'
              }
            >
              {task.local_score.toFixed(1)}
            </span>
          </span>
        )}
      </div>

      {/* Row 4: MITRE tags */}
      {(task.mitre_ids?.length ?? 0) > 0 && (
        <div className="mt-1.5 flex flex-wrap gap-1">
          {task.mitre_ids?.map((m) => (
            <SocTag key={m}>⚔ {m}</SocTag>
          ))}
        </div>
      )}

      {/* Row 5: action buttons */}
      <div
        className="mt-2 flex items-center gap-1.5"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Investigate → navigate to Snipen */}
        <ActionBtn
          icon={Search}
          label="Investigate"
          onClick={() => onInvestigate(task.host)}
        />

        {/* Workflow buttons based on current status */}
        {status === 'new' && (
          <ActionBtn
            label="Start Investigation"
            onClick={() => onStatusChange(task.task_id, 'investigating')}
          />
        )}
        {status === 'investigating' && (
          <>
            <ActionBtn
              icon={CheckCircle2}
              label="Resolve"
              tone="success"
              onClick={() => onStatusChange(task.task_id, 'resolved')}
            />
            <ActionBtn
              label="False Positive"
              onClick={() => onStatusChange(task.task_id, 'false_positive')}
            />
          </>
        )}
        {(status === 'resolved' || status === 'false_positive') && (
          <ActionBtn
            label="↩ Reset"
            onClick={() => onStatusChange(task.task_id, 'new')}
          />
        )}
      </div>
    </div>
  );
}

function ActionBtn({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon?: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'critical' | 'success';
  onClick?: () => void;
}) {
  const tones: Record<string, string> = {
    default: 'border-[var(--soc-border)] hover:bg-[var(--soc-accent)] text-[var(--soc-foreground)]',
    critical: 'border-soc-critical/50 hover:bg-soc-critical/15 text-soc-critical',
    success:  'border-soc-success/40 hover:bg-soc-success/10 text-soc-success',
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={`h-6 px-2 rounded-sm border font-mono text-[11px] inline-flex items-center gap-1 transition-colors ${tones[tone]}`}
    >
      {Icon && <Icon className="h-3 w-3" />}
      {label}
    </button>
  );
}
