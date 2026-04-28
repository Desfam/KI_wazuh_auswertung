/**
 * SOC Design System — ContextPanel
 *
 * Adapted from __REDESIGN__/src/components/soc/ContextPanel.tsx
 * Supports both GeneratedTask (Tasks view) and SocEvent (Dashboard view).
 */

import React from 'react';

/** Format a UTC ISO timestamp string as HH:MM:SS in the browser's local timezone. */
function fmtTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
import { ExternalLink, Search, ShieldOff, CheckCircle2, Terminal } from 'lucide-react';
import { SeverityBadge, StatusBadge, SocTag } from './Badges';
import type { GeneratedTask } from './IncidentCard';

/** Minimal event shape used by DashboardPage */
export type SocEvent = {
  /** Internal key for selection */
  _key: string;
  host: string;
  severity: string;
  rule_description: string;
  event_id?: string | null;
  timestamp: string;
  user?: string | null;
  process?: string | null;
  ip_address?: string | null;
  mitre_id?: string | null;
  mitre_tactic?: string | null;
  groups?: string[];
  rule_level?: number | null;
  command_line?: string | null;
  service_name?: string | null;
  location?: string | null;
};

interface TaskPanelProps {
  kind: 'task';
  task: GeneratedTask;
  onInvestigate: (host: string) => void;
  onStatusChange: (taskId: string, status: GeneratedTask['status']) => void;
}

interface EventPanelProps {
  kind: 'event';
  event: SocEvent;
  relatedEvents?: SocEvent[];
  onInvestigate: (host: string) => void;
}

type Props = TaskPanelProps | EventPanelProps;

export function ContextPanel(props: Props | { kind: 'empty' }) {
  if (props.kind === 'empty') {
    return (
      <div className="flex-1 grid place-items-center font-mono text-[12px] text-[var(--soc-muted-fg)]">
        select an incident →
      </div>
    );
  }

  if (props.kind === 'task') {
    return <TaskContextPanel {...props} />;
  }

  return <EventContextPanel {...props} />;
}

function TaskContextPanel({ task, onInvestigate, onStatusChange }: TaskPanelProps) {
  const status = task.status ?? 'new';

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2 border-b border-[var(--soc-border)]">
        <div className="flex items-center gap-2">
          <SeverityBadge level={task.severity} />
          <StatusBadge status={status} />
          <span className="font-mono text-[10.5px] text-[var(--soc-muted-fg)]">
            {task.rule_id ?? task.event_id ?? '—'}
          </span>
          <button
            type="button"
            onClick={() => onInvestigate(task.host)}
            className="ml-auto text-[var(--soc-muted-fg)] hover:text-[var(--soc-foreground)]"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </button>
        </div>
        <h2 className="mt-1.5 text-[13.5px] font-semibold leading-snug text-[var(--soc-foreground)]">
          {task.title}
        </h2>

        <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[11px]">
          <KV k="host"  v={task.host} />
          {task.event_id && <KV k="eid"  v={task.event_id} />}
          {task.platform && <KV k="plat" v={task.platform} />}
          {task.local_score != null && <KV k="risk" v={String(task.local_score.toFixed(1))} />}
          {task.count != null && task.count > 1 && <KV k="count" v={`${task.count}×`} />}
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <ActionBtn icon={Search} label="Investigate" onClick={() => onInvestigate(task.host)} />
          {status === 'new' && (
            <ActionBtn label="Start Investigation" onClick={() => onStatusChange(task.task_id, 'investigating')} />
          )}
          {status === 'investigating' && (
            <>
              <ActionBtn label="Resolve" tone="success" onClick={() => onStatusChange(task.task_id, 'resolved')} />
              <ActionBtn label="False Positive" onClick={() => onStatusChange(task.task_id, 'false_positive')} />
            </>
          )}
          {(status === 'resolved' || status === 'false_positive') && (
            <ActionBtn label="↩ Reset" onClick={() => onStatusChange(task.task_id, 'new')} />
          )}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto soc-scroll">
        <Section title="Description">
          <p className="text-[12px] leading-snug text-[var(--soc-foreground)]">{task.details || task.reason || '—'}</p>
          {(task.mitre_ids?.length ?? 0) > 0 && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {task.mitre_ids?.map((m) => <SocTag key={m}>⚔ {m}</SocTag>)}
            </div>
          )}
        </Section>

        {(task.recommended_checks?.length ?? 0) > 0 && (
          <Section title={`Recommended Checks · ${task.recommended_checks.length}`}>
            <ul className="space-y-0.5">
              {task.recommended_checks.map((c, i) => (
                <li key={i} className="font-mono text-[11.5px] py-0.5 text-[var(--soc-foreground)]">
                  → {c}
                </li>
              ))}
            </ul>
          </Section>
        )}

        <Section title="Quick Pivots">
          <div className="grid grid-cols-2 gap-1">
            {[
              `host:${task.host}`,
              task.event_id && `eid:${task.event_id}`,
              task.rule_id && `rule:${task.rule_id}`,
            ]
              .filter(Boolean)
              .map((q) => (
                <button
                  key={q as string}
                  type="button"
                  className="text-left h-6 px-2 rounded-sm border border-[var(--soc-border)] hover:bg-[var(--soc-accent)] font-mono text-[11px] truncate text-[var(--soc-foreground)]"
                >
                  → {q}
                </button>
              ))}
          </div>
        </Section>
      </div>
    </div>
  );
}

function EventContextPanel({ event, relatedEvents = [], onInvestigate }: EventPanelProps) {
  // Build a pseudo-timeline from related events + this event sorted by time
  const timelineItems = React.useMemo(() => {
    const all = [...relatedEvents, event]
      .filter((e) => Boolean(e.timestamp))
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    return all.slice(-5); // last 5 chronologically
  }, [relatedEvents, event]);
  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2 border-b border-[var(--soc-border)]">
        <div className="flex items-center gap-2">
          <SeverityBadge level={event.severity} />
          <span className="font-mono text-[10.5px] text-[var(--soc-muted-fg)]">
            {event.event_id ?? '—'}
          </span>
          <button
            type="button"
            onClick={() => onInvestigate(event.host)}
            className="ml-auto text-[var(--soc-muted-fg)] hover:text-[var(--soc-foreground)]"
          >
            <ExternalLink className="h-3.5 w-3.5" />
          </button>
        </div>
        <h2 className="mt-1.5 text-[13.5px] font-semibold leading-snug text-[var(--soc-foreground)]">
          {event.rule_description}
        </h2>

        <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 font-mono text-[11px]">
          <KV k="host" v={event.host} />
          {event.event_id && <KV k="eid" v={event.event_id} />}
          <KV k="time" v={fmtTs(event.timestamp)} />
          {event.user && <KV k="user" v={event.user} />}
          {event.process && <KV k="proc" v={event.process} />}
          {event.ip_address && <KV k="ip" v={event.ip_address} />}
        </div>

        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          <ActionBtn icon={Search} label="Investigate" onClick={() => onInvestigate(event.host)} />
          <ActionBtn icon={ShieldOff} label="Isolate Host" tone="critical" onClick={() => {
            if (window.confirm(`Isolate ${event.host}?`)) alert('Isolation not yet supported by backend.');
          }} />
          <ActionBtn icon={CheckCircle2} label="Mark Safe" tone="success" onClick={() => {}} />
          <ActionBtn icon={Terminal} label="Run Script" onClick={() => {}} />
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto soc-scroll">
        {(event.groups?.length ?? 0) > 0 && (
          <Section title="Event Tags">
            <div className="flex flex-wrap gap-1">
              {event.groups?.map((g) => <SocTag key={g}>#{g}</SocTag>)}
            </div>
          </Section>
        )}

        {(event.mitre_id || event.mitre_tactic) && (
          <Section title="MITRE ATT&CK">
            <div className="flex flex-wrap gap-1">
              {event.mitre_id && <SocTag>⚔ {event.mitre_id}</SocTag>}
              {event.mitre_tactic && <SocTag>{event.mitre_tactic}</SocTag>}
            </div>
          </Section>
        )}

        {event.command_line && (
          <Section title="Command Line">
            <pre className="text-[10.5px] font-mono text-[var(--soc-foreground)] whitespace-pre-wrap break-all bg-[var(--soc-muted)] p-2 rounded">
              {event.command_line}
            </pre>
          </Section>
        )}

        <Section title="Quick Pivots">
          <div className="grid grid-cols-2 gap-1">
            {[
              `host:${event.host}`,
              event.event_id && `eid:${event.event_id}`,
              event.user && `user:${event.user}`,
              event.ip_address && `ip:${event.ip_address}`,
            ]
              .filter(Boolean)
              .map((q) => (
                <button
                  key={q as string}
                  type="button"
                  className="text-left h-6 px-2 rounded-sm border border-[var(--soc-border)] hover:bg-[var(--soc-accent)] font-mono text-[11px] truncate text-[var(--soc-foreground)]"
                >
                  → {q}
                </button>
              ))}
          </div>
        </Section>

        {relatedEvents.length > 0 && (
          <Section title={`Related Events · ${relatedEvents.length}`}>
            {relatedEvents.slice(0, 4).map((re) => (
              <div
                key={re._key}
                className="grid gap-1 py-1 border-b border-[var(--soc-border)]/60 last:border-0 font-mono text-[11px]"
                style={{ gridTemplateColumns: '44px 36px 1fr' }}
              >
                <span className="text-[var(--soc-muted-fg)] tabular-nums">{fmtTime(re.timestamp)}</span>
                <span className="text-[var(--soc-muted-fg)]">[{re.event_id ?? '—'}]</span>
                <span className="truncate text-[var(--soc-foreground)]">{re.rule_description}</span>
              </div>
            ))}
          </Section>
        )}

        {timelineItems.length > 1 && (
          <Section title="Timeline">
            {timelineItems.map((item, idx) => {
              const isThis = item._key === event._key;
              const dot = isThis ? '●' : '○';
              const cls = isThis
                ? 'text-[var(--soc-foreground)] font-semibold'
                : 'text-[var(--soc-muted-fg)]';
              return (
                <div key={item._key} className={`flex items-start gap-2 py-0.5 font-mono text-[11px] ${cls}`}>
                  <span className="w-3 shrink-0">{dot}</span>
                  <span className="tabular-nums shrink-0 text-[var(--soc-muted-fg)]">{fmtTime(item.timestamp)}</span>
                  <span className="truncate">{item.rule_description}</span>
                  {idx < timelineItems.length - 1 && (
                    <span className="absolute left-[5px] h-full border-l border-[var(--soc-border)] hidden" />
                  )}
                </div>
              );
            })}
          </Section>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-[var(--soc-border)]">
      <div className="text-[10px] font-mono uppercase tracking-wider text-[var(--soc-muted-fg)] mb-1.5">
        {title}
      </div>
      {children}
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2 min-w-0">
      <span className="text-[var(--soc-muted-fg)] w-12 shrink-0">{k}</span>
      <span className="font-mono truncate text-[var(--soc-foreground)]">{v}</span>
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
    default:  'border-[var(--soc-border)] hover:bg-[var(--soc-accent)] text-[var(--soc-foreground)]',
    critical: 'border-soc-critical/50 hover:bg-soc-critical/10 text-soc-critical',
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

function fmtTs(ts: string): string {
  try {
    return new Date(ts).toLocaleString('de-DE', {
      day: '2-digit', month: '2-digit', year: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return ts;
  }
}
