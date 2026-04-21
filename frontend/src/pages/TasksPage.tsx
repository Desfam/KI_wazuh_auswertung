import { useEffect, useState } from 'react';
import type { HostProfileAssignment } from '../types';
import { ProfileBadge } from '../components/ProfileBadge';
import { IncidentCard } from '../components/soc/IncidentCard';
import type { GeneratedTask as SocTask } from '../components/soc/IncidentCard';
import { ContextPanel } from '../components/soc/ContextPanel';

// ── Types ─────────────────────────────────────────────────────────────────────

type TaskStatus = 'neu' | 'investigating' | 'resolved' | 'false_positive';

type GeneratedTask = {
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
};

type TasksPageProps = {
  active: boolean;
  theme: 'light' | 'dark';
  onThemeToggle: () => void;
  generatedTasks: GeneratedTask[];
  onSwitchTab: (tab: 'chat' | 'tasks' | 'snipen', context?: { host?: string }) => void;
  profileAssignments: Record<string, HostProfileAssignment>;
};

// ── Severity helpers ──────────────────────────────────────────────────────────

const SEV_BORDER: Record<string, string> = {
  critical: 'border-l-red-500',
  high:     'border-l-orange-400',
  medium:   'border-l-amber-400',
  low:      'border-l-emerald-500',
  info:     'border-l-sky-400',
};

const SEV_BADGE_DARK: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-300 border border-red-400/30',
  high:     'bg-orange-500/15 text-orange-300 border border-orange-400/30',
  medium:   'bg-amber-400/15 text-amber-300 border border-amber-400/30',
  low:      'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30',
  info:     'bg-sky-500/15 text-sky-300 border border-sky-400/30',
};

const SEV_BADGE_LIGHT: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border border-red-200',
  high:     'bg-orange-100 text-orange-700 border border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border border-yellow-200',
  low:      'bg-green-100 text-green-700 border border-green-200',
  info:     'bg-sky-100 text-sky-700 border border-sky-200',
};

function sevBorder(sev: string) {
  return SEV_BORDER[sev.toLowerCase()] ?? 'border-l-slate-500';
}

function sevBadge(sev: string, dark: boolean) {
  const map = dark ? SEV_BADGE_DARK : SEV_BADGE_LIGHT;
  return map[sev.toLowerCase()] ?? (dark ? 'bg-slate-700 text-slate-300 border border-slate-600' : 'bg-slate-100 text-slate-600 border border-slate-200');
}

// ── Status helpers ────────────────────────────────────────────────────────────

const STATUS_LABELS: Record<TaskStatus, string> = {
  neu:            '🟡 Neu',
  investigating:  '🔵 Investigation',
  resolved:       '🟢 Resolved',
  false_positive: '⚪ False Positive',
};

const STATUS_BADGE_DARK: Record<TaskStatus, string> = {
  neu:            'bg-amber-800/30 text-amber-300 border border-amber-600/30',
  investigating:  'bg-sky-800/30 text-sky-300 border border-sky-600/30',
  resolved:       'bg-emerald-800/30 text-emerald-300 border border-emerald-600/30',
  false_positive: 'bg-slate-700/50 text-slate-400 border border-slate-600/30',
};

const STATUS_BADGE_LIGHT: Record<TaskStatus, string> = {
  neu:            'bg-amber-100 text-amber-700 border border-amber-200',
  investigating:  'bg-sky-100 text-sky-700 border border-sky-200',
  resolved:       'bg-emerald-100 text-emerald-700 border border-emerald-200',
  false_positive: 'bg-slate-100 text-slate-500 border border-slate-200',
};

function statusBadgeCls(status: TaskStatus, dark: boolean) {
  return dark ? STATUS_BADGE_DARK[status] : STATUS_BADGE_LIGHT[status];
}

// ── Component ─────────────────────────────────────────────────────────────────

export function TasksPage({ active, theme, generatedTasks, onSwitchTab, profileAssignments }: TasksPageProps) {
  const dark = theme === 'dark';

  const [taskStatuses, setTaskStatuses] = useState<Record<string, TaskStatus>>({});
  const [visibleTasks, setVisibleTasks] = useState<number>(0);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<'all' | TaskStatus>('all');
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null);

  useEffect(() => {
    if (!active || generatedTasks.length === 0) { setVisibleTasks(0); return; }
    let idx = 0;
    const iv = setInterval(() => {
      idx++;
      if (idx > generatedTasks.length) { clearInterval(iv); return; }
      setVisibleTasks(idx);
    }, 80);
    return () => clearInterval(iv);
  }, [active, generatedTasks.length]);

  function setStatus(taskId: string, status: TaskStatus) {
    setTaskStatuses((p) => ({ ...p, [taskId]: status }));
  }

  function handleIncidentStatusChange(taskId: string, status: SocTask['status']) {
    const mapped: TaskStatus = status === 'new' ? 'neu' : (status ?? 'neu');
    setStatus(taskId, mapped);
  }

  function toggleExpand(_taskId: string) {
    // Replaced by ContextPanel selection — kept for API compatibility
  }

  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  const sortedTasks = [...generatedTasks]
    .sort((a, b) => (severityOrder[b.severity.toLowerCase()] ?? 0) - (severityOrder[a.severity.toLowerCase()] ?? 0))
    .filter((task) => {
      if (severityFilter !== 'all' && task.severity.toLowerCase() !== severityFilter) return false;
      const st = taskStatuses[task.task_id] ?? 'neu';
      if (statusFilter !== 'all' && st !== statusFilter) return false;
      return true;
    });

  const totalCount = generatedTasks.length;
  const resolvedCount = Object.values(taskStatuses).filter((s) => s === 'resolved').length;
  const investigatingCount = Object.values(taskStatuses).filter((s) => s === 'investigating').length;
  const fpCount = Object.values(taskStatuses).filter((s) => s === 'false_positive').length;
  const openCount = Math.max(0, totalCount - resolvedCount - investigatingCount - fpCount);

  const selectedTask = selectedTaskId
    ? sortedTasks.find((t) => t.task_id === selectedTaskId) ?? null
    : null;
  const selectedTaskStatus = selectedTask
    ? (taskStatuses[selectedTask.task_id] ?? 'neu')
    : null;

  // Map internal 'neu' status to IncidentCard's 'new'
  function toSocStatus(s: TaskStatus): SocTask['status'] {
    return s === 'neu' ? 'new' : s;
  }

  return (
    <div
      className={`flex h-full flex-col overflow-hidden${!active ? ' hidden' : ''}`}
      style={{ background: 'var(--soc-background)', color: 'var(--soc-foreground)' }}
    >
      {/* KPI strip */}
      <div className="soc-kpi-strip flex-shrink-0" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="soc-kpi-cell">
          <div className="font-mono text-[9.5px] uppercase tracking-wider" style={{ color: 'var(--soc-muted-fg)' }}>Total</div>
          <div className="font-mono text-[22px] font-bold leading-tight tabular-nums" style={{ color: 'var(--soc-foreground)' }}>{totalCount}</div>
        </div>
        <div className="soc-kpi-cell">
          <div className="font-mono text-[9.5px] uppercase tracking-wider" style={{ color: 'var(--soc-muted-fg)' }}>Open</div>
          <div className="font-mono text-[22px] font-bold leading-tight tabular-nums" style={{ color: openCount > 0 ? 'var(--soc-warning)' : 'var(--soc-foreground)' }}>{openCount}</div>
        </div>
        <div className="soc-kpi-cell">
          <div className="font-mono text-[9.5px] uppercase tracking-wider" style={{ color: 'var(--soc-muted-fg)' }}>Investigating</div>
          <div className="font-mono text-[22px] font-bold leading-tight tabular-nums" style={{ color: investigatingCount > 0 ? 'var(--soc-info)' : 'var(--soc-foreground)' }}>{investigatingCount}</div>
        </div>
        <div className="soc-kpi-cell">
          <div className="font-mono text-[9.5px] uppercase tracking-wider" style={{ color: 'var(--soc-muted-fg)' }}>Resolved</div>
          <div className="font-mono text-[22px] font-bold leading-tight tabular-nums" style={{ color: 'var(--soc-success)' }}>{resolvedCount}</div>
        </div>
      </div>

      {/* Two-column layout */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: filter header + incident list */}
        <div className="flex flex-col flex-1 min-w-0 overflow-hidden" style={{ borderRight: '1px solid var(--soc-border)' }}>

          {/* Section header + filters */}
          <div className="soc-section-header flex-shrink-0 gap-1">
            <span style={{ color: 'var(--soc-muted-fg)' }}>INCIDENTS</span>
            <span
              className="rounded px-1.5 font-mono text-[10px] font-bold leading-5"
              style={{ background: 'var(--soc-muted)', color: 'var(--soc-muted-fg)' }}
            >
              {sortedTasks.length}
            </span>
            <div className="flex-1" />
            {/* Severity filters */}
            {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className="h-5 px-2 rounded-sm border font-mono text-[10px] transition-colors"
                style={{
                  borderColor: severityFilter === sev ? 'var(--soc-primary)' : 'var(--soc-border)',
                  color: severityFilter === sev ? 'var(--soc-primary)' : 'var(--soc-muted-fg)',
                  background: severityFilter === sev ? 'color-mix(in srgb, var(--soc-primary) 12%, transparent)' : 'transparent',
                }}
              >
                {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
              </button>
            ))}
            <span style={{ color: 'var(--soc-border)' }}>|</span>
            {/* Status filters */}
            {(['all', 'neu', 'investigating', 'resolved'] as const).map((st) => {
              const lbl = st === 'all' ? 'All Status' : st === 'investigating' ? 'Active' : st === 'neu' ? 'Open' : 'Resolved';
              return (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className="h-5 px-2 rounded-sm border font-mono text-[10px] transition-colors"
                  style={{
                    borderColor: statusFilter === st ? 'var(--soc-primary)' : 'var(--soc-border)',
                    color: statusFilter === st ? 'var(--soc-primary)' : 'var(--soc-muted-fg)',
                    background: statusFilter === st ? 'color-mix(in srgb, var(--soc-primary) 12%, transparent)' : 'transparent',
                  }}
                >
                  {lbl}
                </button>
              );
            })}
          </div>

          {/* Incident list */}
          <div className="flex-1 overflow-y-auto soc-scroll">
            {generatedTasks.length === 0 && (
              <div className="px-4 py-10 text-center font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                No incidents. Run script in the Chat tab to generate tasks.
              </div>
            )}
            {generatedTasks.length > 0 && sortedTasks.length === 0 && (
              <div className="px-4 py-8 text-center font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                No incidents match the active filter.
              </div>
            )}
            {sortedTasks.map((task, index) => {
              const taskStatus = taskStatuses[task.task_id] ?? 'neu';
              const mergedTask: SocTask = {
                ...task,
                status: toSocStatus(taskStatus),
              };
              const isVisible = index < visibleTasks;
              return (
                <div
                  key={task.task_id}
                  className="transition-all duration-300"
                  style={{
                    opacity: isVisible ? 1 : 0,
                    transform: isVisible ? 'translateY(0)' : 'translateY(4px)',
                    transitionDelay: `${index * 50}ms`,
                  }}
                >
                  <IncidentCard
                    task={mergedTask}
                    selected={selectedTaskId === task.task_id}
                    onSelect={() => setSelectedTaskId((id) => (id === task.task_id ? null : task.task_id))}
                    onInvestigate={(host) => onSwitchTab('snipen', { host })}
                    onStatusChange={handleIncidentStatusChange}
                  />
                  <div style={{ borderBottom: '1px solid var(--soc-border)' }} />
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: ContextPanel */}
        <div
          className="flex-shrink-0 flex flex-col overflow-hidden"
          style={{ width: 340, background: 'var(--soc-panel)' }}
        >
          {selectedTask && selectedTaskStatus ? (
            <ContextPanel
              kind="task"
              task={{ ...selectedTask, status: toSocStatus(selectedTaskStatus) }}
              onInvestigate={(host) => onSwitchTab('snipen', { host })}
              onStatusChange={handleIncidentStatusChange}
            />
          ) : (
            <ContextPanel kind="empty" />
          )}
        </div>
      </div>
    </div>
  );
}
