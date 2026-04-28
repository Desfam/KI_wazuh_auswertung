import { Database, Monitor, Package, RefreshCw, Shield, User, UserX, Zap } from 'lucide-react';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type EventRow = Record<string, any>;

type TimelineEvent = {
  time: string;
  label: string;
  detail: string;
  eventIds: string[];
  color: string;
  Icon: typeof Shield;
  isSuspicious: boolean;
};

function getField(obj: EventRow, ...paths: string[]): string {
  for (const path of paths) {
    const parts = path.split('.');
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let cur: any = obj;
    for (const p of parts) {
      if (cur == null) break;
      cur = cur[p];
    }
    if (cur != null && cur !== '') return String(cur);
  }
  return '';
}

function formatTime(ts: string): string {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts.slice(0, 8);
    return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return ts.slice(0, 8);
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const EID_META: Record<string, { label: string; color: string; Icon: any; suspicious: boolean }> = {
  '1074':  { label: 'System Restart',       color: '#ef4444', Icon: RefreshCw,  suspicious: false },
  '7045':  { label: 'Service Install',      color: '#f97316', Icon: Package,    suspicious: true  },
  '4697':  { label: 'Service Install (SCM)',color: '#f97316', Icon: Package,    suspicious: true  },
  '4625':  { label: 'Logon Failure',        color: '#eab308', Icon: UserX,      suspicious: true  },
  '4740':  { label: 'Account Lockout',      color: '#eab308', Icon: UserX,      suspicious: true  },
  '7040':  { label: 'Service Change',       color: '#60a5fa', Icon: Zap,        suspicious: false },
  '4698':  { label: 'Scheduled Task',       color: '#f97316', Icon: Zap,        suspicious: true  },
  '4624':  { label: 'Logon',               color: '#6b7280', Icon: User,       suspicious: false },
  '4634':  { label: 'Logoff',              color: '#6b7280', Icon: User,       suspicious: false },
  '4648':  { label: 'Logon (RunAs)',        color: '#60a5fa', Icon: User,       suspicious: false },
  '16384': { label: 'Software Protection',  color: '#6b7280', Icon: Shield,     suspicious: false },
  '1102':  { label: 'Audit Log Cleared',    color: '#ef4444', Icon: Shield,     suspicious: true  },
  '4719':  { label: 'Audit Policy Changed', color: '#f97316', Icon: Shield,     suspicious: true  },
  '4720':  { label: 'User Account Created', color: '#f97316', Icon: User,       suspicious: true  },
  '7023':  { label: 'Service Failed',       color: '#eab308', Icon: Database,   suspicious: false },
  '7036':  { label: 'Service State Change', color: '#60a5fa', Icon: Zap,        suspicious: false },
};

function DEFAULT_META(eid: string, description: string) {
  const level = description.toLowerCase();
  const suspicious = level.includes('fail') || level.includes('error') || level.includes('block');
  return {
    label: description.slice(0, 40) || `Event ${eid}`,
    color: suspicious ? '#eab308' : '#6b7280',
    Icon: Monitor,
    suspicious,
  };
}

function buildTimeline(events: EventRow[]): TimelineEvent[] {
  if (!events || events.length === 0) return [];

  // Group by rule.id / eventID
  const groups: Record<string, { rows: EventRow[]; eid: string; description: string }> = {};

  for (const ev of events) {
    const eid =
      getField(ev, 'data.win.system.eventID', 'rule.id', 'rule_id', 'eventID') || 'unknown';
    const description = getField(ev, 'rule.description', 'description') || '';
    const key = eid;
    if (!groups[key]) groups[key] = { rows: [], eid, description };
    groups[key].rows.push(ev);
  }

  // Sort by first occurrence
  const sorted = Object.values(groups).sort((a, b) => {
    const ta = getField(a.rows[0], '@timestamp', 'timestamp') || '';
    const tb = getField(b.rows[0], '@timestamp', 'timestamp') || '';
    return ta.localeCompare(tb);
  });

  return sorted.slice(0, 8).map(({ rows, eid, description }) => {
    const meta = EID_META[eid] ?? DEFAULT_META(eid, description);
    const firstTs = getField(rows[0], '@timestamp', 'timestamp');
    const lastTs  = rows.length > 1 ? getField(rows[rows.length - 1], '@timestamp', 'timestamp') : '';
    const timeLabel =
      rows.length > 1
        ? `${formatTime(firstTs)} – ${formatTime(lastTs)}`
        : formatTime(firstTs);

    const users = [...new Set(rows.map((r) => getField(r, 'data.win.eventdata.targetUserName', 'data.win.eventdata.subjectUserName', 'user.name')).filter(Boolean))];
    const detail = users.length > 0 ? users.slice(0, 2).join(', ') : (description.slice(0, 50) || '—');

    return {
      time: timeLabel,
      label: meta.label,
      detail,
      eventIds: rows.length > 1 ? [`${rows.length}x ${eid}`] : [eid],
      color: meta.color,
      Icon: meta.Icon,
      isSuspicious: meta.suspicious,
    };
  });
}

type Props = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  result: any;
};

export default function EventTimelinePanel({ result }: Props) {
  const rawEvents: EventRow[] = Array.isArray(result?.events) ? result.events : [];
  const timeline = buildTimeline(rawEvents);

  if (timeline.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Zeitachse – Wichtige Ereignisse
        </span>
      </div>

      <div className="p-4 overflow-x-auto">
        <div className="flex gap-3 min-w-0" style={{ minWidth: Math.max(timeline.length * 140, 400) }}>
          {timeline.map((ev, i) => {
            const { Icon } = ev;
            return (
              <div key={i} className="flex flex-col items-center flex-1 min-w-[110px] max-w-[160px] relative">
                {/* Connector line */}
                {i < timeline.length - 1 && (
                  <div className="absolute top-[22px] left-[calc(50%+16px)] right-[-50%] h-px bg-border/60 z-0" />
                )}

                {/* Icon circle */}
                <div
                  className="relative z-10 h-10 w-10 rounded-full border-2 flex items-center justify-center mb-2 shrink-0"
                  style={{
                    borderColor: ev.color,
                    background: `color-mix(in srgb, ${ev.color} 12%, transparent)`,
                  }}
                >
                  <Icon className="h-4 w-4" style={{ color: ev.color }} />
                </div>

                {/* Time */}
                <div className="text-[9px] font-mono text-muted-foreground/70 text-center mb-0.5">
                  {ev.time}
                </div>

                {/* Label */}
                <div className="text-[10.5px] font-medium text-center leading-snug mb-1">
                  {ev.label}
                </div>

                {/* Event IDs */}
                <div className="flex flex-wrap gap-0.5 justify-center mb-1">
                  {ev.eventIds.map((id, j) => (
                    <span
                      key={j}
                      className="text-[8.5px] font-mono px-1 py-px rounded-sm border text-muted-foreground/70 border-border/50"
                    >
                      {id}
                    </span>
                  ))}
                </div>

                {/* Detail */}
                {ev.detail && (
                  <div className="text-[9.5px] font-mono text-muted-foreground/60 text-center truncate w-full">
                    {ev.detail}
                  </div>
                )}

                {/* Suspicious badge */}
                {ev.isSuspicious && (
                  <span className="mt-1 text-[8px] font-mono uppercase tracking-wider text-warning/80">
                    ⚠ review
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
