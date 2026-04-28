type Pair = [string, number] | string[];

function safeList(v: unknown): Pair[] {
  if (!Array.isArray(v)) return [];
  return v as Pair[];
}

function Chip({ label, count }: { label: string; count?: number }) {
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-px rounded-sm border border-border/60 bg-[var(--panel)] text-foreground/80 mb-1 mr-1">
      {label}
      {count != null && count > 0 && (
        <span className="text-muted-foreground">{count}x</span>
      )}
    </span>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="py-1.5 border-b border-border/40 last:border-0">
      <div className="text-[9px] font-mono uppercase tracking-wider text-muted-foreground mb-1">
        {label}
      </div>
      <div className="flex flex-wrap">{children}</div>
    </div>
  );
}

type Props = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  result: any;
};

export default function KeyDataPanel({ result }: Props) {
  const summary = result?.summary ?? {};
  const insights = result?.raw_json?.insights ?? {};

  const topEventIds = safeList(summary.top_event_ids ?? insights.top_event_ids);
  const topRuleIds  = safeList(summary.top_rule_ids  ?? insights.top_rule_ids);
  const topProcs    = safeList(insights.top_processes);
  const topUsers    = safeList(insights.top_users);

  return (
    <div className="rounded-lg border border-border bg-[var(--panel)] overflow-hidden">
      <div className="px-4 py-2.5 border-b border-border">
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          Key Data
        </span>
      </div>
      <div className="px-4 py-1">
        {topEventIds.length > 0 && (
          <Row label="Top Event-IDs">
            {topEventIds.slice(0, 6).map(([eid, cnt], i) => (
              <Chip key={i} label={String(eid)} count={Number(cnt)} />
            ))}
          </Row>
        )}
        {topRuleIds.length > 0 && (
          <Row label="Top Regeln">
            {topRuleIds.slice(0, 5).map(([rid, cnt], i) => (
              <Chip key={i} label={String(rid)} count={Number(cnt)} />
            ))}
          </Row>
        )}
        {topProcs.length > 0 && (
          <Row label="Top Prozess">
            {topProcs.slice(0, 3).map(([proc], i) => (
              <Chip key={i} label={String(proc).split('\\').pop() ?? String(proc)} />
            ))}
          </Row>
        )}
        {topUsers.length > 0 && (
          <Row label="Top Nutzer">
            {topUsers.slice(0, 4).map(([user], i) => (
              <Chip key={i} label={String(user)} />
            ))}
          </Row>
        )}
        {topEventIds.length === 0 && topRuleIds.length === 0 && topProcs.length === 0 && (
          <div className="py-3 text-[11px] font-mono text-muted-foreground">No data available</div>
        )}
      </div>
    </div>
  );
}
