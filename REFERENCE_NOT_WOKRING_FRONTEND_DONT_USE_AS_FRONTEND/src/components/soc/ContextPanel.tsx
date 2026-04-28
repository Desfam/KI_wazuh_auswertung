import type { Incident } from "./data";
import { SeverityBadge, StatusBadge, Tag } from "./Badges";
import { Search, ShieldOff, CheckCircle2, Terminal, ExternalLink } from "lucide-react";

export function ContextPanel({ incident }: { incident: Incident | null }) {
  if (!incident) {
    return (
      <div className="flex-1 grid place-items-center text-[12px] text-muted-foreground font-mono">
        select an incident →
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <div className="px-3 py-2 border-b border-border">
        <div className="flex items-center gap-2">
          <SeverityBadge level={incident.severity} />
          <StatusBadge status={incident.status} />
          <span className="text-[10.5px] font-mono text-muted-foreground">{incident.id}</span>
          <button className="ml-auto text-muted-foreground hover:text-foreground">
            <ExternalLink className="h-3.5 w-3.5" />
          </button>
        </div>
        <h2 className="mt-1.5 text-[13.5px] font-semibold leading-snug">{incident.title}</h2>

        <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
          <KV k="host" v={incident.host} mono />
          <KV k="eid" v={incident.eventId} mono />
          <KV k="source" v={incident.source} mono />
          <KV k="time" v={incident.ts} mono />
          {incident.user && <KV k="user" v={incident.user} mono />}
          {incident.process && <KV k="proc" v={incident.process} mono />}
        </div>

        <div className="mt-2 flex items-center gap-1.5">
          <Btn icon={Search} label="Investigate" />
          <Btn icon={ShieldOff} label="Isolate Host" tone="critical" />
          <Btn icon={CheckCircle2} label="Mark Safe" tone="success" />
          <Btn icon={Terminal} label="Run Script" />
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        <Section title="Description">
          <p className="text-[12px] leading-snug">{incident.description}</p>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {incident.mitre.map((m) => <Tag key={m}>⚔ {m}</Tag>)}
            {incident.tags.map((t) => <Tag key={t}>#{t}</Tag>)}
          </div>
        </Section>

        <Section title={`Related Events · ${incident.related.length}`}>
          {incident.related.length === 0 ? (
            <div className="text-[11px] font-mono text-muted-foreground">— none —</div>
          ) : (
            <ul className="space-y-0.5">
              {incident.related.map((r, i) => (
                <li
                  key={i}
                  className="grid grid-cols-[60px_56px_1fr] gap-2 text-[11.5px] font-mono py-1 border-b border-border/60 last:border-0"
                >
                  <span className="text-muted-foreground">{r.ts}</span>
                  <span className="text-info">[{r.eid}]</span>
                  <span className="truncate">{r.text}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Timeline">
          <ul className="space-y-1.5">
            {incident.timeline.map((t, i) => (
              <li key={i} className="grid grid-cols-[60px_1fr] gap-2 text-[11.5px] font-mono">
                <span className="text-muted-foreground">{t.ts}</span>
                <span className="flex items-start gap-1.5">
                  <span
                    className={
                      "mt-1 h-1.5 w-1.5 rounded-full shrink-0 " +
                      (t.type === "detect"
                        ? "bg-critical"
                        : t.type === "enrich"
                          ? "bg-info"
                          : "bg-success")
                    }
                  />
                  <span>{t.text}</span>
                </span>
              </li>
            ))}
          </ul>
        </Section>

        <Section title="Quick Pivots">
          <div className="grid grid-cols-2 gap-1">
            {[
              `host:${incident.host}`,
              `eid:${incident.eventId}`,
              incident.user && `user:${incident.user}`,
              incident.process && `proc:${incident.process}`,
            ]
              .filter(Boolean)
              .map((q) => (
                <button
                  key={q as string}
                  className="text-left h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono truncate"
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      {children}
    </div>
  );
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex gap-2 min-w-0">
      <span className="text-muted-foreground w-12 shrink-0">{k}</span>
      <span className={`truncate ${mono ? "font-mono" : ""}`}>{v}</span>
    </div>
  );
}

function Btn({
  icon: Icon,
  label,
  tone = "default",
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: "default" | "critical" | "success";
}) {
  const tones = {
    default: "border-border hover:bg-accent text-foreground",
    critical: "border-critical/50 hover:bg-critical/15 text-critical",
    success: "border-success/40 hover:bg-success/10 text-success",
  } as const;
  return (
    <button className={`h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ${tones[tone]}`}>
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
