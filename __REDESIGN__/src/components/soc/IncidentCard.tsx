import { Search, ShieldOff, CheckCircle2, Terminal } from "lucide-react";
import type { Incident } from "./data";
import { SeverityBadge, StatusBadge, Tag } from "./Badges";

interface Props {
  incident: Incident;
  selected: boolean;
  onSelect: () => void;
}

export function IncidentCard({ incident, selected, onSelect }: Props) {
  return (
    <div
      onClick={onSelect}
      className={[
        "border-l-2 cursor-pointer px-3 py-2 hover:bg-[var(--row-hover)] transition-colors",
        selected
          ? "bg-[var(--row-hover)] border-l-primary"
          : incident.severity === "CRITICAL"
            ? "border-l-critical"
            : incident.severity === "HIGH"
              ? "border-l-high"
              : incident.severity === "MEDIUM"
                ? "border-l-warning"
                : incident.severity === "LOW"
                  ? "border-l-info"
                  : "border-l-border",
      ].join(" ")}
    >
      <div className="flex items-center gap-2">
        <SeverityBadge level={incident.severity} />
        <StatusBadge status={incident.status} />
        <span className="text-[10.5px] font-mono text-muted-foreground">{incident.id}</span>
        <span className="ml-auto text-[10.5px] font-mono text-muted-foreground">{incident.time}</span>
      </div>

      <div className="mt-1 text-[12.5px] font-medium leading-snug">{incident.title}</div>

      <div className="mt-1 flex items-center gap-3 text-[11px] font-mono text-muted-foreground">
        <span><span className="text-foreground/70">host</span> {incident.host}</span>
        <span><span className="text-foreground/70">eid</span> {incident.eventId}</span>
        <span><span className="text-foreground/70">src</span> {incident.source}</span>
        {incident.user && <span className="truncate"><span className="text-foreground/70">user</span> {incident.user}</span>}
      </div>

      <div className="mt-1.5 flex flex-wrap gap-1">
        {incident.mitre.map((m) => (
          <Tag key={m}>⚔ {m}</Tag>
        ))}
        {incident.tags.slice(0, 3).map((t) => (
          <Tag key={t}>#{t}</Tag>
        ))}
      </div>

      <div
        className="mt-2 flex items-center gap-1.5"
        onClick={(e) => e.stopPropagation()}
      >
        <ActionBtn icon={Search} label="Investigate" />
        <ActionBtn icon={ShieldOff} label="Isolate" tone="critical" />
        <ActionBtn icon={CheckCircle2} label="Mark Safe" tone="success" />
        <ActionBtn icon={Terminal} label="Run Script" />
      </div>
    </div>
  );
}

function ActionBtn({
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
    <button
      className={`h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ${tones[tone]}`}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
