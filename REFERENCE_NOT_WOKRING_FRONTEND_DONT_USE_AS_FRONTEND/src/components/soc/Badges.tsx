import type { Severity, IncidentStatus } from "./data";

const sevMap: Record<Severity, string> = {
  CRITICAL: "bg-critical text-critical-foreground",
  HIGH: "bg-high text-high-foreground",
  MEDIUM: "bg-warning text-warning-foreground",
  LOW: "bg-info text-info-foreground",
  INFO: "bg-muted text-muted-foreground border border-border",
};

export function SeverityBadge({ level }: { level: Severity }) {
  return (
    <span
      className={`inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono font-semibold tracking-wider ${sevMap[level]}`}
    >
      {level}
    </span>
  );
}

const statusMap: Record<IncidentStatus, string> = {
  OPEN: "text-critical border-critical/50",
  INVESTIGATING: "text-warning border-warning/50",
  CONTAINED: "text-info border-info/50",
  CLOSED: "text-muted-foreground border-border",
};

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span
      className={`inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono tracking-wider bg-transparent border ${statusMap[status]}`}
    >
      {status}
    </span>
  );
}

export function Tag({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10.5px] font-mono bg-muted text-muted-foreground border border-border">
      {children}
    </span>
  );
}

export function Kbd({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="text-[10px] font-mono px-1 rounded-sm bg-muted border border-border text-muted-foreground">
      {children}
    </kbd>
  );
}
