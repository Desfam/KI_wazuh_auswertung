import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  ScanLine,
  RefreshCw,
  Download,
  ShieldOff,
  Eye,
  Terminal,
  GitCompareArrows,
} from "lucide-react";
import { SocLayout } from "@/components/soc/SocLayout";
import { SeverityBadge, Tag } from "@/components/soc/Badges";
import { hosts } from "@/components/soc/extra-data";
import { scanFindings, scanSuggestions } from "@/components/soc/extra-data";

export const Route = createFileRoute("/full-scan")({
  component: FullScanView,
  head: () => ({
    meta: [
      { title: "Full Scan · Sentinel/Ops" },
      { name: "description", content: "Per-host full forensic scan and findings." },
    ],
  }),
});

function FullScanView() {
  const [hostName, setHostName] = useState(hosts[1].name);
  const host = hosts.find((h) => h.name === hostName) ?? hosts[1];

  return (
    <SocLayout title="FULL SCAN" sub={`// ${host.name} · ${host.os}`}>
      <div className="h-full grid grid-cols-[200px_1fr_360px] min-h-0">
        {/* Left: host picker */}
        <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
          <div className="px-3 py-2 border-b border-border">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
              Scan Targets
            </div>
            <button className="w-full h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1">
              <ScanLine className="h-3 w-3" /> New Scan
            </button>
          </div>
          <div className="flex-1 overflow-y-auto">
            {hosts.map((h) => {
              const sel = h.name === host.name;
              return (
                <button
                  key={h.name}
                  onClick={() => setHostName(h.name)}
                  className={
                    "w-full text-left px-3 py-2 border-b border-border/60 hover:bg-[var(--row-hover)] " +
                    (sel ? "bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]" : "")
                  }
                >
                  <div className="text-[12px] font-mono truncate">{h.name}</div>
                  <div className="mt-0.5 flex items-center gap-2 text-[10.5px] font-mono">
                    <span
                      className={
                        h.risk >= 80
                          ? "text-critical"
                          : h.risk >= 60
                            ? "text-high"
                            : h.risk >= 40
                              ? "text-warning"
                              : "text-success"
                      }
                    >
                      risk {h.risk}
                    </span>
                    <span className="text-muted-foreground">· {h.alerts} alr</span>
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        {/* Center scan report */}
        <div className="flex flex-col min-h-0 border-r border-border overflow-y-auto">
          {/* Header */}
          <div className="px-3 py-3 border-b border-border bg-[var(--panel)] flex items-start gap-4">
            <div className="flex-1">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                target
              </div>
              <div className="text-[16px] font-mono font-semibold">{host.name}</div>
              <div className="text-[11px] font-mono text-muted-foreground">
                {host.os} · {host.ip}
              </div>
              <div className="mt-1 flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
                  <span className="h-1.5 w-1.5 rounded-full bg-success animate-pulse" />
                  scan complete · 09:42:18
                </span>
                <span className="text-[11px] font-mono text-muted-foreground">· duration 3m 12s · 41,228 events</span>
              </div>
            </div>

            <div className="text-right">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                risk score
              </div>
              <div
                className={
                  "text-[40px] font-mono font-semibold leading-none " +
                  (host.risk >= 80
                    ? "text-critical"
                    : host.risk >= 60
                      ? "text-high"
                      : host.risk >= 40
                        ? "text-warning"
                        : "text-success")
                }
              >
                {host.risk}
              </div>
              <div className="text-[10.5px] font-mono text-muted-foreground">/ 100</div>
            </div>

            <div className="flex flex-col gap-1.5">
              <BarBtn icon={RefreshCw} label="Re-scan" />
              <BarBtn icon={Download} label="Export PDF" />
              <BarBtn icon={ShieldOff} label="Isolate" tone="critical" />
            </div>
          </div>

          {/* 1. Summary KPIs */}
          <Section title="1. Summary">
            <div className="grid grid-cols-4 gap-2">
              <Stat label="Risk Level" value="ELEVATED" tone="warning" />
              <Stat label="Findings" value={String(scanFindings.length)} />
              <Stat label="Critical" value={String(scanFindings.filter((f) => f.severity === "CRITICAL").length)} tone="critical" />
              <Stat label="High" value={String(scanFindings.filter((f) => f.severity === "HIGH").length)} tone="high" />
            </div>
          </Section>

          {/* 2. Key Data */}
          <Section title="2. Key Data">
            <div className="grid grid-cols-3 gap-3">
              <KeyBlock title="Top Event IDs">
                {["4688", "7045", "10", "4624", "3", "4698"].map((e) => (
                  <Tag key={e}>[{e}]</Tag>
                ))}
              </KeyBlock>
              <KeyBlock title="Top Rules">
                {["WIN-7045-RAREPATH", "PS-ENC-PAYLOAD", "TASK-HIDDEN", "TI-C2-MATCH"].map((r) => (
                  <Tag key={r}>{r}</Tag>
                ))}
              </KeyBlock>
              <KeyBlock title="Top Users">
                {["SYSTEM", "admin.svc", "j.weber"].map((u) => (
                  <Tag key={u}>👤 {u}</Tag>
                ))}
              </KeyBlock>
            </div>
          </Section>

          {/* 3. Baseline vs Current */}
          <Section title="3. Baseline vs Current">
            <div className="grid grid-cols-4 gap-0 border border-border rounded-sm overflow-hidden">
              <BaseCol title="New Processes" items={["svc_upd.exe", "powershell -enc", "rundll32→lsass"]} count={3} />
              <BaseCol title="New Users" items={["tmpadm"]} count={1} />
              <BaseCol title="New Services" items={["WinUpdSvc"]} count={1} />
              <BaseCol title="New IPs" items={["185.244.25.74", "45.142.x.x"]} count={2} />
            </div>
          </Section>

          {/* 4. Findings */}
          <Section title={`4. Findings · ${scanFindings.length}`}>
            <div className="border border-border rounded-sm overflow-hidden">
              {scanFindings.map((f, i) => (
                <div
                  key={f.id}
                  className={
                    "grid grid-cols-[60px_70px_1fr_auto] items-center gap-2 px-2 py-1.5 " +
                    (i % 2 ? "bg-[var(--row-hover)]/40" : "") +
                    " border-b border-border/60 last:border-0"
                  }
                >
                  <span className="text-[10.5px] font-mono text-muted-foreground">{f.id}</span>
                  <SeverityBadge level={f.severity} />
                  <div className="min-w-0">
                    <div className="text-[12px] truncate">{f.title}</div>
                    <div className="text-[10.5px] font-mono text-muted-foreground truncate">
                      {f.reason} · #{f.category}
                    </div>
                  </div>
                  <div className="flex items-center gap-1">
                    <MiniBtn icon={Eye} label="Investigate" />
                    <MiniBtn icon={Terminal} label="Script" />
                    <MiniBtn icon={GitCompareArrows} label="Baseline" />
                  </div>
                </div>
              ))}
            </div>
          </Section>

          {/* 5. Suggested Actions */}
          <Section title="5. Suggested Actions">
            <div className="space-y-1">
              {scanSuggestions.map((s, i) => (
                <div
                  key={i}
                  className="grid grid-cols-[1fr_120px] gap-2 items-center px-2 py-1.5 border border-border rounded-sm bg-[var(--row-hover)]/20"
                >
                  <div className="min-w-0">
                    <div className="text-[12px] font-mono">
                      <span className="text-muted-foreground">Check</span> {s.check}
                    </div>
                    <div className="text-[11px] font-mono text-muted-foreground truncate">
                      <span className="text-foreground/70">Why:</span> {s.why}
                    </div>
                  </div>
                  <div className="text-right">
                    <button className="h-6 px-2 rounded-sm border border-primary/40 hover:bg-primary/10 text-[11px] font-mono text-primary inline-flex items-center gap-1">
                      → {s.tool}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Section>
        </div>

        {/* Right context */}
        <aside className="bg-[var(--panel)] flex flex-col min-h-0">
          <div className="h-9 px-3 flex items-center border-b border-border">
            <span className="text-[12px] font-semibold tracking-wide">SCAN META</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            <Sec title="Coverage">
              <KV k="files" v="412,889 scanned" />
              <KV k="processes" v="186 inspected" />
              <KV k="services" v="74 enumerated" />
              <KV k="tasks" v="31 enumerated" />
              <KV k="reg keys" v="2,114 audited" />
            </Sec>
            <Sec title="MITRE Coverage">
              <div className="flex flex-wrap gap-1">
                {["T1543.003", "T1059.001", "T1053.005", "T1071.001", "T1098", "T1003.001"].map((t) => (
                  <Tag key={t}>⚔ {t}</Tag>
                ))}
              </div>
            </Sec>
            <Sec title="Recent Scans">
              {[
                { t: "09:42 today", risk: 88, dur: "3m 12s" },
                { t: "yesterday", risk: 64, dur: "3m 04s" },
                { t: "2d ago", risk: 41, dur: "3m 22s" },
              ].map((r, i) => (
                <div
                  key={i}
                  className="grid grid-cols-[1fr_50px_60px] gap-2 text-[11px] font-mono py-1 border-b border-border/60 last:border-0"
                >
                  <span className="text-muted-foreground">{r.t}</span>
                  <span className={r.risk >= 80 ? "text-critical" : r.risk >= 60 ? "text-high" : "text-warning"}>
                    risk {r.risk}
                  </span>
                  <span className="text-right text-muted-foreground">{r.dur}</span>
                </div>
              ))}
            </Sec>
          </div>
        </aside>
      </div>
    </SocLayout>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2.5 border-b border-border">
      <div className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
        {title}
      </div>
      {children}
    </div>
  );
}
function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      {children}
    </div>
  );
}
function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2 text-[11.5px] font-mono py-0.5">
      <span className="text-muted-foreground w-16">{k}</span>
      <span>{v}</span>
    </div>
  );
}
function Stat({
  label,
  value,
  tone = "default",
}: {
  label: string;
  value: string;
  tone?: "default" | "critical" | "high" | "warning";
}) {
  const c =
    tone === "critical"
      ? "text-critical"
      : tone === "high"
        ? "text-high"
        : tone === "warning"
          ? "text-warning"
          : "text-foreground";
  return (
    <div className="border border-border rounded-sm px-2 py-1.5">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`text-[15px] font-mono font-semibold ${c}`}>{value}</div>
    </div>
  );
}
function KeyBlock({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border border-border rounded-sm p-2">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      <div className="flex flex-wrap gap-1">{children}</div>
    </div>
  );
}
function BaseCol({ title, items, count }: { title: string; items: string[]; count: number }) {
  return (
    <div className="border-r border-border last:border-0 p-2">
      <div className="flex items-baseline justify-between">
        <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          {title}
        </div>
        <div className="text-[11px] font-mono text-warning">+{count}</div>
      </div>
      <ul className="mt-1 space-y-0.5">
        {items.map((it) => (
          <li key={it} className="text-[11px] font-mono truncate hover:text-warning cursor-pointer">
            • {it}
          </li>
        ))}
      </ul>
    </div>
  );
}
function BarBtn({
  icon: Icon,
  label,
  tone = "default",
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: "default" | "critical";
}) {
  const t =
    tone === "critical"
      ? "border-critical/50 hover:bg-critical/15 text-critical"
      : "border-border hover:bg-accent text-foreground";
  return (
    <button className={"h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 " + t}>
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
function MiniBtn({
  icon: Icon,
  label,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}) {
  return (
    <button className="h-5 px-1.5 rounded-sm border border-border hover:bg-accent text-[10.5px] font-mono inline-flex items-center gap-1">
      <Icon className="h-2.5 w-2.5" />
      {label}
    </button>
  );
}
