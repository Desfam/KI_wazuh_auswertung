import { useEffect, useRef, useState } from 'react';
import { ScanLine, RefreshCw, Download, ShieldOff, Eye, Terminal } from 'lucide-react';
import { getSnipenHosts } from '../services/api';
import { getFullScanResult, getFullScanStatus, startFullScan } from '../services/fullscan';
import type { HostProfileAssignment, SnipenHostInfo } from '../types';

type FullScanTabProps = {
  theme: 'light' | 'dark';
  profileAssignments: Record<string, HostProfileAssignment>;
};

type ScanState = 'idle' | 'running' | 'finished' | 'failed';

function riskColor(r: number) {
  return r >= 80 ? 'text-critical' : r >= 60 ? 'text-high' : r >= 40 ? 'text-warning' : 'text-success';
}

function riskBg(r: number) {
  return r >= 80 ? 'bg-critical' : r >= 60 ? 'bg-high' : r >= 40 ? 'bg-warning' : 'bg-success';
}

function sevColor(sev: string) {
  const s = sev?.toUpperCase();
  if (s === 'CRITICAL') return 'text-critical';
  if (s === 'HIGH') return 'text-high';
  if (s === 'MEDIUM') return 'text-warning';
  if (s === 'LOW') return 'text-success';
  return 'text-muted-foreground';
}

function sevBadge(sev: string) {
  const s = sev?.toUpperCase();
  if (s === 'CRITICAL') return 'bg-critical/15 text-critical border-critical/40';
  if (s === 'HIGH') return 'bg-warning/15 text-warning border-warning/40';
  if (s === 'MEDIUM') return 'bg-warning/10 text-warning border-warning/40';
  return 'bg-muted text-muted-foreground border-border';
}

export default function FullScanTab(_props: FullScanTabProps) {
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string>('');

  const [scanState, setScanState] = useState<ScanState>('idle');
  const [progress, setProgress] = useState(0);
  const [scanLog, setScanLog] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Scan configuration
  const [timeRange, setTimeRange] = useState<24 | 168 | 720>(168);
  const [scanMode, setScanMode] = useState<'quick' | 'standard' | 'deep'>('standard');
  const [scanScope, setScanScope] = useState({
    processes: true,
    files: true,
    services: true,
    registry: true,
  });

  useEffect(() => {
    setHostsLoading(true);
    setHostsError(null);
    getSnipenHosts(168)
      .then((data) => {
        setHosts(data);
        if (data.length > 0) setSelectedHost(data[0].host);
      })
      .catch((e: unknown) => setHostsError(e instanceof Error ? e.message : 'Failed to load hosts'))
      .finally(() => setHostsLoading(false));
  }, []);

  // Polling for scan status
  useEffect(() => {
    if (!jobId || scanState !== 'running') return;
    const poll = async () => {
      try {
        const status = await getFullScanStatus(jobId);
        const prog = typeof status.progress === 'number' ? status.progress : 0;
        setProgress(prog);
        if (status.log) setScanLog(Array.isArray(status.log) ? status.log : [String(status.log)]);
        if (status.status === 'finished' || status.status === 'done') {
          setScanState('finished');
          clearInterval(pollingRef.current!);
          const r = await getFullScanResult(jobId);
          setResult(r);
          const findings = r?.findings ?? r?.scan_findings ?? [];
          if (findings.length > 0) setSelectedFinding(findings[0]);
        } else if (status.status === 'failed' || status.status === 'error') {
          setScanState('failed');
          clearInterval(pollingRef.current!);
        }
      } catch {
        // ignore polling errors
      }
    };
    pollingRef.current = setInterval(poll, 2000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [jobId, scanState]);

  const handleStartScan = async () => {
    if (!selectedHost) return;
    setScanState('running');
    setScanLog([]);
    setResult(null);
    setSelectedFinding(null);
    setProgress(0);
    setJobId(null);
    const activeScope = Object.entries(scanScope)
      .filter(([, enabled]) => enabled)
      .map(([key]) => key)
      .join(',') || 'full';
    try {
      const { job_id } = await startFullScan(selectedHost, {
        mode: scanMode,
        scope: activeScope,
        time_range_hours: timeRange,
      });
      setJobId(job_id);
    } catch (e: unknown) {
      setScanState('failed');
      setScanLog([`Error: ${e instanceof Error ? e.message : String(e)}`]);
    }
  };

  const host = hosts.find((h) => h.host === selectedHost);
  const risk = host?.top_rule_level != null ? Math.min(100, Math.round(host.top_rule_level * 6.25)) : 0;
  const findings: Array<{ id?: string; title?: string; severity?: string; reason?: string; category?: string }> =
    result?.findings ?? result?.scan_findings ?? [];
  const suggestions: Array<{ check?: string; why?: string; tool?: string }> =
    result?.suggestions ?? result?.scan_suggestions ?? [];

  return (
    <div className="h-full grid grid-cols-[200px_1fr_360px] min-h-0">
      {/* Left: host picker */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-border">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
            Scan Targets
          </div>
          <button
            onClick={handleStartScan}
            disabled={!selectedHost || scanState === 'running'}
            className="w-full h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1 disabled:opacity-50"
          >
            <ScanLine className="h-3 w-3" />
            {scanState === 'running' ? 'Scanning…' : 'New Scan'}
          </button>
        </div>

        {/* Scan configuration */}
        <div className="px-3 py-2 border-b border-border space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Config</div>

          {/* Time range */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Time Range</div>
            <div className="flex gap-1">
              {([24, 168, 720] as const).map((h) => (
                <button
                  key={h}
                  onClick={() => setTimeRange(h)}
                  disabled={scanState === 'running'}
                  className={
                    'flex-1 h-5 rounded-sm border text-[10px] font-mono disabled:opacity-50 ' +
                    (timeRange === h
                      ? 'bg-accent border-primary text-foreground'
                      : 'border-border text-muted-foreground hover:bg-accent')
                  }
                >
                  {h === 24 ? '24h' : h === 168 ? '7d' : '30d'}
                </button>
              ))}
            </div>
          </div>

          {/* Scan mode */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Mode</div>
            <div className="flex gap-1">
              {(['quick', 'standard', 'deep'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setScanMode(m)}
                  disabled={scanState === 'running'}
                  className={
                    'flex-1 h-5 rounded-sm border text-[10px] font-mono disabled:opacity-50 ' +
                    (scanMode === m
                      ? 'bg-accent border-primary text-foreground'
                      : 'border-border text-muted-foreground hover:bg-accent')
                  }
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          {/* Scope checkboxes */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Scope</div>
            <div className="space-y-0.5">
              {(Object.keys(scanScope) as Array<keyof typeof scanScope>).map((key) => (
                <label key={key} className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scanScope[key]}
                    disabled={scanState === 'running'}
                    onChange={(e) =>
                      setScanScope((prev) => ({ ...prev, [key]: e.target.checked }))
                    }
                    className="h-3 w-3 accent-primary"
                  />
                  <span className="text-[10.5px] font-mono">{key}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {hostsLoading && (
            <div className="px-3 py-2 text-[11px] font-mono text-muted-foreground">loading…</div>
          )}
          {hostsError && (
            <div className="px-3 py-2 text-[11px] font-mono text-critical">{hostsError}</div>
          )}
          {hosts.map((h) => {
            const sel = h.host === selectedHost;
            const r = h.top_rule_level != null ? Math.min(100, Math.round(h.top_rule_level * 6.25)) : 0;
            return (
              <button
                key={h.host}
                onClick={() => setSelectedHost(h.host)}
                className={
                  'w-full text-left px-3 py-2 border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                  (sel ? 'bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]' : '')
                }
              >
                <div className="text-[12px] font-mono truncate">{h.host}</div>
                <div className="mt-0.5 flex items-center gap-2 text-[10.5px] font-mono">
                  <span className={r >= 80 ? 'text-critical' : r >= 60 ? 'text-high' : r >= 40 ? 'text-warning' : 'text-success'}>
                    risk {r}
                  </span>
                  <span className="text-muted-foreground">· {h.alert_count} alr</span>
                </div>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Center: scan report */}
      <div className="flex flex-col min-h-0 border-r border-border overflow-y-auto">
        {/* Header */}
        <div className="px-3 py-3 border-b border-border bg-[var(--panel)] flex items-start gap-4">
          <div className="flex-1">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              target
            </div>
            <div className="text-[16px] font-mono font-semibold">{selectedHost || '—'}</div>
            <div className="text-[11px] font-mono text-muted-foreground">
              {(host?.platforms ?? [])[0] ?? '—'} · {host?.last_seen ?? '—'}
            </div>
            <div className="mt-1">
              {scanState === 'idle' && (
                <span className="text-[11px] font-mono text-muted-foreground">ready to scan</span>
              )}
              {scanState === 'running' && (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
                  <span className="h-1.5 w-1.5 rounded-full bg-warning animate-pulse" />
                  scanning… {progress > 0 ? `${progress}%` : ''}
                </span>
              )}
              {scanState === 'finished' && (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" />
                  scan complete
                </span>
              )}
              {scanState === 'failed' && (
                <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-critical">
                  scan failed
                </span>
              )}
            </div>
          </div>

          <div className="text-right">
            <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
              risk score
            </div>
            <div className={'text-[40px] font-mono font-semibold leading-none ' + riskColor(risk)}>
              {risk}
            </div>
            <div className="text-[10.5px] font-mono text-muted-foreground">/ 100</div>
          </div>

          <div className="flex flex-col gap-1.5">
            <BarBtn icon={RefreshCw} label="Re-scan" onClick={handleStartScan} />
            <BarBtn icon={Download} label="Export" />
            <BarBtn icon={ShieldOff} label="Isolate" tone="critical" />
          </div>
        </div>

        {/* Progress bar */}
        {scanState === 'running' && (
          <div className="px-3 py-2 border-b border-border bg-[var(--panel)]">
            <div className="h-1 w-full bg-muted rounded-sm overflow-hidden">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
            {scanLog.length > 0 && (
              <div className="mt-1.5 text-[10.5px] font-mono text-muted-foreground truncate">
                {scanLog[scanLog.length - 1]}
              </div>
            )}
          </div>
        )}

        {/* Scan log (idle/failed) */}
        {(scanState === 'idle' || scanState === 'failed') && scanLog.length > 0 && (
          <Section title="Log">
            <div className="space-y-0.5">
              {scanLog.map((line, i) => (
                <div key={i} className="text-[11px] font-mono text-muted-foreground">
                  {line}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Findings */}
        {findings.length > 0 && (
          <Section title={`Findings · ${findings.length}`}>
            <div className="border border-border rounded-sm overflow-hidden">
              {findings.map((f, i) => (
                <div
                  key={f.id ?? i}
                  onClick={() => setSelectedFinding(f)}
                  className={
                    'grid grid-cols-[60px_70px_1fr_auto] items-center gap-2 px-2 py-1.5 cursor-pointer ' +
                    (i % 2 ? 'bg-[var(--row-hover)]/40' : '') +
                    ' border-b border-border/60 last:border-0 hover:bg-[var(--row-hover)]'
                  }
                >
                  <span className="text-[10.5px] font-mono text-muted-foreground">{f.id ?? `F-${i + 1}`}</span>
                  <span
                    className={
                      'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border ' +
                      sevBadge(f.severity ?? 'INFO')
                    }
                  >
                    {(f.severity ?? 'INFO').toLowerCase()}
                  </span>
                  <div className="min-w-0">
                    <div className="text-[12px] truncate">{f.title}</div>
                    {f.reason && (
                      <div className="text-[10.5px] font-mono text-muted-foreground truncate">
                        {f.reason}
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-1">
                    <MiniBtn icon={Eye} label="Investigate" />
                    <MiniBtn icon={Terminal} label="Script" />
                  </div>
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Suggestions */}
        {suggestions.length > 0 && (
          <Section title="Suggested Actions">
            <div className="space-y-1">
              {suggestions.map((s, i) => (
                <div
                  key={i}
                  className="grid grid-cols-[1fr_120px] gap-2 items-center px-2 py-1.5 border border-border rounded-sm bg-[var(--row-hover)]/20"
                >
                  <div className="min-w-0">
                    <div className="text-[12px] font-mono">
                      <span className="text-muted-foreground">Check</span> {s.check}
                    </div>
                    {s.why && (
                      <div className="text-[11px] font-mono text-muted-foreground truncate">
                        <span className="text-foreground/70">Why:</span> {s.why}
                      </div>
                    )}
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
        )}

        {/* Markdown report */}
        {scanState === 'finished' && result?.markdown_report && (
          <Section title="Report">
            <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug text-muted-foreground max-h-[600px] overflow-y-auto">
              {result.markdown_report}
            </pre>
          </Section>
        )}

        {scanState === 'idle' && findings.length === 0 && (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select a host and start a scan →
          </div>
        )}
      </div>

      {/* Right: context / finding detail */}
      <aside className="bg-[var(--panel)] flex flex-col min-h-0">
        <div className="h-9 px-3 flex items-center border-b border-border">
          <span className="text-[12px] font-semibold tracking-wide">
            {selectedFinding ? 'FINDING' : 'SCAN META'}
          </span>
        </div>
        <div className="flex-1 overflow-y-auto">
          {selectedFinding ? (
            <>
              <Sec title="Finding">
                <KV k="id" v={selectedFinding.id ?? '—'} />
                <KV k="severity" v={selectedFinding.severity ?? '—'} />
                <KV k="category" v={selectedFinding.category ?? '—'} />
              </Sec>
              <Sec title="Title">
                <div className="text-[12px] leading-snug">{selectedFinding.title}</div>
              </Sec>
              {selectedFinding.reason && (
                <Sec title="Reason">
                  <div className="text-[11.5px] font-mono leading-snug">{selectedFinding.reason}</div>
                </Sec>
              )}
            </>
          ) : (
            <>
              <Sec title="Host">
                <KV k="name" v={selectedHost || '—'} />
                <KV k="platform" v={(host?.platforms ?? [])[0] ?? '—'} />
                <KV k="alerts" v={String(host?.alert_count ?? 0)} />
                <KV k="last seen" v={host?.last_seen ?? '—'} />
              </Sec>
              <Sec title="Scan State">
                <KV k="status" v={scanState} />
                <KV k="job id" v={jobId ?? '—'} />
                <KV k="progress" v={progress > 0 ? `${progress}%` : '—'} />
                <KV k="findings" v={String(findings.length)} />
              </Sec>
            </>
          )}
        </div>
      </aside>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

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

function BarBtn({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'critical';
  onClick?: () => void;
}) {
  const t =
    tone === 'critical'
      ? 'border-critical/50 hover:bg-critical/15 text-critical'
      : 'border-border hover:bg-accent text-foreground';
  return (
    <button onClick={onClick} className={'h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ' + t}>
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
