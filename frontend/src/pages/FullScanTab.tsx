import { useEffect, useRef, useState } from 'react';
import { Download, Layers, RefreshCw, ScanLine, ShieldOff } from 'lucide-react';
import { getSnipenHosts } from '../services/api';
import { getFullScanResult, getFullScanStatus, startFullScan } from '../services/fullscan';
import FullScanReportDashboard from '../components/fullscan/FullScanReportDashboard';
import type { HostProfileAssignment, SnipenHostInfo } from '../types';

type FullScanTabProps = {
  theme: 'light' | 'dark';
  profileAssignments: Record<string, HostProfileAssignment>;
};

type ScanState = 'idle' | 'running' | 'finished' | 'failed';

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
  const [scanTime, setScanTime] = useState('');
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Quick Scan All state
  const [bulkRunning, setBulkRunning] = useState(false);
  const [bulkDone, setBulkDone] = useState(0);
  const [bulkTotal, setBulkTotal] = useState(0);
  const [bulkCurrentHost, setBulkCurrentHost] = useState<string | null>(null);
  const bulkCancelRef = useRef(false);

  async function pollUntilDone(jid: string): Promise<void> {
    return new Promise((resolve) => {
      const iv = setInterval(async () => {
        try {
          const st = await getFullScanStatus(jid);
          if (st.status === 'finished' || st.status === 'done' || st.status === 'failed' || st.status === 'error') {
            clearInterval(iv);
            resolve();
          }
        } catch {
          clearInterval(iv);
          resolve();
        }
      }, 2500);
    });
  }

  const handleQuickScanAll = async () => {
    if (bulkRunning || hosts.length === 0) return;
    setBulkRunning(true);
    setBulkDone(0);
    setBulkTotal(hosts.length);
    bulkCancelRef.current = false;
    for (let i = 0; i < hosts.length; i++) {
      if (bulkCancelRef.current) break;
      const h = hosts[i].host;
      setBulkCurrentHost(h);
      try {
        const { job_id } = await startFullScan(h, {
          mode: 'quick',
          scope: 'full',
          time_range_hours: 24,
        });
        await pollUntilDone(job_id);
      } catch {
        // continue on error
      }
      setBulkDone(i + 1);
    }
    setBulkCurrentHost(null);
    setBulkRunning(false);
  };

  const handleCancelBulk = () => { bulkCancelRef.current = true; };

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
          setScanTime(new Date().toLocaleString('de-DE'));
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const findings: Array<Record<string, any>> = result?.findings ?? result?.scan_findings ?? [];
  const suggestions: Array<{ check?: string; why?: string; tool?: string }> =
    result?.suggestions ?? result?.scan_suggestions ?? [];

  const showDashboard = scanState === 'finished' && result != null;

  return (
    <div className={`h-full min-h-0 grid ${showDashboard ? 'grid-cols-[200px_1fr]' : 'grid-cols-[200px_1fr_360px]'}`}>
      {/* Left: host picker */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-border">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
            Scan Targets
          </div>
          <div className="flex gap-1">
            <button
              onClick={handleStartScan}
              disabled={!selectedHost || scanState === 'running' || bulkRunning}
              className="flex-1 h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1 disabled:opacity-50"
            >
              <ScanLine className="h-3 w-3" />
              {scanState === 'running' ? 'Scanning…' : 'New Scan'}
            </button>
            <button
              onClick={bulkRunning ? handleCancelBulk : handleQuickScanAll}
              disabled={hosts.length === 0 || scanState === 'running'}
              title={bulkRunning ? 'Abbrechen' : `Quick Scan alle ${hosts.length} Hosts (24h, quick)`}
              className={`h-7 px-2 rounded-sm border text-[11.5px] font-mono inline-flex items-center gap-1 disabled:opacity-50 transition-colors ${
                bulkRunning
                  ? 'border-warning/60 bg-warning/10 text-warning hover:bg-warning/20'
                  : 'border-border hover:bg-accent'
              }`}
            >
              <Layers className="h-3 w-3" />
              {bulkRunning ? `${bulkDone}/${bulkTotal}` : 'All'}
            </button>
          </div>
          {/* Bulk progress bar */}
          {bulkRunning && (
            <div className="mt-1.5 space-y-0.5">
              <div className="h-1 w-full rounded-full bg-border overflow-hidden">
                <div
                  className="h-full bg-warning transition-all duration-300 rounded-full"
                  style={{ width: `${bulkTotal > 0 ? Math.round((bulkDone / bulkTotal) * 100) : 0}%` }}
                />
              </div>
              {bulkCurrentHost && (
                <div className="text-[9.5px] font-mono text-muted-foreground truncate">
                  → {bulkCurrentHost}
                </div>
              )}
            </div>
          )}
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
        {/* Pre-dashboard header (idle / running / failed) */}
        {!showDashboard && (
          <div className="px-3 py-3 border-b border-border bg-[var(--panel)] flex items-start gap-4">
            <div className="flex-1">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">target</div>
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
                {scanState === 'failed' && (
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-critical">scan failed</span>
                )}
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <BarBtn icon={RefreshCw} label="Re-scan" onClick={handleStartScan} />
              <BarBtn icon={Download} label="Export" />
              <BarBtn icon={ShieldOff} label="Isolate" tone="critical" />
            </div>
          </div>
        )}

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

        {/* SOC dashboard (finished state) */}
        {showDashboard && (
          <FullScanReportDashboard
            result={result}
            findings={findings}
            suggestions={suggestions}
            selectedFinding={selectedFinding}
            onSelectFinding={setSelectedFinding}
            selectedHost={selectedHost}
            host={host}
            onRescan={handleStartScan}
            scanTime={scanTime}
          />
        )}

        {/* Scan-in-progress animation */}
        {scanState === 'running' && (
          <div className="flex-1 flex flex-col items-center justify-center gap-7 select-none relative overflow-hidden">

            {/* Background dot-grid */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{
                backgroundImage: `radial-gradient(circle, color-mix(in oklab, var(--primary) 18%, transparent) 1px, transparent 1px)`,
                backgroundSize: '28px 28px',
                opacity: 0.35,
              }}
            />
            {/* Vignette overlay */}
            <div
              className="absolute inset-0 pointer-events-none"
              style={{ background: 'radial-gradient(ellipse 70% 70% at 50% 50%, transparent 40%, var(--background) 100%)' }}
            />

            {/* ── Main reticle ── */}
            <div className="relative" style={{ width: 280, height: 280 }}>

              {/* Corner target brackets */}
              {([
                { style: { top: 0, left: 0 },         path: 'M2 26 L2 2 L26 2' },
                { style: { top: 0, right: 0 },         path: 'M2 2 L26 2 L26 26' },
                { style: { bottom: 0, right: 0 },      path: 'M26 2 L26 26 L2 26' },
                { style: { bottom: 0, left: 0 },       path: 'M26 26 L2 26 L2 2' },
              ] as const).map(({ style, path }, i) => (
                <svg
                  key={i}
                  className="absolute"
                  width="28" height="28"
                  viewBox="0 0 28 28"
                  fill="none"
                  style={{ ...style, animation: 'scanCornerPulse 2s ease-in-out infinite', animationDelay: `${i * 0.18}s` }}
                >
                  <path d={path} stroke="var(--primary)" strokeWidth="1.5" strokeLinecap="square" />
                </svg>
              ))}

              {/* Outermost slow counter-rotating dashed ring */}
              <div
                className="absolute inset-0 rounded-full"
                style={{
                  border: '1px dashed color-mix(in oklab, var(--primary) 22%, transparent)',
                  animation: 'spin 22s linear infinite reverse',
                }}
              />

              {/* Fast sweep ring (gradient-border effect) */}
              <div
                className="absolute rounded-full"
                style={{
                  inset: 16,
                  border: '1px solid transparent',
                  borderTopColor: 'color-mix(in oklab, var(--primary) 80%, transparent)',
                  borderRightColor: 'color-mix(in oklab, var(--primary) 30%, transparent)',
                  borderBottomColor: 'color-mix(in oklab, var(--primary) 6%, transparent)',
                  borderLeftColor: 'color-mix(in oklab, var(--primary) 45%, transparent)',
                  borderRadius: '50%',
                  animation: 'spin 4.5s linear infinite',
                  boxShadow: '0 0 6px 1px color-mix(in oklab, var(--primary) 25%, transparent)',
                }}
              />

              {/* Counter-rotating inner accent ring */}
              <div
                className="absolute rounded-full"
                style={{
                  inset: 44,
                  border: '1px solid transparent',
                  borderRightColor: 'color-mix(in oklab, var(--primary) 60%, transparent)',
                  borderBottomColor: 'color-mix(in oklab, var(--primary) 20%, transparent)',
                  borderRadius: '50%',
                  animation: 'spin 3s linear infinite reverse',
                }}
              />

              {/* Static reference rings */}
              {[180, 128, 82].map((d, i) => (
                <div
                  key={i}
                  className="absolute rounded-full"
                  style={{
                    width: d, height: d,
                    top: '50%', left: '50%',
                    transform: 'translate(-50%, -50%)',
                    border: `1px solid color-mix(in oklab, var(--primary) ${10 + i * 4}%, transparent)`,
                  }}
                />
              ))}

              {/* Sweep cone */}
              <div
                className="absolute rounded-full overflow-hidden"
                style={{ inset: 16 }}
              >
                <div
                  className="absolute inset-0 origin-center"
                  style={{
                    animation: 'spin 2s linear infinite',
                    background: `conic-gradient(
                      from 0deg,
                      transparent 0%,
                      transparent 42%,
                      color-mix(in oklab, var(--primary) 4%, transparent) 58%,
                      color-mix(in oklab, var(--primary) 18%, transparent) 75%,
                      color-mix(in oklab, var(--primary) 50%, transparent) 90%,
                      color-mix(in oklab, var(--primary) 75%, transparent) 100%
                    )`,
                  }}
                />
              </div>

              {/* Scanning beam (horizontal line sweeps top→bottom) */}
              <div
                className="absolute overflow-hidden"
                style={{ inset: 16, borderRadius: '50%' }}
              >
                <div
                  className="absolute left-0 right-0"
                  style={{
                    height: 1,
                    background: `linear-gradient(90deg,
                      transparent 0%,
                      color-mix(in oklab, var(--primary) 85%, transparent) 35%,
                      color-mix(in oklab, var(--primary) 85%, transparent) 65%,
                      transparent 100%)`,
                    boxShadow: `0 0 10px 2px color-mix(in oklab, var(--primary) 55%, transparent)`,
                    animation: 'scanBeam 2.4s ease-in-out infinite',
                  }}
                />
              </div>

              {/* Crosshair ticks */}
              <div className="absolute inset-0">
                <div className="absolute top-1/2 left-4 right-4 -translate-y-px"
                  style={{ height: 1, background: 'color-mix(in oklab, var(--primary) 7%, transparent)' }} />
                <div className="absolute left-1/2 top-4 bottom-4 -translate-x-px"
                  style={{ width: 1, background: 'color-mix(in oklab, var(--primary) 7%, transparent)' }} />
                {/* Edge tick marks */}
                {[
                  { style: { top: '50%', left: 16, width: 10, height: 1, transform: 'translateY(-50%)' } },
                  { style: { top: '50%', right: 16, width: 10, height: 1, transform: 'translateY(-50%)' } },
                  { style: { left: '50%', top: 16, width: 1, height: 10, transform: 'translateX(-50%)' } },
                  { style: { left: '50%', bottom: 16, width: 1, height: 10, transform: 'translateX(-50%)' } },
                ].map((t, i) => (
                  <div
                    key={i}
                    className="absolute"
                    style={{ ...t.style, background: 'color-mix(in oklab, var(--primary) 45%, transparent)' }}
                  />
                ))}
              </div>

              {/* Data blip dots on outer ring */}
              {[0, 60, 120, 180, 240, 300].map((deg, i) => (
                <div
                  key={i}
                  className="absolute rounded-full"
                  style={{
                    width: 3, height: 3,
                    background: 'var(--primary)',
                    top:  `calc(50% + ${Math.sin((deg * Math.PI) / 180) * 122}px - 1.5px)`,
                    left: `calc(50% + ${Math.cos((deg * Math.PI) / 180) * 122}px - 1.5px)`,
                    animation: 'scanDataBlip 2s ease-in-out infinite',
                    animationDelay: `${i * 0.33}s`,
                    boxShadow: '0 0 4px 1px color-mix(in oklab, var(--primary) 70%, transparent)',
                  }}
                />
              ))}

              {/* Center reticle */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="relative flex items-center justify-center">
                  <div
                    className="h-2.5 w-2.5 rounded-full"
                    style={{
                      background: 'var(--primary)',
                      boxShadow: '0 0 14px 4px color-mix(in oklab, var(--primary) 65%, transparent)',
                      animation: 'scanCornerPulse 1.4s ease-in-out infinite',
                    }}
                  />
                  <div
                    className="absolute rounded-full border border-primary/50 animate-ping"
                    style={{ width: 20, height: 20, animationDuration: '1.6s' }}
                  />
                  <div
                    className="absolute rounded-full border border-primary/20 animate-ping"
                    style={{ width: 36, height: 36, animationDuration: '2.2s', animationDelay: '0.4s' }}
                  />
                </div>
              </div>
            </div>

            {/* ── HUD status panel ── */}
            <div className="text-center space-y-2.5 relative z-10">
              <div className="text-[9px] font-mono tracking-[0.4em] uppercase"
                style={{ color: 'color-mix(in oklab, var(--primary) 45%, transparent)' }}>
                threat · scan · protocol
              </div>
              <div
                className="text-[15px] font-mono font-semibold tracking-[0.15em]"
                style={{
                  color: 'var(--primary)',
                  textShadow: '0 0 20px color-mix(in oklab, var(--primary) 60%, transparent)',
                }}
              >
                {selectedHost}
              </div>

              {/* Segmented progress bar */}
              <div className="flex gap-[3px] justify-center">
                {Array.from({ length: 24 }).map((_, i) => {
                  const filled = progress > 0 ? i < Math.round((progress / 100) * 24) : i < 1;
                  const isFront = progress > 0 && i === Math.round((progress / 100) * 24) - 1;
                  return (
                    <div
                      key={i}
                      style={{
                        width: 9, height: 5,
                        borderRadius: 1,
                        background: filled
                          ? 'var(--primary)'
                          : 'color-mix(in oklab, var(--primary) 13%, transparent)',
                        opacity: filled ? 1 : 0.5,
                        boxShadow: isFront
                          ? '0 0 10px 3px color-mix(in oklab, var(--primary) 80%, transparent)'
                          : 'none',
                        transition: 'box-shadow 0.2s',
                      }}
                    />
                  );
                })}
              </div>

              <div className="text-[10.5px] font-mono tabular-nums"
                style={{ color: 'color-mix(in oklab, var(--primary) 65%, transparent)' }}>
                {progress > 0 ? `${progress}%` : 'initializing…'}
              </div>
              {scanLog.length > 0 && (
                <div className="text-[10px] font-mono max-w-[400px] truncate"
                  style={{ color: 'color-mix(in oklab, var(--primary) 35%, transparent)' }}>
                  ▸ {scanLog[scanLog.length - 1]}
                </div>
              )}
            </div>
          </div>
        )}

        {scanState === 'idle' && findings.length === 0 && (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select a host and start a scan →
          </div>
        )}
      </div>

      {/* Right: context / finding detail (hidden when dashboard is showing) */}
      {!showDashboard && (
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
      )}
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
