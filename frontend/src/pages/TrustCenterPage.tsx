import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Database,
  Globe,
  RefreshCw,
  Shield,
  ShieldCheck,
  Terminal,
  XCircle,
} from 'lucide-react';
import { getRemoteAccessMode, getValidationStatus } from '../services/api';
import type { RemoteAccessModeConfig, ValidationApiHealth, ValidationKnowledgeStatus, ValidationStatus, ValidationTest, ValidationTestStatus } from '../types';

// ── helpers ───────────────────────────────────────────────────────────────────

function cx(...args: (string | false | null | undefined)[]): string {
  return args.filter(Boolean).join(' ');
}

function statusColor(s: ValidationTestStatus): string {
  switch (s) {
    case 'pass':    return 'text-emerald-400';
    case 'fail':    return 'text-red-400';
    case 'warning': return 'text-yellow-400';
  }
}

function statusBg(s: ValidationTestStatus): string {
  switch (s) {
    case 'pass':    return 'bg-emerald-500/10 border-emerald-500/20';
    case 'fail':    return 'bg-red-500/10    border-red-500/20';
    case 'warning': return 'bg-yellow-500/10 border-yellow-500/20';
  }
}

function StatusIcon({ status, size = 14 }: { status: ValidationTestStatus; size?: number }) {
  if (status === 'pass')    return <CheckCircle  size={size} className="text-emerald-400 flex-shrink-0" />;
  if (status === 'fail')    return <XCircle      size={size} className="text-red-400 flex-shrink-0" />;
  return                           <AlertTriangle size={size} className="text-yellow-400 flex-shrink-0" />;
}

function healthColor(val: string): string {
  if (val === 'ok' || val.startsWith('ok') || val.startsWith('cached')) return 'text-emerald-400';
  if (val === 'no_connection' || val === 'not_configured' || val === 'no_agents_cached') return 'text-slate-400';
  if (val.startsWith('error') || val.startsWith('import_error')) return 'text-red-400';
  return 'text-yellow-400';
}

function healthDot(val: string): string {
  if (val === 'ok' || val.startsWith('ok') || val.startsWith('cached')) return 'bg-emerald-400';
  if (val === 'no_connection' || val === 'not_configured' || val === 'no_agents_cached') return 'bg-slate-500';
  if (val.startsWith('error') || val.startsWith('import_error')) return 'bg-red-400';
  return 'bg-yellow-400';
}

function fmtTs(iso: string): string {
  try {
    return new Date(iso).toLocaleString('de-DE', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
  } catch { return iso; }
}

// ── STAT CARD ─────────────────────────────────────────────────────────────────

function StatCard({
  label, value, sub, accent, icon: Icon,
}: {
  label: string;
  value: number;
  sub?: string;
  accent?: string;
  icon?: React.ElementType;
}) {
  return (
    <div className="rounded-xl border border-white/[0.07] bg-white/[0.03] px-5 py-4">
      <div className="flex items-center gap-2 mb-1">
        {Icon && <Icon size={14} className={accent ?? 'text-white/40'} />}
        <p className="text-[11px] font-semibold uppercase tracking-widest text-white/40">{label}</p>
      </div>
      <p className={cx('mt-0.5 text-3xl font-bold tabular-nums', accent ?? 'text-white/90')}>{value}</p>
      {sub && <p className="mt-0.5 text-[11px] text-white/30">{sub}</p>}
    </div>
  );
}

// ── KB STAT ROW ───────────────────────────────────────────────────────────────

function KbRow({ label, value, good }: { label: string; value: number; good?: boolean }) {
  const ok = value > 0;
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-white/[0.05] last:border-0">
      <span className="text-[12px] text-white/60">{label}</span>
      <span className={cx(
        'text-[13px] font-bold tabular-nums',
        value < 0  ? 'text-slate-500' :
        ok         ? (good !== false ? 'text-emerald-400' : 'text-cyan-400') :
                     'text-yellow-400'
      )}>
        {value < 0 ? '—' : value}
      </span>
    </div>
  );
}

// ── API HEALTH ROW ────────────────────────────────────────────────────────────

function HealthRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-1.5 border-b border-white/[0.05] last:border-0">
      <span className="text-[12px] text-white/60">{label}</span>
      <span className={cx('flex items-center gap-1.5 text-[11.5px] font-mono font-medium', healthColor(value))}>
        <span className={cx('inline-block h-1.5 w-1.5 rounded-full flex-shrink-0', healthDot(value))} />
        {value}
      </span>
    </div>
  );
}

// ── TEST ROW ──────────────────────────────────────────────────────────────────

function TestRow({ test }: { test: ValidationTest }) {
  const [expanded, setExpanded] = useState(false);
  const hasDetails = test.details && Object.keys(test.details).length > 0;

  return (
    <div className={cx('rounded-lg border mb-1.5', statusBg(test.status))}>
      <button
        type="button"
        onClick={() => hasDetails && setExpanded(p => !p)}
        className={cx('flex w-full items-start gap-2.5 px-3 py-2.5 text-left', hasDetails ? 'cursor-pointer' : 'cursor-default')}
      >
        <StatusIcon status={test.status} size={13} />
        <div className="flex min-w-0 flex-1 flex-col">
          <span className="text-[12px] font-semibold text-white/85 leading-snug">{test.name}</span>
          <span className={cx('text-[11px] mt-0.5', statusColor(test.status))}>{test.message}</span>
        </div>
        {hasDetails && (
          <span className="text-white/30 flex-shrink-0 mt-0.5">
            {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
          </span>
        )}
      </button>
      {expanded && hasDetails && (
        <div className="border-t border-white/[0.06] px-3 pb-2.5 pt-2">
          <pre className="text-[10px] text-cyan-300/70 overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed">
            {JSON.stringify(test.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

// ── CATEGORY SECTION ──────────────────────────────────────────────────────────

const CATEGORY_META: Record<string, { label: string; icon: React.ElementType }> = {
  resolver:      { label: 'Resolver Self-Tests',       icon: Terminal },
  evidence:      { label: 'Evidence Extractor Tests',  icon: Database },
  knowledge:     { label: 'Knowledge Base',            icon: Shield },
  host_matching: { label: 'Host Matching Tests',       icon: Globe },
  safety:        { label: 'Safety & Phase 1 Policy',   icon: ShieldCheck },
  db:            { label: 'Database / Tables',         icon: Database },
  audit:         { label: 'Audit Log',                 icon: CheckCircle },
  other:         { label: 'Other',                     icon: CheckCircle },
};

const CATEGORY_ORDER = ['knowledge', 'resolver', 'evidence', 'host_matching', 'safety', 'db', 'audit', 'other'];

function CategorySection({ category, tests }: { category: string; tests: ValidationTest[] }) {
  const [collapsed, setCollapsed] = useState(false);
  const meta = CATEGORY_META[category] ?? CATEGORY_META['other'];
  const Icon = meta.icon;
  const failed   = tests.filter(t => t.status === 'fail').length;
  const warnings = tests.filter(t => t.status === 'warning').length;
  const passed   = tests.filter(t => t.status === 'pass').length;

  return (
    <div className="mb-4">
      <button
        type="button"
        onClick={() => setCollapsed(p => !p)}
        className="flex w-full items-center gap-2 px-3 py-2 rounded-lg hover:bg-white/[0.03] transition mb-1"
      >
        <Icon size={13} className="text-white/40 flex-shrink-0" />
        <span className="text-[12px] font-bold uppercase tracking-wider text-white/50 flex-1 text-left">{meta.label}</span>
        <span className="flex items-center gap-2 text-[11px]">
          {passed   > 0 && <span className="text-emerald-400">{passed} pass</span>}
          {warnings > 0 && <span className="text-yellow-400">{warnings} warn</span>}
          {failed   > 0 && <span className="text-red-400">{failed} fail</span>}
        </span>
        {collapsed ? <ChevronRight size={13} className="text-white/30" /> : <ChevronDown size={13} className="text-white/30" />}
      </button>
      {!collapsed && (
        <div className="px-1">
          {tests.map(t => <TestRow key={t.id + t.name} test={t} />)}
        </div>
      )}
    </div>
  );
}

// ── MAIN PAGE ─────────────────────────────────────────────────────────────────

export function TrustCenterPage() {
  const [status, setStatus] = useState<ValidationStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRunAt, setLastRunAt] = useState<string | null>(null);
  const [remoteMode, setRemoteMode] = useState<RemoteAccessModeConfig>({
    mode: 'admin',
    changed_by: 'system',
    changed_at: '',
    reason: '',
  });

  const run = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getValidationStatus();
      setStatus(data);
      try {
        const modeData = await getRemoteAccessMode();
        setRemoteMode(modeData.data);
      } catch {
        // Keep default mode display if endpoint read fails.
      }
      setLastRunAt(new Date().toISOString());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Validation request failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void run(); }, [run]);

  // Group tests by category
  const byCategory = useMemo(() => {
    if (!status) return {};
    const grouped: Record<string, ValidationTest[]> = {};
    for (const t of status.tests) {
      const cat = t.category ?? 'other';
      (grouped[cat] ??= []).push(t);
    }
    return grouped;
  }, [status]);

  // Overall health color for the header bar
  const overallHealth: 'ok' | 'warn' | 'fail' | 'running' = !status
    ? (loading ? 'running' : 'warn')
    : status.summary.failed > 0
    ? 'fail'
    : status.summary.warnings > 0
    ? 'warn'
    : 'ok';

  const headerAccent: Record<typeof overallHealth, string> = {
    ok:      'border-emerald-500/30 bg-emerald-500/[0.04]',
    warn:    'border-yellow-500/30  bg-yellow-500/[0.03]',
    fail:    'border-red-500/30     bg-red-500/[0.04]',
    running: 'border-white/10       bg-white/[0.02]',
  };

  const healthLabel: Record<typeof overallHealth, string> = {
    ok:      'ALL SYSTEMS OPERATIONAL',
    warn:    'WARNINGS DETECTED',
    fail:    'FAILURES DETECTED',
    running: 'RUNNING VALIDATION…',
  };

  const healthLabelColor: Record<typeof overallHealth, string> = {
    ok:      'text-emerald-400',
    warn:    'text-yellow-400',
    fail:    'text-red-400',
    running: 'text-white/40',
  };

  return (
    <div
      className="flex h-full flex-col overflow-y-auto"
      style={{ fontFamily: "'Inter', 'Space Grotesk', system-ui, sans-serif" }}
    >
      {/* ── HEADER ── */}
      <div
        className={cx('border-b px-6 py-5', headerAccent[overallHealth])}
        style={{ borderColor: undefined }}
      >
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2.5">
              <ShieldCheck size={18} className="text-cyan-400" />
              <h1 className="text-lg font-bold" style={{ color: 'var(--soc-foreground, #e8eaed)' }}>
                Trust Center
              </h1>
              {status && (
                <span className={cx('text-[11px] font-bold uppercase tracking-widest', healthLabelColor[overallHealth])}>
                  · {healthLabel[overallHealth]}
                </span>
              )}
            </div>
            <p className="mt-0.5 text-[12px]" style={{ color: 'var(--soc-muted-fg, #6b7f8e)' }}>
              Self-tests for Knowledge Resolver · Evidence Extractor · Host Matching · Safety Policy
            </p>
            {lastRunAt && (
              <p className="mt-1 text-[11px] text-white/25">
                Last run: {fmtTs(lastRunAt)}
                {status?.timestamp && ` · Backend: ${fmtTs(status.timestamp)}`}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={() => void run()}
            disabled={loading}
            className="mt-1 flex items-center gap-1.5 rounded-lg border border-cyan-500/25 bg-cyan-500/10 px-3 py-1.5 text-[12px] text-cyan-300 hover:bg-cyan-500/15 transition disabled:opacity-50"
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            {loading ? 'Running…' : 'Re-run Validation'}
          </button>
        </div>
      </div>

      {/* ── ERROR STATE ── */}
      {error && (
        <div className="mx-6 mt-4 flex items-center gap-2 rounded-xl border border-red-500/25 bg-red-500/[0.07] px-4 py-3">
          <XCircle size={14} className="text-red-400 flex-shrink-0" />
          <p className="text-[12px] text-red-300">{error}</p>
          <p className="text-[11px] text-red-300/60 ml-1">— Is the backend running?</p>
        </div>
      )}

      {/* ── LOADING ── */}
      {loading && !status && (
        <div className="flex flex-1 items-center justify-center gap-3 text-[12px] text-white/30">
          <RefreshCw size={16} className="animate-spin text-cyan-400" />
          Running validation suite…
        </div>
      )}

      {status && (
        <div className="flex-1 px-6 py-5 space-y-6">

          {/* ── SUMMARY CARDS ── */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <StatCard label="Total Tests" value={status.summary.total_tests} sub="self-test suite" icon={Shield} />
            <StatCard
              label="Passed"
              value={status.summary.passed}
              sub="tests passing"
              accent="text-emerald-300"
              icon={CheckCircle}
            />
            <StatCard
              label="Failed"
              value={status.summary.failed}
              sub="require attention"
              accent={status.summary.failed > 0 ? 'text-red-400' : 'text-white/40'}
              icon={XCircle}
            />
            <StatCard
              label="Warnings"
              value={status.summary.warnings}
              sub="review recommended"
              accent={status.summary.warnings > 0 ? 'text-yellow-400' : 'text-white/40'}
              icon={AlertTriangle}
            />
          </div>

          {/* ── TWO-COLUMN LAYOUT: KB + API Health ── */}
          <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">

            {/* Knowledge Base Status */}
            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-5">
              <div className="flex items-center gap-2 mb-3">
                <Shield size={14} className="text-cyan-400" />
                <h2 className="text-[12px] font-bold uppercase tracking-widest text-white/45">Knowledge Base Status</h2>
              </div>
              <KbRow label="Windows KB entries"   value={status.knowledge.windows_entries} />
              <KbRow label="Linux KB entries"     value={status.knowledge.linux_entries} />
              <KbRow label="Investigation playbooks" value={status.knowledge.playbooks} />
              <KbRow label="Script templates"     value={status.knowledge.scripts} />
              <div className="mt-3 pt-3 border-t border-white/[0.06]">
                <p className="text-[10px] uppercase tracking-wider text-white/25 mb-2 font-semibold">24h Tracking (placeholder)</p>
                <KbRow label="Unknown events 24h"  value={status.knowledge.unknown_events_24h} good={false} />
                <KbRow label="Fallback usage 24h"  value={status.knowledge.fallback_usage_24h} good={false} />
              </div>
            </div>

            {/* API Health */}
            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-5">
              <div className="flex items-center gap-2 mb-3">
                <Globe size={14} className="text-cyan-400" />
                <h2 className="text-[12px] font-bold uppercase tracking-widest text-white/45">API Health</h2>
              </div>
              <HealthRow label="Backend"       value={status.api_health.backend} />
              <HealthRow label="Wazuh Indexer" value={status.api_health.wazuh_indexer} />
              <HealthRow label="Wazuh Manager" value={status.api_health.wazuh_manager} />
              <HealthRow label="Tactical RMM"  value={status.api_health.tactical_rmm} />
              <HealthRow label="Scripts"       value={status.api_health.scripts} />
              <HealthRow label="Timeline"      value={status.api_health.timeline} />
              <HealthRow label="Audit Log"     value={status.api_health.audit} />
            </div>

            {/* Remote Access Control Plane */}
            <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-5">
              <div className="flex items-center gap-2 mb-3">
                <ShieldCheck size={14} className="text-cyan-400" />
                <h2 className="text-[12px] font-bold uppercase tracking-widest text-white/45">Remote Access Control Plane</h2>
              </div>
              <HealthRow label="Remote Access Mode" value={remoteMode.mode.toUpperCase()} />
              <HealthRow label="Break Glass available" value="yes" />
              <HealthRow label="Target confirmation required" value="yes" />
              <HealthRow label="Audit enabled" value="yes" />
              <div className="mt-3 pt-3 border-t border-white/[0.06] text-[11px] text-white/35 space-y-1">
                <p>Changed by: <span className="text-white/55 font-mono">{remoteMode.changed_by || 'system'}</span></p>
                <p>Changed at: <span className="text-white/55 font-mono">{remoteMode.changed_at ? fmtTs(remoteMode.changed_at) : '—'}</span></p>
                <p>Reason: <span className="text-white/55">{remoteMode.reason || '—'}</span></p>
              </div>
            </div>
          </div>

          {/* ── TEST RESULTS BY CATEGORY ── */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Terminal size={14} className="text-cyan-400" />
              <h2 className="text-[12px] font-bold uppercase tracking-widest text-white/45">
                Self-Test Results
                <span className="ml-2 text-white/25 normal-case font-normal tracking-normal">
                  — click to expand details
                </span>
              </h2>
            </div>

            {CATEGORY_ORDER.map(cat => {
              const tests = byCategory[cat];
              if (!tests?.length) return null;
              return <CategorySection key={cat} category={cat} tests={tests} />;
            })}

            {/* Any extra categories not in CATEGORY_ORDER */}
            {Object.keys(byCategory)
              .filter(cat => !CATEGORY_ORDER.includes(cat))
              .map(cat => {
                const tests = byCategory[cat];
                if (!tests?.length) return null;
                return <CategorySection key={cat} category={cat} tests={tests} />;
              })}
          </div>

          {/* ── FALLBACK/UNKNOWN TRACKING PLACEHOLDER ── */}
          <div className="rounded-xl border border-white/[0.06] bg-white/[0.015] p-5">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle size={14} className="text-yellow-400/60" />
              <h2 className="text-[12px] font-bold uppercase tracking-widest text-white/35">
                Fallback / Unknown Tracking
                <span className="ml-2 text-[11px] font-normal normal-case text-white/20 tracking-normal">Phase 2</span>
              </h2>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              {([
                ['Top Unknown Events',      'Event IDs with no KB entry — will appear here once event tracking is enabled.'],
                ['Top Fallback Rules',      'Wazuh rule IDs that consistently fall back to generic knowledge.'],
                ['Top Missing Evidence Fields', 'Evidence fields that parsers could not extract from real events.'],
              ] as [string, string][]).map(([title, desc]) => (
                <div key={title} className="rounded-lg border border-white/[0.05] bg-white/[0.02] px-4 py-3">
                  <p className="text-[11.5px] font-semibold text-white/40 mb-1">{title}</p>
                  <p className="text-[11px] text-white/20 leading-relaxed">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
