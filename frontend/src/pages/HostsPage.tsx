import { useEffect, useMemo, useState } from 'react';
import {
  Server, Wifi, WifiOff, ShieldAlert, Gauge,
  Star, Search, RefreshCw, UserCircle, X, MoreVertical,
  Monitor, Globe, Cpu, Clock, FileSearch,
  ShieldCheck, Terminal, UserPlus,
  Eye, ShieldOff,
} from 'lucide-react';
import { getHostsCentral, removeHostProfileAssignment, setHostProfileAssignment } from '../services/api';
import type { HostCentralListItem, HostProfile, HostProfileAssignment } from '../types';
import { ProfileBadge } from '../components/ProfileBadge';

// ── helpers ──────────────────────────────────────────────────────────────────

function cx(...classes: (string | false | undefined | null)[]): string {
  return classes.filter(Boolean).join(' ');
}

const GAUGE_R = 46;
const CIRCUMFERENCE = 2 * Math.PI * GAUGE_R; // ≈ 289.03

function risk10(score: number): number {
  return score; // already 0-10 scale
}

function riskLabel(r10: number): string {
  if (r10 >= 8) return 'Critical';
  if (r10 >= 7) return 'High Risk';
  if (r10 >= 5) return 'Medium Risk';
  if (r10 >= 3) return 'Low Risk';
  return 'Safe';
}

function riskTextClass(r10: number): string {
  if (r10 >= 7) return 'text-red-400';
  if (r10 >= 5) return 'text-orange-400';
  if (r10 >= 3) return 'text-yellow-400';
  return 'text-emerald-400';
}

function riskSubTextClass(r10: number): string {
  if (r10 >= 7) return 'text-red-300';
  if (r10 >= 5) return 'text-orange-300';
  if (r10 >= 3) return 'text-yellow-300';
  return 'text-emerald-300';
}

function riskBadgeCx(r10: number): string {
  if (r10 >= 7) return 'bg-red-500/20 text-red-300 border border-red-500/30';
  if (r10 >= 5) return 'bg-orange-500/20 text-orange-300 border border-orange-500/30';
  if (r10 >= 3) return 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30';
  return 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30';
}

function riskRowAccent(r10: number): string {
  if (r10 >= 7) return 'bg-red-500/[0.04]';
  if (r10 >= 5) return 'bg-orange-500/[0.03]';
  return '';
}

function summaryText(hostname: string, r10: number): string {
  if (r10 >= 8) return `${hostname} is in critical state`;
  if (r10 >= 7) return `${hostname} requires immediate attention`;
  if (r10 >= 5) return `${hostname} has elevated risk`;
  if (r10 >= 3) return `${hostname} shows low-level activity`;
  return `${hostname} is currently safe`;
}

function freshnessInfo(iso: string | null | undefined): { label: string; cx: string } {
  if (!iso) return { label: 'Never', cx: 'text-slate-600' };
  const ms = Date.now() - new Date(iso.replace('Z', '+00:00')).getTime();
  const h = ms / 3_600_000;
  if (h < 1)   return { label: '< 1h ago',                   cx: 'text-emerald-400' };
  if (h < 6)   return { label: `${Math.floor(h)}h ago`,      cx: 'text-emerald-300' };
  if (h < 24)  return { label: `${Math.floor(h)}h ago`,      cx: 'text-yellow-400' };
  if (h < 168) return { label: `${Math.floor(h / 24)}d ago`, cx: 'text-orange-400' };
  return         { label: `${Math.floor(h / 24 / 7)}w ago`,  cx: 'text-red-400' };
}

function riskBorderLClass(r10: number): string {
  if (r10 >= 7) return 'border-l-critical';
  if (r10 >= 5) return 'border-l-high';
  if (r10 >= 3) return 'border-l-warning';
  return 'border-l-success';
}

// ── types ────────────────────────────────────────────────────────────────────

type HostsPageProps = {
  active: boolean;
  theme: 'light' | 'dark';
  profiles: HostProfile[];
  profileAssignments: Record<string, HostProfileAssignment>;
  onProfileAssignmentChanged: (host: string, assignment: HostProfileAssignment | null) => void;
  onSwitchTab: (tab: 'dashboard' | 'chat' | 'tasks' | 'snipen' | 'fullscan' | 'hosts') => void;
  onOpenOverview: (host: string) => void;
};

type StatusFilter = 'ALL' | 'ONLINE' | 'OFFLINE';

// ── KpiCard ───────────────────────────────────────────────────────────────────

function KpiCard({
  label, value, sub, icon: Icon, accent, pulse,
}: {
  label: string;
  value: string | number;
  sub: string;
  icon: React.ComponentType<{ className?: string }>;
  accent: 'cyan' | 'green' | 'red' | 'orange' | 'yellow';
  pulse?: boolean;
}) {
  const t: Record<string, { bg: string; icon: string; val: string; border: string }> = {
    red:    { bg: 'bg-red-500/[0.08]',    icon: 'text-red-400 bg-red-500/15',          val: 'text-red-300',    border: 'border-red-500/25' },
    orange: { bg: 'bg-orange-500/[0.06]', icon: 'text-orange-400 bg-orange-500/15',    val: 'text-orange-300', border: 'border-orange-500/25' },
    green:  { bg: 'bg-emerald-500/[0.05]',icon: 'text-emerald-400 bg-emerald-500/15',  val: 'text-emerald-300',border: 'border-emerald-500/20' },
    cyan:   { bg: 'bg-white/[0.03]',      icon: 'text-cyan-400 bg-cyan-500/15',        val: 'text-white',      border: 'border-white/[0.06]' },
    yellow: { bg: 'bg-yellow-500/[0.04]', icon: 'text-yellow-400 bg-yellow-500/15',    val: 'text-yellow-300', border: 'border-yellow-500/20' },
  };
  const th = t[accent];
  return (
    <div className={cx('flex items-center gap-3 rounded-xl border px-3 py-2.5', th.bg, th.border)}>
      <div className={cx('relative h-9 w-9 rounded-lg flex items-center justify-center shrink-0', th.icon)}>
        <Icon className="h-5 w-5" />
        {pulse && <span className="absolute -right-0.5 -top-0.5 h-2 w-2 rounded-full bg-red-500 ring-2 ring-black" />}
      </div>
      <div className="min-w-0 flex-1">
        <div className={cx('text-xl font-bold leading-tight tabular-nums', th.val)}>{value}</div>
        <div className="truncate text-[11px] font-semibold text-slate-400">{label}</div>
        <div className="truncate text-[10px] text-slate-600">{sub}</div>
      </div>
    </div>
  );
}

// ── CapabilityChips ───────────────────────────────────────────────────────────

function CapabilityChips({ h }: { h: HostCentralListItem }) {
  const tStatus = h.tactical_status || (h.connection_status === 'reachable' ? 'online' : h.connection_status === 'unreachable' ? 'offline' : 'unknown');
  const wazuhOk = !!h.last_activity &&
    (Date.now() - new Date(h.last_activity.replace('Z', '+00:00')).getTime()) < 6 * 3_600_000;

  const chips = [
    { label: 'W', ok: wazuhOk,                                                                title: wazuhOk ? 'Wazuh: connected' : 'Wazuh: stale' },
    { label: 'T', ok: tStatus === 'online' ? true : tStatus === 'unknown' ? null : false,     title: `Tactical: ${tStatus}` },
    { label: 'R', ok: h.rdp_enabled ? true : null,                                            title: h.rdp_enabled ? 'RDP: enabled' : 'RDP: N/A' },
    { label: 'S', ok: h.ssh_enabled ? true : null,                                            title: h.ssh_enabled ? 'SSH: enabled' : 'SSH: N/A' },
  ] as { label: string; ok: boolean | null; title: string }[];

  return (
    <div className="flex items-center gap-0.5">
      {chips.map((c) => (
        <span
          key={c.label}
          title={c.title}
          className={cx(
            'inline-flex h-4 w-4 items-center justify-center rounded text-[8px] font-bold',
            c.ok === true  ? 'bg-emerald-500/20 text-emerald-300' :
            c.ok === false ? 'bg-red-500/20 text-red-400' :
                             'bg-slate-700/60 text-slate-600',
          )}
        >
          {c.label}
        </span>
      ))}
    </div>
  );
}

// ── AlertHeat ─────────────────────────────────────────────────────────────────

function AlertHeat({ count }: { count: number }) {
  const [textCx, barCx, pct] =
    count > 200 ? ['text-red-300',    'bg-red-500',    Math.min(100, (count / 500) * 100)] :
    count >  50 ? ['text-orange-300', 'bg-orange-400', Math.min(100, (count / 500) * 100)] :
    count >   0 ? ['text-slate-300',  'bg-cyan-600',   Math.min(100, (count / 500) * 100)] :
                  ['text-slate-600',  'bg-slate-700',  0];
  return (
    <div className="flex flex-col items-end gap-0.5">
      <span className={cx('text-[11px] font-bold tabular-nums', textCx)}>{count}</span>
      <div className="h-0.5 w-10 rounded-full bg-slate-800">
        <div className={cx('h-full rounded-full', barCx)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

// ── InfoRow ───────────────────────────────────────────────────────────────────

function InfoRow({
  icon: Icon, label, value, good, warn,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: React.ReactNode;
  good?: boolean;
  warn?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 py-0.5">
      <span className="flex items-center gap-2 text-xs text-slate-400">
        <Icon className="h-3.5 w-3.5 shrink-0 text-slate-600" />
        {label}
      </span>
      <span className={cx(
        'max-w-[160px] truncate text-xs font-semibold',
        good ? 'text-emerald-300' : warn ? 'text-orange-300' : 'text-slate-100',
      )}>
        {value}
      </span>
    </div>
  );
}

// ── RiskGauge ─────────────────────────────────────────────────────────────────

function RiskGauge({ score100 }: { score100: number }) {
  const r10 = risk10(score100);
  const offset = CIRCUMFERENCE * (1 - Math.min(r10, 10) / 10);
  return (
    <div className="relative h-28 w-28 shrink-0">
      <svg viewBox="0 0 120 120" className="h-28 w-28 -rotate-90">
        <circle cx="60" cy="60" r={GAUGE_R} stroke="currentColor" strokeWidth="10" fill="none" className="text-slate-800" />
        <circle
          cx="60" cy="60" r={GAUGE_R}
          stroke="currentColor" strokeWidth="10" fill="none"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          className={riskTextClass(r10)}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center text-center">
        <div>
          <div className={cx('text-3xl font-bold', riskTextClass(r10))}>{r10.toFixed(1)}</div>
          <div className={cx('text-[10px] font-semibold', riskSubTextClass(r10))}>{riskLabel(r10)}</div>
        </div>
      </div>
    </div>
  );
}

// ── TacticalBadge ────────────────────────────────────────────────────────────

function tacticalDotCx(s: string): string {
  if (s === 'online')  return 'bg-emerald-400 animate-pulse';
  if (s === 'offline') return 'bg-red-500';
  if (s === 'overdue') return 'bg-orange-400';
  return 'bg-slate-500';
}
function tacticalTextCx(s: string): string {
  if (s === 'online')  return 'text-emerald-300';
  if (s === 'offline') return 'text-red-400';
  if (s === 'overdue') return 'text-orange-300';
  return 'text-slate-500';
}
function tacticalBgCx(s: string): string {
  if (s === 'online')  return 'bg-emerald-500/15';
  if (s === 'offline') return 'bg-red-500/15';
  if (s === 'overdue') return 'bg-orange-500/15';
  return 'bg-slate-500/15';
}
function tacticalLabel(s: string): string {
  if (s === 'online')  return 'Online';
  if (s === 'offline') return 'Offline';
  if (s === 'overdue') return 'Overdue';
  return 'Unknown';
}

function TacticalBadge({ status }: { status: string }) {
  return (
    <span className={cx(
      'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-semibold',
      tacticalBgCx(status), tacticalTextCx(status),
    )}>
      <span className={cx('h-1.5 w-1.5 rounded-full', tacticalDotCx(status))} />
      {tacticalLabel(status)}
    </span>
  );
}

// ── DetailPanel ───────────────────────────────────────────────────────────────

function DetailPanel({
  host, allHosts, profileAssignments, profiles, onSwitchTab,
  assigningHost, setAssigningHost, handleAssignProfile,
}: {
  host: HostCentralListItem | null;
  allHosts: HostCentralListItem[];
  profileAssignments: Record<string, HostProfileAssignment>;
  profiles: HostProfile[];
  onSwitchTab: HostsPageProps['onSwitchTab'];
  assigningHost: string | null;
  setAssigningHost: (h: string | null) => void;
  handleAssignProfile: (host: string, profileId: number | null) => Promise<void>;
}) {
  if (!host) {
    return (
      <aside className="w-80 shrink-0 border-l border-white/[0.06] bg-[var(--panel)] grid place-items-center">
        <div className="text-center px-4">
          <Monitor className="h-8 w-8 text-slate-700 mx-auto mb-2" />
          <p className="text-sm text-slate-600">Select a host to inspect</p>
          <p className="text-[11px] text-slate-700 mt-1">Double-click to open full overview</p>
        </div>
      </aside>
    );
  }

  const tStatus = host.tactical_status || (
    host.connection_status === 'reachable' ? 'online' :
    host.connection_status === 'unreachable' ? 'offline' : 'unknown'
  );
  const r10 = risk10(host.risk_score ?? 0);
  const asgn = profileAssignments[host.host];
  const freshness = freshnessInfo(host.last_activity);
  const wazuhOk = !!host.last_activity &&
    (Date.now() - new Date(host.last_activity.replace('Z', '+00:00')).getTime()) < 6 * 3_600_000;

  const percentile = allHosts.length > 0
    ? Math.round((allHosts.filter(h => (h.risk_score ?? 0) < (host.risk_score ?? 0)).length / allHosts.length) * 100)
    : null;

  const accentTop =
    r10 >= 7 ? 'border-t-red-500/70' :
    r10 >= 5 ? 'border-t-orange-500/60' :
    r10 >= 3 ? 'border-t-yellow-500/50' :
    'border-t-emerald-500/40';

  const bullets: { symbol: string; symbolCx: string; text: string; textCx: string }[] = [
    {
      symbol: (host.alerts_24h ?? 0) === 0 ? '✓' : (host.alerts_24h ?? 0) > 200 ? '✗' : '⚠',
      symbolCx: (host.alerts_24h ?? 0) === 0 ? 'text-emerald-400' : (host.alerts_24h ?? 0) > 200 ? 'text-red-400' : 'text-orange-400',
      text: `${host.alerts_24h ?? 0} alerts in last 24h`,
      textCx: (host.alerts_24h ?? 0) > 200 ? 'text-red-300' : (host.alerts_24h ?? 0) > 50 ? 'text-orange-300' : 'text-slate-300',
    },
    {
      symbol: (host.findings_count ?? 0) === 0 ? '✓' : '⚠',
      symbolCx: (host.findings_count ?? 0) === 0 ? 'text-emerald-400' : 'text-orange-400',
      text: `${host.findings_count ?? 0} security findings`,
      textCx: (host.findings_count ?? 0) > 0 ? 'text-orange-300' : 'text-slate-300',
    },
    {
      symbol: wazuhOk ? '✓' : '✗',
      symbolCx: wazuhOk ? 'text-emerald-400' : 'text-red-400',
      text: wazuhOk ? 'Wazuh agent connected' : 'Wazuh agent not reporting',
      textCx: wazuhOk ? 'text-slate-300' : 'text-red-300',
    },
    {
      symbol: tStatus === 'online' ? '✓' : tStatus === 'overdue' ? '⚠' : tStatus === 'unknown' ? '·' : '✗',
      symbolCx: tStatus === 'online' ? 'text-emerald-400' : tStatus === 'overdue' ? 'text-orange-400' : tStatus === 'unknown' ? 'text-slate-600' : 'text-red-400',
      text: `Tactical RMM: ${tacticalLabel(tStatus)}`,
      textCx: tStatus === 'online' ? 'text-slate-300' : tStatus === 'overdue' ? 'text-orange-300' : tStatus === 'offline' ? 'text-red-300' : 'text-slate-500',
    },
    {
      symbol: asgn ? '✓' : '⚠',
      symbolCx: asgn ? 'text-emerald-400' : 'text-orange-400',
      text: asgn ? `Profile: ${asgn.profile_name}` : 'No security profile assigned',
      textCx: asgn ? 'text-slate-300' : 'text-orange-300',
    },
  ];

  return (
    <aside className={cx(
      'flex w-80 shrink-0 flex-col overflow-y-auto border-l border-white/[0.06] bg-[var(--panel)] border-t-2',
      accentTop,
    )}>

      {/* ── Hero ── */}
      <div className="px-4 pt-4 pb-3 border-b border-white/[0.06]">
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-bold leading-tight text-white truncate">{host.host}</h3>
            <p className={cx('text-[11px] mt-0.5 font-medium', riskSubTextClass(r10))}>
              {summaryText(host.host, r10)}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <div className={cx('text-xl font-bold tabular-nums leading-tight', riskTextClass(r10))}>{r10.toFixed(1)}</div>
            <div className={cx('text-[10px] font-semibold', riskSubTextClass(r10))}>{riskLabel(r10)}</div>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <TacticalBadge status={tStatus} />
          {host.ip && <span className="font-mono text-[11px] text-slate-500">{host.ip}</span>}
          {(host.platforms ?? [])[0] && (
            <span className="text-[10px] text-slate-600">{(host.platforms ?? [])[0]}</span>
          )}
        </div>
      </div>

      <div className="flex-1 divide-y divide-white/[0.06]">

        {/* ── Status Overview ── */}
        <section className="px-4 py-3">
          <h4 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Status Overview</h4>
          <div className="space-y-0.5">
            {bullets.map((b, i) => (
              <div key={i} className="flex items-center gap-2 py-0.5">
                <span className={cx('w-3 shrink-0 text-[11px] font-bold', b.symbolCx)}>{b.symbol}</span>
                <span className={cx('text-[11px]', b.textCx)}>{b.text}</span>
              </div>
            ))}
          </div>
          <div className={cx('mt-2 flex items-center gap-1.5 text-[11px]', freshness.cx)}>
            <Clock className="h-3 w-3 opacity-70" />
            <span>Last seen: {freshness.label}</span>
          </div>
        </section>

        {/* ── Risk Score ── */}
        <section className="px-4 py-3">
          <h4 className="mb-3 text-[10px] font-bold uppercase tracking-wider text-slate-500">Risk Score</h4>
          <div className="flex items-center gap-4">
            <RiskGauge score100={host.risk_score ?? 0} />
            <div className="flex-1 space-y-2 text-xs">
              <div>
                <div className="mb-1 flex justify-between text-[10px] text-slate-600">
                  <span>0</span><span>5</span><span>10</span>
                </div>
                <div className="h-1.5 rounded-full bg-slate-800">
                  <div
                    className="h-1.5 rounded-full bg-gradient-to-r from-emerald-400 via-yellow-400 to-red-500"
                    style={{ width: `${(host.risk_score ?? 0) * 10}%` }}
                  />
                </div>
              </div>
              {percentile !== null && (
                <div className="flex justify-between text-slate-400">
                  <span>Fleet rank</span>
                  <span className={cx(
                    'font-semibold',
                    percentile < 25 ? 'text-emerald-300' :
                    percentile > 75 ? 'text-red-300' : 'text-slate-100',
                  )}>
                    top {100 - percentile}%
                  </span>
                </div>
              )}
              <div className="flex justify-between text-slate-400">
                <span>vs. fleet avg</span>
                <span className={riskSubTextClass(r10)}>
                  {r10 >= 7 ? 'High' : r10 >= 5 ? 'Above avg' : r10 >= 3 ? 'Below avg' : 'Low'}
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* ── Scan ── */}
        <section className="px-4 py-3">
          <h4 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Scan</h4>
          <div className="space-y-1.5">
            <InfoRow icon={ShieldCheck} label="Status"    value={host.fullscan_status || 'Never'} good={host.fullscan_status === 'finished'} />
            <InfoRow icon={Clock}       label="Last Scan" value={host.last_scan_at ?? 'No scan yet'} />
            <InfoRow icon={FileSearch}  label="Findings"  value={host.findings_count ?? 0}        good={(host.findings_count ?? 0) === 0} />
          </div>
        </section>

        {/* ── Identity ── */}
        <section className="px-4 py-3">
          <h4 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Identity</h4>
          <div className="space-y-1.5">
            <InfoRow icon={Globe}       label="IP"       value={host.ip ?? <span className="text-slate-600 font-normal">No IP known</span>} />
            <InfoRow icon={Cpu}         label="OS"       value={(host.platforms ?? [])[0] ?? <span className="text-slate-600 font-normal">Unknown OS</span>} />
            <InfoRow
              icon={UserCircle}
              label="Profile"
              value={asgn
                ? <ProfileBadge assignment={asgn} size="sm" showLabel />
                : <span className="text-orange-300/80 text-[11px]">⚠ Not assigned</span>
              }
              warn={!asgn}
            />
          </div>
        </section>

        {/* ── Quick Actions ── */}
        <section className="px-4 py-3">
          <h4 className="mb-2 text-[10px] font-bold uppercase tracking-wider text-slate-500">Quick Actions</h4>
          <div className="grid grid-cols-2 gap-1.5 mb-1.5">
            <button
              onClick={() => onSwitchTab('snipen')}
              className="flex items-center justify-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 transition-colors"
            >
              <Eye className="h-3.5 w-3.5" /> Investigate
            </button>
            <button
              onClick={() => onSwitchTab('fullscan')}
              className="flex items-center justify-center gap-1.5 rounded-lg border border-cyan-400/30 bg-cyan-500/10 px-2 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 transition-colors"
            >
              <Terminal className="h-3.5 w-3.5" /> Full Scan
            </button>
          </div>
          {r10 >= 5 && (
            <button
              onClick={() => { if (window.confirm(`Isolate ${host.host}?`)) alert('Isolation not yet supported.'); }}
              className="flex w-full items-center justify-center gap-1.5 rounded-lg border border-red-400/40 bg-red-500/10 px-2 py-2 text-xs font-semibold text-red-300 hover:bg-red-500/20 transition-colors mb-1.5"
            >
              <ShieldOff className="h-3.5 w-3.5" /> Isolate Host
            </button>
          )}

          <div className="mt-1">
            {assigningHost === host.host ? (
              <div className="flex items-center gap-1.5">
                <select
                  autoFocus
                  className="h-9 flex-1 rounded-lg border border-white/[0.08] bg-white/[0.04] px-2 text-xs text-slate-200 outline-none"
                  defaultValue=""
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val === '__remove__') void handleAssignProfile(host.host, null);
                    else if (val) void handleAssignProfile(host.host, Number(val));
                    else setAssigningHost(null);
                  }}
                >
                  <option value="">Select profile…</option>
                  {profiles.map((p) => (
                    <option key={p.id} value={String(p.id ?? '')}>{p.display_name}</option>
                  ))}
                  {asgn && <option value="__remove__">Remove assignment</option>}
                </select>
                <button
                  onClick={() => setAssigningHost(null)}
                  className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-white/[0.08] bg-white/[0.03] text-slate-500 hover:text-slate-300"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setAssigningHost(host.host)}
                className={cx(
                  'flex w-full items-center justify-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition-colors',
                  asgn
                    ? 'border-white/[0.06] bg-white/[0.02] text-slate-400 hover:bg-white/[0.05] hover:text-slate-200'
                    : 'border-orange-400/35 bg-orange-500/10 text-orange-200 hover:bg-orange-500/20',
                )}
              >
                <UserPlus className="h-3.5 w-3.5" />
                {asgn ? 'Change Profile' : '⚠ Assign Profile'}
              </button>
            )}
          </div>
        </section>
      </div>
    </aside>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function HostsPage({ active, onSwitchTab, onOpenOverview, profiles, profileAssignments, onProfileAssignmentChanged }: HostsPageProps) {
  const [hosts, setHosts] = useState<HostCentralListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL');
  const [profileFilter, setProfileFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<HostCentralListItem | null>(null);
  const [assigningHost, setAssigningHost] = useState<string | null>(null);
  const [favorites, setFavorites] = useState<Set<string>>(new Set());

  const loadHosts = () => {
    setLoading(true);
    setError(null);
    getHostsCentral()
      .then((data) => {
        setHosts(data);
        if (data.length > 0 && !selected) setSelected(data[0]);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : 'Failed to load hosts'))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    if (!active) return;
    loadHosts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  const filtered = useMemo(
    () =>
      hosts.filter((h) => {
        const isOnline = (h.tactical_status || h.connection_status) === 'online' || h.connection_status === 'reachable';
        const statusOk =
          statusFilter === 'ALL' ||
          (statusFilter === 'ONLINE' && isOnline) ||
          (statusFilter === 'OFFLINE' && !isOnline);
        const qOk =
          !q ||
          (h.host + (h.ip ?? '') + (h.platforms ?? []).join(','))
            .toLowerCase()
            .includes(q.toLowerCase());
        const profileOk =
          profileFilter === null ||
          (profileFilter === '__none__'
            ? !profileAssignments[h.host]
            : profileAssignments[h.host]?.profile_name === profileFilter);
        return statusOk && qOk && profileOk;
      }),
    [hosts, q, statusFilter, profileFilter, profileAssignments],
  );

  const stats = useMemo(() => {
    const total = hosts.length;
    const online = hosts.filter((h) => {
      const ts = h.tactical_status || h.connection_status;
      return ts === 'online' || ts === 'reachable';
    }).length;
    const offline = total - online;
    const overdue = hosts.filter(h => h.tactical_status === 'overdue').length;
    const highRisk = hosts.filter((h) => (h.risk_score ?? 0) >= 7).length;
    const avgRisk = total > 0
      ? hosts.reduce((acc, h) => acc + (h.risk_score ?? 0), 0) / total
      : 0;
    return { total, online, offline, overdue, highRisk, avgRisk };
  }, [hosts]);

  // Profile counts for filter chips
  const profileCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    hosts.forEach(h => {
      const pname = profileAssignments[h.host]?.profile_name;
      if (pname) counts[pname] = (counts[pname] || 0) + 1;
    });
    return { ...counts, __none__: hosts.filter(h => !profileAssignments[h.host]).length };
  }, [hosts, profileAssignments]);

  async function handleAssignProfile(host: string, profileId: number | null) {
    try {
      if (profileId === null) {
        await removeHostProfileAssignment(host);
        onProfileAssignmentChanged(host, null);
      } else {
        const assignment = await setHostProfileAssignment(host, profileId);
        onProfileAssignmentChanged(host, assignment);
      }
    } catch (e) {
      console.error('Profile assignment failed:', e);
    } finally {
      setAssigningHost(null);
    }
  }

  function toggleFavorite(host: string, e: React.MouseEvent) {
    e.stopPropagation();
    setFavorites((prev) => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host);
      else next.add(host);
      return next;
    });
  }

  if (!active) return null;

  const pct = (n: number) =>
    stats.total > 0 ? `${((n / stats.total) * 100).toFixed(1)}% of fleet` : '0%';

  return (
    <div className="flex h-full min-h-0 flex-col">

      {/* ── KPI Cards ── order: High Risk → Offline → Online → Total → Avg Risk */}
      <div className="grid grid-cols-5 gap-3 border-b border-white/[0.06] px-4 py-3">
        <KpiCard
          label="High Risk"
          value={stats.highRisk}
          sub={stats.highRisk > 0 ? `${pct(stats.highRisk)} · action needed` : 'No critical hosts'}
          icon={ShieldAlert}
          accent={stats.highRisk > 0 ? 'red' : 'green'}
          pulse={stats.highRisk > 0}
        />
        <KpiCard
          label="Offline / Overdue"
          value={stats.offline}
          sub={stats.offline > 0
            ? `${pct(stats.offline)}${stats.overdue > 0 ? ` · ${stats.overdue} overdue` : ''}`
            : 'All agents reachable'}
          icon={WifiOff}
          accent={stats.offline > 0 ? 'orange' : 'green'}
          pulse={stats.offline > 5}
        />
        <KpiCard
          label="Online"
          value={stats.online}
          sub={pct(stats.online)}
          icon={Wifi}
          accent="green"
        />
        <KpiCard
          label="Total Hosts"
          value={stats.total}
          sub="All assets in fleet"
          icon={Server}
          accent="cyan"
        />
        <KpiCard
          label="Avg Risk Score"
          value={`${stats.avgRisk.toFixed(1)} / 10`}
          sub="Fleet average risk"
          icon={Gauge}
          accent={stats.avgRisk >= 5 ? 'orange' : stats.avgRisk >= 3 ? 'yellow' : 'green'}
        />
      </div>

      {/* ── Table + detail ── */}
      <div className="flex min-h-0 flex-1">

        {/* left: table */}
        <div className="flex min-w-0 flex-1 flex-col">

          {/* toolbar */}
          <div className="flex items-center gap-2 border-b border-white/[0.06] bg-[var(--panel)] px-4 py-2">
            {/* status tabs */}
            <div className="flex items-center gap-0.5 rounded-lg border border-white/[0.06] bg-white/[0.03] p-0.5">
              {(['ALL', 'ONLINE', 'OFFLINE'] as StatusFilter[]).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={cx(
                    'h-6 rounded-md px-3 text-[11px] font-semibold transition-colors',
                    statusFilter === s
                      ? 'bg-white/[0.08] text-white'
                      : 'text-slate-500 hover:text-slate-300',
                  )}
                >
                  {s === 'ALL'
                    ? `Fleet (${stats.total})`
                    : s === 'ONLINE'
                    ? `Online (${stats.online})`
                    : `Offline (${stats.offline})`}
                </button>
              ))}
            </div>

            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={loadHosts}
                className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/[0.06] bg-white/[0.03] text-slate-500 hover:bg-white/[0.06] hover:text-slate-300"
                title="Refresh"
              >
                <RefreshCw className={cx('h-3.5 w-3.5', loading && 'animate-spin')} />
              </button>
              <div className="flex h-7 w-60 items-center gap-2 rounded-lg border border-white/[0.06] bg-white/[0.03] px-2.5">
                <Search className="h-3.5 w-3.5 shrink-0 text-slate-600" />
                <input
                  value={q}
                  onChange={(e) => setQ(e.target.value)}
                  placeholder="Search hosts, IP, OS…"
                  className="flex-1 bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600"
                />
              </div>
            </div>
          </div>

          {/* profile filter chips with counts */}
          {profiles.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5 border-b border-white/[0.06] bg-[var(--panel)] px-4 py-2">
              {[
                { key: null,       label: 'All Profiles', count: hosts.length },
                ...profiles.map((p) => ({ key: p.name, label: p.display_name, count: (profileCounts as Record<string, number>)[p.name] ?? 0 })),
                { key: '__none__', label: 'Unassigned',   count: profileCounts.__none__ ?? 0 },
              ].map(({ key, label, count }) => {
                const isUnassigned = key === '__none__';
                const isActive = profileFilter === key;
                const hasWarning = isUnassigned && (count ?? 0) > 0;
                return (
                  <button
                    key={key ?? '__all__'}
                    onClick={() => setProfileFilter(key)}
                    className={cx(
                      'inline-flex h-6 items-center gap-1.5 rounded-full border px-2.5 text-[11px] font-semibold transition-colors',
                      isActive
                        ? hasWarning
                          ? 'border-orange-400/50 bg-orange-500/20 text-orange-200'
                          : 'border-cyan-400/40 bg-cyan-500/15 text-cyan-200'
                        : hasWarning
                        ? 'border-orange-400/25 bg-orange-500/[0.07] text-orange-400 hover:bg-orange-500/15'
                        : 'border-white/[0.06] bg-white/[0.02] text-slate-500 hover:text-slate-300',
                    )}
                  >
                    {label}
                    <span className={cx(
                      'rounded-full px-1.5 py-px text-[9px] font-bold',
                      isActive
                        ? hasWarning ? 'bg-orange-500/30 text-orange-100' : 'bg-cyan-500/30 text-cyan-100'
                        : hasWarning ? 'bg-orange-500/20 text-orange-300' : 'bg-white/[0.08] text-slate-500',
                    )}>
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>
          )}

          {/* table */}
          <div className="flex-1 overflow-auto">
            {loading && (
              <div className="flex h-20 items-center justify-center text-xs text-slate-600">Loading hosts…</div>
            )}
            {error && (
              <div className="px-4 py-3 text-xs text-red-400">{error}</div>
            )}
            {!loading && !error && (
              <table className="w-full text-xs">
                <thead className="sticky top-0 border-b border-white/[0.06] bg-[var(--panel)] text-[10px] uppercase tracking-wider text-slate-600">
                  <tr>
                    <th className="w-8 px-2 py-2.5" />
                    <th className="px-3 py-2.5 text-left font-medium">Hostname</th>
                    <th className="px-3 py-2.5 text-left font-medium" title="W=Wazuh T=Tactical R=RDP S=SSH">Sources</th>
                    <th className="px-3 py-2.5 text-left font-medium">Profile</th>
                    <th className="px-3 py-2.5 text-right font-medium">Risk</th>
                    <th className="px-3 py-2.5 text-left font-medium">Status</th>
                    <th className="px-3 py-2.5 text-right font-medium">Alerts 24h</th>
                    <th className="px-3 py-2.5 text-left font-medium">Last Seen</th>
                    <th className="px-3 py-2.5 text-left font-medium">IP</th>
                    <th className="w-8 px-2 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={10} className="px-4 py-8 text-center text-slate-600">
                        No hosts found
                      </td>
                    </tr>
                  )}
                  {filtered.map((h) => {
                    const isSel     = selected?.host === h.host;
                    const r10       = risk10(h.risk_score ?? 0);
                    const tStatus   = h.tactical_status || (h.connection_status === 'reachable' ? 'online' : h.connection_status === 'unreachable' ? 'offline' : 'unknown');
                    const isFav     = favorites.has(h.host);
                    const freshness = freshnessInfo(h.last_activity);
                    const hasProfile = !!profileAssignments[h.host];
                    return (
                      <tr
                        key={h.host}
                        onClick={() => setSelected(h)}
                        onDoubleClick={() => onOpenOverview(h.host)}
                        className={cx(
                          'group cursor-pointer border-b border-white/[0.03] transition-colors hover:bg-white/[0.04]',
                          isSel ? 'bg-white/[0.07]' : riskRowAccent(r10),
                        )}
                      >
                        {/* star */}
                        <td className="px-2 py-2 text-center">
                          <button
                            onClick={(e) => toggleFavorite(h.host, e)}
                            className={cx('transition-opacity', isFav ? 'opacity-100' : 'opacity-0 group-hover:opacity-100')}
                          >
                            <Star className={cx('h-3.5 w-3.5', isFav ? 'fill-yellow-400 text-yellow-400' : 'text-slate-600')} />
                          </button>
                        </td>

                        {/* hostname with risk left border */}
                        <td className="px-3 py-2">
                          <span className={cx('border-l-2 pl-2 font-semibold', isSel ? 'text-white' : 'text-slate-100', riskBorderLClass(r10))}>
                            {h.host}
                          </span>
                          {(h.platforms ?? [])[0] && (
                            <div className="mt-0.5 pl-3.5 text-[10px] text-slate-600">{(h.platforms ?? [])[0]}</div>
                          )}
                        </td>

                        {/* capability chips */}
                        <td className="px-3 py-2">
                          <CapabilityChips h={h} />
                        </td>

                        {/* profile */}
                        <td className="px-3 py-2">
                          {hasProfile
                            ? <ProfileBadge assignment={profileAssignments[h.host]} size="sm" />
                            : <span className="text-[10px] text-orange-400/70">⚠ None</span>}
                        </td>

                        {/* risk badge */}
                        <td className="px-3 py-2 text-right">
                          <span className={cx('inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-bold', riskBadgeCx(r10))}>
                            {r10.toFixed(1)}
                          </span>
                        </td>

                        {/* status */}
                        <td className="px-3 py-2">
                          <TacticalBadge status={tStatus} />
                        </td>

                        {/* alerts heat */}
                        <td className="px-3 py-2 text-right">
                          <AlertHeat count={h.alerts_24h ?? 0} />
                        </td>

                        {/* last seen */}
                        <td className="px-3 py-2">
                          <span className={cx('text-[11px]', freshness.cx)}>{freshness.label}</span>
                        </td>

                        {/* IP */}
                        <td className="px-3 py-2 font-mono text-[11px] text-slate-500">
                          {h.ip ?? <span className="font-sans not-italic text-slate-700">—</span>}
                        </td>

                        {/* actions */}
                        <td className="px-2 py-2 text-center">
                          <button className="text-slate-600 opacity-0 hover:text-slate-300 group-hover:opacity-100">
                            <MoreVertical className="h-3.5 w-3.5" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>

          {/* pagination hint */}
          {!loading && filtered.length > 0 && (
            <div className="flex items-center justify-between border-t border-white/[0.06] px-4 py-2">
              <span className="text-[11px] text-slate-600">
                Showing {Math.min(filtered.length, 20)} of {filtered.length} hosts
              </span>
            </div>
          )}
        </div>

        {/* right: detail panel */}
        <DetailPanel
          host={selected}
          allHosts={hosts}
          profileAssignments={profileAssignments}
          profiles={profiles}
          onSwitchTab={onSwitchTab}
          assigningHost={assigningHost}
          setAssigningHost={setAssigningHost}
          handleAssignProfile={handleAssignProfile}
        />
      </div>
    </div>
  );
}
