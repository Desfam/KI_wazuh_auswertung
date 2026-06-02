/**
 * WazuhAgentDetailDrawer
 * ======================
 * Full-featured, read-only Wazuh agent detail panel.
 *
 * Props:
 *   agentId?   – Wazuh agent ID (preferred)
 *   agentName? – fallback resolution if no ID
 *   open       – controls visibility
 *   onClose    – close handler
 *
 * Tabs:
 *   Overview · Syscollector · SCA · FIM · Rootcheck · Recent Alerts · Raw
 *
 * All data is loaded lazily per tab.
 * A per-tab in-memory cache (60 s TTL) avoids re-fetching during the same
 * drawer session.
 */
import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle, ChevronDown, ChevronRight,
  ExternalLink, Info, Lock, RefreshCw, Search, Shield, X,
} from 'lucide-react';
import {
  getWazuhAgentEnrichment,
  getWazuhAgent,
  getWazuhSyscollectorOS,
  getWazuhSyscollectorHardware,
  getWazuhSyscollectorPackages,
  getWazuhSyscollectorPorts,
  getWazuhSyscollectorProcesses,
  getWazuhSyscollectorServices,
  getWazuhSCAResults,
  getWazuhSCAChecks,
  getWazuhSyscheckLastScan,
  getWazuhSyscheckResults,
  getWazuhRootcheckLastScan,
  getWazuhRootcheckResults,
  getAgentRecentAlerts,
  logAuditAction,
  reconnectWazuhAgent,
  getWazuhPermissions,
  type WazuhReconnectResult,
} from '../services/api';
import type { WazuhAgentEnrichment, WazuhControlledActionProbe } from '../types';

// ─── Types ────────────────────────────────────────────────────────────────────

type TabId =
  | 'overview'
  | 'syscollector'
  | 'sca'
  | 'fim'
  | 'rootcheck'
  | 'alerts'
  | 'raw';

export interface WazuhAgentDetailDrawerProps {
  agentId?: string | null;
  agentName?: string | null;
  open: boolean;
  onClose: () => void;
  /** Optional context for audit logging */
  auditMeta?: {
    source_page?: string;
    cluster_id?: string;
    rule_ids?: string[];
    event_ids?: string[];
  };
}

// Sensitive FIM paths to highlight
const SENSITIVE_PATHS = [
  '/etc/passwd', '/etc/shadow', '/etc/sudoers', 'authorized_keys',
  'sshd_config', '/etc/crontab', '/etc/hosts',
  'HKLM\\\\System\\\\CurrentControlSet\\\\Services',
  'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
  '\\\\Startup\\\\', '\\\\autorun',
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isSensitivePath(path: string): boolean {
  const p = path.toLowerCase();
  return SENSITIVE_PATHS.some(s => p.includes(s.toLowerCase()));
}

function fmtTs(ts: string | null | undefined): string {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function sevColor(sev: string): string {
  return ({
    critical: '#ff2f55', high: '#ff7a18',
    medium: '#ffd21f', low: '#23d36b', info: '#7fa4b8',
  } as Record<string, string>)[sev] ?? '#7fa4b8';
}

function statusColor(status: string | null | undefined): string {
  return ({
    active: 'var(--soc-success, #23d36b)',
    disconnected: 'var(--soc-danger, #ff2f55)',
    never_connected: 'var(--soc-muted-fg, #7fa4b8)',
  } as Record<string, string>)[(status ?? '').toLowerCase()] ?? '#ffd21f';
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  if (value == null || value === '' || value === '—') return null;
  return (
    <div className="flex gap-2 py-0.5">
      <span className="min-w-[110px] text-[11px] shrink-0" style={{ color: 'var(--soc-muted-fg)' }}>{label}</span>
      <span className={`text-[11px] break-all ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--soc-foreground)' }}>
        {value}
      </span>
    </div>
  );
}

function TabBtn({ id, active, label, onClick }: { id: string; active: boolean; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      key={id}
      onClick={onClick}
      className="px-3 py-2 text-[11px] whitespace-nowrap transition shrink-0"
      style={{
        color: active ? 'var(--soc-accent)' : 'var(--soc-muted-fg)',
        borderBottom: active ? '2px solid var(--soc-accent)' : '2px solid transparent',
      }}
    >
      {label}
    </button>
  );
}

function LoadingState() {
  return <p className="text-[12px] py-4" style={{ color: 'var(--soc-muted-fg)' }}>Loading…</p>;
}

function ErrorState({ msg }: { msg: string }) {
  return (
    <div className="flex items-start gap-2 rounded p-3 mt-2"
      style={{ background: 'rgba(255,47,85,0.08)', border: '1px solid rgba(255,47,85,0.2)', color: '#ff2f55' }}>
      <AlertTriangle size={12} className="mt-0.5 shrink-0"/>
      <p className="text-[11px]">{msg}</p>
    </div>
  );
}

function EmptyState({ msg = 'No data available.' }: { msg?: string }) {
  return <p className="text-[11px] py-4" style={{ color: 'var(--soc-muted-fg)' }}>{msg}</p>;
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p className="text-[10px] uppercase tracking-widest mt-4 mb-1"
      style={{ color: 'var(--soc-muted-fg)', letterSpacing: '0.08em' }}>
      {children}
    </p>
  );
}

function SearchBar({ value, onChange, placeholder }: { value: string; onChange: (v: string) => void; placeholder: string }) {
  return (
    <div className="relative mb-2">
      <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: 'var(--soc-muted-fg)' }}/>
      <input
        type="text"
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full rounded pl-7 pr-3 py-1.5 text-[11px]"
        style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)', outline: 'none' }}
      />
    </div>
  );
}

function CollapsibleJson({ label, data }: { label: string; data: unknown }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-3">
      <button
        type="button"
        onClick={() => setOpen(p => !p)}
        className="flex items-center gap-1.5 text-[11px] w-full text-left py-1"
        style={{ color: 'var(--soc-muted-fg)' }}
      >
        {open ? <ChevronDown size={11}/> : <ChevronRight size={11}/>}
        {label}
      </button>
      {open && (
        <pre className="text-[10px] rounded p-3 overflow-x-auto mt-1"
          style={{ background: 'var(--soc-input)', color: 'var(--soc-muted-fg)', border: '1px solid var(--soc-border)', maxHeight: '300px', overflowY: 'auto' }}>
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ─── Tab: Overview ────────────────────────────────────────────────────────────

function OverviewTab({ enrich }: { enrich: WazuhAgentEnrichment }) {
  const ag = enrich.agent;
  const sourceLabel = enrich.source === 'manager_api' ? 'Manager API (live)' : enrich.source === 'cache' ? 'Manager API (cached)' : 'Event data only';
  const sourceLabelColor = enrich.source === 'manager_api' ? 'var(--soc-success, #23d36b)' : enrich.source === 'cache' ? '#ffd21f' : 'var(--soc-muted-fg)';
  const cacheAge = (enrich as WazuhAgentEnrichment & { cache_age_seconds?: number | null }).cache_age_seconds;
  const sourceReason = (enrich as WazuhAgentEnrichment & { source_reason?: string }).source_reason;

  return (
    <div>
      <SectionLabel>Agent Identity</SectionLabel>
      <KV label="Agent ID"     value={ag.id}   mono />
      <KV label="Name"         value={ag.name} />
      <KV label="IP"           value={ag.ip}   mono />
      <KV label="Status"       value={
        <span style={{ color: statusColor(ag.status), fontWeight: 700 }}>{ag.status ?? '—'}</span>
      } />
      <KV label="OS"           value={ag.os?.name ?? ag.os?.platform} />
      <KV label="Version"      value={ag.version} />
      <KV label="Groups"       value={(ag.groups ?? []).join(', ') || null} />
      <KV label="Node"         value={ag.node_name} mono />
      <KV label="Manager"      value={ag.manager_name} />
      <KV label="Last keep-alive" value={fmtTs(ag.last_keep_alive)} />

      <SectionLabel>Data Source</SectionLabel>
      <div className="rounded p-2.5 text-[11px] flex flex-col gap-1"
        style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)' }}>
        <div className="flex items-center gap-2">
          <span style={{ color: sourceLabelColor, fontWeight: 700 }}>{sourceLabel}</span>
          {enrich.source === 'cache' && cacheAge != null && (
            <span style={{ color: 'var(--soc-muted-fg)' }}>· {cacheAge}s ago</span>
          )}
        </div>
        {sourceReason && (
          <span style={{ color: 'var(--soc-muted-fg)', fontStyle: 'italic' }}>{sourceReason}</span>
        )}
      </div>

      {/* Syscollector summary */}
      <SectionLabel>Syscollector availability</SectionLabel>
      <div className="flex flex-wrap gap-1.5">
        {Object.entries(enrich.syscollector).map(([k, v]) => (
          <span key={k} className="text-[10px] px-2 py-0.5 rounded"
            style={{
              background: v ? 'rgba(35,211,107,0.1)' : 'rgba(180,210,230,0.05)',
              color: v ? '#23d36b' : 'var(--soc-muted-fg)',
              border: `1px solid ${v ? 'rgba(35,211,107,0.2)' : 'rgba(180,210,230,0.1)'}`,
            }}>
            {k.replace('_available', '')}
          </span>
        ))}
      </div>

      {/* SCA summary */}
      {enrich.sca.available && (
        <>
          <SectionLabel>SCA summary</SectionLabel>
          <KV label="Score"         value={enrich.sca.score != null ? `${enrich.sca.score}%` : '—'} />
          <KV label="Failed checks" value={enrich.sca.failed_checks ?? '—'} />
        </>
      )}

      {/* FIM / Rootcheck */}
      <SectionLabel>FIM / Rootcheck</SectionLabel>
      <KV label="FIM available"        value={enrich.fim.available ? 'yes' : 'no'} />
      <KV label="FIM last scan"        value={fmtTs(enrich.fim.last_scan)} />
      <KV label="Rootcheck available"  value={enrich.rootcheck.available ? 'yes' : 'no'} />
      <KV label="Rootcheck last scan"  value={fmtTs(enrich.rootcheck.last_scan)} />

      {/* Warnings */}
      {enrich.warnings.length > 0 && (
        <>
          <SectionLabel>Warnings</SectionLabel>
          {enrich.warnings.map((w, i) => (
            <div key={i} className="flex items-start gap-1.5 mb-1">
              <AlertTriangle size={10} className="mt-0.5 shrink-0" style={{ color: '#ffd21f' }}/>
              <p className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{w}</p>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ─── Tab: Syscollector ────────────────────────────────────────────────────────

type ScSection = 'os' | 'hardware' | 'packages' | 'ports' | 'processes' | 'services';

const SC_SECTIONS: { id: ScSection; label: string; fetch: (id: string) => Promise<unknown> }[] = [
  { id: 'os',        label: 'OS',        fetch: getWazuhSyscollectorOS },
  { id: 'hardware',  label: 'Hardware',  fetch: getWazuhSyscollectorHardware },
  { id: 'packages',  label: 'Packages',  fetch: (id) => getWazuhSyscollectorPackages(id, 200) },
  { id: 'ports',     label: 'Ports',     fetch: (id) => getWazuhSyscollectorPorts(id, 200) },
  { id: 'processes', label: 'Processes', fetch: (id) => getWazuhSyscollectorProcesses(id, 200) },
  { id: 'services',  label: 'Services',  fetch: (id) => getWazuhSyscollectorServices(id, 200) },
];

function SyscollectorTab({ agentId }: { agentId: string }) {
  const [activeSection, setActiveSection] = useState<ScSection>('os');
  const [data, setData] = useState<Partial<Record<ScSection, unknown>>>({});
  const [loading, setLoading] = useState<Partial<Record<ScSection, boolean>>>({});
  const [errors, setErrors] = useState<Partial<Record<ScSection, string>>>({});
  const [filter, setFilter] = useState('');

  const load = useCallback((sec: ScSection) => {
    if (data[sec] !== undefined || loading[sec]) return;
    setLoading(prev => ({ ...prev, [sec]: true }));
    const entry = SC_SECTIONS.find(s => s.id === sec)!;
    entry.fetch(agentId)
      .then(r => setData(prev => ({ ...prev, [sec]: r })))
      .catch(e => setErrors(prev => ({ ...prev, [sec]: String(e) })))
      .finally(() => setLoading(prev => ({ ...prev, [sec]: false })));
  }, [agentId, data, loading]);

  useEffect(() => { load('os'); }, [load]);

  function handleSection(sec: ScSection) {
    setActiveSection(sec);
    setFilter('');
    load(sec);
  }

  const items: Record<string, unknown>[] = (() => {
    const raw = data[activeSection];
    if (!raw) return [];
    const d = (raw as Record<string, unknown>)?.data;
    if (!d) return [];
    const items = (d as Record<string, unknown>)?.affected_items;
    return Array.isArray(items) ? items as Record<string, unknown>[] : [];
  })();

  const filtered = filter
    ? items.filter(item => JSON.stringify(item).toLowerCase().includes(filter.toLowerCase()))
    : items;

  return (
    <div>
      {/* Sub-section tabs */}
      <div className="flex gap-1 flex-wrap mb-3">
        {SC_SECTIONS.map(s => (
          <button
            key={s.id}
            type="button"
            onClick={() => handleSection(s.id)}
            className="px-2 py-1 rounded text-[10px] transition"
            style={{
              background: activeSection === s.id ? 'var(--soc-accent)' : 'var(--soc-input)',
              color: activeSection === s.id ? '#fff' : 'var(--soc-muted-fg)',
              border: '1px solid var(--soc-border)',
            }}
          >
            {s.label}
          </button>
        ))}
      </div>

      {loading[activeSection] && <LoadingState />}
      {errors[activeSection] && <ErrorState msg={errors[activeSection]!} />}

      {!loading[activeSection] && !errors[activeSection] && items.length > 0 && (
        <>
          {['packages', 'ports', 'processes', 'services'].includes(activeSection) && (
            <SearchBar value={filter} onChange={setFilter} placeholder={`Filter ${activeSection}…`} />
          )}
          <p className="text-[10px] mb-2" style={{ color: 'var(--soc-muted-fg)' }}>
            {filtered.length} {activeSection === 'packages' && filter ? 'matches' : 'item(s)'}
            {items.length > filtered.length ? ` of ${items.length}` : ''}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-[10.5px] border-collapse">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--soc-border)' }}>
                  {Object.keys(filtered[0] ?? {}).slice(0, 8).map(k => (
                    <th key={k} className="text-left py-1 pr-3 font-medium"
                      style={{ color: 'var(--soc-muted-fg)', whiteSpace: 'nowrap' }}>{k}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 100).map((row, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(180,210,230,0.06)' }}>
                    {Object.values(row).slice(0, 8).map((v, j) => (
                      <td key={j} className="py-0.5 pr-3 font-mono align-top"
                        style={{ color: 'var(--soc-foreground)', maxWidth: '180px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {v == null ? '—' : String(v)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length > 100 && (
              <p className="text-[10px] mt-1" style={{ color: 'var(--soc-muted-fg)' }}>
                Showing 100 of {filtered.length} results.
              </p>
            )}
          </div>
        </>
      )}
      {!loading[activeSection] && !errors[activeSection] && items.length === 0 && data[activeSection] !== undefined && (
        <EmptyState msg={`No ${activeSection} data available.`} />
      )}
    </div>
  );
}

// ─── Tab: SCA ─────────────────────────────────────────────────────────────────

interface SCAPolicy {
  policy_id?: string;
  name?: string;
  description?: string;
  score?: number;
  pass?: number;
  fail?: number;
  invalid?: number;
}

function SCATab({ agentId, enrichSCA }: { agentId: string; enrichSCA: WazuhAgentEnrichment['sca'] }) {
  const [policies, setPolicies] = useState<SCAPolicy[]>(enrichSCA.policies as SCAPolicy[] ?? []);
  const [loadingPolicies, setLoadingPolicies] = useState(!enrichSCA.policies?.length);
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [checks, setChecks] = useState<Record<string, unknown>[]>([]);
  const [loadingChecks, setLoadingChecks] = useState(false);
  const [checksError, setChecksError] = useState<string | null>(null);
  const [filterResult, setFilterResult] = useState<'' | 'failed' | 'passed'>('');
  const [checkFilter, setCheckFilter] = useState('');

  useEffect(() => {
    if (enrichSCA.policies?.length) { setPolicies(enrichSCA.policies as SCAPolicy[]); setLoadingPolicies(false); return; }
    setLoadingPolicies(true);
    getWazuhSCAResults(agentId)
      .then(r => {
        const items = ((r as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        setPolicies(Array.isArray(items) ? items as SCAPolicy[] : []);
      })
      .catch(() => setPolicies([]))
      .finally(() => setLoadingPolicies(false));
  }, [agentId, enrichSCA.policies]);

  function loadChecks(policyId: string) {
    setSelectedPolicy(policyId);
    setChecks([]); setChecksError(null); setLoadingChecks(true);
    getWazuhSCAChecks(agentId, policyId, 200, filterResult || undefined)
      .then(r => {
        const items = ((r as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        setChecks(Array.isArray(items) ? items as Record<string, unknown>[] : []);
      })
      .catch(e => setChecksError(String(e)))
      .finally(() => setLoadingChecks(false));
  }

  const filteredChecks = checkFilter
    ? checks.filter(c => JSON.stringify(c).toLowerCase().includes(checkFilter.toLowerCase()))
    : checks;

  return (
    <div>
      {loadingPolicies && <LoadingState />}
      {!loadingPolicies && policies.length === 0 && <EmptyState msg="No SCA policies found." />}
      {policies.map(p => (
        <div key={p.policy_id} className="mb-2 rounded p-2.5 cursor-pointer"
          style={{ background: selectedPolicy === p.policy_id ? 'rgba(var(--soc-accent-rgb, 0,184,255),0.08)' : 'var(--soc-input)', border: `1px solid ${selectedPolicy === p.policy_id ? 'var(--soc-accent)' : 'var(--soc-border)'}` }}
          onClick={() => loadChecks(p.policy_id ?? '')}>
          <div className="flex items-start justify-between gap-2">
            <div>
              <p className="text-[12px] font-semibold" style={{ color: 'var(--soc-foreground)' }}>{p.name ?? p.policy_id}</p>
              {p.description && <p className="text-[10.5px] mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>{p.description}</p>}
            </div>
            {p.score != null && (
              <span className="text-[11px] font-bold shrink-0" style={{ color: p.score >= 75 ? '#23d36b' : p.score >= 50 ? '#ffd21f' : '#ff7a18' }}>
                {p.score}%
              </span>
            )}
          </div>
          <div className="flex gap-3 mt-1.5 text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
            {p.pass != null && <span style={{ color: '#23d36b' }}>✓ {p.pass} passed</span>}
            {p.fail != null && <span style={{ color: '#ff7a18' }}>✗ {p.fail} failed</span>}
            {p.invalid != null && <span>~ {p.invalid} n/a</span>}
          </div>
        </div>
      ))}

      {selectedPolicy && (
        <>
          <div className="flex items-center gap-2 my-3">
            <SearchBar value={checkFilter} onChange={setCheckFilter} placeholder="Filter checks…" />
            <select
              value={filterResult}
              onChange={e => { setFilterResult(e.target.value as '' | 'failed' | 'passed'); loadChecks(selectedPolicy); }}
              className="text-[11px] rounded px-2 py-1.5 shrink-0"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
            >
              <option value="">All</option>
              <option value="failed">Failed only</option>
              <option value="passed">Passed only</option>
            </select>
          </div>
          {loadingChecks && <LoadingState />}
          {checksError && <ErrorState msg={checksError} />}
          {!loadingChecks && !checksError && filteredChecks.length === 0 && <EmptyState msg="No checks." />}
          {filteredChecks.map((c, i) => {
            const res = String((c as Record<string, unknown>).result ?? '');
            const title = String((c as Record<string, unknown>).title ?? (c as Record<string, unknown>).description ?? '');
            const remediation = String((c as Record<string, unknown>).remediation ?? '');
            const resColor = res === 'passed' ? '#23d36b' : res === 'failed' ? '#ff7a18' : 'var(--soc-muted-fg)';
            return (
              <div key={i} className="mb-1.5 rounded p-2 text-[10.5px]"
                style={{ background: 'var(--soc-input)', border: `1px solid ${res === 'failed' ? 'rgba(255,122,24,0.25)' : 'var(--soc-border)'}` }}>
                <div className="flex items-start gap-2">
                  <span style={{ color: resColor, fontWeight: 700, minWidth: '44px' }}>{res || '—'}</span>
                  <span style={{ color: 'var(--soc-foreground)' }}>{title}</span>
                </div>
                {remediation && res === 'failed' && (
                  <p className="mt-1 text-[10px]" style={{ color: 'var(--soc-muted-fg)', fontStyle: 'italic' }}>
                    Remediation: {remediation}
                  </p>
                )}
              </div>
            );
          })}
        </>
      )}
    </div>
  );
}

// ─── Tab: FIM ─────────────────────────────────────────────────────────────────

function FIMTab({ agentId, enrichFIM }: { agentId: string; enrichFIM: WazuhAgentEnrichment['fim'] }) {
  const [results, setResults] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  function load() {
    if (results !== null || loading) return;
    setLoading(true);
    getWazuhSyscheckResults(agentId, 200)
      .then(r => {
        const items = ((r as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        setResults(Array.isArray(items) ? items as Record<string, unknown>[] : []);
      })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }

  const filtered = (results ?? []).filter(row =>
    !filter || JSON.stringify(row).toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <SectionLabel>Last scan</SectionLabel>
      <KV label="Available"  value={enrichFIM.available ? 'yes' : 'no'} />
      <KV label="Last scan"  value={fmtTs(enrichFIM.last_scan)} />

      <SectionLabel>Recent FIM events</SectionLabel>
      {results === null && !loading && (
        <button
          type="button"
          onClick={load}
          className="rounded px-3 py-1.5 text-[11px] transition"
          style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        >
          Load FIM events
        </button>
      )}
      {loading && <LoadingState />}
      {error && <ErrorState msg={error} />}
      {results !== null && results.length > 0 && (
        <>
          <SearchBar value={filter} onChange={setFilter} placeholder="Filter by path, event type…" />
          {filtered.map((row, i) => {
            const path = String(row.file ?? row.path ?? '');
            const event = String(row.event ?? row.type ?? '');
            const ts = String(row.date ?? row.timestamp ?? '');
            const sensitive = isSensitivePath(path);
            return (
              <div key={i} className="mb-1.5 rounded p-2 text-[10.5px]"
                style={{ background: sensitive ? 'rgba(255,47,85,0.07)' : 'var(--soc-input)', border: `1px solid ${sensitive ? 'rgba(255,47,85,0.25)' : 'var(--soc-border)'}` }}>
                <div className="flex items-start gap-2">
                  {sensitive && <AlertTriangle size={10} className="mt-0.5 shrink-0" style={{ color: '#ff7a18' }}/>}
                  <span className="font-mono break-all" style={{ color: sensitive ? '#ff7a18' : 'var(--soc-foreground)' }}>{path || '—'}</span>
                </div>
                <div className="flex gap-3 mt-1 text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                  {event && <span style={{ color: event === 'deleted' ? '#ff2f55' : event === 'added' ? '#23d36b' : 'var(--soc-foreground)' }}>{event}</span>}
                  {ts && <span>{fmtTs(ts)}</span>}
                </div>
              </div>
            );
          })}
          {filtered.length === 0 && <EmptyState msg="No matches." />}
        </>
      )}
      {results !== null && results.length === 0 && <EmptyState msg="No FIM events found." />}
    </div>
  );
}

// ─── Tab: Rootcheck ───────────────────────────────────────────────────────────

function RootcheckTab({ agentId, enrichRC }: { agentId: string; enrichRC: WazuhAgentEnrichment['rootcheck'] }) {
  const [results, setResults] = useState<Record<string, unknown>[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState('');

  function load() {
    if (results !== null || loading) return;
    setLoading(true);
    getWazuhRootcheckResults(agentId, 100)
      .then(r => {
        const items = ((r as Record<string, unknown>)?.data as Record<string, unknown>)?.affected_items;
        setResults(Array.isArray(items) ? items as Record<string, unknown>[] : []);
      })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }

  const filtered = (results ?? []).filter(row =>
    !filter || JSON.stringify(row).toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <SectionLabel>Status</SectionLabel>
      <KV label="Available"  value={enrichRC.available ? 'yes' : 'no'} />
      <KV label="Last scan"  value={fmtTs(enrichRC.last_scan)} />

      <SectionLabel>Rootcheck findings</SectionLabel>
      {results === null && !loading && (
        <button
          type="button"
          onClick={load}
          className="rounded px-3 py-1.5 text-[11px] transition"
          style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        >
          Load findings
        </button>
      )}
      {loading && <LoadingState />}
      {error && <ErrorState msg={error} />}
      {results !== null && results.length > 0 && (
        <>
          <SearchBar value={filter} onChange={setFilter} placeholder="Filter findings…" />
          {filtered.map((row, i) => {
            const title = String(row.log ?? row.description ?? '');
            const status = String(row.status ?? '');
            const ts = String(row.date ?? row.timestamp ?? '');
            return (
              <div key={i} className="mb-1.5 rounded p-2 text-[10.5px]"
                style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)' }}>
                <div className="flex items-start gap-2">
                  <span className="shrink-0 text-[10px]" style={{ color: status === 'outstanding' ? '#ff7a18' : status === 'solved' ? '#23d36b' : 'var(--soc-muted-fg)' }}>
                    {status || '—'}
                  </span>
                  <span style={{ color: 'var(--soc-foreground)' }}>{title || '—'}</span>
                </div>
                {ts && <p className="text-[10px] mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>{fmtTs(ts)}</p>}
              </div>
            );
          })}
          {filtered.length === 0 && <EmptyState msg="No matches." />}
        </>
      )}
      {results !== null && results.length === 0 && <EmptyState msg="No rootcheck findings." />}
    </div>
  );
}

// ─── Tab: Recent Alerts ───────────────────────────────────────────────────────

interface AlertItem {
  timestamp: string | null;
  rule_id: string | null;
  rule_level: number;
  severity: string;
  description: string | null;
  agent_name: string | null;
  event_id: string | null;
  mitre_tactic: string | null;
  mitre_id: string | null;
}

function RecentAlertsTab({ agentId, agentName }: { agentId: string; agentName: string | null }) {
  const [alerts, setAlerts] = useState<AlertItem[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lookback, setLookback] = useState(24);
  const [sevFilter, setSevFilter] = useState('');
  const [search, setSearch] = useState('');

  const load = useCallback((hours: number) => {
    setLoading(true); setError(null);
    getAgentRecentAlerts(agentId, agentName ?? undefined, hours, 100)
      .then(r => setAlerts(r.alerts))
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }, [agentId, agentName]);

  useEffect(() => { load(lookback); }, [load, lookback]);

  const filtered = (alerts ?? []).filter(a => {
    if (sevFilter && a.severity !== sevFilter) return false;
    if (search) {
      const s = search.toLowerCase();
      return (a.description ?? '').toLowerCase().includes(s) ||
        (a.rule_id ?? '').includes(s) || (a.event_id ?? '').includes(s);
    }
    return true;
  });

  return (
    <div>
      {/* Controls */}
      <div className="flex gap-2 mb-3 flex-wrap">
        {[6, 24, 72, 168].map(h => (
          <button key={h} type="button"
            onClick={() => { setLookback(h); load(h); }}
            className="px-2 py-1 rounded text-[10px] transition"
            style={{ background: lookback === h ? 'var(--soc-accent)' : 'var(--soc-input)', color: lookback === h ? '#fff' : 'var(--soc-muted-fg)', border: '1px solid var(--soc-border)' }}>
            {h < 24 ? `${h}h` : `${h / 24}d`}
          </button>
        ))}
        <select
          value={sevFilter}
          onChange={e => setSevFilter(e.target.value)}
          className="text-[10px] rounded px-2 py-1"
          style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        >
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>
      <SearchBar value={search} onChange={setSearch} placeholder="Search rule, event ID, description…" />

      {loading && <LoadingState />}
      {error && <ErrorState msg={error} />}
      {!loading && !error && filtered.length === 0 && <EmptyState msg="No alerts in this time window." />}
      {filtered.map((a, i) => (
        <div key={i} className="mb-1.5 rounded p-2 text-[10.5px]"
          style={{ background: 'var(--soc-input)', border: `1px solid rgba(${a.severity === 'critical' ? '255,47,85' : a.severity === 'high' ? '255,122,24' : '180,210,230'},0.15)` }}>
          <div className="flex items-start justify-between gap-2">
            <span style={{ color: sevColor(a.severity), fontWeight: 700, minWidth: '52px' }}>{a.severity}</span>
            <span className="flex-1" style={{ color: 'var(--soc-foreground)' }}>{a.description ?? '—'}</span>
            <span className="text-[10px] shrink-0" style={{ color: 'var(--soc-muted-fg)' }}>lvl {a.rule_level}</span>
          </div>
          <div className="flex gap-3 mt-1 text-[10px] flex-wrap" style={{ color: 'var(--soc-muted-fg)' }}>
            {a.timestamp && <span>{fmtTs(a.timestamp)}</span>}
            {a.rule_id && <span>Rule {a.rule_id}</span>}
            {a.event_id && <span>EID {a.event_id}</span>}
            {a.mitre_tactic && <span style={{ color: '#b4a0d4' }}>{a.mitre_tactic}</span>}
            {a.mitre_id && <span className="font-mono" style={{ color: '#b4a0d4' }}>{a.mitre_id}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Tab: Raw ─────────────────────────────────────────────────────────────────

function RawTab({ agentId, enrich }: { agentId: string; enrich: WazuhAgentEnrichment }) {
  const [rawAgent, setRawAgent] = useState<unknown>(null);
  const [loading, setLoading] = useState(false);

  function loadRaw() {
    if (rawAgent || loading) return;
    setLoading(true);
    getWazuhAgent(agentId)
      .then(setRawAgent)
      .catch(() => setRawAgent({ error: 'Failed to load' }))
      .finally(() => setLoading(false));
  }

  return (
    <div>
      <CollapsibleJson label="Enrichment context" data={enrich} />
      <div className="mb-2">
        <button type="button" onClick={loadRaw} disabled={loading || !!rawAgent}
          className="text-[11px] px-3 py-1.5 rounded transition"
          style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)', opacity: rawAgent ? 0.5 : 1 }}>
          {loading ? 'Loading…' : rawAgent ? 'Loaded' : 'Load raw agent API response'}
        </button>
      </div>
      {rawAgent != null && <CollapsibleJson label="Raw agent (Manager API)" data={rawAgent} />}
    </div>
  );
}

// ─── Main Drawer ──────────────────────────────────────────────────────────────

// ─── Reconnect Confirmation Modal ─────────────────────────────────────────────

interface ReconnectModalProps {
  agentId: string;
  agentName: string | null;
  submitting?: boolean;
  result?: WazuhReconnectResult | null;
  submitError?: string | null;
  onConfirm: (reason: string, waitForComplete: boolean) => void;
  onCancel: () => void;
}

function ReconnectModal({
  agentId,
  agentName,
  submitting,
  result,
  submitError,
  onConfirm,
  onCancel,
}: ReconnectModalProps) {
  const [reason, setReason] = useState('');
  const [waitForComplete, setWaitForComplete] = useState(false);

  const hasResult = result != null || submitError != null;
  const isSuccess = result?.status === 'ok';

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.65)' }}
      onClick={e => { if (e.target === e.currentTarget && !submitting) onCancel(); }}
    >
      <div
        className="rounded-lg flex flex-col gap-4 p-5"
        style={{ width: '440px', maxWidth: '95vw', background: 'var(--soc-panel)', border: '1px solid var(--soc-border)', boxShadow: '0 8px 40px rgba(0,0,0,0.6)' }}
      >
        {/* Header */}
        <div className="flex items-center justify-between">
          <p className="text-[14px] font-semibold flex items-center gap-2" style={{ color: 'var(--soc-foreground)' }}>
            <RefreshCw size={14} style={{ color: 'var(--soc-accent)' }}/>
            Reconnect Agent
          </p>
          <button type="button" onClick={onCancel} disabled={submitting} style={{ color: 'var(--soc-muted-fg)' }}>
            <X size={15}/>
          </button>
        </div>

        {/* Agent info */}
        <div className="rounded p-3 text-[11px]"
          style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
          <div className="flex gap-2">
            <span style={{ color: 'var(--soc-muted-fg)', minWidth: 80 }}>Agent ID</span>
            <span className="font-mono" style={{ color: 'var(--soc-foreground)' }}>{agentId}</span>
          </div>
          <div className="flex gap-2 mt-1">
            <span style={{ color: 'var(--soc-muted-fg)', minWidth: 80 }}>Name</span>
            <span style={{ color: 'var(--soc-foreground)' }}>{agentName ?? '—'}</span>
          </div>
        </div>

        {/* Warning — only shown before submission */}
        {!hasResult && (
          <div className="rounded p-3 flex items-start gap-2"
            style={{ background: 'rgba(255,210,31,0.08)', border: '1px solid rgba(255,210,31,0.25)' }}>
            <AlertTriangle size={12} className="mt-0.5 shrink-0" style={{ color: '#ffd21f' }}/>
            <p className="text-[11px]" style={{ color: '#ffd21f' }}>
              This reconnects the selected Wazuh agent only.
              It does <strong>not</strong> restart the host or affect other agents.
            </p>
          </div>
        )}

        {/* Result panel — shown after submission */}
        {hasResult && (
          <div className="rounded p-3 text-[11px]"
            style={{
              background: isSuccess ? 'rgba(35,211,107,0.07)' : 'rgba(255,47,85,0.07)',
              border: `1px solid ${isSuccess ? 'rgba(35,211,107,0.3)' : 'rgba(255,47,85,0.3)'}`,
            }}>
            <div className="font-semibold mb-1"
              style={{ color: isSuccess ? '#23d36b' : result?.status === 'blocked' ? '#ffd21f' : '#ff2f55' }}>
              {result?.status === 'ok'      && '✓ Reconnect signal sent'}
              {result?.status === 'blocked' && '⚠ Action blocked by policy'}
              {result?.status === 'denied'  && '✗ Permission denied by Wazuh RBAC'}
              {result?.status === 'error'   && '✗ Reconnect failed'}
              {submitError                  && '✗ Request error'}
            </div>
            {result?.message && (
              <div style={{ color: 'rgba(180,210,230,0.75)' }}>{result.message}</div>
            )}
            {submitError && (
              <div style={{ color: 'rgba(255,47,85,0.75)', fontFamily: 'monospace', fontSize: 10 }}>{submitError}</div>
            )}
            {result?.wazuh_response && (
              <div className="mt-2 text-[10px]" style={{ color: 'rgba(180,210,230,0.5)' }}>
                Affected: {result.wazuh_response.total_affected_items}
                {result.wazuh_response.total_failed_items > 0 && (
                  <span style={{ color: '#ff2f55', marginLeft: 6 }}>Failed: {result.wazuh_response.total_failed_items}</span>
                )}
                {result.wazuh_response.message && (
                  <div style={{ marginTop: 2 }}>{result.wazuh_response.message}</div>
                )}
              </div>
            )}
            {result?.audit_id_completed != null && (
              <div className="mt-1 text-[10px]" style={{ color: 'rgba(180,210,230,0.3)' }}>
                Audit #{result.audit_id_completed}
              </div>
            )}
          </div>
        )}

        {/* Reason — hidden after successful submit */}
        {!isSuccess && (
          <div>
            <label className="block text-[11px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>
              Reason <span style={{ color: '#ff2f55' }}>*</span>
            </label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              rows={3}
              disabled={submitting}
              placeholder="e.g. Agent appears disconnected but host is reachable"
              className="w-full rounded px-2.5 py-1.5 text-[11px] resize-none"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)', outline: 'none', opacity: submitting ? 0.5 : 1 }}
            />
          </div>
        )}

        {/* Wait for complete — hidden after result */}
        {!hasResult && (
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={waitForComplete}
              onChange={e => setWaitForComplete(e.target.checked)}
              disabled={submitting}
              className="rounded"
            />
            <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
              Wait for complete (synchronous — may be slow)
            </span>
          </label>
        )}

        {/* Actions */}
        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={onCancel}
            disabled={submitting}
            className="px-3 py-1.5 rounded text-[11px]"
            style={{ background: 'transparent', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)', cursor: submitting ? 'not-allowed' : 'pointer' }}
          >
            {isSuccess ? 'Close' : 'Cancel'}
          </button>
          {!isSuccess && (
            <button
              type="button"
              disabled={!reason.trim() || submitting}
              onClick={() => onConfirm(reason.trim(), waitForComplete)}
              className="px-3 py-1.5 rounded text-[11px] font-semibold flex items-center gap-1.5"
              style={{
                background: reason.trim() && !submitting ? 'var(--soc-accent)' : 'rgba(0,184,255,0.15)',
                color: reason.trim() && !submitting ? '#fff' : 'rgba(0,184,255,0.4)',
                border: 'none',
                cursor: reason.trim() && !submitting ? 'pointer' : 'not-allowed',
              }}
            >
              <RefreshCw size={10}/>
              {submitting ? 'Reconnecting…' : hasResult ? 'Retry' : 'Reconnect'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function WazuhAgentDetailDrawer({
  agentId,
  agentName,
  open,
  onClose,
  auditMeta,
}: WazuhAgentDetailDrawerProps) {
  const [enrich, setEnrich]           = useState<WazuhAgentEnrichment | null>(null);
  const [loadingEnrich, setLoadingEnrich] = useState(false);
  const [enrichError, setEnrichError] = useState<string | null>(null);
  const [activeTab, setActiveTab]     = useState<TabId>('overview');
  const auditSent                     = useRef(false);

  // Reconnect state
  const [reconnectModalOpen, setReconnectModalOpen] = useState(false);
  const [reconnecting, setReconnecting]             = useState(false);
  const [reconnectResult, setReconnectResult]       = useState<WazuhReconnectResult | null>(null);
  const [reconnectError, setReconnectError]         = useState<string | null>(null);

  // Permission state for controlled actions
  const [reconnectPermission, setReconnectPermission] = useState<WazuhControlledActionProbe | null>(null);

  async function handleReconnectConfirm(reason: string, waitForComplete: boolean) {
    const id   = enrich?.agent?.id ?? agentId;
    const name = enrich?.agent?.name ?? agentName ?? undefined;
    if (!id) return;
    // Keep modal open — it shows loading state and result
    setReconnecting(true);
    setReconnectResult(null);
    setReconnectError(null);
    try {
      const result = await reconnectWazuhAgent(id, {
        reason,
        wait_for_complete: waitForComplete,
        agent_name: name,
        source_page: auditMeta?.source_page ?? 'wazuh_agent_drawer',
      });
      setReconnectResult(result);
      // Close modal automatically only on success
      if (result.status === 'ok') {
        setReconnectModalOpen(false);
      }
    } catch (e) {
      setReconnectError(String(e));
      // Keep modal open so user can see/copy error
    } finally {
      setReconnecting(false);
    }
  }

  // Reset when drawer opens with new agent
  useEffect(() => {
    if (!open) return;
    setEnrich(null);
    setEnrichError(null);
    setActiveTab('overview');
    setReconnectResult(null);
    setReconnectError(null);
    setReconnectPermission(null);
    auditSent.current = false;

    if (!agentId && !agentName) return;

    setLoadingEnrich(true);
    const id   = agentId ?? '0';
    const name = agentName ?? undefined;

    // Fetch enrichment + permissions in parallel
    Promise.all([
      getWazuhAgentEnrichment(id, name),
      getWazuhPermissions().catch(() => null),
    ]).then(([r, perms]) => {
        setEnrich(r);
        if (perms?.controlled_actions) {
          const ca = perms.controlled_actions.find(c => c.key === 'reconnect_single_agent') ?? null;
          setReconnectPermission(ca);
        }
        if (!auditSent.current) {
          auditSent.current = true;
          const resolvedId = r.agent?.id ?? agentId ?? null;
          const resolvedName = r.agent?.name ?? agentName ?? null;
          void logAuditAction({
            action_type: 'wazuh_agent_detail_opened',
            source_page: auditMeta?.source_page ?? 'unknown',
            wazuh_agent_id: resolvedId ?? undefined,
            host: resolvedName ?? undefined,
            details_json: {
              cluster_id: auditMeta?.cluster_id,
              rule_ids: auditMeta?.rule_ids,
              event_ids: auditMeta?.event_ids,
              source_reason: (r as WazuhAgentEnrichment & { source_reason?: string }).source_reason,
            },
          }).catch(() => {});
        }
      })
      .catch(e => setEnrichError(String(e)))
      .finally(() => setLoadingEnrich(false));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, agentId, agentName]);

  if (!open) return null;

  const resolvedId   = enrich?.agent?.id ?? agentId ?? null;
  const resolvedName = enrich?.agent?.name ?? agentName ?? null;

  const TABS: { id: TabId; label: string }[] = [
    { id: 'overview',     label: 'Overview' },
    { id: 'syscollector', label: 'Syscollector' },
    { id: 'sca',          label: 'SCA' },
    { id: 'fim',          label: 'FIM' },
    { id: 'rootcheck',    label: 'Rootcheck' },
    { id: 'alerts',       label: 'Recent Alerts' },
    { id: 'raw',          label: 'Raw' },
  ];

  const statusLabel = enrich?.agent?.status ?? '—';

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40"
        style={{ background: 'rgba(0,0,0,0.45)' }}
        onClick={onClose}
      />

      {/* Panel */}
      <div
        className="fixed inset-y-0 right-0 z-50 flex flex-col"
        style={{ width: '520px', maxWidth: '95vw', background: 'var(--soc-panel)', borderLeft: '1px solid var(--soc-border)', boxShadow: '0 0 40px rgba(0,0,0,0.5)' }}
      >
        {/* Header */}
        <div className="flex items-start justify-between px-4 py-3 shrink-0"
          style={{ borderBottom: '1px solid var(--soc-border)' }}>
          <div className="min-w-0">
            <p className="text-[14px] font-semibold truncate" style={{ color: 'var(--soc-foreground)' }}>
              {resolvedName ?? 'Wazuh Agent'}
            </p>
            <p className="text-[11px] font-mono mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
              {resolvedId ? `ID ${resolvedId}` : 'ID unknown'}
              {enrich?.agent?.ip ? ` · ${enrich.agent.ip}` : ''}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0 ml-3">
            {enrich?.agent?.status && (
              <span className="text-[11px] px-2 py-0.5 rounded"
                style={{ background: `${statusColor(enrich.agent.status)}18`, color: statusColor(enrich.agent.status), border: `1px solid ${statusColor(enrich.agent.status)}40`, fontWeight: 700 }}>
                {statusLabel}
              </span>
            )}
            <button type="button" onClick={onClose}
              className="rounded p-1 transition"
              style={{ color: 'var(--soc-muted-fg)' }}>
              <X size={16}/>
            </button>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex overflow-x-auto shrink-0" style={{ borderBottom: '1px solid var(--soc-border)' }}>
          {TABS.map(t => (
            <TabBtn key={t.id} id={t.id} label={t.label} active={activeTab === t.id}
              onClick={() => setActiveTab(t.id)} />
          ))}
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-4 py-3">
          {loadingEnrich && <LoadingState />}
          {enrichError && <ErrorState msg={enrichError} />}

          {!loadingEnrich && !enrich && !enrichError && (
            <EmptyState msg="No agent data available." />
          )}

          {enrich && (
            <>
              {activeTab === 'overview'     && <OverviewTab enrich={enrich} />}
              {activeTab === 'syscollector' && resolvedId && <SyscollectorTab agentId={resolvedId} />}
              {activeTab === 'sca'          && resolvedId && <SCATab agentId={resolvedId} enrichSCA={enrich.sca} />}
              {activeTab === 'fim'          && resolvedId && <FIMTab agentId={resolvedId} enrichFIM={enrich.fim} />}
              {activeTab === 'rootcheck'    && resolvedId && <RootcheckTab agentId={resolvedId} enrichRC={enrich.rootcheck} />}
              {activeTab === 'alerts'       && resolvedId && <RecentAlertsTab agentId={resolvedId} agentName={resolvedName} />}
              {activeTab === 'raw'          && resolvedId && <RawTab agentId={resolvedId} enrich={enrich} />}
              {!resolvedId && activeTab !== 'overview' && (
                <EmptyState msg="Agent ID required for this tab. Select an agent with a known Wazuh ID." />
              )}
            </>
          )}
        </div>

        {/* Controlled Wazuh Actions footer */}
        <div className="shrink-0 px-4 py-3" style={{ borderTop: '1px solid var(--soc-border)' }}>
          <p className="text-[10px] uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)', letterSpacing: '0.08em' }}>Controlled Wazuh Actions</p>

          {/* Reconnect result panel — stays visible after action */}
          {reconnectResult && (
            <div className="mb-2 rounded p-2.5 text-[11px]"
              style={{
                background: reconnectResult.status === 'ok'
                  ? 'rgba(35,211,107,0.07)'
                  : reconnectResult.status === 'blocked'
                  ? 'rgba(255,210,31,0.07)'
                  : 'rgba(255,47,85,0.07)',
                border: `1px solid ${reconnectResult.status === 'ok' ? 'rgba(35,211,107,0.25)' : reconnectResult.status === 'blocked' ? 'rgba(255,210,31,0.25)' : 'rgba(255,47,85,0.25)'}`,
              }}>
              {/* Status line */}
              <div className="font-semibold mb-1"
                style={{ color: reconnectResult.status === 'ok' ? '#23d36b' : reconnectResult.status === 'blocked' ? '#ffd21f' : '#ff2f55' }}>
                {reconnectResult.status === 'ok'    && '✓ Reconnect signal sent'}
                {reconnectResult.status === 'blocked' && '⚠ Action blocked by policy'}
                {reconnectResult.status === 'denied'  && '✗ Permission denied by Wazuh RBAC'}
                {reconnectResult.status === 'error'   && '✗ Reconnect failed'}
              </div>
              {/* Message */}
              {reconnectResult.message && (
                <div style={{ color: 'rgba(180,210,230,0.7)', marginBottom: 2 }}>{reconnectResult.message}</div>
              )}
              {/* Wazuh response summary */}
              {reconnectResult.wazuh_response && (
                <div className="mt-1 text-[10px]" style={{ color: 'rgba(180,210,230,0.5)' }}>
                  Affected: {reconnectResult.wazuh_response.total_affected_items}
                  {reconnectResult.wazuh_response.total_failed_items > 0 && (
                    <span style={{ color: '#ff2f55', marginLeft: 6 }}>
                      Failed: {reconnectResult.wazuh_response.total_failed_items}
                    </span>
                  )}
                </div>
              )}
              {/* Audit confirmation */}
              {reconnectResult.audit_id_completed != null && (
                <div className="mt-1 text-[10px]" style={{ color: 'rgba(180,210,230,0.35)' }}>
                  Audit #{reconnectResult.audit_id_completed}
                </div>
              )}
              {/* Close result */}
              <button
                type="button"
                onClick={() => setReconnectResult(null)}
                className="mt-1.5 text-[10px] underline"
                style={{ color: 'rgba(180,210,230,0.35)', background: 'none', border: 'none', cursor: 'pointer' }}
              >
                dismiss
              </button>
            </div>
          )}
          {reconnectError && (
            <div className="mb-2 rounded p-2 text-[11px]"
              style={{ background: 'rgba(255,47,85,0.08)', border: '1px solid rgba(255,47,85,0.25)', color: '#ff2f55' }}>
              ✗ {reconnectError}
              <button
                type="button"
                onClick={() => setReconnectError(null)}
                className="ml-2 underline text-[10px]"
                style={{ color: 'rgba(255,47,85,0.5)', background: 'none', border: 'none', cursor: 'pointer' }}
              >
                dismiss
              </button>
            </div>
          )}

          <div className="flex flex-wrap gap-1.5">
            {/* Reconnect — permission-aware */}
            {(() => {
              // Determine disabled reason in priority order
              let disabledReason: string | null = null;
              if (!resolvedId) {
                disabledReason = 'Agent ID required to reconnect';
              } else if (reconnectPermission?.status === 'denied') {
                disabledReason = reconnectPermission.message || 'Permission denied by Wazuh RBAC';
              } else if (reconnectPermission?.status === 'unavailable') {
                disabledReason = 'Manager API unavailable — cannot reconnect';
              }
              const isEnabled = !disabledReason && !reconnecting;
              return (
                <button
                  type="button"
                  disabled={!isEnabled}
                  onClick={() => { setReconnectResult(null); setReconnectError(null); setReconnectModalOpen(true); }}
                  title={disabledReason ?? (reconnectPermission?.status === 'unknown'
                    ? 'Reconnect this agent only — permission will be verified at execution time'
                    : 'Reconnect this agent only (requires confirmation)')}
                  className="rounded px-2.5 py-1 text-[10.5px] flex items-center gap-1.5 transition"
                  style={{
                    border: `1px solid ${isEnabled ? 'rgba(0,184,255,0.4)' : 'var(--soc-border)'}`,
                    color: isEnabled ? 'var(--soc-accent)' : 'var(--soc-muted-fg)',
                    background: isEnabled ? 'rgba(0,184,255,0.08)' : 'transparent',
                    opacity: isEnabled ? 1 : 0.45,
                    cursor: isEnabled ? 'pointer' : 'not-allowed',
                  }}
                >
                  <RefreshCw size={9}/>
                  {reconnecting ? 'Reconnecting…' : 'Reconnect Agent'}
                </button>
              );
            })()}

            {/* Still-disabled actions */}
            {['Restart agent', 'Run syscheck', 'Run rootcheck', 'Active response', 'Upgrade agent'].map(a => (
              <button
                key={a}
                type="button"
                disabled
                title="Disabled until Phase 3 — RBAC, Action Policy and Audit approval required."
                className="rounded px-2.5 py-1 text-[10.5px] flex items-center gap-1.5 cursor-not-allowed"
                style={{ border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)', background: 'transparent', opacity: 0.45 }}
              >
                <Lock size={9}/> {a}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Reconnect confirmation modal */}
      {reconnectModalOpen && resolvedId && (
        <ReconnectModal
          agentId={resolvedId}
          agentName={resolvedName}
          submitting={reconnecting}
          result={reconnectResult}
          submitError={reconnectError}
          onConfirm={handleReconnectConfirm}
          onCancel={() => { setReconnectModalOpen(false); setReconnectResult(null); setReconnectError(null); }}
        />
      )}
    </>
  );
}

export default WazuhAgentDetailDrawer;
