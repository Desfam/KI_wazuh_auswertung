import { useEffect, useState } from 'react';
import { AlertTriangle, BookOpen, CheckCircle, ChevronDown, ChevronRight, Clock, Code2, ExternalLink, Filter, Info, KeyRound, Lightbulb, Lock, MonitorCheck, RefreshCw, Server, Settings, Shield, ShieldCheck, Wifi, WifiOff, XCircle } from 'lucide-react';
import type { WazuhAgent, WazuhAPICapabilitiesResult, WazuhAPIDocSection, WazuhAPIRecipe, WazuhManagerHealth, WazuhPermissionsResult } from '../types';
import type { WazuhPingStep } from '../services/api';
import { getWazuhAgentsFiltered, getWazuhCapabilities, getWazuhDocSections, getWazuhManagerHealth, getWazuhManagerPing, getWazuhPermissions, getWazuhRecipes, logAuditAction, runWazuhLogtest } from '../services/api';
import { WazuhAgentDetailDrawer } from '../components/WazuhAgentDetailDrawer';

// ── helpers ───────────────────────────────────────────────────────────────────

function StatusPill({ ok, warn, label }: { ok?: boolean; warn?: boolean; label: string }) {
  const base = 'inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-semibold';
  if (ok)   return <span className={`${base} bg-green-500/15 text-green-400`}><CheckCircle size={11}/>{label}</span>;
  if (warn) return <span className={`${base} bg-yellow-500/15 text-yellow-400`}><AlertTriangle size={11}/>{label}</span>;
  return      <span className={`${base} bg-red-500/15 text-red-400`}><XCircle size={11}/>{label}</span>;
}

function AgentStatusBadge({ status }: { status: string }) {
  const s = status?.toLowerCase();
  if (s === 'active')           return <span className="rounded px-1.5 py-0.5 text-[10px] bg-green-500/15 text-green-400">active</span>;
  if (s === 'disconnected')     return <span className="rounded px-1.5 py-0.5 text-[10px] bg-red-500/15 text-red-400">disconnected</span>;
  if (s === 'never_connected')  return <span className="rounded px-1.5 py-0.5 text-[10px] bg-zinc-500/15 text-zinc-400">never connected</span>;
  return <span className="rounded px-1.5 py-0.5 text-[10px] bg-yellow-500/15 text-yellow-400">{status}</span>;
}

function SectionHeader({ icon, title, sub }: { icon: React.ReactNode; title: string; sub?: string }) {
  return (
    <div className="flex items-center gap-2 border-b pb-2 mb-3" style={{ borderColor: 'var(--soc-border)' }}>
      <span style={{ color: 'var(--soc-accent)' }}>{icon}</span>
      <div>
        <p className="text-[13px] font-semibold" style={{ color: 'var(--soc-foreground)' }}>{title}</p>
        {sub && <p className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{sub}</p>}
      </div>
    </div>
  );
}

function Panel({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg p-4 ${className}`} style={{ background: 'var(--soc-panel)', border: '1px solid var(--soc-border)' }}>
      {children}
    </div>
  );
}

function KV({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-2 py-0.5">
      <span className="text-[11px] shrink-0" style={{ color: 'var(--soc-muted-fg)' }}>{label}</span>
      <span className={`text-[11px] text-right ${mono ? 'font-mono' : ''}`} style={{ color: 'var(--soc-foreground)' }}>{value ?? '—'}</span>
    </div>
  );
}

const SAFETY_COLORS: Record<string, string> = {
  read_only:        'text-green-400',
  safe_test:        'text-blue-400',
  controlled_action: 'text-yellow-400',
  dangerous:        'text-red-400',
};

// ── Connection Status card ────────────────────────────────────────────────────

const PING_STEP_LABELS: Record<string, string> = {
  config: 'Config', dns: 'DNS', tcp: 'TCP', http: 'HTTP', auth: 'Auth',
};

function PingResult({ steps }: { steps: WazuhPingStep[] }) {
  return (
    <div className="mt-3 rounded p-2.5 space-y-1.5" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
      <p className="text-[10px] uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)', letterSpacing: '0.08em' }}>
        Connection test
      </p>
      {steps.map((s, i) => (
        <div key={i} className="flex items-start gap-2">
          {s.ok
            ? <CheckCircle size={11} className="shrink-0 mt-0.5" style={{ color: '#23d36b' }}/>
            : <XCircle    size={11} className="shrink-0 mt-0.5" style={{ color: '#ff2f55' }}/>
          }
          <div className="min-w-0">
            <span className="text-[11px] font-semibold mr-2"
              style={{ color: s.ok ? '#23d36b' : '#ff2f55' }}>
              {PING_STEP_LABELS[s.step] ?? s.step}
            </span>
            <span className="text-[11px]" style={{ color: 'var(--soc-foreground)' }}>{s.detail}</span>
            <span className="text-[10px] ml-2" style={{ color: 'var(--soc-muted-fg)' }}>{s.duration_ms} ms</span>
          </div>
        </div>
      ))}
    </div>
  );
}

function ConnectionStatusCard({ health, loading, onRefresh }: {
  health: WazuhManagerHealth | null;
  loading: boolean;
  onRefresh: () => void;
}) {
  const [pingSteps, setPingSteps]   = useState<WazuhPingStep[] | null>(null);
  const [pinging, setPinging]       = useState(false);

  function runPing() {
    setPingSteps(null);
    setPinging(true);
    getWazuhManagerPing()
      .then(r => setPingSteps(r.steps))
      .catch(e => setPingSteps([{ step: 'config', ok: false, detail: String(e), duration_ms: 0 }]))
      .finally(() => setPinging(false));
  }

  return (
    <Panel>
      <SectionHeader icon={<Wifi size={15}/>} title="Manager API Connection" sub="Wazuh Manager REST API (port 55000)" />
      {loading && <p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>Checking…</p>}
      {!loading && !health && (
        <p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>No data — click refresh</p>
      )}
      {!loading && health && (
        <div className="space-y-1.5">
          <div className="flex gap-2 flex-wrap mb-2">
            <StatusPill ok={health.configured} warn={!health.configured} label={health.configured ? 'Configured' : 'Not configured'} />
            <StatusPill ok={health.reachable} warn={!health.reachable} label={health.reachable ? 'Reachable' : 'Unreachable'} />
            <StatusPill ok={health.authenticated} warn={!health.authenticated} label={health.authenticated ? 'Authenticated' : 'Auth failed'} />
          </div>
          <KV label="Manager version" value={health.manager_version} />
          <KV label="API version"     value={health.api_version} />
          <KV label="Hostname"        value={health.hostname} mono />
          <KV label="Cluster"         value={health.cluster_enabled == null ? '?' : health.cluster_enabled ? 'enabled' : 'disabled'} />
          {health.agent_status_summary && (
            <div className="mt-2 rounded p-2" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
              <p className="text-[10px] uppercase tracking-widest mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Agent status</p>
              <div className="flex gap-4 flex-wrap">
                {Object.entries(health.agent_status_summary).map(([k, v]) => (
                  <div key={k} className="text-center">
                    <p className="text-[13px] font-bold" style={{ color: 'var(--soc-foreground)' }}>{String(v)}</p>
                    <p className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>{k}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
          {health.message && health.message !== 'OK' && (
            <p className="text-[11px] mt-1" style={{ color: 'var(--soc-muted-fg)' }}>{health.message}</p>
          )}
          {health.last_checked && (
            <p className="text-[10px] mt-1 flex items-center gap-1" style={{ color: 'var(--soc-muted-fg)' }}>
              <Clock size={10}/> {new Date(health.last_checked).toLocaleTimeString()}
            </p>
          )}
          {!health.configured && (
            <div className="mt-2 rounded p-2 text-[11px]" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
              <Info size={12} className="inline mr-1"/>
              Set <code className="font-mono">manager_url</code>, <code className="font-mono">manager_username</code> and{' '}
              <code className="font-mono">manager_password</code> in Settings to enable Manager API features.
              <br/>The Indexer still works independently.
            </div>
          )}
        </div>
      )}
      <button
        type="button"
        onClick={onRefresh}
        disabled={loading}
        className="mt-3 flex items-center gap-1 rounded px-3 py-1 text-[11px] transition"
        style={{ border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)', background: 'transparent' }}
      >
        <RefreshCw size={11} className={loading ? 'animate-spin' : ''}/> Refresh
      </button>
      <button
        type="button"
        onClick={runPing}
        disabled={pinging}
        className="mt-2 flex items-center gap-1 rounded px-3 py-1 text-[11px] transition"
        style={{ border: '1px solid var(--soc-border)', color: pinging ? 'var(--soc-muted-fg)' : 'var(--soc-foreground)', background: 'transparent' }}
      >
        <Wifi size={11} className={pinging ? 'animate-pulse' : ''}/> {pinging ? 'Testing…' : 'Test connection'}
      </button>
      {pingSteps && <PingResult steps={pingSteps} />}
    </Panel>
  );
}

// ── Agents table row ──────────────────────────────────────────────────────────

function AgentRow({ agent, onSelect }: { agent: WazuhAgent; onSelect: (a: WazuhAgent) => void }) {
  return (
    <tr
      className="cursor-pointer hover:bg-white/5"
      style={{ borderBottom: '1px solid var(--soc-border)' }}
      onClick={() => onSelect(agent)}
    >
      <td className="py-1.5 pr-3 font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{agent.id}</td>
      <td className="py-1.5 pr-3 text-[12px] font-medium" style={{ color: 'var(--soc-foreground)' }}>{agent.name}</td>
      <td className="py-1.5 pr-3"><AgentStatusBadge status={agent.status} /></td>
      <td className="py-1.5 pr-3 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
        {agent.os?.name ?? agent.os?.platform ?? '—'}
      </td>
      <td className="py-1.5 pr-3 font-mono text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{agent.ip ?? '—'}</td>
      <td className="py-1.5 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
        {Array.isArray(agent.group) ? agent.group.join(', ') : (agent.group ?? '—')}
      </td>
    </tr>
  );
}

// ── Icon map for doc sections ─────────────────────────────────────────────────

const DOC_ICON: Record<string, React.ReactNode> = {
  BookOpen: <BookOpen size={16}/>,
  FileJson: <Code2 size={16}/>,
  Filter: <Filter size={16}/>,
  ShieldCheck: <ShieldCheck size={16}/>,
  KeyRound: <KeyRound size={16}/>,
  Settings: <Settings size={16}/>,
  Lightbulb: <Lightbulb size={16}/>,
  Code2: <Code2 size={16}/>,
};

// ── Permission status dot ─────────────────────────────────────────────────────

function PermStatusDot({ status }: { status: string }) {
  if (status === 'ok')          return <span className="inline-block w-2 h-2 rounded-full bg-green-400 mr-1.5 shrink-0"/>;
  if (status === 'denied')      return <span className="inline-block w-2 h-2 rounded-full bg-red-400 mr-1.5 shrink-0"/>;
  if (status === 'unavailable') return <span className="inline-block w-2 h-2 rounded-full bg-yellow-400 mr-1.5 shrink-0"/>;
  if (status === 'skipped')     return <span className="inline-block w-2 h-2 rounded-full bg-zinc-500 mr-1.5 shrink-0"/>;
  return                               <span className="inline-block w-2 h-2 rounded-full bg-orange-400 mr-1.5 shrink-0"/>;
}

// ── Recipe safety badge ───────────────────────────────────────────────────────

function RecipeSafetyBadge({ safety }: { safety: string }) {
  const map: Record<string, string> = {
    read_only:        'bg-green-500/15 text-green-400',
    safe_test:        'bg-blue-500/15 text-blue-400',
    controlled_action: 'bg-yellow-500/15 text-yellow-400',
    dangerous:        'bg-red-500/15 text-red-400',
  };
  return (
    <span className={`rounded px-2 py-0.5 text-[10px] font-semibold ${map[safety] ?? 'bg-zinc-500/15 text-zinc-400'}`}>
      {safety.replace('_', ' ')}
    </span>
  );
}

// ── Tab: Overview ────────────────────────────────────────────────────────────

function OverviewTab({
  health, healthLoading, caps, onRefreshHealth,
}: {
  health: WazuhManagerHealth | null;
  healthLoading: boolean;
  caps: WazuhAPICapabilitiesResult | null;
  onRefreshHealth: () => void;
}) {
  return (
    <div className="space-y-4">
      {/* Architecture overview */}
      <Panel>
        <SectionHeader icon={<Info size={15}/>} title="Architecture" sub="Two independent data sources" />
        <div className="grid grid-cols-2 gap-3 text-[11px]">
          <div className="rounded p-3" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
            <p className="font-semibold mb-1" style={{ color: 'var(--soc-foreground)' }}>Wazuh Indexer (OpenSearch)</p>
            <ul className="space-y-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
              {['Alert search', 'Timeline', 'Event Map', 'Full Scan', 'Export / Reports', 'Historical data'].map(i => (
                <li key={i} className="flex items-center gap-1"><CheckCircle size={10} className="text-green-400 shrink-0"/>{i}</li>
              ))}
            </ul>
          </div>
          <div className="rounded p-3" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
            <p className="font-semibold mb-1" style={{ color: 'var(--soc-foreground)' }}>Wazuh Manager API (port 55000)</p>
            <ul className="space-y-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
              {['Agent inventory', 'Syscollector', 'FIM / Syscheck', 'SCA', 'Rootcheck', 'Rules & decoders', 'Logtest'].map(i => (
                <li key={i} className="flex items-center gap-1"><CheckCircle size={10} className="text-blue-400 shrink-0"/>{i}</li>
              ))}
            </ul>
          </div>
        </div>
        {health && !health.reachable && health.configured && (
          <div className="mt-2 rounded p-2 text-[11px]"
            style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
            <AlertTriangle size={11} className="inline mr-1 text-yellow-400"/>
            Indexer queries work, but Manager API features may be limited.
          </div>
        )}
      </Panel>

      {/* Connection status */}
      <ConnectionStatusCard health={health} loading={healthLoading} onRefresh={onRefreshHealth} />

      {/* Capability summary */}
      {caps && (
        <Panel>
          <SectionHeader icon={<MonitorCheck size={15}/>} title="API Capability Summary" />
          {caps.spec_loaded === false && (
            <div className="mb-3 flex items-start gap-2 rounded p-2 text-[11px]"
              style={{ background: 'var(--soc-warning-bg, rgba(234,179,8,0.08))', border: '1px solid rgba(234,179,8,0.3)', color: 'var(--soc-warning, #ca8a04)' }}>
              <AlertTriangle size={13} className="mt-0.5 shrink-0" style={{ color: '#ca8a04' }}/>
              <div>
                <span className="font-semibold">Spec file not found</span>
                {' — '}endpoint counts below show 0. Place <code>spec-v4.14.5.yaml</code> in the project root or set{' '}
                <code>WAZUH_API_SPEC_PATH</code> environment variable.
                {caps.spec_search_paths && caps.spec_search_paths.length > 0 && (
                  <div className="mt-1 font-mono opacity-70">{caps.spec_search_paths[0]}</div>
                )}
              </div>
            </div>
          )}
          <div className="flex gap-3 flex-wrap">
            <div className="text-center rounded p-3 flex-1" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
              <p className="text-[20px] font-bold text-green-400">{caps.summary.read_only_implemented}</p>
              <p className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>Implemented</p>
            </div>
            <div className="text-center rounded p-3 flex-1" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
              <p className="text-[20px] font-bold text-yellow-400">{caps.summary.controlled_disabled}</p>
              <p className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>Controlled (gated)</p>
            </div>
            <div className="text-center rounded p-3 flex-1" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
              <p className="text-[20px] font-bold text-red-400">{caps.summary.dangerous_disabled}</p>
              <p className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>Dangerous (disabled)</p>
            </div>
            <div className="text-center rounded p-3 flex-1" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
              <p className="text-[20px] font-bold" style={{ color: 'var(--soc-foreground)' }}>{caps.summary.total}</p>
              <p className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>Total spec endpoints</p>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

// ── Tab: Agents ──────────────────────────────────────────────────────────────

function AgentsTab({ onSelectAgent }: { onSelectAgent: (a: WazuhAgent) => void }) {
  const [agents, setAgents]           = useState<WazuhAgent[]>([]);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [search, setSearch]           = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterOS, setFilterOS]       = useState('');
  const [filterGroup, setFilterGroup] = useState('');
  const [builtWQL, setBuiltWQL]       = useState('');
  const [customQ, setCustomQ]         = useState('');

  function buildWqlPreview() {
    const parts: string[] = [];
    if (filterStatus)  parts.push(`status=${filterStatus}`);
    if (filterOS)      parts.push(`os.platform=${filterOS}`);
    if (filterGroup)   parts.push(`group=${filterGroup}`);
    if (search)        parts.push(`name~${search}`);
    return parts.join(';');
  }

  useEffect(() => {
    setBuiltWQL(buildWqlPreview());
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filterStatus, filterOS, filterGroup, search]);

  function load() {
    setLoading(true); setError(null);
    const q = customQ || builtWQL || undefined;
    getWazuhAgentsFiltered({ limit: 500, q })
      .then(r => setAgents(r.data?.affected_items ?? []))
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }

  const statusCounts = agents.reduce<Record<string, number>>((acc, a) => {
    acc[a.status] = (acc[a.status] ?? 0) + 1; return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* WQL filter bar */}
      <Panel>
        <SectionHeader icon={<Filter size={15}/>} title="WQL Filter" sub="Combine filters or use raw WQL" />
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 mb-2">
          <div>
            <p className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Status</p>
            <select value={filterStatus} onChange={e => setFilterStatus(e.target.value)}
              className="w-full rounded px-2 py-1 text-[11px]"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}>
              <option value="">Any</option>
              <option value="active">Active</option>
              <option value="disconnected">Disconnected</option>
              <option value="never_connected">Never connected</option>
            </select>
          </div>
          <div>
            <p className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>OS Platform</p>
            <select value={filterOS} onChange={e => setFilterOS(e.target.value)}
              className="w-full rounded px-2 py-1 text-[11px]"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}>
              <option value="">Any</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="darwin">macOS</option>
            </select>
          </div>
          <div>
            <p className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Group</p>
            <input value={filterGroup} onChange={e => setFilterGroup(e.target.value)}
              placeholder="e.g. default"
              className="w-full rounded px-2 py-1 text-[11px]"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }} />
          </div>
          <div>
            <p className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Name contains</p>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search name…"
              className="w-full rounded px-2 py-1 text-[11px]"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }} />
          </div>
        </div>
        {/* WQL preview / custom override */}
        <div className="flex gap-2 items-start mb-2">
          <div className="flex-1">
            <p className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>
              Generated WQL (editable — overrides filters above)
            </p>
            <input
              value={customQ || builtWQL}
              onChange={e => setCustomQ(e.target.value)}
              placeholder="e.g. status=active;os.platform=windows"
              className="w-full rounded px-2 py-1 text-[11px] font-mono"
              style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
            />
          </div>
          {customQ && (
            <button type="button" onClick={() => setCustomQ('')}
              className="mt-5 text-[10px] px-2 py-1 rounded"
              style={{ border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)', background: 'transparent' }}>
              Reset
            </button>
          )}
        </div>
        <button type="button" onClick={load} disabled={loading}
          className="flex items-center gap-1 rounded px-4 py-1.5 text-[11px] transition"
          style={{ background: 'var(--soc-accent)', color: '#fff', opacity: loading ? 0.6 : 1 }}>
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''}/> {loading ? 'Loading…' : 'Load agents'}
        </button>
      </Panel>

      {/* Results */}
      <Panel>
        <div className="flex items-center justify-between mb-3">
          <SectionHeader icon={<Server size={15}/>} title="Agents"
            sub={agents.length > 0 ? `${agents.length} agents loaded` : 'Click Load agents'} />
        </div>

        {agents.length > 0 && (
          <div className="flex gap-2 mb-3 flex-wrap">
            {Object.entries(statusCounts).map(([s, n]) => (
              <span key={s} className="rounded px-2 py-0.5 text-[10px]"
                style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
                {n} {s}
              </span>
            ))}
          </div>
        )}

        {error && (
          <p className="text-[12px] text-red-400 mb-2">
            {error.includes('503') || error.includes('not configured')
              ? 'Manager API not configured — set manager_url/credentials in Settings.'
              : error.includes('getaddrinfo') || error.includes('Errno 11001')
              ? 'Manager API host unreachable — check hostname/network in Settings.'
              : error}
          </p>
        )}

        {agents.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-[11px] border-collapse">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--soc-border)' }}>
                  {['ID', 'Name', 'Status', 'OS', 'IP', 'Groups'].map(h => (
                    <th key={h} className="text-left py-1 pr-3 font-semibold" style={{ color: 'var(--soc-muted-fg)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {agents.map(a => (
                  <AgentRow key={a.id} agent={a} onSelect={ag => {
                    void logAuditAction({
                      action_type: 'wazuh_agent_detail_opened',
                      source_page: 'wazuh_integration',
                      wazuh_agent_id: ag.id,
                      host: ag.name,
                    }).catch(() => {});
                    onSelectAgent(ag);
                  }} />
                ))}
              </tbody>
            </table>
          </div>
        )}
        {agents.length === 0 && !loading && !error && (
          <p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>No agents loaded. Use the filter above and click Load agents.</p>
        )}
      </Panel>
    </div>
  );
}

// ── Tab: Capabilities ────────────────────────────────────────────────────────

function CapabilitiesTab({ caps }: { caps: WazuhAPICapabilitiesResult | null }) {
  const [showAll, setShowAll]       = useState(false);
  const [filterSafety, setFilterSafety] = useState('');
  const [filterTag, setFilterTag]   = useState('');

  if (!caps) {
    return (
      <Panel>
        <SectionHeader icon={<MonitorCheck size={15}/>} title="API Capability Matrix" />
        <p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
          Place <code className="font-mono text-[11px]">spec-v4.14.5.yaml</code> in the project root to enable this view.
        </p>
      </Panel>
    );
  }

  const { summary, capabilities } = caps;
  const tags = [...new Set(capabilities.map(c => c.tag))].sort();
  const filtered = capabilities.filter(c =>
    (!filterSafety || c.safety === filterSafety) &&
    (!filterTag || c.tag === filterTag)
  );
  const shown = showAll ? filtered : filtered.slice(0, 40);

  return (
    <div className="space-y-4">
      <Panel>
        <SectionHeader icon={<MonitorCheck size={15}/>} title="API Capability Matrix"
          sub={`${summary.total} endpoints from OpenAPI spec`} />
        <div className="flex gap-2 flex-wrap mb-3">
          <span className="rounded px-2 py-0.5 text-[11px] bg-green-500/15 text-green-400">{summary.read_only_implemented} implemented</span>
          <span className="rounded px-2 py-0.5 text-[11px] bg-zinc-500/15 text-zinc-400">{summary.read_only_total - summary.read_only_implemented} read-only missing</span>
          <span className="rounded px-2 py-0.5 text-[11px] bg-yellow-500/15 text-yellow-400">{summary.controlled_disabled} controlled (gated)</span>
          <span className="rounded px-2 py-0.5 text-[11px] bg-red-500/15 text-red-400">{summary.dangerous_disabled} dangerous (disabled)</span>
        </div>
        <div className="flex gap-2 mb-3 flex-wrap">
          <select value={filterSafety} onChange={e => setFilterSafety(e.target.value)}
            className="rounded px-2 py-1 text-[11px]"
            style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}>
            <option value="">All safety levels</option>
            <option value="read_only">read_only</option>
            <option value="safe_test">safe_test</option>
            <option value="controlled_action">controlled_action</option>
            <option value="dangerous">dangerous</option>
          </select>
          <select value={filterTag} onChange={e => setFilterTag(e.target.value)}
            className="rounded px-2 py-1 text-[11px]"
            style={{ background: 'var(--soc-input)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}>
            <option value="">All tags</option>
            {tags.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-[11px] border-collapse">
            <thead>
              <tr style={{ borderBottom: '1px solid var(--soc-border)' }}>
                {['Method', 'Path', 'Tag', 'Safety', 'Status'].map(h => (
                  <th key={h} className="text-left py-1 pr-3 font-semibold" style={{ color: 'var(--soc-muted-fg)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((c, i) => (
                <tr key={i} style={{ borderBottom: '1px solid var(--soc-border)' }} className="hover:bg-white/5">
                  <td className="py-1 pr-3 font-mono font-bold" style={{ color: 'var(--soc-accent)' }}>{c.method}</td>
                  <td className="py-1 pr-3 font-mono" style={{ color: 'var(--soc-foreground)', maxWidth: 280, wordBreak: 'break-all' }}>{c.path}</td>
                  <td className="py-1 pr-3" style={{ color: 'var(--soc-muted-fg)' }}>{c.tag}</td>
                  <td className={`py-1 pr-3 ${SAFETY_COLORS[c.safety] ?? ''}`}>{c.safety}</td>
                  <td className="py-1">
                    {c.safety === 'dangerous' || c.safety === 'controlled_action'
                      ? <span className="flex items-center gap-1 text-zinc-500"><Lock size={10}/> disabled</span>
                      : c.implemented
                      ? <span className="flex items-center gap-1 text-green-400"><CheckCircle size={10}/> yes</span>
                      : <span className="flex items-center gap-1 text-zinc-500">—</span>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length > 40 && (
          <button type="button" onClick={() => setShowAll(v => !v)}
            className="mt-2 text-[11px] flex items-center gap-1" style={{ color: 'var(--soc-accent)' }}>
            {showAll ? <ChevronDown size={12}/> : <ChevronRight size={12}/>}
            {showAll ? 'Show less' : `Show all ${filtered.length}`}
          </button>
        )}
      </Panel>
    </div>
  );
}

// ── Tab: Permissions ─────────────────────────────────────────────────────────

function PermissionsTab() {
  const [data, setData]     = useState<WazuhPermissionsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState<string | null>(null);

  function run() {
    setLoading(true); setError(null);
    getWazuhPermissions()
      .then(setData)
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }

  const overallColor = data?.overall === 'ok' ? 'text-green-400'
    : data?.overall === 'warning' ? 'text-yellow-400'
    : 'text-red-400';

  return (
    <Panel>
      <SectionHeader icon={<ShieldCheck size={15}/>} title="RBAC Permission Probe"
        sub="Read-only live check of all required API permissions" />

      <button type="button" onClick={run} disabled={loading}
        className="flex items-center gap-1 rounded px-4 py-1.5 text-[11px] mb-4 transition"
        style={{ background: 'var(--soc-accent)', color: '#fff', opacity: loading ? 0.6 : 1 }}>
        <ShieldCheck size={11} className={loading ? 'animate-spin' : ''}/> {loading ? 'Checking…' : 'Run permission probe'}
      </button>

      {error && <p className="text-[12px] text-red-400 mb-3">{error}</p>}

      {data && (
        <>
          <div className="flex items-center gap-2 mb-3">
            <span className={`text-[13px] font-semibold ${overallColor}`}>
              Overall: {data.overall.toUpperCase()}
            </span>
            <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
              · Checked {new Date(data.checked_at).toLocaleTimeString()}
            </span>
            {data.sample_agent_id && (
              <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                · Sample agent: {data.sample_agent_id}
              </span>
            )}
          </div>

          {data.warnings.length > 0 && (
            <div className="mb-3 text-[11px] space-y-0.5">
              {data.warnings.map((w, i) => (
                <p key={i} className="text-yellow-400"><AlertTriangle size={10} className="inline mr-1"/>{w}</p>
              ))}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-[11px] border-collapse">
              <thead>
                <tr style={{ borderBottom: '1px solid var(--soc-border)' }}>
                  {['Status', 'Permission', 'Endpoint', 'Required for', 'Impact if missing'].map(h => (
                    <th key={h} className="text-left py-1 pr-3 font-semibold" style={{ color: 'var(--soc-muted-fg)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {data.permissions.map((p, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--soc-border)' }} className="hover:bg-white/5">
                    <td className="py-1.5 pr-3">
                      <span className="flex items-center">
                        <PermStatusDot status={p.status}/>
                        <span className={
                          p.status === 'ok' ? 'text-green-400' :
                          p.status === 'denied' ? 'text-red-400' :
                          p.status === 'skipped' ? 'text-zinc-400' : 'text-yellow-400'
                        }>{p.status}</span>
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 font-semibold" style={{ color: 'var(--soc-foreground)' }}>{p.label}</td>
                    <td className="py-1.5 pr-3 font-mono text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>{p.endpoint}</td>
                    <td className="py-1.5 pr-3 text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                      {p.required_for.join(', ')}
                    </td>
                    <td className="py-1.5 text-[10px]" style={{ color: p.status !== 'ok' ? 'var(--soc-foreground)' : 'var(--soc-muted-fg)' }}>
                      {p.status !== 'ok' ? p.impact_if_missing : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {!data && !loading && !error && (
        <p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>
          Click "Run permission probe" to test all required RBAC permissions against the live API.
        </p>
      )}
    </Panel>
  );
}

// ── Tab: Recipes ──────────────────────────────────────────────────────────────

function RecipesTab() {
  const [recipes, setRecipes] = useState<WazuhAPIRecipe[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    getWazuhRecipes()
      .then(r => setRecipes(r.recipes))
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Panel><p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>Loading recipes…</p></Panel>;
  if (error)   return <Panel><p className="text-[12px] text-red-400">{error}</p></Panel>;

  return (
    <div className="space-y-3">
      {recipes.map(r => (
        <Panel key={r.recipe_id}>
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[13px] font-semibold" style={{ color: 'var(--soc-foreground)' }}>{r.title}</span>
                <RecipeSafetyBadge safety={r.safety} />
                <span className={`text-[10px] rounded px-1.5 py-0.5 ${r.implemented ? 'bg-green-500/15 text-green-400' : 'bg-zinc-500/15 text-zinc-400'}`}>
                  {r.implemented ? 'Phase 1 ✓' : `Phase ${r.phase}`}
                </span>
              </div>
              <p className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{r.purpose}</p>
            </div>
            <button type="button" onClick={() => setExpanded(expanded === r.recipe_id ? null : r.recipe_id)}
              className="shrink-0" style={{ color: 'var(--soc-accent)' }}>
              {expanded === r.recipe_id ? <ChevronDown size={14}/> : <ChevronRight size={14}/>}
            </button>
          </div>

          {expanded === r.recipe_id && (
            <div className="mt-3 space-y-2 text-[11px]">
              <div>
                <p className="font-semibold mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Endpoints</p>
                {r.endpoints.map((ep, i) => (
                  <code key={i} className="block font-mono text-[10px] rounded px-2 py-0.5 mb-0.5"
                    style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-accent)' }}>
                    {ep}
                  </code>
                ))}
              </div>
              <div>
                <p className="font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>Required permissions</p>
                <p style={{ color: 'var(--soc-foreground)' }}>{r.required_permissions.join(', ')}</p>
              </div>
              <div>
                <p className="font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>Used in app</p>
                {r.app_locations.map((loc, i) => (
                  <p key={i} style={{ color: 'var(--soc-foreground)' }}>• {loc}</p>
                ))}
              </div>
              {r.notes && (
                <div className="rounded p-2 text-[10px]" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
                  <Info size={10} className="inline mr-1"/>{r.notes}
                </div>
              )}
            </div>
          )}
        </Panel>
      ))}
    </div>
  );
}

// ── Tab: Docs ─────────────────────────────────────────────────────────────────

function DocsTab() {
  const [sections, setSections] = useState<WazuhAPIDocSection[]>([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState<string | null>(null);

  useEffect(() => {
    getWazuhDocSections()
      .then(r => setSections(r.sections))
      .catch(e => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="grid grid-cols-2 gap-3"><Panel><p className="text-[12px]" style={{ color: 'var(--soc-muted-fg)' }}>Loading…</p></Panel></div>;
  if (error)   return <Panel><p className="text-[12px] text-red-400">{error}</p></Panel>;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
      {sections.map(s => (
        <Panel key={s.key}>
          <div className="flex items-start gap-3">
            <span style={{ color: 'var(--soc-accent)' }} className="mt-0.5 shrink-0">
              {DOC_ICON[s.icon] ?? <BookOpen size={16}/>}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between gap-2 mb-1">
                <p className="text-[13px] font-semibold" style={{ color: 'var(--soc-foreground)' }}>{s.title}</p>
                <a href={s.url} target="_blank" rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[11px] shrink-0"
                  style={{ color: 'var(--soc-accent)' }}>
                  Docs <ExternalLink size={10}/>
                </a>
              </div>
              <p className="text-[11px] mb-1.5" style={{ color: 'var(--soc-muted-fg)' }}>{s.purpose}</p>
              <div className="rounded p-1.5 text-[10px]"
                style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
                <span className="font-semibold">App usage: </span>{s.app_usage}
              </div>
            </div>
          </div>
        </Panel>
      ))}
    </div>
  );
}

// ── Tab: Safety ───────────────────────────────────────────────────────────────

function SafetyTab({ caps }: { caps: WazuhAPICapabilitiesResult | null }) {
  const implemented   = caps?.capabilities.filter(c => c.implemented) ?? [];
  const controlled    = caps?.capabilities.filter(c => c.safety === 'controlled_action') ?? [];
  const dangerous     = caps?.capabilities.filter(c => c.safety === 'dangerous') ?? [];

  return (
    <div className="space-y-4">
      <Panel>
        <SectionHeader icon={<Shield size={15}/>} title="Safety Framework"
          sub="How this app classifies Wazuh API endpoints" />
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 text-[11px]">
          <div className="rounded p-3" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
            <p className="font-semibold text-green-400 mb-1">Read-only ✓ Implemented</p>
            <p style={{ color: 'var(--soc-muted-fg)' }}>Safe GET endpoints with no side effects. {implemented.length} implemented in Phase 1.</p>
          </div>
          <div className="rounded p-3" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
            <p className="font-semibold text-yellow-400 mb-1">Controlled (gated)</p>
            <p style={{ color: 'var(--soc-muted-fg)' }}>Actions that cause real change on a single target. Require explicit user confirmation. {controlled.length} endpoints — Phase 2.</p>
          </div>
          <div className="rounded p-3" style={{ background: 'var(--soc-bg)', border: '1px solid var(--soc-border)' }}>
            <p className="font-semibold text-red-400 mb-1">Dangerous (disabled)</p>
            <p style={{ color: 'var(--soc-muted-fg)' }}>Bulk actions, manager restart, config changes, rule updates. {dangerous.length} endpoints — never enabled without formal approval.</p>
          </div>
        </div>
      </Panel>

      <Panel>
        <SectionHeader icon={<CheckCircle size={15}/>} title="Phase 1 — Implemented (read-only)"
          sub={`${implemented.length} endpoints`} />
        <div className="space-y-0.5">
          {implemented.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] py-0.5" style={{ borderBottom: '1px solid var(--soc-border)' }}>
              <span className="font-mono font-bold w-10 shrink-0" style={{ color: 'var(--soc-accent)' }}>{c.method}</span>
              <span className="font-mono flex-1" style={{ color: 'var(--soc-foreground)' }}>{c.path}</span>
              <span style={{ color: 'var(--soc-muted-fg)' }}>{c.tag}</span>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <SectionHeader icon={<Lock size={15}/>} title="Phase 2 — Controlled (gated, not yet enabled)"
          sub={`${controlled.length} endpoints — require confirmation dialog`} />
        <div className="space-y-0.5">
          {controlled.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] py-0.5 opacity-60" style={{ borderBottom: '1px solid var(--soc-border)' }}>
              <span className="font-mono font-bold w-10 shrink-0 text-yellow-400">{c.method}</span>
              <span className="font-mono flex-1" style={{ color: 'var(--soc-foreground)' }}>{c.path}</span>
              <Lock size={10} className="text-yellow-400 shrink-0"/>
            </div>
          ))}
        </div>
      </Panel>

      <Panel>
        <SectionHeader icon={<XCircle size={15}/>} title="Dangerous (permanently disabled)"
          sub={`${dangerous.length} endpoints — cannot be called through this app`} />
        <div className="space-y-0.5">
          {dangerous.map((c, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] py-0.5 opacity-40" style={{ borderBottom: '1px solid var(--soc-border)' }}>
              <span className="font-mono font-bold w-10 shrink-0 text-red-400">{c.method}</span>
              <span className="font-mono flex-1" style={{ color: 'var(--soc-foreground)' }}>{c.path}</span>
              <XCircle size={10} className="text-red-400 shrink-0"/>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

// ── Main page (7 tabs) ────────────────────────────────────────────────────────

type PageTab = 'overview' | 'agents' | 'capabilities' | 'permissions' | 'recipes' | 'docs' | 'safety';

const TAB_LABELS: { id: PageTab; label: string }[] = [
  { id: 'overview',     label: 'Overview' },
  { id: 'agents',       label: 'Agents' },
  { id: 'capabilities', label: 'Capabilities' },
  { id: 'permissions',  label: 'Permissions' },
  { id: 'recipes',      label: 'Recipes' },
  { id: 'docs',         label: 'Docs' },
  { id: 'safety',       label: 'Safety' },
];

export function WazuhIntegrationPage() {
  const [activeTab, setActiveTab]         = useState<PageTab>('overview');
  const [health, setHealth]               = useState<WazuhManagerHealth | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);
  const [caps, setCaps]                   = useState<WazuhAPICapabilitiesResult | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<WazuhAgent | null>(null);

  function loadHealth() {
    setHealthLoading(true);
    getWazuhManagerHealth()
      .then(setHealth)
      .catch(() => setHealth(null))
      .finally(() => setHealthLoading(false));
  }

  useEffect(() => {
    loadHealth();
    getWazuhCapabilities()
      .then(setCaps)
      .catch(() => setCaps(null));
  }, []);

  return (
    <div className="h-full overflow-y-auto" style={{ padding: '12px' }}>
      <div className="max-w-[1400px] mx-auto space-y-4">

        {/* page header */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-[0.3em]" style={{ color: 'var(--soc-muted-fg)' }}>Wazuh</p>
            <h2 className="text-[18px] font-bold" style={{ color: 'var(--soc-foreground)' }}>Integration</h2>
          </div>
          <div className="flex gap-2 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
            <span className="flex items-center gap-1">
              <Server size={12}/> Indexer: independent
            </span>
            <span className="flex items-center gap-1">
              {health?.reachable
                ? <Wifi size={12} className="text-green-400"/>
                : <WifiOff size={12} className="text-red-400"/>}
              Manager API: {health?.reachable ? 'ok' : health ? 'unreachable' : 'unknown'}
            </span>
          </div>
        </div>

        {/* tab bar */}
        <div className="flex border-b gap-0.5" style={{ borderColor: 'var(--soc-border)' }}>
          {TAB_LABELS.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              className="px-4 py-2 text-[12px] transition whitespace-nowrap"
              style={{
                color: activeTab === t.id ? 'var(--soc-accent)' : 'var(--soc-muted-fg)',
                borderBottom: activeTab === t.id ? '2px solid var(--soc-accent)' : '2px solid transparent',
                background: 'transparent',
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* tab content */}
        {activeTab === 'overview' && (
          <OverviewTab health={health} healthLoading={healthLoading} caps={caps} onRefreshHealth={loadHealth} />
        )}
        {activeTab === 'agents' && (
          <AgentsTab onSelectAgent={setSelectedAgent} />
        )}
        {activeTab === 'capabilities' && (
          <CapabilitiesTab caps={caps} />
        )}
        {activeTab === 'permissions' && (
          <PermissionsTab />
        )}
        {activeTab === 'recipes' && (
          <RecipesTab />
        )}
        {activeTab === 'docs' && (
          <DocsTab />
        )}
        {activeTab === 'safety' && (
          <SafetyTab caps={caps} />
        )}
      </div>

      {/* Agent detail drawer */}
      <WazuhAgentDetailDrawer
        agentId={selectedAgent?.id ?? null}
        agentName={selectedAgent?.name ?? null}
        open={!!selectedAgent}
        onClose={() => {
          void logAuditAction({
            action_type: 'wazuh_agent_detail_closed',
            source_page: 'wazuh_integration',
            wazuh_agent_id: selectedAgent?.id,
            host: selectedAgent?.name,
          }).catch(() => {});
          setSelectedAgent(null);
        }}
        auditMeta={{ source_page: 'wazuh_integration' }}
      />
    </div>
  );
}

