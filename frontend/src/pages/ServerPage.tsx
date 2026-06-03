/**
 * ServerPage — Server Operations
 * Remote access management: SSH, RDP, file browser, network tools.
 * Integrates with legacy SSH/RDP Manager logic via backend services.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity,
  Archive,
  Copy,
  Download,
  FileText,
  Folder,
  Globe,
  Heart,
  Info,
  Layers,
  Monitor,
  Network,
  Plus,
  RefreshCw,
  Search,
  Server,
  Terminal,
  Trash2,
  Upload,
  Wifi,
  X,
  Zap,
} from 'lucide-react';
import type {
  LegacyFeatureRisk,
  LegacyFeatureStatus,
  LegacyServerFeature,
  LegacyServerFeatureResponse,
  LegacyImportReport,
  PingResult,
  ServerActionResult,
  ServerActivityLog,
  ServerConnection,
  ServerConnectionInput,
  SshConfigExportResult,
  SshFileBrowserEntry,
  SshHostInfoResult,
  SshReadOnlyCommand,
  SshReadOnlyCommandResult,
} from '../types';
import {
  createServerConnection,
  deleteServerConnection,
  dnsServerConnection,
  exportSshConfig,
  getServerActivity,
  getServerConnections,
  getServerLegacyFeatures,
  getSshReadOnlyCommands,
  getSshConfig,
  healthCheckServerConnection,
  importLegacyServerConnections,
  openWinRmConnection,
  openRdpConnection,
  pingServerConnection,
  portCheckServerConnection,
  sshConnectNative,
  sshDeployPublicKey,
  sshFileDelete,
  sshFileList,
  sshFileUpload,
  sshHostInfo,
  sshInteractiveShell,
  sshRunArbitraryCommand,
  sshRunReadOnlyCommand,
  sshStartPortForward,
  testServerConnection,
  updateServerConnection,
  wakeOnLanConnection,
} from '../services/api';
import { AddConnectionModal } from '../components/server/AddConnectionModal';
import { LegacyImportModal } from '../components/server/LegacyImportModal';
import { ServerGroupsTab } from '../components/server/ServerGroupsTab';
import {
  connDisplayHost,
  FavoriteStar,
  ProtocolBadge,
  TagChip,
} from '../components/server/ServerBadges';

type Props = {
  active: boolean;
  theme?: string;
};

// ── helpers ────────────────────────────────────────────────────────────────────

function relTime(ts?: string | null): string {
  if (!ts) return '—';
  try {
    const diff = Date.now() - new Date(ts).getTime();
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return `${Math.floor(diff / 86400000)}d ago`;
  } catch { return ts; }
}

// ── Status card ───────────────────────────────────────────────────────

function StatCard({ label, value, tone = 'default' }: { label: string; value: number | string; tone?: 'ok' | 'warn' | 'critical' | 'default' }) {
  const colors = { ok: 'var(--soc-success)', warn: 'var(--soc-warning)', critical: 'var(--soc-critical)', default: 'var(--soc-fg)' };
  return (
    <div className="rounded p-3" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
      <div className="text-[10px] font-semibold uppercase tracking-widest mb-1" style={{ color: 'var(--soc-muted-fg)' }}>{label}</div>
      <div className="text-xl font-bold font-mono" style={{ color: colors[tone] }}>{value}</div>
    </div>
  );
}

// ── Connection table row ──────────────────────────────────────────────

function ConnectionRow({
  conn,
  selected,
  onSelect,
  onFavorite,
  onDelete,
}: {
  conn: ServerConnection;
  selected: boolean;
  onSelect: () => void;
  onFavorite: () => void;
  onDelete: () => void;
}) {
  return (
    <tr
      onClick={onSelect}
      className={`cursor-pointer border-b transition-colors text-[12px] ${selected ? 'bg-cyan-500/10' : 'hover:bg-white/5'}`}
      style={{ borderColor: 'var(--soc-border)' }}
    >
      <td className="px-2 py-2 w-6 text-center" onClick={e => { e.stopPropagation(); onFavorite(); }}>
        <FavoriteStar favorite={conn.favorite} />
      </td>
      <td className="px-2 py-2 font-semibold" style={{ color: selected ? 'var(--soc-primary)' : 'var(--soc-fg)' }}>
        {conn.name}
      </td>
      <td className="px-2 py-2 font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
        {connDisplayHost(conn)}
      </td>
      <td className="px-2 py-2"><ProtocolBadge protocol={conn.protocol} /></td>
      <td className="px-2 py-2 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{conn.os || '—'}</td>
      <td className="px-2 py-2">
        <div className="flex flex-wrap gap-1">
          {conn.tags.slice(0, 3).map(t => <TagChip key={t} tag={t} />)}
          {conn.tags.length > 3 && <span className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>+{conn.tags.length - 3}</span>}
        </div>
      </td>
      <td className="px-2 py-2 text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
        {conn.unified_host_id ? '✓ linked' : '—'}
      </td>
      <td className="px-2 py-2" onClick={e => { e.stopPropagation(); onDelete(); }}>
        <button type="button" title="Delete" className="text-slate-600 hover:text-red-400 transition-colors">
          <Trash2 size={12} />
        </button>
      </td>
    </tr>
  );
}

// ── Detail tab type ───────────────────────────────────────────────────

type DetailTab = 'overview' | 'ssh' | 'rdp' | 'files' | 'tools' | 'activity' | 'raw';
type PageTab   = 'connections' | 'groups' | 'legacy';

// ── Legacy catalog helpers ─────────────────────────────────────────────

function StatusBadge({ status }: { status: LegacyFeatureStatus }) {
  const cfg: Record<LegacyFeatureStatus, { label: string; color: string; bg: string }> = {
    implemented: { label: 'Available',              color: 'var(--soc-success)',  bg: 'rgba(34,197,94,0.12)'  },
    planned:     { label: 'Backend route missing',  color: 'var(--soc-primary)',  bg: 'rgba(6,182,212,0.12)'  },
    disabled:    { label: 'Requires confirmation',  color: 'var(--soc-muted-fg)', bg: 'rgba(100,116,139,0.15)'},
    rejected:    { label: 'Not supported',          color: 'var(--soc-critical)', bg: 'rgba(239,68,68,0.12)'  },
  };
  const { label, color, bg } = cfg[status] ?? cfg.disabled;
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold" style={{ color, background: bg }}>
      {label}
    </span>
  );
}

function RiskBadge({ risk }: { risk: LegacyFeatureRisk }) {
  const cfg: Record<LegacyFeatureRisk, { label: string; color: string; bg: string }> = {
    none:     { label: '—',        color: 'var(--soc-muted-fg)',              bg: 'transparent'            },
    low:      { label: 'Low',      color: 'var(--soc-success)',               bg: 'rgba(34,197,94,0.10)'   },
    medium:   { label: 'Medium',   color: 'rgba(245,158,11,0.9)',             bg: 'rgba(245,158,11,0.10)'  },
    high:     { label: 'High',     color: 'rgba(249,115,22,0.9)',             bg: 'rgba(249,115,22,0.10)'  },
    critical: { label: 'Critical', color: 'var(--soc-critical)',              bg: 'rgba(239,68,68,0.12)'   },
  };
  const { label, color, bg } = cfg[risk] ?? cfg.none;
  return (
    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold" style={{ color, background: bg }}>
      {label}
    </span>
  );
}

function AccessBadge({ feature }: { feature: LegacyServerFeature }) {
  if (feature.phase1)
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold" style={{ color: 'var(--soc-success)', background: 'rgba(34,197,94,0.12)' }}>Available</span>;
  if (feature.phase2)
    return <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold" style={{ color: 'rgba(245,158,11,0.9)', background: 'rgba(245,158,11,0.10)' }}>Requires confirmation</span>;
  return <span className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>Backend route missing</span>;
}

function TransportBadge({ feature }: { feature: LegacyServerFeature }) {
  const pa = feature.policy_action ?? '';
  const src = feature.source.toLowerCase();
  let label = '—';
  if (feature.id === 'agent_deployment') label = 'Agent HTTP';
  else if (pa === 'ssh_interactive_shell') label = 'WS/SSH';
  else if (pa.startsWith('ssh') || src.includes('ssh')) label = 'SSH';
  else if (pa.startsWith('rdp') || src.includes('rdp')) label = 'RDP';
  else if (pa.startsWith('winrm') || src.includes('winrm')) label = 'WinRM';
  else if (feature.id === 'wol') label = 'UDP';
  else if (['ping', 'dns_lookup', 'reverse_dns', 'port_check', 'traceroute', 'arp_lookup'].includes(pa)) label = 'Local';
  else if (pa.includes('import') || pa.includes('connection') || pa === 'list_connections') label = 'API/DB';
  return <span className="text-[11px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>{label}</span>;
}

// ── Legacy Catalog View ───────────────────────────────────────────────────────

function LegacyCatalogView({ data, loading }: { data: LegacyServerFeatureResponse | null; loading: boolean }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');

  const filtered = (data?.features ?? []).filter(f => {
    if (statusFilter && f.status !== statusFilter) return false;
    if (riskFilter && f.risk_level !== riskFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!f.name.toLowerCase().includes(q) &&
          !f.source.toLowerCase().includes(q) &&
          !f.description.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  return (
    <div className="flex flex-col flex-1 overflow-hidden">

      {/* Warning banner */}
      <div className="flex items-start gap-2 px-4 py-3 flex-shrink-0 text-[11px]"
        style={{ background: 'rgba(245,158,11,0.06)', borderBottom: '1px solid rgba(245,158,11,0.2)', color: 'rgba(245,158,11,0.85)' }}>
        <Info size={13} className="flex-shrink-0 mt-0.5" />
        <span>
          <strong>Idea source only.</strong>{' '}
          The SSH_Manager repository is used exclusively as a migration reference.
          It is not cloned, not modified, and not executed.
          Features with elevated risk require explicit policy, confirmation and audit flow before activation.
        </span>
      </div>

      {/* Source info strip */}
      {data && (
        <div className="flex items-center gap-4 px-4 py-2 flex-shrink-0 border-b text-[11px]"
          style={{ borderColor: 'var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
          <span>Source:</span>
          <code className="font-mono text-[10px]">{data.source_repo}</code>
          <span className="rounded px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-widest"
            style={{ background: 'rgba(34,197,94,0.1)', color: 'var(--soc-success)' }}>
            {data.mode}
          </span>
        </div>
      )}

      {/* Summary stat cards */}
      {data && (
        <div className="grid grid-cols-6 gap-3 px-4 py-3 flex-shrink-0"
          style={{ borderBottom: '1px solid var(--soc-border)' }}>
          <StatCard label="Total"     value={data.summary.total} />
          <StatCard label="Available" value={data.summary.phase1}   tone="ok" />
          <StatCard label="Confirm"   value={data.summary.phase2}   tone="warn" />
          <StatCard label="Guarded"   value={data.summary.disabled} />
          <StatCard label="Unsupported" value={data.summary.rejected}  tone="critical" />
          <StatCard label="Dangerous" value={data.summary.dangerous} tone="critical" />
        </div>
      )}

      {/* Filter bar */}
      <div className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--soc-border)' }}>
        <div className="relative flex-1 max-w-xs">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--soc-muted-fg)' }} />
          <input
            className="w-full pl-7 pr-3 py-1.5 rounded text-[12px] outline-none"
            style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}
            placeholder="Search features…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="rounded px-2 py-1.5 text-[11px] outline-none"
          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="implemented">Implemented</option>
          <option value="planned">Planned</option>
          <option value="disabled">Disabled</option>
          <option value="rejected">Rejected</option>
        </select>
        <select
          className="rounded px-2 py-1.5 text-[11px] outline-none"
          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
        >
          <option value="">All risk levels</option>
          <option value="none">None</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
          {filtered.length} / {data?.features.length ?? 0}
        </span>
      </div>

      {/* Feature table */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-full" style={{ color: 'var(--soc-muted-fg)' }}>
            <RefreshCw size={16} className="animate-spin mr-2" /> Loading catalog…
          </div>
        ) : (
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-[10px] font-semibold uppercase tracking-wider border-b"
                style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-sidebar)', color: 'var(--soc-muted-fg)', position: 'sticky', top: 0 }}>
                <th className="px-3 py-2 text-left">Feature</th>
                <th className="px-2 py-2 text-left">Source</th>
                <th className="px-2 py-2 text-left">Transport</th>
                <th className="px-2 py-2 text-left">Risk</th>
                <th className="px-2 py-2 text-left">Status</th>
                <th className="px-2 py-2 text-left">Access</th>
                <th className="px-2 py-2 text-left">Notes</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr key={f.id} className="border-b hover:bg-white/5 transition-colors"
                  style={{ borderColor: 'var(--soc-border)', opacity: f.status === 'rejected' ? 0.6 : 1 }}>
                  <td className="px-3 py-2.5 max-w-[220px]">
                    <div className="font-semibold text-[12px]">{f.name}</div>
                    <div className="text-[10px] mt-0.5 leading-relaxed" style={{ color: 'var(--soc-muted-fg)' }}>
                      {f.description.length > 110 ? f.description.slice(0, 110) + '…' : f.description}
                    </div>
                  </td>
                  <td className="px-2 py-2.5 text-[11px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
                    {f.source.split('/').slice(-1)[0] ?? f.source}
                  </td>
                  <td className="px-2 py-2.5"><TransportBadge feature={f} /></td>
                  <td className="px-2 py-2.5"><RiskBadge risk={f.risk_level} /></td>
                  <td className="px-2 py-2.5"><StatusBadge status={f.status} /></td>
                  <td className="px-2 py-2.5"><AccessBadge feature={f} /></td>
                  <td className="px-2 py-2.5 text-[11px] max-w-[200px]" style={{ color: 'var(--soc-muted-fg)' }}>
                    {f.rejection_reason
                      ? <span style={{ color: 'rgba(239,68,68,0.75)' }}>{f.rejection_reason}</span>
                      : f.policy_action
                        ? <code className="text-[10px] font-mono">{f.policy_action}</code>
                        : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ── MAIN COMPONENT ────────────────────────────────────────────────────────────

export function ServerPage({ active }: Props) {
  const [connections, setConnections]     = useState<ServerConnection[]>([]);
  const [selected, setSelected]           = useState<ServerConnection | null>(null);
  const [activity, setActivity]           = useState<ServerActivityLog[]>([]);
  const [loading, setLoading]             = useState(false);
  const [search, setSearch]               = useState('');
  const [filterProtocol, setFilterProtocol] = useState('');
  const [showFavOnly, setShowFavOnly]     = useState(false);

  // Modals
  const [showAdd, setShowAdd]             = useState(false);
  const [showImport, setShowImport]       = useState(false);
  const [importing, setImporting]         = useState(false);
  const [importResult, setImportResult]   = useState<LegacyImportReport | null>(null);

  // Detail panel
  const [detailTab, setDetailTab]         = useState<DetailTab>('overview');

  // Action states
  const [pingResult, setPingResult]       = useState<PingResult | null>(null);
  const [pingLoading, setPingLoading]     = useState(false);
  const [hostInfoResult, setHostInfoResult] = useState<SshHostInfoResult | null>(null);
  const [hostInfoLoading, setHostInfoLoading] = useState(false);
  const [cmdResult, setCmdResult]         = useState<SshReadOnlyCommandResult | null>(null);
  const [cmdLoading, setCmdLoading]       = useState(false);
  const [rdpLoading, setRdpLoading]       = useState(false);
  const [rdpResult, setRdpResult]         = useState<ServerActionResult | null>(null);
  const [fileList, setFileList]           = useState<SshFileBrowserEntry[]>([]);
  const [filePath, setFilePath]           = useState('/');
  const [fileLoading, setFileLoading]     = useState(false);
  const [fileActionResult, setFileActionResult] = useState<ServerActionResult | null>(null);
  const [sshCommands, setSshCommands]     = useState<SshReadOnlyCommand[]>([]);
  const [sshConfig, setSshConfig]         = useState<string>('');
  const [healthResult, setHealthResult]   = useState<ServerActionResult | null>(null);
  const [portInput, setPortInput]         = useState('22,80,443,3389,5985');
  const [portResult, setPortResult]       = useState<ServerActionResult | null>(null);
  const [dnsResult, setDnsResult]         = useState<ServerActionResult | null>(null);
  const [testResult, setTestResult]       = useState<ServerActionResult | null>(null);
  const [testLoading, setTestLoading]     = useState(false);
  const [shellResult, setShellResult]     = useState<ServerActionResult | null>(null);
  const [shellLoading, setShellLoading]   = useState(false);
  const [arbitraryCommand, setArbitraryCommand] = useState('id && uname -a');
  const [arbitraryReason, setArbitraryReason] = useState('manual diagnostics');
  const [arbitraryResult, setArbitraryResult] = useState<ServerActionResult | null>(null);
  const [arbitraryLoading, setArbitraryLoading] = useState(false);
  const [publicKey, setPublicKey]         = useState('');
  const [keyReason, setKeyReason]         = useState('temporary admin access');
  const [keyDeployResult, setKeyDeployResult] = useState<ServerActionResult | null>(null);
  const [keyDeployLoading, setKeyDeployLoading] = useState(false);
  const [pfLocalPort, setPfLocalPort]     = useState('8080');
  const [pfRemoteHost, setPfRemoteHost]   = useState('localhost');
  const [pfRemotePort, setPfRemotePort]   = useState('80');
  const [pfReason, setPfReason]           = useState('secure local tunnel');
  const [pfResult, setPfResult]           = useState<ServerActionResult | null>(null);
  const [pfLoading, setPfLoading]         = useState(false);
  const [winrmResult, setWinrmResult]     = useState<ServerActionResult | null>(null);
  const [winrmLoading, setWinrmLoading]   = useState(false);

  // Page-level tab
  const [pageTab, setPageTab]             = useState<PageTab>('connections');
  // Legacy feature catalog
  const [legacyData, setLegacyData]       = useState<LegacyServerFeatureResponse | null>(null);
  const [legacyLoading, setLegacyLoading] = useState(false);
  // SSH config export
  const [showSshExport, setShowSshExport]         = useState(false);
  const [sshExportResult, setSshExportResult]     = useState<SshConfigExportResult | null>(null);
  const [sshExportLoading, setSshExportLoading]   = useState(false);
  const [sshExportFavOnly, setSshExportFavOnly]   = useState(false);
  const [sshExportTag, setSshExportTag]           = useState('');
  const [sshExportCopied, setSshExportCopied]     = useState(false);

  const searchRef = useRef<HTMLInputElement>(null);

  const loadConnections = useCallback(async () => {
    setLoading(true);
    try {
      const resp = await getServerConnections({
        search: search || undefined,
        protocol: filterProtocol || undefined,
        favorite_only: showFavOnly || undefined,
      } as Parameters<typeof getServerConnections>[0]);
      setConnections(resp.data ?? []);
    } finally {
      setLoading(false);
    }
  }, [search, filterProtocol, showFavOnly]);

  const loadActivity = useCallback(async () => {
    const resp = await getServerActivity(50);
    setActivity(resp.data ?? []);
  }, []);

  const loadLegacyFeatures = useCallback(async () => {
    setLegacyLoading(true);
    try { const r = await getServerLegacyFeatures(); setLegacyData(r); }
    catch { /* ignore — catalog is cosmetic */ }
    finally { setLegacyLoading(false); }
  }, []);

  const handleSshExport = useCallback(async () => {
    setSshExportLoading(true);
    setSshExportResult(null);
    try {
      const result = await exportSshConfig({
        favorites_only: sshExportFavOnly,
        tag: sshExportTag.trim() || undefined,
      });
      setSshExportResult(result);
    } catch {
      setSshExportResult({ status: 'error', host_count: 0, config: '', warnings: ['Request failed — is the backend running?'] });
    } finally {
      setSshExportLoading(false);
    }
  }, [sshExportFavOnly, sshExportTag]);

  function handleSshExportCopy() {
    if (!sshExportResult?.config) return;
    navigator.clipboard.writeText(sshExportResult.config).then(() => {
      setSshExportCopied(true);
      setTimeout(() => setSshExportCopied(false), 2000);
    });
  }

  function handleSshExportDownload() {
    if (!sshExportResult?.config) return;
    const blob = new Blob([sshExportResult.config], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ssh_config.generated';
    a.click();
    URL.revokeObjectURL(url);
  }

  useEffect(() => {
    if (!active) return;
    loadConnections();
    loadActivity();
    getSshReadOnlyCommands().then(r => setSshCommands(r.data ?? []));
    loadLegacyFeatures();
  }, [active, loadConnections, loadActivity, loadLegacyFeatures]);

  useEffect(() => {
    if (selected && !connections.find(c => c.id === selected.id)) setSelected(null);
  }, [connections, selected]);

  function resetPanelState() {
    setPingResult(null);
    setHostInfoResult(null);
    setCmdResult(null);
    setRdpResult(null);
    setTestResult(null);
    setFileList([]);
    setFileActionResult(null);
    setDnsResult(null);
    setPortResult(null);
    setSshConfig('');
    setHealthResult(null);
    setFilePath('/');
    setShellResult(null);
    setArbitraryResult(null);
    setKeyDeployResult(null);
    setPfResult(null);
    setWinrmResult(null);
  }

  async function handleCreate(data: ServerConnectionInput) {
    await createServerConnection(data);
    setShowAdd(false);
    loadConnections();
  }

  async function handleDelete(conn: ServerConnection) {
    if (!confirm(`Delete connection "${conn.name}"?`)) return;
    await deleteServerConnection(conn.id);
    if (selected?.id === conn.id) setSelected(null);
    loadConnections();
    loadActivity();
  }

  async function handleToggleFavorite(conn: ServerConnection) {
    await updateServerConnection(conn.id, { favorite: !conn.favorite });
    loadConnections();
  }

  async function handleImport(format: 'json' | 'csv', data: string, autoLink: boolean) {
    setImporting(true);
    try {
      const resp = await importLegacyServerConnections({ format, data, auto_link: autoLink });
      setImportResult(resp.data);
      setShowImport(false);
      loadConnections();
    } finally {
      setImporting(false);
    }
  }

  async function handlePing() {
    if (!selected) return;
    setPingLoading(true); setPingResult(null);
    try { const r = await pingServerConnection(selected.id); setPingResult(r.data as PingResult); }
    finally { setPingLoading(false); }
  }

  async function handleDns() {
    if (!selected) return;
    const r = await dnsServerConnection(selected.id);
    setDnsResult(r);
  }

  async function handlePortCheck() {
    if (!selected) return;
    const ports = portInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p > 0);
    const r = await portCheckServerConnection(selected.id, ports);
    setPortResult(r);
  }

  async function handleTest() {
    if (!selected) return;
    setTestLoading(true); setTestResult(null);
    try { const r = await testServerConnection(selected.id); setTestResult(r); }
    finally { setTestLoading(false); }
  }

  async function handleSshHostInfo() {
    if (!selected) return;
    setHostInfoLoading(true); setHostInfoResult(null);
    try { const r = await sshHostInfo(selected.id); setHostInfoResult(r.data as SshHostInfoResult); }
    finally { setHostInfoLoading(false); }
  }

  async function handleRunCommand(cmdId: string) {
    if (!selected) return;
    setCmdLoading(true); setCmdResult(null);
    try { const r = await sshRunReadOnlyCommand(selected.id, cmdId); setCmdResult(r.data as SshReadOnlyCommandResult); }
    finally { setCmdLoading(false); }
  }

  async function handleOpenRdp() {
    if (!selected) return;
    setRdpLoading(true); setRdpResult(null);
    try { const r = await openRdpConnection(selected.id); setRdpResult(r); }
    finally { setRdpLoading(false); }
  }

  async function handleOpenShell() {
    if (!selected) return;
    setShellLoading(true); setShellResult(null);
    try {
      const r = await sshInteractiveShell(selected.id);
      setShellResult(r);
      loadActivity();
    } finally { setShellLoading(false); }
  }

  async function handleQuickConnect() {
    if (!selected) return;
    setShellLoading(true); setShellResult(null);
    try {
      const r = await sshConnectNative(selected.id);
      setShellResult(r);
      loadActivity();
    } finally { setShellLoading(false); }
  }

  async function handleArbitraryCommand() {
    if (!selected) return;
    if (!arbitraryReason.trim() || !arbitraryCommand.trim()) {
      alert('Command and reason are required.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm action:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('Action cancelled: target confirmation mismatch.');
      return;
    }
    setArbitraryLoading(true); setArbitraryResult(null);
    try {
      const r = await sshRunArbitraryCommand(selected.id, arbitraryCommand.trim(), arbitraryReason.trim(), target, true, 45);
      setArbitraryResult(r);
      loadActivity();
    } finally { setArbitraryLoading(false); }
  }

  async function handleKeyDeploy() {
    if (!selected) return;
    if (!publicKey.trim() || !keyReason.trim()) {
      alert('Public key and reason are required.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm action:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('Action cancelled: target confirmation mismatch.');
      return;
    }
    setKeyDeployLoading(true); setKeyDeployResult(null);
    try {
      const r = await sshDeployPublicKey(selected.id, publicKey.trim(), keyReason.trim(), target, true);
      setKeyDeployResult(r);
      loadActivity();
    } finally { setKeyDeployLoading(false); }
  }

  async function handlePortForward() {
    if (!selected) return;
    const local = parseInt(pfLocalPort, 10);
    const remote = parseInt(pfRemotePort, 10);
    if (!Number.isFinite(local) || !Number.isFinite(remote) || !pfRemoteHost.trim() || !pfReason.trim()) {
      alert('Local port, remote host, remote port and reason are required.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm action:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('Action cancelled: target confirmation mismatch.');
      return;
    }
    setPfLoading(true); setPfResult(null);
    try {
      const r = await sshStartPortForward(selected.id, local, pfRemoteHost.trim(), remote, pfReason.trim(), target, true);
      setPfResult(r);
      loadActivity();
    } finally { setPfLoading(false); }
  }

  async function handleOpenWinRm() {
    if (!selected) return;
    const reason = prompt('WinRM reason (required for audit):', 'remote troubleshooting') ?? '';
    if (!reason.trim()) {
      alert('WinRM cancelled: reason is required.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm WinRM session:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('WinRM cancelled: target confirmation mismatch.');
      return;
    }
    setWinrmLoading(true); setWinrmResult(null);
    try {
      const r = await openWinRmConnection(selected.id, reason.trim(), target, true);
      setWinrmResult(r);
      loadActivity();
    } finally { setWinrmLoading(false); }
  }

  async function handleLoadFiles(path = '/') {
    if (!selected) return;
    setFileActionResult(null);
    setFileLoading(true); setFileList([]); setFilePath(path);
    try {
      const r = await sshFileList(selected.id, path);
      setFileList((r.data as { entries?: SshFileBrowserEntry[] })?.entries ?? []);
    } finally { setFileLoading(false); }
  }

  async function handleUploadFile(file: File) {
    if (!selected) return;
    const reason = prompt('Upload reason (required for audit):', 'incident response / evidence collection') ?? '';
    if (!reason.trim()) {
      alert('Upload cancelled: reason is required.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm upload:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('Upload cancelled: target confirmation mismatch.');
      return;
    }
    try {
      const result = await sshFileUpload(selected.id, file, filePath, reason.trim(), target);
      setFileActionResult(result);
      await handleLoadFiles(filePath);
      loadActivity();
    } catch (err) {
      setFileActionResult({ status: 'error', message: err instanceof Error ? err.message : 'Upload failed' });
    }
  }

  async function handleDeleteFile(entry: SshFileBrowserEntry) {
    if (!selected || entry.type !== 'file') return;
    const basePath = filePath === '/' ? '' : filePath.replace(/\/$/, '');
    const fullPath = `${basePath}/${entry.name}` || `/${entry.name}`;
    const reason = prompt(`Delete reason for ${entry.name} (required):`, 'cleanup / rollback') ?? '';
    if (!reason.trim()) {
      alert('Delete cancelled: reason is required.');
      return;
    }
    const confirmName = prompt(`Type the exact filename to confirm delete:\n${entry.name}`, '') ?? '';
    if (confirmName !== entry.name) {
      alert('Delete cancelled: filename confirmation mismatch.');
      return;
    }
    const target = (selected.hostname || selected.ip || '').trim();
    if (!target) {
      alert('Selected connection has no hostname/ip for confirmation.');
      return;
    }
    const confirmTarget = prompt(`Type target host to confirm delete:\n${target}`, '') ?? '';
    if (confirmTarget.trim() !== target) {
      alert('Delete cancelled: target confirmation mismatch.');
      return;
    }
    const confirmAction = prompt('Type DELETE to confirm destructive action:', '') ?? '';
    if (confirmAction.trim().toUpperCase() !== 'DELETE') {
      alert('Delete cancelled: action confirmation mismatch.');
      return;
    }
    try {
      const result = await sshFileDelete(selected.id, fullPath, reason.trim(), confirmName, target, confirmAction.trim());
      setFileActionResult(result);
      await handleLoadFiles(filePath);
      loadActivity();
    } catch (err) {
      setFileActionResult({ status: 'error', message: err instanceof Error ? err.message : 'Delete failed' });
    }
  }

  async function handleHealthCheck() {
    if (!selected) return;
    const r = await healthCheckServerConnection(selected.id);
    setHealthResult(r); loadActivity();
  }

  async function handleLoadSshConfig() {
    if (!selected) return;
    const r = await getSshConfig(selected.id);
    setSshConfig((r.data as { config?: string })?.config ?? '');
  }

  async function handleWol() {
    if (!selected) return;
    const r = await wakeOnLanConnection(selected.id);
    setRdpResult(r);
  }

  // Stats
  const sshCount = connections.filter(c => c.protocol === 'ssh').length;
  const rdpCount = connections.filter(c => c.protocol === 'rdp').length;

  const sectionHeader = 'text-[10px] font-semibold uppercase tracking-widest mb-2';

  if (!active) return null;

  return (
    <div className="flex flex-col h-full overflow-hidden" style={{ color: 'var(--soc-fg)' }}>

      {/* ── Top bar ── */}
      <div className="flex items-center justify-between px-4 py-3 border-b flex-shrink-0"
        style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-sidebar)' }}>
        <div>
          <h1 className="text-base font-bold flex items-center gap-2">
            <Server size={16} className="text-cyan-400" /> Server Operations
          </h1>
          <p className="text-[11px] mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
            Remote access, health checks, file access and controlled response
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => setShowAdd(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white">
            <Plus size={12} /> Add Connection
          </button>
          <button type="button" onClick={() => setShowImport(true)}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[11px]"
            style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
            <Upload size={12} /> Import Legacy
          </button>
          <button type="button" onClick={() => { setShowSshExport(true); setSshExportResult(null); }}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[11px]"
            style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}
            title="Export SSH connections as OpenSSH config (preview only)">
            <Download size={12} /> SSH Config
          </button>
          <button type="button" onClick={() => { loadConnections(); loadActivity(); }}
            className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[11px]"
            style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Status cards ── */}
      <div className="grid grid-cols-6 gap-3 px-4 py-3 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--soc-border)' }}>
        <StatCard label="Total" value={connections.length} />
        <StatCard label="SSH" value={sshCount} tone="ok" />
        <StatCard label="RDP" value={rdpCount} tone="ok" />
        <StatCard label="Favorites" value={connections.filter(c => c.favorite).length} />
        <StatCard label="Linked" value={connections.filter(c => c.unified_host_id).length} tone="ok" />
        <StatCard label="Unlinked" value={connections.filter(c => !c.unified_host_id).length} tone="warn" />
      </div>

      {/* ── Page tab bar ── */}
      <div className="flex items-center border-b flex-shrink-0" style={{ borderColor: 'var(--soc-border)' }}>
        {([['connections', 'Connections'], ['groups', 'Groups & Batch'], ['legacy', 'Legacy Ideas']] as [PageTab, string][]).map(([t, label]) => (
          <button key={t} type="button" onClick={() => setPageTab(t)}
            className={`px-4 py-2.5 text-[11px] font-semibold uppercase tracking-wider flex items-center gap-1.5 transition-colors border-b-2 ${pageTab === t ? 'border-cyan-400' : 'border-transparent'}`}
            style={{ color: pageTab === t ? 'var(--soc-primary)' : 'var(--soc-muted-fg)' }}>
            {t === 'connections' ? <Server size={11} /> : t === 'groups' ? <Layers size={11} /> : <Archive size={11} />} {label}
          </button>
        ))}
      </div>

      {/* ── Connections view ── */}
      {pageTab === 'connections' && <>

      {/* ── Import result banner ── */}
      {importResult && (
        <div className="flex items-center justify-between px-4 py-2 text-[11px] flex-shrink-0"
          style={{ background: 'rgba(34,197,94,0.08)', borderBottom: '1px solid rgba(34,197,94,0.2)', color: 'var(--soc-success)' }}>
          <span>
            Import complete: {importResult.imported} imported,
            {' '}{importResult.conflicts} conflicts, {importResult.skipped} skipped
          </span>
          <button type="button" onClick={() => setImportResult(null)}><X size={12} /></button>
        </div>
      )}

      {/* ── Filter row ── */}
      <div className="flex items-center gap-3 px-4 py-2 flex-shrink-0"
        style={{ borderBottom: '1px solid var(--soc-border)' }}>
        <div className="relative flex-1 max-w-xs">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--soc-muted-fg)' }} />
          <input
            ref={searchRef}
            className="w-full pl-7 pr-3 py-1.5 rounded text-[12px] outline-none focus:ring-1 focus:ring-cyan-500/50"
            style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}
            placeholder="Search name, host, tags…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select
          className="rounded px-2 py-1.5 text-[11px] outline-none"
          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}
          value={filterProtocol}
          onChange={e => setFilterProtocol(e.target.value)}
        >
          <option value="">All protocols</option>
          <option value="ssh">SSH</option>
          <option value="rdp">RDP</option>
          <option value="winrm">WinRM</option>
        </select>
        <label className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
          <input type="checkbox" checked={showFavOnly} onChange={e => setShowFavOnly(e.target.checked)} />
          Favorites only
        </label>
      </div>

      {/* ── Main split ── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ── Left: Connection table + activity log ── */}
        <div className="flex flex-col overflow-hidden"
          style={{ width: selected ? '52%' : '100%', borderRight: selected ? '1px solid var(--soc-border)' : 'none', transition: 'width 0.2s' }}>
          <div className="overflow-auto flex-1">
            {connections.length === 0 && !loading && (
              <div className="flex flex-col items-center justify-center h-full py-20"
                style={{ color: 'var(--soc-muted-fg)' }}>
                <Server size={36} className="mb-3 opacity-30" />
                <div className="text-sm font-semibold mb-1">No connections yet</div>
                <div className="text-[11px] mb-4">Add a connection or import from the legacy SSH/RDP Manager</div>
                <button type="button" onClick={() => setShowAdd(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white">
                  <Plus size={12} /> Add Connection
                </button>
              </div>
            )}
            {connections.length > 0 && (
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="text-[10px] font-semibold uppercase tracking-wider border-b"
                    style={{ borderColor: 'var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
                    <th className="px-2 py-2 w-6"></th>
                    <th className="px-2 py-2 text-left">Name</th>
                    <th className="px-2 py-2 text-left">Host / IP</th>
                    <th className="px-2 py-2 text-left">Protocol</th>
                    <th className="px-2 py-2 text-left">OS</th>
                    <th className="px-2 py-2 text-left">Tags</th>
                    <th className="px-2 py-2 text-left">Unified Host</th>
                    <th className="px-2 py-2 w-8"></th>
                  </tr>
                </thead>
                <tbody>
                  {connections.map(conn => (
                    <ConnectionRow
                      key={conn.id}
                      conn={conn}
                      selected={selected?.id === conn.id}
                      onSelect={() => { setSelected(conn); setDetailTab('overview'); resetPanelState(); }}
                      onFavorite={() => handleToggleFavorite(conn)}
                      onDelete={() => handleDelete(conn)}
                    />
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Activity footer */}
          <div className="border-t flex-shrink-0" style={{ borderColor: 'var(--soc-border)', maxHeight: '160px', overflow: 'auto' }}>
            <div className="px-3 py-2 border-b flex items-center gap-2 sticky top-0"
              style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-sidebar)' }}>
              <Activity size={12} style={{ color: 'var(--soc-muted-fg)' }} />
              <span className="text-[10px] font-semibold uppercase tracking-widest" style={{ color: 'var(--soc-muted-fg)' }}>
                Recent Activity
              </span>
            </div>
            {activity.length === 0 ? (
              <div className="px-3 py-3 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>No activity yet</div>
            ) : (
              <table className="w-full text-[11px]">
                <tbody>
                  {activity.slice(0, 20).map(a => (
                    <tr key={a.id} className="border-b" style={{ borderColor: 'var(--soc-border)' }}>
                      <td className="px-3 py-1 font-mono" style={{ color: 'var(--soc-muted-fg)' }}>{relTime(a.timestamp)}</td>
                      <td className="px-2 py-1 font-mono"
                        style={{ color: a.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)' }}>
                        {a.status}
                      </td>
                      <td className="px-2 py-1">{a.action}</td>
                      <td className="px-2 py-1" style={{ color: 'var(--soc-muted-fg)' }}>{a.host || '—'}</td>
                      <td className="px-2 py-1" style={{ color: 'var(--soc-muted-fg)' }}>{a.message}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* ── Right: Detail panel ── */}
        {selected && (
          <div className="flex flex-col overflow-hidden flex-1">
            {/* Panel header */}
            <div className="flex items-center justify-between px-4 py-2.5 border-b flex-shrink-0"
              style={{ borderColor: 'var(--soc-border)', background: 'var(--soc-sidebar)' }}>
              <div>
                <div className="font-semibold text-sm flex items-center gap-2">
                  <ProtocolBadge protocol={selected.protocol} />
                  {selected.name}
                </div>
                <div className="text-[11px] font-mono mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>
                  {connDisplayHost(selected)}:{selected.port}
                  {selected.username && <> · {selected.username}</>}
                </div>
              </div>
              <button type="button" onClick={() => setSelected(null)} style={{ color: 'var(--soc-muted-fg)' }}>
                <X size={14} />
              </button>
            </div>

            {/* Tab bar */}
            <div className="flex border-b overflow-x-auto flex-shrink-0" style={{ borderColor: 'var(--soc-border)' }}>
              {(['overview', 'ssh', 'rdp', 'files', 'tools', 'activity', 'raw'] as DetailTab[]).map(tab => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setDetailTab(tab)}
                  className={`px-3 py-2 text-[11px] font-semibold uppercase tracking-wider whitespace-nowrap transition-colors ${detailTab === tab ? 'border-b-2 border-cyan-400' : ''}`}
                  style={{ color: detailTab === tab ? 'var(--soc-primary)' : 'var(--soc-muted-fg)' }}
                >
                  {tab}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div className="flex-1 overflow-auto p-4 space-y-4">

              {/* Overview */}
              {detailTab === 'overview' && (
                <>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Connection Details</div>
                    <div className="rounded p-3 space-y-1.5" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      {([
                        ['Protocol', <ProtocolBadge key="p" protocol={selected.protocol} />],
                        ['Host', connDisplayHost(selected)],
                        ['Port', selected.port],
                        ['Username', selected.username || '—'],
                        ['Auth', selected.auth_type],
                        ['OS', selected.os || '—'],
                        ['MAC', selected.mac || '—'],
                        ['Unified Host', selected.unified_host_id || '—'],
                        ['Wazuh Agent', selected.wazuh_agent_id || '—'],
                        ['Tactical Agent', selected.tactical_agent_id || '—'],
                      ] as [string, React.ReactNode][]).map(([label, val]) => (
                        <div key={label} className="flex items-center justify-between">
                          <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{label}</span>
                          <span className="text-[11px] font-mono">{val}</span>
                        </div>
                      ))}
                    </div>
                  </section>
                  {selected.tags.length > 0 && (
                    <section>
                      <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Tags</div>
                      <div className="flex flex-wrap gap-1">
                        {selected.tags.map(t => <TagChip key={t} tag={t} />)}
                      </div>
                    </section>
                  )}
                  {selected.notes && (
                    <section>
                      <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Notes</div>
                      <div className="rounded p-3 text-[11px]" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        {selected.notes}
                      </div>
                    </section>
                  )}
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Quick Actions</div>
                    <div className="flex flex-wrap gap-2">
                      <button type="button" onClick={handleTest} disabled={testLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Wifi size={11} /> {testLoading ? 'Testing…' : 'Connection Test'}
                      </button>
                      <button type="button" onClick={handlePing} disabled={pingLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Activity size={11} /> {pingLoading ? 'Pinging…' : 'Ping'}
                      </button>
                      <button type="button" onClick={handleHealthCheck}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Heart size={11} /> Health Check
                      </button>
                    </div>
                    {testResult && (
                      <div className="mt-2 rounded p-2.5 text-[11px] font-mono"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${testResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        Status: {(testResult.data?.status as string | undefined) || testResult.status}
                        {testResult.data?.tcp_ms != null && <> · TCP {testResult.data.tcp_ms as number}ms</>}
                        {testResult.data?.ssh_ms != null && <> · SSH {testResult.data.ssh_ms as number}ms</>}
                        {testResult.data?.error != null && <> · {testResult.data.error as string}</>}
                      </div>
                    )}
                    {pingResult && (
                      <div className="mt-2 rounded p-2.5 text-[11px] font-mono"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${pingResult.reachable ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        {pingResult.reachable ? '● REACHABLE' : '● UNREACHABLE'}
                        {pingResult.avg_rtt_ms != null && <> · {pingResult.avg_rtt_ms}ms avg</>}
                      </div>
                    )}
                    {healthResult && (
                      <div className="mt-2 rounded p-2.5 text-[11px] font-mono"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${healthResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        Status: {healthResult.status}
                        {Boolean((healthResult.data as Record<string,unknown>)?.uptime) && <div>Uptime: {String((healthResult.data as Record<string,unknown>).uptime)}</div>}
                        {Boolean((healthResult.data as Record<string,unknown>)?.disk) && <div>Disk: {String((healthResult.data as Record<string,unknown>).disk)}</div>}
                        {Boolean((healthResult.data as Record<string,unknown>)?.error) && <div style={{ color: 'var(--soc-critical)' }}>{String((healthResult.data as Record<string,unknown>).error)}</div>}
                      </div>
                    )}
                  </section>
                </>
              )}

              {/* SSH tab */}
              {detailTab === 'ssh' && (
                <>
                  {selected.protocol !== 'ssh' && (
                    <div className="rounded p-3 text-[11px]"
                      style={{ background: 'rgba(234,179,8,0.08)', color: 'var(--soc-warning)' }}>
                      This connection uses {selected.protocol.toUpperCase()}, not SSH.
                    </div>
                  )}
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Host Info</div>
                    <button type="button" onClick={handleSshHostInfo} disabled={hostInfoLoading}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Info size={11} /> {hostInfoLoading ? 'Fetching…' : 'Fetch Host Info'}
                    </button>
                    {hostInfoResult && hostInfoResult.status === 'ok' && hostInfoResult.fields && (
                      <div className="rounded p-3 space-y-2"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        {Object.entries(hostInfoResult.fields).map(([k, v]) => (
                          <div key={k}>
                            <div className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>{k.toUpperCase()}</div>
                            <pre className="text-[11px] whitespace-pre-wrap font-mono">{v}</pre>
                          </div>
                        ))}
                      </div>
                    )}
                    {hostInfoResult && hostInfoResult.status !== 'ok' && (
                      <div className="rounded p-2.5 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-critical)' }}>
                        {hostInfoResult.error || 'Failed to fetch host info'}
                      </div>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Read-Only Commands</div>
                    <div className="grid grid-cols-2 gap-1.5 mb-2">
                      {sshCommands.map(cmd => (
                        <button key={cmd.id} type="button" onClick={() => handleRunCommand(cmd.id)}
                          disabled={cmdLoading}
                          className="flex items-center gap-1.5 px-2 py-1.5 rounded text-[11px] text-left"
                          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                          <Terminal size={10} /> <span className="truncate">{cmd.id}</span>
                        </button>
                      ))}
                    </div>
                    {cmdResult && (
                      <div className="rounded p-3" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <div className="text-[10px] font-mono mb-1" style={{ color: 'var(--soc-muted-fg)' }}>$ {cmdResult.command}</div>
                        <pre className="text-[11px] font-mono whitespace-pre-wrap max-h-60 overflow-auto">
                          {cmdResult.output || cmdResult.error || '(no output)'}
                        </pre>
                      </div>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>SSH Config Export</div>
                    <button type="button" onClick={handleLoadSshConfig}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <FileText size={11} /> Generate SSH Config Block
                    </button>
                    {sshConfig && (
                      <pre className="rounded p-3 text-[11px] font-mono whitespace-pre"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        {sshConfig}
                      </pre>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Interactive Shell</div>
                    <div className="flex flex-wrap gap-2 mb-2">
                      <button type="button" onClick={handleOpenShell} disabled={shellLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Terminal size={11} /> {shellLoading ? 'Launching…' : 'Open Interactive Shell'}
                      </button>
                      <button type="button" onClick={handleQuickConnect} disabled={shellLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Terminal size={11} /> Quick SSH Connect
                      </button>
                    </div>
                    {shellResult && (
                      <div className="rounded p-2.5 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${shellResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        <div>{shellResult.message || shellResult.status}</div>
                        {Boolean((shellResult.data as Record<string, unknown>)?.command_used) && (
                          <div className="font-mono text-[10px] mt-1" style={{ color: 'var(--soc-muted-fg)' }}>
                            {String((shellResult.data as Record<string, unknown>).command_used)}
                          </div>
                        )}
                      </div>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Arbitrary SSH Command</div>
                    <textarea
                      className="w-full rounded px-2 py-1.5 text-[11px] font-mono outline-none mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                      rows={3}
                      value={arbitraryCommand}
                      onChange={e => setArbitraryCommand(e.target.value)}
                    />
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        className="flex-1 rounded px-2 py-1.5 text-[11px] outline-none"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                        value={arbitraryReason}
                        onChange={e => setArbitraryReason(e.target.value)}
                        placeholder="Reason for audit"
                      />
                      <button type="button" onClick={handleArbitraryCommand} disabled={arbitraryLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Terminal size={11} /> {arbitraryLoading ? 'Running…' : 'Run Command'}
                      </button>
                    </div>
                    {arbitraryResult && (
                      <pre className="rounded p-2.5 text-[11px] font-mono whitespace-pre-wrap max-h-56 overflow-auto"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        {JSON.stringify(arbitraryResult.data ?? arbitraryResult, null, 2)}
                      </pre>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>SSH Public Key Deploy</div>
                    <textarea
                      className="w-full rounded px-2 py-1.5 text-[11px] font-mono outline-none mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                      rows={3}
                      placeholder="ssh-ed25519 AAAA... user@host"
                      value={publicKey}
                      onChange={e => setPublicKey(e.target.value)}
                    />
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        className="flex-1 rounded px-2 py-1.5 text-[11px] outline-none"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                        value={keyReason}
                        onChange={e => setKeyReason(e.target.value)}
                        placeholder="Reason for key deployment"
                      />
                      <button type="button" onClick={handleKeyDeploy} disabled={keyDeployLoading}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Upload size={11} /> {keyDeployLoading ? 'Deploying…' : 'Deploy Key'}
                      </button>
                    </div>
                    {keyDeployResult && (
                      <div className="rounded p-2 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${keyDeployResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        {keyDeployResult.message || keyDeployResult.status}
                      </div>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>SSH Port Forward</div>
                    <div className="grid grid-cols-4 gap-2 mb-2">
                      <input className="rounded px-2 py-1.5 text-[11px] outline-none" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }} value={pfLocalPort} onChange={e => setPfLocalPort(e.target.value)} placeholder="Local port" />
                      <input className="rounded px-2 py-1.5 text-[11px] outline-none" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }} value={pfRemoteHost} onChange={e => setPfRemoteHost(e.target.value)} placeholder="Remote host" />
                      <input className="rounded px-2 py-1.5 text-[11px] outline-none" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }} value={pfRemotePort} onChange={e => setPfRemotePort(e.target.value)} placeholder="Remote port" />
                      <button type="button" onClick={handlePortForward} disabled={pfLoading}
                        className="flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Network size={11} /> {pfLoading ? 'Starting…' : 'Start Tunnel'}
                      </button>
                    </div>
                    <input
                      className="w-full rounded px-2 py-1.5 text-[11px] outline-none mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                      value={pfReason}
                      onChange={e => setPfReason(e.target.value)}
                      placeholder="Reason for audit"
                    />
                    {pfResult && (
                      <div className="rounded p-2 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${pfResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        {pfResult.message || pfResult.status}
                      </div>
                    )}
                  </section>
                </>
              )}

              {/* RDP tab */}
              {detailTab === 'rdp' && (
                <>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Open RDP</div>
                    <p className="text-[11px] mb-3" style={{ color: 'var(--soc-muted-fg)' }}>
                      Opens mstsc.exe with a temp .rdp file. No passwords are stored or transmitted.
                    </p>
                    <button type="button" onClick={handleOpenRdp} disabled={rdpLoading}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-green-600 hover:bg-green-500 text-white disabled:opacity-40 mb-2">
                      <Monitor size={12} /> {rdpLoading ? 'Opening…' : 'Open RDP Client'}
                    </button>
                    {rdpResult && (
                      <div className="rounded p-2.5 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${rdpResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-warning)'}` }}>
                        <div>{rdpResult.message || rdpResult.status}</div>
                        {Boolean((rdpResult.data as Record<string,unknown>)?.command_used) && (
                          <div className="font-mono text-[10px] mt-1" style={{ color: 'var(--soc-muted-fg)' }}>
                            {String((rdpResult.data as Record<string,unknown>).command_used)}
                          </div>
                        )}
                      </div>
                    )}
                  </section>
                  {selected.mac && (
                    <section>
                      <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Wake-on-LAN</div>
                      <p className="text-[11px] mb-2" style={{ color: 'var(--soc-muted-fg)' }}>
                        MAC: <span className="font-mono">{selected.mac}</span>
                      </p>
                      <button type="button" onClick={handleWol}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Zap size={11} /> Send Magic Packet
                      </button>
                    </section>
                  )}
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>PowerShell Remoting / WinRM</div>
                    <button type="button" onClick={handleOpenWinRm} disabled={winrmLoading}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Terminal size={11} /> {winrmLoading ? 'Launching…' : 'Open WinRM Session'}
                    </button>
                    {winrmResult && (
                      <div className="rounded p-2 text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${winrmResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        {winrmResult.message || winrmResult.status}
                      </div>
                    )}
                  </section>
                </>
              )}

              {/* Files tab */}
              {detailTab === 'files' && (
                <section>
                  <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>File Browser (SFTP)</div>
                  <div className="flex items-center gap-2 mb-2">
                    <input
                      className="flex-1 rounded px-2 py-1.5 text-[12px] font-mono outline-none"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                      value={filePath}
                      onChange={e => setFilePath(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleLoadFiles(filePath)}
                      placeholder="Remote path e.g. /"
                    />
                    <button type="button" onClick={() => handleLoadFiles(filePath)} disabled={fileLoading}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Folder size={11} /> {fileLoading ? 'Loading…' : 'Browse'}
                    </button>
                    <label
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] cursor-pointer"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Upload size={11} /> Upload
                      <input
                        type="file"
                        className="hidden"
                        onChange={e => {
                          const file = e.target.files?.[0];
                          if (file) {
                            void handleUploadFile(file);
                            e.currentTarget.value = '';
                          }
                        }}
                      />
                    </label>
                  </div>
                  {fileActionResult && (
                    <div className="mb-2 rounded p-2 text-[11px]"
                      style={{
                        background: 'var(--soc-sidebar-accent)',
                        borderLeft: `3px solid ${fileActionResult.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}`,
                      }}>
                      <div className="font-mono">{fileActionResult.status.toUpperCase()} · {fileActionResult.message || 'SFTP action completed'}</div>
                      {fileActionResult.audit_id && (
                        <div className="text-[10px] mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>audit: {fileActionResult.audit_id.slice(0, 8)}</div>
                      )}
                    </div>
                  )}
                  {fileList.length > 0 && (
                    <div className="rounded overflow-hidden" style={{ border: '1px solid var(--soc-border)' }}>
                      <table className="w-full text-[11px]">
                        <thead>
                          <tr className="border-b text-[10px]"
                            style={{ borderColor: 'var(--soc-border)', color: 'var(--soc-muted-fg)' }}>
                            <th className="px-2 py-1.5 text-left">Name</th>
                            <th className="px-2 py-1.5 text-left">Type</th>
                            <th className="px-2 py-1.5 text-right">Size</th>
                            <th className="px-2 py-1.5 text-right">Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filePath !== '/' && (
                            <tr className="border-b hover:bg-white/5 cursor-pointer"
                              style={{ borderColor: 'var(--soc-border)' }}
                              onClick={() => handleLoadFiles(filePath.replace(/\/[^/]+\/?$/, '') || '/')}>
                              <td className="px-2 py-1.5 font-mono" style={{ color: 'var(--soc-primary)' }}>../</td>
                              <td className="px-2 py-1.5" style={{ color: 'var(--soc-muted-fg)' }}>dir</td>
                              <td></td>
                              <td></td>
                            </tr>
                          )}
                          {fileList.map(entry => (
                            <tr key={entry.name} className="border-b hover:bg-white/5"
                              style={{ borderColor: 'var(--soc-border)' }}>
                              <td className="px-2 py-1.5 font-mono">
                                {entry.type === 'dir' ? (
                                  <button type="button" className="text-left"
                                    style={{ color: 'var(--soc-primary)' }}
                                    onClick={() => handleLoadFiles(`${filePath.replace(/\/$/, '')}/${entry.name}`)}>
                                    📁 {entry.name}/
                                  </button>
                                ) : <span>{entry.name}</span>}
                              </td>
                              <td className="px-2 py-1.5" style={{ color: 'var(--soc-muted-fg)' }}>{entry.type}</td>
                              <td className="px-2 py-1.5 text-right font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
                                {entry.size != null ? `${Math.ceil(entry.size / 1024)}KB` : '—'}
                              </td>
                              <td className="px-2 py-1.5 text-right">
                                {entry.type === 'file' ? (
                                  <button
                                    type="button"
                                    className="text-[10px] px-2 py-0.5 rounded"
                                    style={{ background: 'rgba(239,68,68,0.12)', color: 'var(--soc-critical)' }}
                                    onClick={() => void handleDeleteFile(entry)}>
                                    Delete
                                  </button>
                                ) : (
                                  <span style={{ color: 'var(--soc-muted-fg)' }}>—</span>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                  <div className="mt-3 rounded p-2.5 text-[11px]"
                    style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', color: 'rgba(239,68,68,0.7)' }}>
                    Upload and delete require mandatory reason + audit trail. Interactive edit is not implemented yet.
                  </div>
                </section>
              )}

              {/* Tools tab */}
              {detailTab === 'tools' && (
                <>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Ping</div>
                    <button type="button" onClick={handlePing} disabled={pingLoading}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Activity size={11} /> {pingLoading ? 'Pinging…' : 'Ping 4x'}
                    </button>
                    {pingResult && (
                      <div className="rounded p-2.5 text-[11px] font-mono whitespace-pre-wrap"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', borderLeft: `3px solid ${pingResult.reachable ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                        {pingResult.reachable ? '● REACHABLE' : '● UNREACHABLE'}
                        {pingResult.avg_rtt_ms != null ? ` · avg ${pingResult.avg_rtt_ms}ms` : ''}{'\n'}
                        {pingResult.raw || ''}
                      </div>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>DNS Lookup</div>
                    <button type="button" onClick={handleDns}
                      className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] mb-2"
                      style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                      <Globe size={11} /> DNS Lookup
                    </button>
                    {dnsResult && (
                      <pre className="rounded p-2.5 text-[11px] font-mono whitespace-pre-wrap"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        {JSON.stringify(dnsResult.data, null, 2)}
                      </pre>
                    )}
                  </section>
                  <section>
                    <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Port Check</div>
                    <div className="flex items-center gap-2 mb-2">
                      <input
                        className="flex-1 rounded px-2 py-1.5 text-[12px] font-mono outline-none"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
                        value={portInput}
                        onChange={e => setPortInput(e.target.value)}
                        placeholder="22,80,443"
                      />
                      <button type="button" onClick={handlePortCheck}
                        className="flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px]"
                        style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                        <Network size={11} /> Check
                      </button>
                    </div>
                    {portResult?.data && (
                      <div className="rounded overflow-hidden" style={{ border: '1px solid var(--soc-border)' }}>
                        {((portResult.data as { ports?: { port: number; open: boolean }[] }).ports ?? []).map(p => (
                          <div key={p.port}
                            className="flex items-center justify-between px-3 py-1.5 border-b text-[11px]"
                            style={{ borderColor: 'var(--soc-border)' }}>
                            <span className="font-mono">{p.port}</span>
                            <span style={{ color: p.open ? 'var(--soc-success)' : 'var(--soc-muted-fg)' }}>
                              {p.open ? '● OPEN' : '○ CLOSED'}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                </>
              )}

              {/* Activity tab */}
              {detailTab === 'activity' && (
                <section>
                  <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Connection Activity</div>
                  {activity.filter(a => a.connection_id === selected.id).length === 0 ? (
                    <div className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>No activity for this connection yet.</div>
                  ) : (
                    <div className="space-y-1">
                      {activity.filter(a => a.connection_id === selected.id).map(a => (
                        <div key={a.id} className="rounded p-2.5 text-[11px]"
                          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', borderLeft: `3px solid ${a.status === 'ok' ? 'var(--soc-success)' : 'var(--soc-critical)'}` }}>
                          <div className="flex items-center justify-between mb-0.5">
                            <span className="font-semibold">{a.action}</span>
                            <span className="font-mono text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>{relTime(a.timestamp)}</span>
                          </div>
                          <div style={{ color: 'var(--soc-muted-fg)' }}>{a.message}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              )}

              {/* Raw tab */}
              {detailTab === 'raw' && (
                <section>
                  <div className={sectionHeader} style={{ color: 'var(--soc-muted-fg)' }}>Raw Connection JSON</div>
                  <pre className="rounded p-3 text-[11px] font-mono whitespace-pre-wrap overflow-auto"
                    style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', maxHeight: '500px' }}>
                    {JSON.stringify(selected, null, 2)}
                  </pre>
                </section>
              )}

            </div>
          </div>
        )}
      </div>

      </>}  {/* end connections view */}

      {/* ── Groups & Batch view ── */}
      {pageTab === 'groups' && (
        <ServerGroupsTab connections={connections} />
      )}

      {/* ── Legacy Ideas view ── */}
      {pageTab === 'legacy' && (
        <LegacyCatalogView data={legacyData} loading={legacyLoading} />
      )}

      {/* ── Modals ── */}
      {showAdd && (
        <AddConnectionModal onSave={handleCreate} onClose={() => setShowAdd(false)} />
      )}
      {showImport && (
        <LegacyImportModal onImport={handleImport} onClose={() => setShowImport(false)} importing={importing} />
      )}

      {/* ── SSH Config Export Modal ── */}
      {showSshExport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ background: 'rgba(0,0,0,0.65)' }}
          onClick={e => { if (e.target === e.currentTarget) setShowSshExport(false); }}>
          <div className="flex flex-col rounded-lg shadow-2xl overflow-hidden"
            style={{ width: 680, maxHeight: '90vh', background: 'var(--soc-sidebar)', border: '1px solid var(--soc-border)' }}>

            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b flex-shrink-0"
              style={{ borderColor: 'var(--soc-border)' }}>
              <div className="flex items-center gap-2">
                <Download size={14} className="text-cyan-400" />
                <span className="text-sm font-semibold">Export SSH Config</span>
              </div>
              <button type="button" onClick={() => setShowSshExport(false)}
                style={{ color: 'var(--soc-muted-fg)' }}><X size={14} /></button>
            </div>

            {/* Safety notice */}
            <div className="mx-4 mt-3 px-3 py-2 rounded text-[11px] flex-shrink-0"
              style={{ background: 'rgba(234,179,8,0.08)', border: '1px solid rgba(234,179,8,0.25)', color: 'var(--soc-warning)' }}>
              <strong>Preview only.</strong> This file is <em>never</em> written to disk automatically.
              Review before appending to <code>~/.ssh/config</code>.
              Passwords are never included.
            </div>

            {/* Options */}
            <div className="flex items-center gap-4 px-4 py-3 flex-shrink-0"
              style={{ borderBottom: '1px solid var(--soc-border)' }}>
              <label className="flex items-center gap-1.5 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                <input type="checkbox" checked={sshExportFavOnly}
                  onChange={e => setSshExportFavOnly(e.target.checked)} />
                Favorites only
              </label>
              <div className="flex items-center gap-1.5">
                <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>Tag filter:</span>
                <input
                  className="rounded px-2 py-1 text-[11px] outline-none focus:ring-1 focus:ring-cyan-500/50"
                  style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)', width: 120 }}
                  placeholder="e.g. prod"
                  value={sshExportTag}
                  onChange={e => setSshExportTag(e.target.value)}
                />
              </div>
              <button type="button" onClick={handleSshExport} disabled={sshExportLoading}
                className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50">
                {sshExportLoading ? <RefreshCw size={11} className="animate-spin" /> : <Download size={11} />}
                Generate
              </button>
            </div>

            {/* Result area */}
            <div className="flex-1 overflow-auto px-4 py-3 min-h-0">
              {!sshExportResult && !sshExportLoading && (
                <div className="flex items-center justify-center h-32 text-[12px]"
                  style={{ color: 'var(--soc-muted-fg)' }}>
                  Click <strong className="mx-1">Generate</strong> to preview the SSH config
                </div>
              )}
              {sshExportLoading && (
                <div className="flex items-center justify-center h-32 gap-2 text-[12px]"
                  style={{ color: 'var(--soc-muted-fg)' }}>
                  <RefreshCw size={14} className="animate-spin" /> Building config…
                </div>
              )}
              {sshExportResult && (
                <>
                  <div className="flex items-center gap-3 mb-2 text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                    <span className="font-semibold" style={{ color: 'var(--soc-success)' }}>
                      {sshExportResult.host_count} host{sshExportResult.host_count !== 1 ? 's' : ''} exported
                    </span>
                    {sshExportResult.audit_id && (
                      <span className="font-mono text-[10px]">audit: {sshExportResult.audit_id.slice(0, 8)}</span>
                    )}
                  </div>
                  {sshExportResult.warnings.length > 0 && (
                    <div className="mb-2 px-2 py-1.5 rounded text-[10px]"
                      style={{ background: 'rgba(234,179,8,0.07)', border: '1px solid rgba(234,179,8,0.2)', color: 'var(--soc-warning)' }}>
                      {sshExportResult.warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
                    </div>
                  )}
                  <textarea
                    readOnly
                    className="w-full rounded font-mono text-[11px] p-3 outline-none resize-none"
                    style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)', minHeight: 280 }}
                    value={sshExportResult.config}
                  />
                </>
              )}
            </div>

            {/* Footer actions */}
            {sshExportResult && sshExportResult.host_count > 0 && (
              <div className="flex items-center gap-2 px-4 py-3 border-t flex-shrink-0"
                style={{ borderColor: 'var(--soc-border)' }}>
                <button type="button" onClick={handleSshExportCopy}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold"
                  style={{ background: sshExportCopied ? 'rgba(34,197,94,0.15)' : 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: sshExportCopied ? 'var(--soc-success)' : 'var(--soc-fg)' }}>
                  <Copy size={11} /> {sshExportCopied ? 'Copied!' : 'Copy to clipboard'}
                </button>
                <button type="button" onClick={handleSshExportDownload}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold bg-cyan-600 hover:bg-cyan-500 text-white">
                  <Download size={11} /> Download ssh_config.generated
                </button>
                <span className="ml-auto text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                  Review before adding to ~/.ssh/config
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

