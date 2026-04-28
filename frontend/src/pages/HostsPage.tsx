import { useEffect, useMemo, useState } from 'react';
import { Server, Search, ShieldOff, Terminal, Eye, RefreshCw, UserCircle, X } from 'lucide-react';
import { getHostsCentral, removeHostProfileAssignment, setHostProfileAssignment } from '../services/api';
import type { HostCentralListItem, HostProfile, HostProfileAssignment } from '../types';
import { ProfileBadge } from '../components/ProfileBadge';

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
const STATUSES: StatusFilter[] = ['ALL', 'ONLINE', 'OFFLINE'];

function riskColor(r: number) {
  return r >= 80 ? 'text-critical' : r >= 60 ? 'text-high' : r >= 40 ? 'text-warning' : 'text-success';
}
function riskBg(r: number) {
  return r >= 80 ? 'bg-critical' : r >= 60 ? 'bg-high' : r >= 40 ? 'bg-warning' : 'bg-success';
}
function riskBorderL(r: number) {
  return r >= 80 ? 'border-l-critical' : r >= 60 ? 'border-l-high' : r >= 40 ? 'border-l-warning' : 'border-l-success';
}

export function HostsPage({ active, onSwitchTab, onOpenOverview, profiles, profileAssignments, onProfileAssignmentChanged }: HostsPageProps) {
  const [hosts, setHosts] = useState<HostCentralListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('ALL');
  const [profileFilter, setProfileFilter] = useState<string | null>(null);
  const [selected, setSelected] = useState<HostCentralListItem | null>(null);
  const [assigningHost, setAssigningHost] = useState<string | null>(null);

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
        const isOnline = h.connection_status === 'reachable';
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

  if (!active) return null;

  return (
    <div className="h-full grid grid-cols-[1fr_360px] min-h-0">
      {/* Left: table */}
      <div className="flex flex-col min-h-0 border-r border-border">
        {/* Toolbar */}
        <div className="border-b border-border bg-[var(--panel)] px-3 py-2 flex flex-wrap items-center gap-2">
          <Server className="h-3.5 w-3.5 text-info" />
          <span className="text-[12px] font-semibold tracking-wide">FLEET</span>
          <div className="ml-2 flex items-center gap-1">
            {STATUSES.map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={
                  'h-6 px-2 rounded-sm text-[11px] font-mono border ' +
                  (statusFilter === s
                    ? 'bg-accent border-border text-foreground'
                    : 'border-border text-muted-foreground hover:text-foreground hover:bg-accent')
                }
              >
                {s}
              </button>
            ))}
          </div>
          <div className="ml-auto flex items-center gap-2">
            <button
              onClick={() => onSwitchTab('fullscan')}
              className="h-6 px-2 rounded-sm border border-border hover:bg-accent inline-flex items-center gap-1 text-[11px] font-mono text-muted-foreground hover:text-foreground"
              title="Full Scan All Hosts"
            >
              <Terminal className="h-3 w-3" />
              Full Scan All
            </button>
            <button
              onClick={loadHosts}
              className="h-6 w-6 rounded-sm border border-border hover:bg-accent inline-flex items-center justify-center"
              title="Refresh"
            >
              <RefreshCw className="h-3 w-3 text-muted-foreground" />
            </button>
            <div className="flex items-center gap-2 h-6 w-[260px] px-2 rounded-sm bg-input border border-border">
              <Search className="h-3 w-3 text-muted-foreground" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="host, ip, platform…"
                className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
              />
            </div>
          </div>
        </div>

        {/* Profile filter bar */}
        {profiles.length > 0 && (
          <div className="border-b border-border bg-[var(--panel)] px-3 py-1.5 flex items-center gap-1 flex-wrap">
            <UserCircle className="h-3 w-3 text-muted-foreground" />
            <span className="text-[10px] font-mono text-muted-foreground mr-1">Profile:</span>
            <button
              onClick={() => setProfileFilter(null)}
              className={
                'h-5 px-2 rounded-sm border text-[10px] font-mono ' +
                (profileFilter === null
                  ? 'bg-accent border-primary text-foreground'
                  : 'border-border text-muted-foreground hover:bg-accent')
              }
            >
              All
            </button>
            {profiles.map((p) => (
              <button
                key={p.name}
                onClick={() => setProfileFilter(p.name)}
                className={
                  'h-5 px-2 rounded-sm border text-[10px] font-mono ' +
                  (profileFilter === p.name
                    ? 'bg-accent border-primary text-foreground'
                    : 'border-border text-muted-foreground hover:bg-accent')
                }
              >
                {p.display_name}
              </button>
            ))}
            <button
              onClick={() => setProfileFilter('__none__')}
              className={
                'h-5 px-2 rounded-sm border text-[10px] font-mono ' +
                (profileFilter === '__none__'
                  ? 'bg-accent border-primary text-foreground'
                  : 'border-border text-muted-foreground hover:bg-accent')
              }
            >
              Unassigned
            </button>
          </div>
        )}

        {/* Table */}
        <div className="flex-1 overflow-auto">
          {loading && (
            <div className="flex items-center justify-center h-20 text-[12px] font-mono text-muted-foreground">
              loading…
            </div>
          )}
          {error && (
            <div className="px-3 py-2 text-[11.5px] font-mono text-critical">{error}</div>
          )}
          {!loading && !error && (
            <table className="w-full text-[11.5px] font-mono">
              <thead className="sticky top-0 bg-[var(--panel)] border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                <tr>
                  <Th>Hostname</Th>
                  <Th>Profile</Th>
                  <Th align="right">Risk</Th>
                  <Th>Status</Th>
                  <Th>Last Seen</Th>
                  <Th align="right">Alerts 24h</Th>
                  <Th>OS</Th>
                  <Th>IP</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-3 py-6 text-center text-muted-foreground text-[11.5px]">
                      no hosts found
                    </td>
                  </tr>
                )}
                {filtered.map((h) => {
                  const isSel = selected?.host === h.host;
                  const risk = h.risk_score ?? 0;
                  const asgn = profileAssignments[h.host];
                  return (
                    <tr
                      key={h.host}
                      onClick={() => { setSelected(h); onOpenOverview(h.host); }}
                      className={
                        'cursor-pointer border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                        (isSel ? 'bg-[var(--row-hover)]' : '')
                      }
                    >
                      <Td>
                        <span className={'border-l-2 pl-2 -ml-2 inline-block ' + riskBorderL(risk)}>
                          {h.host}
                        </span>
                      </Td>
                      <Td>
                        <ProfileBadge assignment={asgn} size="sm" />
                      </Td>
                      <Td align="right">
                        <span className={'font-semibold ' + riskColor(risk)}>{risk}</span>
                      </Td>
                      <Td>
                        <StatusDot connected={h.connection_status === 'reachable'} />
                      </Td>
                      <Td className="text-muted-foreground">{h.last_activity ?? '—'}</Td>
                      <Td align="right">{h.alerts_24h ?? 0}</Td>
                      <Td className="text-muted-foreground">{(h.platforms ?? [])[0] ?? '—'}</Td>
                      <Td className="text-muted-foreground">{h.ip ?? '—'}</Td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Right: detail */}
      <aside className="bg-[var(--panel)] flex flex-col min-h-0">
        <div className="h-9 px-3 flex items-center border-b border-border">
          <span className="text-[12px] font-semibold tracking-wide">HOST</span>
          {selected && (
            <span className="ml-2 text-[10.5px] font-mono text-muted-foreground truncate">
              {selected.host}
            </span>
          )}
          {selected && (
            <span className="ml-auto">
              <StatusDot connected={selected.connection_status === 'reachable'} />
            </span>
          )}
        </div>

        {selected ? (
          <div className="flex-1 overflow-y-auto">
            <Sec title="Identity">
              <KV k="ip" v={selected.ip ?? '—'} />
              <KV k="os" v={(selected.platforms ?? [])[0] ?? '—'} />
              <KV k="last seen" v={selected.last_activity ?? '—'} />
              <KV k="alerts 24h" v={String(selected.alerts_24h ?? 0)} />
              <KV k="findings" v={String(selected.findings_count ?? 0)} />
            </Sec>

            <Sec title="Risk Score">
              <div className="flex items-baseline gap-2">
                <span className={'text-[28px] font-mono font-semibold ' + riskColor(selected.risk_score ?? 0)}>
                  {selected.risk_score ?? 0}
                </span>
                <span className="text-[11px] font-mono text-muted-foreground">/ 100</span>
              </div>
              <div className="mt-1 h-1 w-full bg-muted rounded-sm overflow-hidden">
                <div
                  className={'h-full ' + riskBg(selected.risk_score ?? 0)}
                  style={{ width: `${selected.risk_score ?? 0}%` }}
                />
              </div>
            </Sec>

            <Sec title="Scan">
              <KV k="status" v={selected.fullscan_status ?? '—'} />
              <KV k="last scan" v={selected.last_scan_at ?? '—'} />
            </Sec>

            <Sec title="Access">
              <KV k="ssh" v={selected.ssh_enabled ? 'enabled' : 'disabled'} />
              <KV k="rdp" v={selected.rdp_enabled ? 'enabled' : 'disabled'} />
              <KV k="connection" v={selected.connection_status ?? '—'} />
            </Sec>

            <Sec title="Quick Actions">
              <div className="flex flex-wrap gap-1.5">
                <ActBtn icon={Eye} label="Investigate" onClick={() => onSwitchTab('snipen')} />
                <ActBtn icon={ShieldOff} label="Isolate" tone="critical" onClick={() => {
                  if (window.confirm(`Isolate ${selected.host}? This will cut network access.`)) {
                    // No API endpoint available yet — placeholder
                    alert('Isolation not yet supported by backend.');
                  }
                }} />
                <ActBtn icon={Terminal} label="Full Scan" onClick={() => onSwitchTab('fullscan')} />
              </div>
            </Sec>

            {/* Profile assignment */}
            <Sec title="Profile">
              <div className="flex items-center gap-2 flex-wrap">
                {profileAssignments[selected.host] && (
                  <ProfileBadge assignment={profileAssignments[selected.host]} size="md" showLabel />
                )}
                {assigningHost === selected.host ? (
                  <div className="flex items-center gap-1 flex-1">
                    <select
                      autoFocus
                      className="flex-1 h-6 rounded-sm border border-border bg-transparent text-[11px] font-mono px-1 outline-none"
                      defaultValue=""
                      onChange={(e) => {
                        const val = e.target.value;
                        if (val === '__remove__') {
                          void handleAssignProfile(selected.host, null);
                        } else if (val) {
                          void handleAssignProfile(selected.host, Number(val));
                        } else {
                          setAssigningHost(null);
                        }
                      }}
                    >
                      <option value="">Select…</option>
                      {profiles.map((p) => (
                        <option key={p.id} value={String(p.id ?? '')}>
                          {p.display_name}
                        </option>
                      ))}
                      {profileAssignments[selected.host] && (
                        <option value="__remove__">Remove assignment</option>
                      )}
                    </select>
                    <button
                      onClick={() => setAssigningHost(null)}
                      className="h-6 w-6 rounded-sm border border-border hover:bg-accent inline-flex items-center justify-center"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => setAssigningHost(selected.host)}
                    className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1"
                  >
                    <UserCircle className="h-3 w-3" />
                    {profileAssignments[selected.host] ? 'Change' : 'Assign'}
                  </button>
                )}
              </div>
            </Sec>
          </div>
        ) : (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select host →
          </div>
        )}
      </aside>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Th({ children, align }: { children: React.ReactNode; align?: 'right' }) {
  return (
    <th className={'px-3 py-2 font-medium ' + (align === 'right' ? 'text-right' : 'text-left')}>
      {children}
    </th>
  );
}

function Td({
  children,
  align,
  className = '',
}: {
  children: React.ReactNode;
  align?: 'right';
  className?: string;
}) {
  return (
    <td className={'px-3 py-1.5 ' + (align === 'right' ? 'text-right ' : '') + className}>
      {children}
    </td>
  );
}

function StatusDot({ connected }: { connected: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
      <span className={'h-1.5 w-1.5 rounded-full ' + (connected ? 'bg-success animate-pulse' : 'bg-muted-foreground')} />
      {connected ? 'online' : 'offline'}
    </span>
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
      <span className="text-muted-foreground w-20 shrink-0">{k}</span>
      <span className="truncate">{v}</span>
    </div>
  );
}

function ActBtn({
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
    <button
      onClick={onClick}
      className={'h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ' + t}
    >
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
