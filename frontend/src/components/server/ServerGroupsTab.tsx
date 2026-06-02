/**
 * ServerGroupsTab.tsx
 * Host Groups management + Batch Health Check UI.
 * Phase 1 — read-only batch operations only.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity, CheckCircle, ChevronRight, Circle, Clock,
  Edit2, FolderPlus, Layers, Loader, MinusCircle,
  Plus, RefreshCw, Server, Shield, Trash2, Users, XCircle, Zap,
} from 'lucide-react';
import type {
  ServerBatchResult, ServerBatchRun, ServerBatchSummary,
  ServerConnection, ServerHostGroup, ServerHostGroupMember,
} from '../../types';
import {
  addServerGroupMember, createServerGroup, deleteServerGroup,
  getServerBatchResults, getServerBatchRuns, getServerGroupMembers,
  getServerGroups, removeServerGroupMember, runServerGroupHealth,
  updateServerGroup,
} from '../../services/api';

// ── Colour palette for groups ──────────────────────────────────────────
const GROUP_COLORS = [
  '#6366f1', '#8b5cf6', '#06b6d4', '#10b981',
  '#f59e0b', '#ef4444', '#ec4899', '#64748b',
];

// ── Helpers ────────────────────────────────────────────────────────────
function fmtDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}
function fmtTime(iso: string) {
  if (!iso) return '—';
  try { return new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }); }
  catch { return iso; }
}

// ── Status badge ───────────────────────────────────────────────────────
function StatusDot({ status }: { status: string }) {
  const cfg: Record<string, { color: string; icon: React.ReactNode }> = {
    ok:      { color: '#10b981', icon: <CheckCircle size={11} /> },
    partial: { color: '#f59e0b', icon: <Activity size={11} /> },
    done:    { color: '#10b981', icon: <CheckCircle size={11} /> },
    failed:  { color: '#ef4444', icon: <XCircle size={11} /> },
    blocked: { color: '#f59e0b', icon: <Shield size={11} /> },
    timeout: { color: '#f59e0b', icon: <Clock size={11} /> },
    running: { color: '#06b6d4', icon: <Loader size={11} className="animate-spin" /> },
    pending: { color: '#94a3b8', icon: <Circle size={11} /> },
  };
  const c = cfg[status] ?? { color: '#94a3b8', icon: <Circle size={11} /> };
  return <span style={{ color: c.color }} className="flex items-center gap-1">{c.icon} {status}</span>;
}

// ── Group card (left sidebar) ──────────────────────────────────────────
function GroupCard({
  group, selected, onClick,
}: { group: ServerHostGroup; selected: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full text-left px-3 py-2.5 rounded-lg transition-all flex items-center gap-2.5"
      style={{
        background: selected ? 'rgba(99,102,241,0.15)' : 'transparent',
        border: `1px solid ${selected ? group.color : 'var(--soc-border)'}`,
      }}
    >
      <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: group.color }} />
      <div className="flex-1 min-w-0">
        <div className="text-[12px] font-semibold truncate" style={{ color: 'var(--soc-fg)' }}>{group.name}</div>
        <div className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
          {group.member_count ?? 0} member{(group.member_count ?? 0) !== 1 ? 's' : ''}
        </div>
      </div>
      <ChevronRight size={12} style={{ color: 'var(--soc-muted-fg)' }} />
    </button>
  );
}

// ── Batch summary bar ──────────────────────────────────────────────────
function SummaryBar({ summary }: { summary: ServerBatchSummary }) {
  const total = summary.total || 1;
  return (
    <div className="flex items-center gap-4 text-[11px]">
      <span style={{ color: '#10b981' }}><CheckCircle size={11} className="inline mr-1" />{summary.ok} ok</span>
      <span style={{ color: '#ef4444' }}><XCircle size={11} className="inline mr-1" />{summary.failed} failed</span>
      <span style={{ color: '#f59e0b' }}><Shield size={11} className="inline mr-1" />{summary.blocked} blocked</span>
      <span style={{ color: 'var(--soc-muted-fg)' }}>{fmtDuration(summary.duration_ms)}</span>
      <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: 'var(--soc-border)' }}>
        <div className="h-full rounded-full" style={{ width: `${(summary.ok / total) * 100}%`, background: '#10b981' }} />
      </div>
    </div>
  );
}

// ── Props ──────────────────────────────────────────────────────────────
type Props = { connections: ServerConnection[] };

// ══════════════════════════════════════════════════════════════════════
// Main component
// ══════════════════════════════════════════════════════════════════════
export function ServerGroupsTab({ connections }: Props) {
  // Groups
  const [groups, setGroups]               = useState<ServerHostGroup[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<ServerHostGroup | null>(null);
  const [members, setMembers]             = useState<ServerHostGroupMember[]>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [loadingMembers, setLoadingMembers] = useState(false);

  // Group form
  const [showGroupForm, setShowGroupForm] = useState(false);
  const [editGroup, setEditGroup]         = useState<ServerHostGroup | null>(null);
  const [formName, setFormName]           = useState('');
  const [formDesc, setFormDesc]           = useState('');
  const [formColor, setFormColor]         = useState(GROUP_COLORS[0]);

  // Member add
  const [addConnId, setAddConnId]         = useState('');

  // Batch
  const [batchRuns, setBatchRuns]         = useState<ServerBatchRun[]>([]);
  const [selectedRun, setSelectedRun]     = useState<ServerBatchRun | null>(null);
  const [runResults, setRunResults]       = useState<ServerBatchResult[]>([]);
  const [runningBatch, setRunningBatch]   = useState(false);
  const [batchChecks, setBatchChecks]     = useState<('ping' | 'port' | 'ssh_health')[]>(['ping', 'port']);
  const [error, setError]                 = useState('');

  // Panel view: 'detail' | 'runs'
  const [panel, setPanel]                 = useState<'detail' | 'runs'>('detail');

  const mountedRef = useRef(true);
  useEffect(() => { mountedRef.current = true; return () => { mountedRef.current = false; }; }, []);

  // ── Load groups ──────────────────────────────────────────────────────
  const loadGroups = useCallback(async () => {
    setLoadingGroups(true);
    try {
      const res = await getServerGroups();
      if (mountedRef.current) setGroups(res.data);
    } catch (e: unknown) {
      if (mountedRef.current) setError(String(e));
    } finally {
      if (mountedRef.current) setLoadingGroups(false);
    }
  }, []);

  useEffect(() => { loadGroups(); }, [loadGroups]);

  // ── Load members when group changes ─────────────────────────────────
  useEffect(() => {
    if (!selectedGroup) { setMembers([]); return; }
    setLoadingMembers(true);
    getServerGroupMembers(selectedGroup.id)
      .then(r => { if (mountedRef.current) setMembers(r.data); })
      .catch(() => { if (mountedRef.current) setMembers([]); })
      .finally(() => { if (mountedRef.current) setLoadingMembers(false); });
  }, [selectedGroup]);

  // ── Load batch runs ──────────────────────────────────────────────────
  const loadBatchRuns = useCallback(async () => {
    try {
      const res = await getServerBatchRuns(30);
      if (mountedRef.current) setBatchRuns(res.data);
    } catch { /* silent */ }
  }, []);

  useEffect(() => { if (panel === 'runs') loadBatchRuns(); }, [panel, loadBatchRuns]);

  // ── Load run results ─────────────────────────────────────────────────
  useEffect(() => {
    if (!selectedRun) { setRunResults([]); return; }
    getServerBatchResults(selectedRun.id)
      .then(r => { if (mountedRef.current) setRunResults(r.data); })
      .catch(() => {});
  }, [selectedRun]);

  // ── Save group (create or update) ───────────────────────────────────
  const saveGroup = async () => {
    if (!formName.trim()) return;
    try {
      if (editGroup) {
        await updateServerGroup(editGroup.id, { name: formName, description: formDesc, color: formColor });
      } else {
        await createServerGroup({ name: formName, description: formDesc, color: formColor });
      }
      setShowGroupForm(false);
      setEditGroup(null);
      setFormName(''); setFormDesc(''); setFormColor(GROUP_COLORS[0]);
      await loadGroups();
    } catch (e: unknown) { setError(String(e)); }
  };

  const startEdit = (g: ServerHostGroup) => {
    setEditGroup(g);
    setFormName(g.name);
    setFormDesc(g.description);
    setFormColor(g.color);
    setShowGroupForm(true);
  };

  const deleteGroup = async (g: ServerHostGroup) => {
    if (!window.confirm(`Delete group "${g.name}"?`)) return;
    try {
      await deleteServerGroup(g.id);
      if (selectedGroup?.id === g.id) setSelectedGroup(null);
      await loadGroups();
    } catch (e: unknown) { setError(String(e)); }
  };

  // ── Add member ───────────────────────────────────────────────────────
  const addMember = async () => {
    if (!selectedGroup || !addConnId) return;
    try {
      await addServerGroupMember(selectedGroup.id, addConnId);
      setAddConnId('');
      const r = await getServerGroupMembers(selectedGroup.id);
      setMembers(r.data);
      await loadGroups();
    } catch (e: unknown) { setError(String(e)); }
  };

  const removeMember = async (m: ServerHostGroupMember) => {
    if (!selectedGroup) return;
    try {
      await removeServerGroupMember(selectedGroup.id, m.connection_id);
      setMembers(prev => prev.filter(x => x.connection_id !== m.connection_id));
      await loadGroups();
    } catch (e: unknown) { setError(String(e)); }
  };

  // ── Run batch health ─────────────────────────────────────────────────
  const runBatch = async () => {
    if (!selectedGroup) return;
    setRunningBatch(true);
    setError('');
    try {
      const res = await runServerGroupHealth(selectedGroup.id, batchChecks, 5);
      if (mountedRef.current) {
        await loadBatchRuns();
        setPanel('runs');
        // find the new run
        const run: ServerBatchRun = {
          id: res.batch_run_id!,
          group_id: selectedGroup.id,
          action: batchChecks.join('+'),
          status: res.summary.status,
          started_at: new Date().toISOString(),
          summary: res.summary,
        };
        setSelectedRun(run);
        setRunResults(res.results);
      }
    } catch (e: unknown) {
      if (mountedRef.current) setError(String(e));
    } finally {
      if (mountedRef.current) setRunningBatch(false);
    }
  };

  // Connections not yet in group
  const memberIds = new Set(members.map(m => m.connection_id));
  const nonMembers = connections.filter(c => !memberIds.has(c.id));

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-1 min-h-0 overflow-hidden" style={{ gap: 0 }}>

      {/* ── Left sidebar: group list ── */}
      <div className="flex flex-col flex-shrink-0 overflow-y-auto" style={{
        width: 220, borderRight: '1px solid var(--soc-border)',
        background: 'var(--soc-sidebar-bg)',
      }}>
        <div className="flex items-center justify-between px-3 py-2.5" style={{ borderBottom: '1px solid var(--soc-border)' }}>
          <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: 'var(--soc-muted-fg)' }}>
            Host Groups
          </span>
          <button type="button" title="New group" onClick={() => { setEditGroup(null); setFormName(''); setFormDesc(''); setFormColor(GROUP_COLORS[0]); setShowGroupForm(true); }}
            className="p-1 rounded hover:bg-white/10 transition-colors" style={{ color: 'var(--soc-primary)' }}>
            <FolderPlus size={14} />
          </button>
        </div>

        {loadingGroups && (
          <div className="flex justify-center py-6"><Loader size={14} className="animate-spin" style={{ color: 'var(--soc-muted-fg)' }} /></div>
        )}

        <div className="flex flex-col gap-1 p-2">
          {groups.map(g => (
            <div key={g.id} className="group relative">
              <GroupCard group={g} selected={selectedGroup?.id === g.id} onClick={() => { setSelectedGroup(g); setPanel('detail'); }} />
              <div className="absolute right-1 top-1/2 -translate-y-1/2 hidden group-hover:flex gap-0.5">
                <button type="button" onClick={e => { e.stopPropagation(); startEdit(g); }}
                  className="p-1 rounded hover:bg-white/10" style={{ color: 'var(--soc-muted-fg)' }}>
                  <Edit2 size={10} />
                </button>
                <button type="button" onClick={e => { e.stopPropagation(); deleteGroup(g); }}
                  className="p-1 rounded hover:bg-white/10" style={{ color: '#ef4444' }}>
                  <Trash2 size={10} />
                </button>
              </div>
            </div>
          ))}
          {!loadingGroups && groups.length === 0 && (
            <div className="px-3 py-6 text-center text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
              No groups yet.<br />Click <FolderPlus size={10} className="inline" /> to create one.
            </div>
          )}
        </div>

        {/* Batch Runs button */}
        <div className="mt-auto p-2 border-t" style={{ borderColor: 'var(--soc-border)' }}>
          <button type="button" onClick={() => setPanel('runs')}
            className="w-full flex items-center gap-2 px-3 py-2 rounded text-[11px] transition-colors"
            style={{
              background: panel === 'runs' ? 'rgba(99,102,241,0.15)' : 'transparent',
              color: panel === 'runs' ? 'var(--soc-primary)' : 'var(--soc-muted-fg)',
              border: '1px solid var(--soc-border)',
            }}>
            <Activity size={12} /> Batch Runs
            {batchRuns.length > 0 && (
              <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded-full" style={{ background: 'var(--soc-border)' }}>
                {batchRuns.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* ── Main panel ── */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">

        {error && (
          <div className="flex items-center justify-between px-4 py-2 text-[11px] flex-shrink-0"
            style={{ background: 'rgba(239,68,68,0.08)', borderBottom: '1px solid rgba(239,68,68,0.2)', color: '#ef4444' }}>
            {error}
            <button type="button" onClick={() => setError('')}><XCircle size={12} /></button>
          </div>
        )}

        {/* ── Group form modal ── */}
        {showGroupForm && (
          <div className="absolute inset-0 z-50 flex items-center justify-center" style={{ background: 'rgba(0,0,0,0.5)' }}>
            <div className="rounded-xl p-5 flex flex-col gap-3 w-80" style={{ background: 'var(--soc-card-bg)', border: '1px solid var(--soc-border)' }}>
              <div className="text-[13px] font-semibold" style={{ color: 'var(--soc-fg)' }}>
                {editGroup ? 'Edit Group' : 'New Group'}
              </div>
              <input value={formName} onChange={e => setFormName(e.target.value)} placeholder="Group name"
                className="px-3 py-2 rounded text-[12px] outline-none focus:ring-1 focus:ring-cyan-500/50"
                style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }} />
              <input value={formDesc} onChange={e => setFormDesc(e.target.value)} placeholder="Description (optional)"
                className="px-3 py-2 rounded text-[12px] outline-none focus:ring-1 focus:ring-cyan-500/50"
                style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }} />
              <div>
                <div className="text-[10px] mb-1.5" style={{ color: 'var(--soc-muted-fg)' }}>Color</div>
                <div className="flex gap-2 flex-wrap">
                  {GROUP_COLORS.map(c => (
                    <button key={c} type="button" onClick={() => setFormColor(c)}
                      className="w-6 h-6 rounded-full transition-transform hover:scale-110"
                      style={{ background: c, outline: formColor === c ? `2px solid white` : 'none', outlineOffset: 2 }} />
                  ))}
                </div>
              </div>
              <div className="flex gap-2 justify-end mt-1">
                <button type="button" onClick={() => setShowGroupForm(false)}
                  className="px-3 py-1.5 rounded text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>
                  Cancel
                </button>
                <button type="button" onClick={saveGroup} disabled={!formName.trim()}
                  className="px-3 py-1.5 rounded text-[11px] font-semibold disabled:opacity-40"
                  style={{ background: formColor, color: 'white' }}>
                  {editGroup ? 'Save' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ── Panel: Group detail ── */}
        {panel === 'detail' && !selectedGroup && (
          <div className="flex flex-1 items-center justify-center flex-col gap-3" style={{ color: 'var(--soc-muted-fg)' }}>
            <Layers size={32} strokeWidth={1} />
            <div className="text-[12px]">Select a group to see members and run health checks.</div>
            {groups.length === 0 && (
              <button type="button" onClick={() => setShowGroupForm(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold"
                style={{ background: 'var(--soc-primary)', color: 'white' }}>
                <FolderPlus size={12} /> Create first group
              </button>
            )}
          </div>
        )}

        {panel === 'detail' && selectedGroup && (
          <div className="flex flex-col flex-1 min-h-0 overflow-y-auto">
            {/* Group header */}
            <div className="flex items-center justify-between px-4 py-3 flex-shrink-0"
              style={{ borderBottom: '1px solid var(--soc-border)' }}>
              <div className="flex items-center gap-2.5">
                <span className="w-3 h-3 rounded-full" style={{ background: selectedGroup.color }} />
                <div>
                  <div className="text-[13px] font-semibold" style={{ color: 'var(--soc-fg)' }}>{selectedGroup.name}</div>
                  {selectedGroup.description && (
                    <div className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{selectedGroup.description}</div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {/* Check options */}
                <div className="flex items-center gap-2 mr-2">
                  {(['ping', 'port', 'ssh_health'] as const).map(c => (
                    <label key={c} className="flex items-center gap-1 text-[11px] cursor-pointer select-none"
                      style={{ color: batchChecks.includes(c) ? 'var(--soc-primary)' : 'var(--soc-muted-fg)' }}>
                      <input type="checkbox" checked={batchChecks.includes(c)}
                        onChange={ev => setBatchChecks(prev =>
                          ev.target.checked ? [...prev, c] : prev.filter(x => x !== c)
                        )} className="rounded" />
                      {c}
                    </label>
                  ))}
                </div>
                <button type="button" onClick={runBatch} disabled={runningBatch || members.length === 0 || batchChecks.length === 0}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded text-[11px] font-semibold disabled:opacity-40 transition-colors"
                  style={{ background: 'var(--soc-primary)', color: 'white' }}>
                  {runningBatch ? <Loader size={11} className="animate-spin" /> : <Zap size={11} />}
                  {runningBatch ? 'Running…' : 'Run Health Check'}
                </button>
              </div>
            </div>

            {/* Add member row */}
            <div className="flex items-center gap-2 px-4 py-2 flex-shrink-0"
              style={{ borderBottom: '1px solid var(--soc-border)', background: 'rgba(255,255,255,0.02)' }}>
              <Users size={12} style={{ color: 'var(--soc-muted-fg)' }} />
              <select value={addConnId} onChange={e => setAddConnId(e.target.value)}
                className="flex-1 px-2 py-1 rounded text-[11px] outline-none"
                style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-fg)' }}>
                <option value="">Add connection to group…</option>
                {nonMembers.map(c => (
                  <option key={c.id} value={c.id}>{c.name} ({c.hostname || c.ip || '?'}) [{c.protocol}]</option>
                ))}
              </select>
              <button type="button" onClick={addMember} disabled={!addConnId}
                className="flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-semibold disabled:opacity-40"
                style={{ background: 'rgba(99,102,241,0.2)', color: 'var(--soc-primary)', border: '1px solid rgba(99,102,241,0.3)' }}>
                <Plus size={11} /> Add
              </button>
            </div>

            {/* Members table */}
            {loadingMembers ? (
              <div className="flex justify-center py-8"><Loader size={16} className="animate-spin" style={{ color: 'var(--soc-muted-fg)' }} /></div>
            ) : members.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 gap-2" style={{ color: 'var(--soc-muted-fg)' }}>
                <Server size={24} strokeWidth={1} />
                <div className="text-[11px]">No members yet. Add connections above.</div>
              </div>
            ) : (
              <table className="w-full text-[11px]">
                <thead>
                  <tr style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
                    {['Name', 'Host', 'Protocol', 'OS', 'Wazuh', 'Added', ''].map(h => (
                      <th key={h} className="px-3 py-2 text-left font-semibold">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {members.map(m => (
                    <tr key={m.id} className="border-b hover:bg-white/5 transition-colors"
                      style={{ borderColor: 'var(--soc-border)' }}>
                      <td className="px-3 py-2 font-medium" style={{ color: 'var(--soc-fg)' }}>{m.name ?? m.connection_id}</td>
                      <td className="px-3 py-2" style={{ color: 'var(--soc-muted-fg)' }}>{m.hostname || m.ip || '—'}</td>
                      <td className="px-3 py-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase"
                          style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
                          {m.protocol ?? '—'}
                        </span>
                      </td>
                      <td className="px-3 py-2" style={{ color: 'var(--soc-muted-fg)' }}>{m.os || '—'}</td>
                      <td className="px-3 py-2">
                        {m.wazuh_agent_id
                          ? <span className="text-[10px]" style={{ color: '#10b981' }}>linked</span>
                          : <span className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>—</span>}
                      </td>
                      <td className="px-3 py-2" style={{ color: 'var(--soc-muted-fg)' }}>{fmtTime(m.added_at)}</td>
                      <td className="px-3 py-2">
                        <button type="button" onClick={() => removeMember(m)}
                          className="p-1 rounded hover:bg-white/10 transition-colors" style={{ color: '#ef4444' }}>
                          <MinusCircle size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── Panel: Batch Runs ── */}
        {panel === 'runs' && (
          <div className="flex flex-col flex-1 min-h-0 overflow-hidden">
            {/* Run list + detail split */}
            <div className="flex flex-1 min-h-0">
              {/* Run list */}
              <div className="flex flex-col overflow-y-auto flex-shrink-0" style={{ width: 300, borderRight: '1px solid var(--soc-border)' }}>
                <div className="flex items-center justify-between px-3 py-2 flex-shrink-0"
                  style={{ borderBottom: '1px solid var(--soc-border)' }}>
                  <span className="text-[11px] font-semibold uppercase" style={{ color: 'var(--soc-muted-fg)' }}>Recent Runs</span>
                  <button type="button" onClick={loadBatchRuns} className="p-1 rounded hover:bg-white/10">
                    <RefreshCw size={11} style={{ color: 'var(--soc-muted-fg)' }} />
                  </button>
                </div>
                {batchRuns.length === 0 && (
                  <div className="py-8 text-center text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>No batch runs yet.</div>
                )}
                {batchRuns.map(run => (
                  <button key={run.id} type="button" onClick={() => setSelectedRun(run)}
                    className="flex flex-col gap-0.5 px-3 py-2.5 text-left transition-colors border-b hover:bg-white/5"
                    style={{
                      borderColor: 'var(--soc-border)',
                      background: selectedRun?.id === run.id ? 'rgba(99,102,241,0.1)' : 'transparent',
                    }}>
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-medium font-mono" style={{ color: 'var(--soc-fg)' }}>{run.action}</span>
                      <StatusDot status={run.status} />
                    </div>
                    <div className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                      {fmtTime(run.started_at)} · {run.summary?.total ?? 0} hosts
                    </div>
                    {run.summary && <SummaryBar summary={run.summary} />}
                  </button>
                ))}
              </div>

              {/* Run results */}
              <div className="flex flex-col flex-1 min-w-0 overflow-y-auto">
                {!selectedRun && (
                  <div className="flex flex-1 items-center justify-center" style={{ color: 'var(--soc-muted-fg)' }}>
                    <div className="text-[12px]">Select a run to see per-host results.</div>
                  </div>
                )}
                {selectedRun && (
                  <>
                    <div className="px-4 py-2.5 flex-shrink-0" style={{ borderBottom: '1px solid var(--soc-border)' }}>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[12px] font-semibold" style={{ color: 'var(--soc-fg)' }}>
                          Run: <span className="font-mono">{selectedRun.action}</span>
                        </span>
                        <StatusDot status={selectedRun.status} />
                      </div>
                      {selectedRun.summary && <SummaryBar summary={selectedRun.summary} />}
                    </div>
                    <table className="w-full text-[11px]">
                      <thead>
                        <tr style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
                          {['Host', 'Status', 'Duration', 'Ping', 'Ports', 'SSH', 'Error'].map(h => (
                            <th key={h} className="px-3 py-2 text-left font-semibold">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {runResults.map(r => {
                          const ping   = r.result?.ping   as Record<string, unknown> | undefined;
                          const port   = r.result?.port   as Record<string, unknown> | undefined;
                          const ssh    = r.result?.ssh_health as Record<string, unknown> | undefined;
                          return (
                            <tr key={r.id} className="border-b hover:bg-white/5"
                              style={{ borderColor: 'var(--soc-border)' }}>
                              <td className="px-3 py-2 font-medium" style={{ color: 'var(--soc-fg)' }}>{r.host}</td>
                              <td className="px-3 py-2"><StatusDot status={r.status} /></td>
                              <td className="px-3 py-2" style={{ color: 'var(--soc-muted-fg)' }}>{fmtDuration(r.duration_ms)}</td>
                              <td className="px-3 py-2">
                                {ping
                                  ? <span style={{ color: ping.reachable ? '#10b981' : '#ef4444' }}>{ping.reachable ? '✓' : '✗'} {ping.avg_rtt_ms != null ? `${ping.avg_rtt_ms}ms` : ''}</span>
                                  : <span style={{ color: 'var(--soc-muted-fg)' }}>—</span>}
                              </td>
                              <td className="px-3 py-2">
                                {port
                                  ? <span style={{ color: 'var(--soc-muted-fg)' }}>{String(port.open_count ?? 0)} open</span>
                                  : <span style={{ color: 'var(--soc-muted-fg)' }}>—</span>}
                              </td>
                              <td className="px-3 py-2">
                                {ssh
                                  ? <span style={{ color: ssh.status === 'ok' ? '#10b981' : '#f59e0b' }}>{String(ssh.status)}</span>
                                  : <span style={{ color: 'var(--soc-muted-fg)' }}>—</span>}
                              </td>
                              <td className="px-3 py-2 max-w-[200px] truncate" style={{ color: '#f59e0b' }}
                                title={r.error ?? ''}>
                                {r.error ?? ''}
                              </td>
                            </tr>
                          );
                        })}
                        {runResults.length === 0 && (
                          <tr><td colSpan={7} className="px-4 py-6 text-center text-[11px]"
                            style={{ color: 'var(--soc-muted-fg)' }}>No results yet.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            </div>

            {/* Planned: Live Multi-Host Ping Monitor */}
            <div className="flex-shrink-0 m-4 rounded-lg px-4 py-3 flex items-center gap-3"
              style={{ background: 'rgba(99,102,241,0.06)', border: '1px dashed rgba(99,102,241,0.3)' }}>
              <Activity size={14} style={{ color: 'rgba(99,102,241,0.7)' }} />
              <div>
                <div className="text-[11px] font-semibold" style={{ color: 'var(--soc-muted-fg)' }}>
                  Live Multi-Host Ping Monitor — Planned
                </div>
                <div className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                  Current phase stores batch ping results. WebSocket streaming monitor will be added later.
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
