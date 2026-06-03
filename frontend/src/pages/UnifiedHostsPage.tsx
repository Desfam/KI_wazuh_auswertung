import React, { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle, ChevronDown, ChevronRight, Copy, Network, RefreshCw, Shield, XCircle } from 'lucide-react';
import {
  getUnifiedHost,
  getUnifiedHostConflicts,
  getUnifiedHosts,
  getTacticalHealth,
  triggerTacticalSync,
  syncWazuhAgents,
  recomputePolicies,
} from '../services/api';
import type { ActionPolicy, HostConflict, IdentityStatus, TacticalSyncResult, UnifiedHost, WazuhSyncReport } from '../types';

// ── Helpers ────────────────────────────────────────────────────────────────────

function identityColor(s: IdentityStatus) {
  if (s === 'trusted') return 'var(--soc-success)';
  if (s === 'likely') return 'var(--soc-warning)';
  if (s === 'uncertain') return 'oklch(0.75 0.18 40)';
  return 'var(--soc-muted-fg)';
}

function identityLabel(s: IdentityStatus) {
  if (s === 'trusted') return 'Trusted';
  if (s === 'likely') return 'Likely';
  if (s === 'uncertain') return 'Uncertain';
  return 'Unknown';
}

function statusDot(status: string) {
  if (status === 'online' || status === 'connected' || status === 'active') return 'var(--soc-success)';
  if (status === 'offline' || status === 'disconnected' || status === 'inactive') return 'var(--soc-critical)';
  return 'var(--soc-muted-fg)';
}

function policyLabel(p: ActionPolicy) {
  if (p === 'full') return 'Full (Phase 2)';
  if (p === 'read_only') return 'Read-only';
  if (p === 'review_required') return 'Review Required';
  return 'Blocked';
}

function policyColor(p: ActionPolicy) {
  if (p === 'full') return 'var(--soc-success)';
  if (p === 'read_only') return 'var(--soc-warning)';
  if (p === 'review_required') return 'rgba(245,158,11,0.9)';
  return 'var(--soc-critical)';
}

function relTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return `${Math.round(diff)}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

function conflictSeverityColor(s: string) {
  if (s === 'critical') return 'var(--soc-critical)';
  if (s === 'warning') return 'var(--soc-warning)';
  return 'var(--soc-muted-fg)';
}

// ── Small status badge ──────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const color = statusDot(status);
  return (
    <span className="flex items-center gap-1 font-mono text-[11px]" style={{ color }}>
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {status}
    </span>
  );
}

// ── Wazuh Sync Report modal ─────────────────────────────────────────────────────

interface SyncReportModalProps {
  report: WazuhSyncReport;
  onClose: () => void;
}

function WazuhSyncReportModal({ report, onClose }: SyncReportModalProps) {
  const [showUnmatched, setShowUnmatched] = useState(false);
  const [showConflicts, setShowConflicts] = useState(false);
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    void navigator.clipboard.writeText(JSON.stringify(report, null, 2)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const mm = report.match_methods;
  const methodRows = [
    { label: 'Agent ID (exact)',  value: mm.agent_id,    color: 'var(--soc-success)' },
    { label: 'Hostname match',    value: mm.hostname,    color: 'var(--soc-primary)' },
    { label: 'FQDN match',        value: mm.fqdn,        color: 'oklch(0.75 0.18 40)' },
    { label: 'IP match',          value: mm.ip,          color: 'var(--soc-warning)' },
    { label: 'New (unmatched)',   value: mm.created_new, color: 'var(--soc-muted-fg)' },
  ];

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.75)' }}
      onClick={onClose}
    >
      <div
        className="rounded-lg w-[680px] max-h-[90vh] overflow-y-auto p-5 space-y-4 text-sm"
        style={{ background: 'var(--soc-panel)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="font-semibold text-base">Wazuh Sync Report</div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={handleCopy}
              className="flex items-center gap-1 px-2 py-1 rounded text-[11px] font-mono"
              style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)', border: '1px solid var(--soc-border)' }}
            >
              <Copy size={11} /> {copied ? 'Copied!' : 'Copy JSON'}
            </button>
            <button type="button" onClick={onClose} className="text-[11px] px-2 py-1 rounded" style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
              ✕
            </button>
          </div>
        </div>

        {/* Errors / Warnings */}
        {report.errors.length > 0 && (
          <div className="rounded p-2.5 space-y-1" style={{ background: 'oklch(0.25 0.05 20)', borderLeft: '3px solid var(--soc-critical)' }}>
            {report.errors.map((e, i) => (
              <div key={i} className="text-[11px] font-mono" style={{ color: 'var(--soc-critical)' }}>{e}</div>
            ))}
          </div>
        )}
        {report.warnings.length > 0 && (
          <div className="rounded p-2.5 space-y-1" style={{ background: 'oklch(0.25 0.05 40)', borderLeft: '3px solid var(--soc-warning)' }}>
            {report.warnings.map((w, i) => (
              <div key={i} className="text-[11px] font-mono" style={{ color: 'var(--soc-warning)' }}>{w}</div>
            ))}
          </div>
        )}

        {/* Totals */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Totals</div>
          <div className="grid grid-cols-4 gap-2">
            {[
              { label: 'Wazuh agents',      value: report.agents_total,        color: 'var(--soc-foreground)' },
              { label: 'Existing hosts',     value: report.unified_hosts_before,color: 'var(--soc-foreground)' },
              { label: 'Matched',            value: report.matched,             color: 'var(--soc-success)' },
              { label: 'Created new',        value: report.created,             color: 'var(--soc-primary)' },
              { label: 'Updated',            value: report.updated,             color: 'oklch(0.75 0.18 40)' },
              { label: 'Conflicts',          value: report.conflicts,           color: 'var(--soc-warning)' },
              { label: 'Unmatched agents',   value: report.unmatched_agents,    color: 'var(--soc-muted-fg)' },
              { label: 'Duration',           value: `${report.duration_ms}ms`,  color: 'var(--soc-muted-fg)' },
            ].map(c => (
              <div key={c.label} className="rounded p-2" style={{ background: 'var(--soc-sidebar-accent)' }}>
                <div className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>{c.label}</div>
                <div className="font-mono font-bold text-[13px]" style={{ color: c.color }}>{c.value}</div>
              </div>
            ))}
          </div>
        </section>

        {/* Match methods */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Match Method Breakdown</div>
          <div className="rounded overflow-hidden" style={{ border: '1px solid var(--soc-border)' }}>
            {methodRows.map((r, i) => (
              <div key={r.label} className="flex items-center justify-between px-3 py-1.5" style={{ borderTop: i > 0 ? '1px solid var(--soc-border)' : undefined }}>
                <span className="text-[11px]" style={{ color: 'var(--soc-muted-fg)' }}>{r.label}</span>
                <span className="font-mono font-bold text-[12px]" style={{ color: r.value > 0 ? r.color : 'var(--soc-muted-fg)' }}>{r.value}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Unmatched agents */}
        {report.unmatched_items.length > 0 && (
          <section>
            <button
              type="button"
              className="flex items-center gap-1.5 w-full text-left text-[10px] font-semibold uppercase tracking-widest mb-2"
              style={{ color: 'var(--soc-muted-fg)' }}
              onClick={() => setShowUnmatched(v => !v)}
            >
              {showUnmatched ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
              Unmatched Agents ({report.unmatched_items.length})
            </button>
            {showUnmatched && (
              <div className="rounded overflow-hidden" style={{ border: '1px solid var(--soc-border)' }}>
                <div className="grid text-[10px] font-semibold px-3 py-1.5 grid-cols-4 gap-2" style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
                  <span>Agent ID</span><span>Name</span><span>IP</span><span>Status</span>
                </div>
                {report.unmatched_items.map((item, i) => (
                  <div key={i} className="grid grid-cols-4 gap-2 px-3 py-1.5 font-mono text-[11px]" style={{ borderTop: '1px solid var(--soc-border)' }}>
                    <span style={{ color: 'var(--soc-muted-fg)' }}>{item.agent_id}</span>
                    <span>{item.agent_name}</span>
                    <span style={{ color: 'var(--soc-muted-fg)' }}>{item.agent_ip || '—'}</span>
                    <span style={{ color: statusDot(item.status) }}>{item.status}</span>
                  </div>
                ))}
              </div>
            )}
          </section>
        )}

        {/* Conflicts */}
        {report.conflict_items.length > 0 && (
          <section>
            <button
              type="button"
              className="flex items-center gap-1.5 w-full text-left text-[10px] font-semibold uppercase tracking-widest mb-2"
              style={{ color: 'var(--soc-warning)' }}
              onClick={() => setShowConflicts(v => !v)}
            >
              {showConflicts ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
              Conflicts ({report.conflict_items.length})
            </button>
            {showConflicts && (
              <div className="space-y-2">
                {report.conflict_items.map((ci, i) => (
                  <div key={i} className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: '3px solid var(--soc-warning)' }}>
                    <div className="font-semibold text-[11px] mb-1">{ci.host_name}</div>
                    <div className="text-[10px] mb-1.5" style={{ color: 'var(--soc-muted-fg)' }}>{ci.reason}</div>
                    {ci.candidates.map((c, j) => (
                      <div key={j} className="font-mono text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>
                        #{c.agent_id} {c.agent_name} {c.agent_ip ? `(${c.agent_ip})` : ''} via {c.match_reason}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

// ── Host detail panel ───────────────────────────────────────────────────────────

interface DetailPanelProps {
  host: UnifiedHost;
  conflicts: HostConflict[];
  onClose: () => void;
}

function HostDetailPanel({ host, conflicts, onClose }: DetailPanelProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      style={{ background: 'rgba(0,0,0,0.7)' }}
      onClick={onClose}
    >
      <div
        className="rounded-lg w-[700px] max-h-[90vh] overflow-y-auto p-6 space-y-5 text-sm"
        style={{ background: 'var(--soc-panel)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="text-base font-semibold">{host.display_name}</div>
            {host.fqdn && <div className="text-[11px] font-mono mt-0.5" style={{ color: 'var(--soc-muted-fg)' }}>{host.fqdn}</div>}
          </div>
          <button type="button" onClick={onClose} className="text-[11px] px-2 py-1 rounded" style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)' }}>
            ✕ Close
          </button>
        </div>

        {/* Host Identity */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Host Identity</div>
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded p-2" style={{ background: 'var(--soc-sidebar-accent)' }}>
              <div className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Match Score</div>
              <div className="font-mono text-lg font-bold" style={{ color: identityColor(host.identity_status) }}>
                {host.match_score}
              </div>
            </div>
            <div className="rounded p-2" style={{ background: 'var(--soc-sidebar-accent)' }}>
              <div className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Identity</div>
              <div className="font-semibold" style={{ color: identityColor(host.identity_status) }}>
                {identityLabel(host.identity_status)}
              </div>
            </div>
            <div className="rounded p-2" style={{ background: 'var(--soc-sidebar-accent)' }}>
              <div className="text-[10px] mb-1" style={{ color: 'var(--soc-muted-fg)' }}>Action Policy</div>
              <div className="font-semibold" style={{ color: policyColor(host.action_policy) }}>
                {policyLabel(host.action_policy)}
              </div>
            </div>
          </div>
        </section>

        {/* Trust Explanation */}
        {(host.identity_reason || host.policy_reason) && (
          <section>
            <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Trust Explanation</div>
            <div className="space-y-2">
              {host.identity_reason && (
                <div className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${identityColor(host.identity_status)}` }}>
                  <div className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>Identity Reason</div>
                  <div className="text-[11px]">{host.identity_reason}</div>
                </div>
              )}
              {host.policy_reason && (
                <div className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${policyColor(host.action_policy)}` }}>
                  <div className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>Policy Reason</div>
                  <div className="text-[11px]">{host.policy_reason}</div>
                </div>
              )}
              {(host.match_evidence?.length ?? 0) > 0 && (
                <div className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)' }}>
                  <div className="text-[10px] font-semibold mb-1.5" style={{ color: 'var(--soc-muted-fg)' }}>Match Evidence</div>
                  <ul className="space-y-0.5">
                    {host.match_evidence!.map((e, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px]">
                        <span style={{ color: 'var(--soc-success)' }}>✓</span>
                        <span>{e}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {(host.conflict_evidence?.length ?? 0) > 0 && (
                <div className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: '3px solid var(--soc-warning)' }}>
                  <div className="text-[10px] font-semibold mb-1.5" style={{ color: 'var(--soc-warning)' }}>Conflict Evidence</div>
                  <ul className="space-y-0.5">
                    {host.conflict_evidence!.map((e, i) => (
                      <li key={i} className="flex items-start gap-1.5 text-[11px]">
                        <span style={{ color: 'var(--soc-warning)' }}>⚠</span>
                        <span>{e}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {host.recommended_next_step && (
                <div className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: '3px solid var(--soc-primary)' }}>
                  <div className="text-[10px] font-semibold mb-0.5" style={{ color: 'var(--soc-muted-fg)' }}>Recommended Next Step</div>
                  <div className="text-[11px]">{host.recommended_next_step}</div>
                </div>
              )}
            </div>
          </section>
        )}

        {/* Wazuh Security */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Wazuh Security</div>
          <div className="rounded p-3 space-y-1" style={{ background: 'var(--soc-sidebar-accent)' }}>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Agent ID</span>
              <span className="font-mono text-[11px]">{host.wazuh_agent_id ?? '—'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Status</span>
              <StatusBadge status={host.wazuh_status} />
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Last seen</span>
              <span className="font-mono text-[11px]">{relTime(host.last_seen_wazuh)}</span>
            </div>
          </div>
        </section>

        {/* Tactical RMM */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Tactical RMM</div>
          <div className="rounded p-3 space-y-1" style={{ background: 'var(--soc-sidebar-accent)' }}>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Agent ID</span>
              <span className="font-mono text-[11px]">{host.tactical_agent_id ?? '—'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Status</span>
              <StatusBadge status={host.tactical_status} />
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Last check-in</span>
              <span className="font-mono text-[11px]">{relTime(host.last_seen_tactical)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>OS</span>
              <span className="font-mono text-[11px]">{host.os_full ?? host.os_platform ?? '—'}</span>
            </div>
          </div>
        </section>

        {/* Remote Access – Phase 1 placeholders */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>Remote Access</div>
          <div className="flex gap-2">
            {(['RDP', 'SSH', 'SFTP'] as const).map((label) => (
              <button
                key={label}
                type="button"
                disabled
                title="Aktion deaktiviert (Phase 1)"
                className="px-3 py-1.5 rounded text-[11px] font-mono opacity-40 cursor-not-allowed"
                style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-muted-fg)', border: '1px solid var(--soc-border)' }}
              >
                {label}
              </button>
            ))}
          </div>
          <div className="text-[10px] mt-1.5" style={{ color: 'var(--soc-muted-fg)' }}>Remote actions disabled in Phase 1</div>
        </section>

        {/* MeshCentral */}
        <section>
          <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>MeshCentral</div>
          <div className="rounded p-3 space-y-2" style={{ background: 'var(--soc-sidebar-accent)' }}>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Node ID</span>
              <span className="font-mono text-[11px]">{host.mesh_node_id ?? '—'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span style={{ color: 'var(--soc-muted-fg)' }}>Status</span>
              <StatusBadge status={host.mesh_status} />
            </div>
            <button
              type="button"
              disabled={!host.mesh_node_id}
              title={host.mesh_node_id ? 'Open in MeshCentral' : 'No MeshCentral node linked'}
              className="px-3 py-1.5 rounded text-[11px] font-mono disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: 'var(--soc-primary)', color: 'oklch(0.98 0 0)' }}
            >
              Open in MeshCentral ↗
            </button>
          </div>
        </section>

        {/* Conflicts */}
        {conflicts.length > 0 && (
          <section>
            <div className="text-[10px] font-semibold uppercase tracking-widest mb-2" style={{ color: 'var(--soc-muted-fg)' }}>
              Conflicts ({conflicts.length})
            </div>
            <div className="space-y-2">
              {conflicts.map((c) => (
                <div key={c.id} className="rounded p-2.5" style={{ background: 'var(--soc-sidebar-accent)', borderLeft: `3px solid ${conflictSeverityColor(c.severity)}` }}>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px]" style={{ color: conflictSeverityColor(c.severity) }}>
                      {c.severity.toUpperCase()}
                    </span>
                    <span className="text-[10px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
                      {c.conflict_type}
                    </span>
                  </div>
                  <div className="text-[11px] mt-1">{c.description}</div>
                  {c.field_name && (
                    <div className="text-[10px] font-mono mt-1" style={{ color: 'var(--soc-muted-fg)' }}>
                      {c.field_name}: tactical={c.tactical_value ?? '—'} / wazuh={c.wazuh_value ?? '—'}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

// ── Filter bar ─────────────────────────────────────────────────────────────────

interface FilterState {
  identity: string;
  tactical: string;
  wazuh: string;
  search: string;
}

function defaultFilter(): FilterState {
  return { identity: 'all', tactical: 'all', wazuh: 'all', search: '' };
}

// ── Main page ──────────────────────────────────────────────────────────────────

interface Props {
  active?: boolean;
}

export function UnifiedHostsPage({ active }: Props) {
  const [hosts, setHosts] = useState<UnifiedHost[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [wazuhSyncing, setWazuhSyncing] = useState(false);
  const [recomputing, setRecomputing] = useState(false);
  const [syncResult, setSyncResult] = useState<WazuhSyncReport | null>(null);
  const [showSyncReport, setShowSyncReport] = useState(false);
  const [syncError, setSyncError] = useState<string | null>(null);
  const [health, setHealth] = useState<{ reachable: boolean; detail: string } | null>(null);
  const [selectedHost, setSelectedHost] = useState<UnifiedHost | null>(null);
  const [selectedConflicts, setSelectedConflicts] = useState<HostConflict[]>([]);
  const [filter, setFilter] = useState<FilterState>(defaultFilter);

  const fetchHosts = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getUnifiedHosts();
      setHosts(data);
    } catch {
      // fail silently — table might be empty
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchHealth = useCallback(async () => {
    try {
      const h = await getTacticalHealth();
      setHealth(h);
    } catch {
      setHealth({ reachable: false, detail: 'Backend unreachable' });
    }
  }, []);

  useEffect(() => {
    if (!active) return;
    void fetchHosts();
    void fetchHealth();
  }, [active, fetchHosts, fetchHealth]);

  async function handleSync() {
    setSyncing(true);
    setSyncError(null);
    try {
      await triggerTacticalSync();
      void fetchHosts();
      void fetchHealth();
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : 'Sync failed');
    } finally {
      setSyncing(false);
    }
  }

  async function handleWazuhSync() {
    setWazuhSyncing(true);
    setSyncResult(null);
    setSyncError(null);
    try {
      const result = await syncWazuhAgents();
      setSyncResult(result);
      setShowSyncReport(true);
      void fetchHosts();
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : 'Wazuh sync failed');
    } finally {
      setWazuhSyncing(false);
    }
  }

  async function handleRecompute() {
    setRecomputing(true);
    setSyncError(null);
    try {
      await recomputePolicies();
      void fetchHosts();
    } catch (e) {
      setSyncError(e instanceof Error ? e.message : 'Recompute failed');
    } finally {
      setRecomputing(false);
    }
  }

  async function handleSelectHost(host: UnifiedHost) {
    setSelectedHost(host);
    try {
      const conflicts = await getUnifiedHostConflicts(host.id);
      setSelectedConflicts(conflicts);
    } catch {
      setSelectedConflicts([]);
    }
  }

  // Apply filters
  const filtered = hosts.filter((h) => {
    if (filter.identity !== 'all' && h.identity_status !== filter.identity) return false;
    if (filter.tactical !== 'all' && h.tactical_status !== filter.tactical) return false;
    if (filter.wazuh !== 'all' && h.wazuh_status !== filter.wazuh) return false;
    if (filter.search) {
      const q = filter.search.toLowerCase();
      if (!h.display_name.toLowerCase().includes(q) && !(h.primary_ip ?? '').includes(q)) return false;
    }
    return true;
  });

  return (
    <div className="flex flex-col h-full overflow-hidden" style={{ color: 'var(--soc-foreground)' }}>
      {/* Top bar */}
      <div
        className="flex items-center gap-3 px-4 py-2 border-b shrink-0"
        style={{ background: 'var(--soc-panel)', borderColor: 'var(--soc-border)' }}
      >
        <Network size={16} style={{ color: 'var(--soc-primary)' }} />
        <span className="font-semibold text-sm">Unified Hosts</span>

        {/* Tactical health */}
        <div className="flex items-center gap-1.5 ml-2">
          {health === null ? (
            <span className="text-[11px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>Checking…</span>
          ) : health.reachable ? (
            <span className="flex items-center gap-1 text-[11px] font-mono" style={{ color: 'var(--soc-success)' }}>
              <CheckCircle size={12} /> Tactical RMM reachable
            </span>
          ) : (
            <span className="flex items-center gap-1 text-[11px] font-mono" style={{ color: 'var(--soc-critical)' }}>
              <XCircle size={12} /> Tactical RMM unreachable
            </span>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {syncResult && (
            <button
              type="button"
              onClick={() => setShowSyncReport(true)}
              className="flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded"
              style={{ color: 'var(--soc-muted-fg)', background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}
              title="View full sync report"
            >
              {syncResult.agents_total} agents · {syncResult.matched} matched · {syncResult.conflicts} conflicts · {syncResult.duration_ms}ms
              <ChevronRight size={10} />
            </button>
          )}
          {syncError && (
            <span className="text-[10px] font-mono" style={{ color: 'var(--soc-critical)' }}>
              <AlertTriangle size={11} className="inline mr-1" />{syncError}
            </span>
          )}
          <button
            type="button"
            onClick={() => void handleSync()}
            disabled={syncing || wazuhSyncing}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-[11px] font-mono disabled:opacity-50"
            style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-foreground)', border: '1px solid var(--soc-border)' }}
            title="Sync from Tactical RMM"
          >
            <RefreshCw size={12} className={syncing ? 'animate-spin' : ''} />
            {syncing ? 'Syncing…' : 'Tactical Sync'}
          </button>
          <button
            type="button"
            onClick={() => void handleWazuhSync()}
            disabled={wazuhSyncing || syncing}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-[11px] font-mono disabled:opacity-50"
            style={{ background: 'var(--soc-primary)', color: 'oklch(0.98 0 0)' }}
            title="Pull Wazuh Manager agents and match to unified hosts"
          >
            <RefreshCw size={12} className={wazuhSyncing ? 'animate-spin' : ''} />
            {wazuhSyncing ? 'Syncing Wazuh…' : 'Wazuh Sync'}
          </button>
          <button
            type="button"
            onClick={() => void handleRecompute()}
            disabled={recomputing || wazuhSyncing || syncing}
            className="flex items-center gap-1.5 px-3 py-1 rounded text-[11px] font-mono disabled:opacity-50"
            style={{ background: 'var(--soc-sidebar-accent)', color: 'var(--soc-foreground)', border: '1px solid var(--soc-border)' }}
            title="Recompute action_policy for all unified hosts based on current trust signals"
          >
            <Shield size={12} className={recomputing ? 'animate-spin' : ''} />
            {recomputing ? 'Recomputing…' : 'Recompute Policy'}
          </button>
        </div>
      </div>

      {/* Filter row */}
      <div
        className="flex items-center gap-3 px-4 py-2 border-b shrink-0 text-[11px]"
        style={{ background: 'var(--soc-panel)', borderColor: 'var(--soc-border)' }}
      >
        <input
          type="text"
          placeholder="Search hostname / IP…"
          value={filter.search}
          onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))}
          className="px-2 py-1 rounded font-mono text-[11px] w-44 outline-none"
          style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
        />
        {(['identity', 'tactical', 'wazuh'] as const).map((field) => (
          <select
            key={field}
            value={filter[field]}
            onChange={(e) => setFilter((f) => ({ ...f, [field]: e.target.value }))}
            className="px-2 py-1 rounded font-mono text-[11px] outline-none"
            style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)', color: 'var(--soc-foreground)' }}
          >
            <option value="all">{field}: all</option>
            {field === 'identity' && (
              <>
                <option value="trusted">trusted</option>
                <option value="likely">likely</option>
                <option value="uncertain">uncertain</option>
                <option value="unknown">unknown</option>
              </>
            )}
            {(field === 'tactical' || field === 'wazuh') && (
              <>
                <option value="online">online</option>
                <option value="offline">offline</option>
                <option value="unknown">unknown</option>
              </>
            )}
          </select>
        ))}
        <span className="ml-auto font-mono" style={{ color: 'var(--soc-muted-fg)' }}>
          {filtered.length} / {hosts.length} hosts
        </span>
      </div>

      {/* Status cards */}
      {hosts.length > 0 && (() => {
        const wazuhMatched = hosts.filter(h => h.wazuh_agent_id).length;
        const tacticalMatched = hosts.filter(h => h.tactical_agent_id).length;
        const conflicts = hosts.filter(h => (h.conflict_count ?? 0) > 0).length;
        const blocked = hosts.filter(h => h.action_policy === 'blocked').length;
        const unknownId = hosts.filter(h => h.identity_status === 'unknown').length;
        const cards = [
          { label: 'Wazuh matched', value: wazuhMatched, color: 'var(--soc-success)' },
          { label: 'Tactical matched', value: tacticalMatched, color: 'var(--soc-primary)' },
          { label: 'Conflicts', value: conflicts, color: 'var(--soc-warning)' },
          { label: 'Blocked', value: blocked, color: 'var(--soc-critical)' },
          { label: 'Unknown identity', value: unknownId, color: 'var(--soc-muted-fg)' },
        ];
        return (
          <div className="flex items-center gap-3 px-4 py-2 border-b shrink-0 flex-wrap" style={{ background: 'var(--soc-panel)', borderColor: 'var(--soc-border)' }}>
            {cards.map(c => (
              <div key={c.label} className="flex items-center gap-2 rounded px-2.5 py-1" style={{ background: 'var(--soc-sidebar-accent)', border: '1px solid var(--soc-border)' }}>
                <span className="font-mono font-bold text-[13px]" style={{ color: c.color }}>{c.value}</span>
                <span className="text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>{c.label}</span>
              </div>
            ))}
            <span className="ml-auto text-[10px] font-mono" style={{ color: 'var(--soc-muted-fg)' }}>{hosts.length} total hosts</span>
          </div>
        );
      })()}

      {/* Table */}
      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-sm" style={{ color: 'var(--soc-muted-fg)' }}>
            Loading…
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2 text-sm" style={{ color: 'var(--soc-muted-fg)' }}>
            <Shield size={24} />
            <span>No unified hosts. Run a sync to import Tactical RMM agents.</span>
          </div>
        ) : (
          <table className="w-full text-[12px] border-collapse">
            <thead>
              <tr style={{ background: 'var(--soc-panel)', borderBottom: '1px solid var(--soc-border)' }}>
                {['Hostname', 'OS', 'IP', 'Wazuh Agent', 'Wazuh', 'Tactical', 'Score', 'Identity', 'Match', 'Policy', 'Conflicts'].map((col) => (
                  <th
                    key={col}
                    className="text-left px-3 py-2 font-semibold text-[10px] uppercase tracking-wider"
                    style={{ color: 'var(--soc-muted-fg)' }}
                  >
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((host) => (
                <tr
                  key={host.id}
                  className="border-b cursor-pointer"
                  style={{ borderColor: 'var(--soc-border)' }}
                  onClick={() => void handleSelectHost(host)}
                  onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--soc-sidebar-accent)')}
                  onMouseLeave={(e) => (e.currentTarget.style.background = '')}
                >
                  <td className="px-3 py-2 font-mono font-semibold">{host.display_name}</td>
                  <td className="px-3 py-2 font-mono text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}>{host.os_platform ?? '—'}</td>
                  <td className="px-3 py-2 font-mono text-[10px]">{host.primary_ip ?? '—'}</td>
                  <td className="px-3 py-2 font-mono text-[10px]" title={host.wazuh_agent_id ? `Agent ID: ${host.wazuh_agent_id}` : 'No Wazuh agent linked'}
                    style={{ color: host.wazuh_agent_id ? 'var(--soc-foreground)' : 'var(--soc-muted-fg)' }}>
                    {host.wazuh_agent_id ?? '—'}
                  </td>
                  <td className="px-3 py-2"><StatusBadge status={host.wazuh_status} /></td>
                  <td className="px-3 py-2"><StatusBadge status={host.tactical_status} /></td>
                  <td className="px-3 py-2">
                    <span
                      className="font-mono font-bold text-[12px]"
                      style={{ color: identityColor(host.identity_status) }}
                    >
                      {host.match_score}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className="text-[10px] font-semibold"
                      style={{ color: identityColor(host.identity_status) }}
                      title={host.identity_reason ?? undefined}
                    >
                      {identityLabel(host.identity_status)}
                      {host.identity_reason && <span className="ml-1 opacity-50 text-[9px]">&#9432;</span>}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px]" style={{ color: 'var(--soc-muted-fg)' }}
                    title={host.match_source ?? ''}>
                    {(host.match_source ?? '').replace('wazuh_', '').replace('_', ' ') || '—'}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className="text-[10px]"
                      style={{ color: policyColor(host.action_policy) }}
                      title={host.policy_reason ?? undefined}
                    >
                      {policyLabel(host.action_policy)}
                      {host.policy_reason && <span className="ml-1 opacity-50 text-[9px]">&#9432;</span>}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    {(host.conflict_count ?? 0) > 0 ? (
                      <span className="flex items-center gap-1 text-[10px]" style={{ color: 'var(--soc-warning)' }}>
                        <AlertTriangle size={10} /> {host.conflict_count}
                      </span>
                    ) : (
                      <span style={{ color: 'var(--soc-muted-fg)' }}>—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail panel modal */}
      {selectedHost && (
        <HostDetailPanel
          host={selectedHost}
          conflicts={selectedConflicts}
          onClose={() => setSelectedHost(null)}
        />
      )}

      {/* Wazuh Sync Report modal */}
      {showSyncReport && syncResult && (
        <WazuhSyncReportModal report={syncResult} onClose={() => setShowSyncReport(false)} />
      )}
    </div>
  );
}
