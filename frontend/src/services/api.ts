import type { AIServiceStatus, AIServiceTestResult, AnalysisJob, AnalysisProfileConfig, AuditEntry, BaselineDeviation, BaselineDiff, BaselineFeature, BaselineSnapshot, BaselineSummary, ChatMessage, ChatResponse, ClusterEvidenceSummary, ClusterEvaluation, ClusterExplanation, ClusterKnowledge, ClusterPlaybook, Connection, ConnectionTestResult, FindingGroup, HealthResponse, HostCentralDetail, HostCentralListItem, HostConflict, HostOverview, HostProfile, HostProfileAssignment, HostRanking, HostTrendPoint, NormalisedActionPolicy, RawPreview, Report, ResolvedUnifiedHost, RunAnalysisPayload, ScriptEntry, SnipenAIQueryResult, SnipenAnalysisResult, SnipenEvent, SnipenExplainResult, SnipenHostInfo, SnipenHostOverview, TacticalAgent, TacticalSyncResult, TimelineItem, UnifiedEventEvaluation, UnifiedHost, WazuhAgent, WazuhAgentEnrichment, WazuhAPICapabilitiesResult, WazuhManagerHealth, WazuhSyncReport, ServerConnection, ServerConnectionInput, ServerActionResult, ServerActivityLog, RemoteSession, LegacyImportReport, PingResult, DnsResult, PortCheckResult, SshReadOnlyCommandResult, SshFileBrowserResult, SshHostInfoResult, SshHealthResult, SshReadOnlyCommand, WolResult, LegacyServerFeatureResponse, SshConfigExportResult, ServerHostGroup, ServerHostGroupMember, ServerBatchRun, ServerBatchResult, ServerBatchHealthRequest, ServerBatchHealthResponse } from '../types';

// Alias for the agent context embedded in cluster responses
export type WazuhAgentContextResult = WazuhAgentEnrichment;

const isDesktopShell =
  window.location.protocol === 'tauri:' ||
  window.location.hostname === 'tauri.localhost' ||
  navigator.userAgent.includes('Tauri');

const API_BASE = isDesktopShell ? 'http://127.0.0.1:8000' : '/api';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json'
    },
    ...init
  });

  if (!response.ok) {
    const text = await response.text();
    // Try to extract a human-readable message from a FastAPI {detail: ...} response
    let message = text || `Request failed with status ${response.status}`;
    try {
      const parsed = JSON.parse(text) as Record<string, unknown>;
      if (typeof parsed.detail === 'string') message = parsed.detail;
      else if (Array.isArray(parsed.detail)) message = parsed.detail.map((d: unknown) => (d as Record<string,unknown>)?.msg ?? String(d)).join('; ');
    } catch { /* leave message as raw text */ }
    throw new Error(message);
  }

  return response.json() as Promise<T>;
}

export function getActiveConnection(): Promise<Connection> {
  return request<Connection>('/connections/active');
}

export function saveConnection(connection: Connection): Promise<Connection> {
  if (connection.id) {
    return request<Connection>(`/connections/${connection.id}`, {
      method: 'PUT',
      body: JSON.stringify(connection)
    });
  }

  return request<Connection>('/connections', {
    method: 'POST',
    body: JSON.stringify(connection)
  });
}

export function testConnection(connection: Connection): Promise<ConnectionTestResult> {
  return request('/connections/test', {
    method: 'POST',
    body: JSON.stringify(connection)
  });
}

export function getJobs(): Promise<AnalysisJob[]> {
  return request<AnalysisJob[]>('/analysis/jobs');
}

export function getJob(jobId: number): Promise<AnalysisJob> {
  return request<AnalysisJob>(`/analysis/jobs/${jobId}`);
}

export function runAnalysis(payload: RunAnalysisPayload): Promise<AnalysisJob> {
  return request<AnalysisJob>('/analysis/run', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function getFindings(jobId: number): Promise<FindingGroup[]> {
  return request<FindingGroup[]>(`/analysis/jobs/${jobId}/findings`);
}

export function getHostRanking(jobId?: number): Promise<HostRanking[]> {
  const query = jobId ? `?job_id=${jobId}` : '';
  return request<HostRanking[]>(`/hosts/ranking${query}`);
}

export function getReports(): Promise<Report[]> {
  return request<Report[]>('/reports');
}

export function getBackendHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health');
}

export function getLatestReport(): Promise<Report> {
  return request<Report>('/reports/latest');
}

export function getIndexerHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health/indexer');
}

export function getOllamaHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health/ollama');
}

export function getAIServiceStatus(): Promise<AIServiceStatus> {
  return request<AIServiceStatus>('/system/ai');
}

export function startAIService(): Promise<AIServiceStatus> {
  return request<AIServiceStatus>('/system/ai/start', { method: 'POST' });
}

export function stopAIService(): Promise<AIServiceStatus> {
  return request<AIServiceStatus>('/system/ai/stop', { method: 'POST' });
}

export function testAIServiceGenerate(): Promise<AIServiceTestResult> {
  return request<AIServiceTestResult>('/system/ai/test', { method: 'POST' });
}

export function sendChatMessage(payload: {
  message: string;
  run_script: boolean;
  lookback_hours?: number;
  history: ChatMessage[];
  report_context?: string | null;
  report_json_content?: string | null;
  analysis_profile?: AnalysisProfileConfig | null;
}): Promise<ChatResponse> {
  return request<ChatResponse>('/system/chat', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function getAnalysisProfile(): Promise<AnalysisProfileConfig> {
  return request<AnalysisProfileConfig>('/system/analysis-profile');
}

export function saveAnalysisProfile(payload: AnalysisProfileConfig): Promise<AnalysisProfileConfig> {
  return request<AnalysisProfileConfig>('/system/analysis-profile', {
    method: 'PUT',
    body: JSON.stringify(payload)
  });
}

export function getHostOverview(host: string): Promise<HostOverview> {
  return request<HostOverview>(`/hosts/${encodeURIComponent(host)}/overview`);
}

export function getHostTrend(host: string, limit = 14): Promise<HostTrendPoint[]> {
  return request<HostTrendPoint[]>(`/hosts/${encodeURIComponent(host)}/trend?limit=${limit}`);
}

export function getHostsCentral(hours = 24): Promise<HostCentralListItem[]> {
  return request<HostCentralListItem[]>(`/hosts/central?hours=${hours}`);
}

export function getHostCentralDetail(host: string, hours = 168, limit = 250): Promise<HostCentralDetail> {
  return request<HostCentralDetail>(`/hosts/${encodeURIComponent(host)}/central?hours=${hours}&limit=${limit}`);
}

// ── Snipen / Threat Hunting API ───────────────────────────────────────────────

export function getSnipenHosts(hours = 24): Promise<SnipenHostInfo[]> {
  return request<SnipenHostInfo[]>(`/snipen/hosts?hours=${hours}`);
}

export function getSnipenAllEvents(params: {
  hours?: number;
  limit?: number;
  min_rule_level?: number | null;
  category?: string | null;
} = {}): Promise<SnipenEvent[]> {
  const q = new URLSearchParams();
  if (params.hours != null) q.set('hours', String(params.hours));
  if (params.limit != null) q.set('limit', String(params.limit));
  if (params.min_rule_level != null) q.set('min_rule_level', String(params.min_rule_level));
  if (params.category) q.set('category', params.category);
  return request<SnipenEvent[]>(`/snipen/events?${q.toString()}`);
}

export function getSnipenHostEvents(
  host: string,
  params: {
    hours?: number;
    limit?: number;
    platform?: string | null;
    min_rule_level?: number | null;
    category?: string | null;
    event_ids?: string | null;
  } = {}
): Promise<SnipenEvent[]> {
  const q = new URLSearchParams();
  if (params.hours != null) q.set('hours', String(params.hours));
  if (params.limit != null) q.set('limit', String(params.limit));
  if (params.platform) q.set('platform', params.platform);
  if (params.min_rule_level != null) q.set('min_rule_level', String(params.min_rule_level));
  if (params.category) q.set('category', params.category);
  if (params.event_ids) q.set('event_ids', params.event_ids);
  return request<SnipenEvent[]>(`/snipen/host/${encodeURIComponent(host)}/events?${q.toString()}`);
}

export function analyzeSnipenHost(
  host: string,
  payload: { hours: number; limit: number; windows_only: boolean; linux_only: boolean; include_noise: boolean; run_ai: boolean }
): Promise<SnipenAnalysisResult> {
  return request<SnipenAnalysisResult>(`/snipen/host/${encodeURIComponent(host)}/analyze`, {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function explainSnipenEvent(event_raw: Record<string, unknown>): Promise<SnipenExplainResult> {
  return request<SnipenExplainResult>('/snipen/event/explain', {
    method: 'POST',
    body: JSON.stringify({ event_raw })
  });
}

export function explainSnipenEventWithContext(event_raw: Record<string, unknown>): Promise<SnipenExplainResult> {
  return request<SnipenExplainResult>('/snipen/event/explain-context', {
    method: 'POST',
    body: JSON.stringify({ event_raw })
  });
}

export function remediateSnipenEvent(event_raw: Record<string, unknown>): Promise<SnipenExplainResult> {
  return request<SnipenExplainResult>('/snipen/event/remediate', {
    method: 'POST',
    body: JSON.stringify({ event_raw })
  });
}
export function getRelatedSnipenEvents(
  event_raw: Record<string, unknown>,
  limit = 20,
  hours = 24
): Promise<SnipenEvent[]> {
  return request<SnipenEvent[]>('/snipen/event/related', {
    method: 'POST',
    body: JSON.stringify({ event_raw, limit, hours })
  });
}

export function aiQuerySnipen(
  host: string,
  query: string,
  hours = 24,
  limit = 100
): Promise<SnipenAIQueryResult> {
  return request<SnipenAIQueryResult>(`/snipen/host/${encodeURIComponent(host)}/ai-query`, {
    method: 'POST',
    body: JSON.stringify({ query, hours, limit })
  });
}

export function getSnipenHostOverview(
  host: string,
  params: { hours?: number; limit?: number; buckets?: number } = {}
): Promise<SnipenHostOverview> {
  const q = new URLSearchParams();
  if (params.hours != null) q.set('hours', String(params.hours));
  if (params.limit != null) q.set('limit', String(params.limit));
  if (params.buckets != null) q.set('buckets', String(params.buckets));
  return request<SnipenHostOverview>(`/snipen/host/${encodeURIComponent(host)}/overview?${q.toString()}`);
}

// ── Host Profile API ──────────────────────────────────────────────────────────

export function getProfiles(): Promise<HostProfile[]> {
  return request<HostProfile[]>('/profiles');
}

export function getAllProfileAssignments(): Promise<HostProfileAssignment[]> {
  return request<HostProfileAssignment[]>('/profiles/assignments/all');
}

export function getHostProfileAssignment(host: string): Promise<HostProfileAssignment> {
  return request<HostProfileAssignment>(`/profiles/assignments/host/${encodeURIComponent(host)}`);
}

export function setHostProfileAssignment(
  host: string,
  profile_id: number,
  notes?: string
): Promise<HostProfileAssignment> {
  return request<HostProfileAssignment>(`/profiles/assignments/host/${encodeURIComponent(host)}`, {
    method: 'PUT',
    body: JSON.stringify({ profile_id, assigned_by: 'user', notes: notes ?? null })
  });
}

export function removeHostProfileAssignment(host: string): Promise<void> {
  return request<void>(`/profiles/assignments/host/${encodeURIComponent(host)}`, {
    method: 'DELETE'
  });
}

// ── Baseline ──────────────────────────────────────────────────────────────────

export function computeBaseline(host: string, windowHours = 168): Promise<BaselineSnapshot> {
  return request<BaselineSnapshot>(`/baseline/${encodeURIComponent(host)}/compute`, {
    method: 'POST',
    body: JSON.stringify({ window_hours: windowHours })
  });
}

export function getBaselineLatest(host: string): Promise<BaselineSnapshot> {
  return request<BaselineSnapshot>(`/baseline/${encodeURIComponent(host)}/latest`);
}

export function getBaselineHistory(host: string, limit = 10): Promise<BaselineSnapshot[]> {
  return request<BaselineSnapshot[]>(`/baseline/${encodeURIComponent(host)}/history?limit=${limit}`);
}

export function getBaselineSummary(host: string): Promise<BaselineSummary> {
  return request<BaselineSummary>(`/baseline/${encodeURIComponent(host)}/summary`);
}

export function getBaselineFeatures(host: string, featureType?: string): Promise<BaselineFeature[]> {
  const qs = featureType ? `?feature_type=${encodeURIComponent(featureType)}` : '';
  return request<BaselineFeature[]>(`/baseline/${encodeURIComponent(host)}/features${qs}`);
}

export function getBaselineDeviations(host: string, unresolvedOnly = true): Promise<BaselineDeviation[]> {
  return request<BaselineDeviation[]>(
    `/baseline/${encodeURIComponent(host)}/deviations?unresolved_only=${unresolvedOnly}`
  );
}

export function resolveDeviation(deviationId: number): Promise<{ status: string }> {
  return request<{ status: string }>(`/baseline/deviations/${deviationId}/resolve`, {
    method: 'POST'
  });
}

export function getBaselineDiff(host: string): Promise<BaselineDiff> {
  return request<BaselineDiff>(`/baseline/${encodeURIComponent(host)}/diff`);
}

export function getGlobalBaselineDeviations(unresolvedOnly = true, limit = 200, classification?: string): Promise<BaselineDeviation[]> {
  const params = new URLSearchParams({ unresolved_only: String(unresolvedOnly), limit: String(limit) });
  if (classification) params.set('classification', classification);
  return request<BaselineDeviation[]>(`/baseline/global/deviations?${params}`);
}

export function getGlobalBaselineSummary(): Promise<{
  total: number; open: number; critical: number; suspicious: number;
  needs_investigation: number; escalated: number;
  by_classification: Record<string, number>;
  top_hosts: Array<{ host: string; open_devs: number; top_score: number }>;
  by_type: Record<string, number>;
}> {
  return request('/baseline/global/summary');
}

// ── Tactical RMM ─────────────────────────────────────────────────────────────

export function getTacticalHealth(): Promise<{ reachable: boolean; detail: string }> {
  return request<{ reachable: boolean; detail: string }>('/integrations/tactical/health');
}

export function getTacticalAgents(): Promise<TacticalAgent[]> {
  return request<TacticalAgent[]>('/integrations/tactical/agents');
}

export function triggerTacticalSync(): Promise<TacticalSyncResult> {
  return request<TacticalSyncResult>('/integrations/tactical/sync', { method: 'POST' });
}

export function syncWazuhAgents(): Promise<WazuhSyncReport> {
  return request<WazuhSyncReport>('/wazuh-manager/sync-agents', { method: 'POST' });
}

export function recomputePolicies(): Promise<{ status: string; updated: number; blocked: number; review_required: number; duration_ms: number }> {
  return request('/wazuh-manager/recompute-policies', { method: 'POST' });
}

// ── Unified Hosts ─────────────────────────────────────────────────────────────

export function getUnifiedHosts(): Promise<UnifiedHost[]> {
  return request<UnifiedHost[]>('/unified-hosts');
}

export function getUnifiedHost(id: number): Promise<UnifiedHost> {
  return request<UnifiedHost>(`/unified-hosts/${id}`);
}

export function getUnifiedHostConflicts(id: number): Promise<HostConflict[]> {
  return request<HostConflict[]>(`/unified-hosts/${id}/conflicts`);
}

// ── Constellation / Event Map ─────────────────────────────────────────────────

export interface ConstellationEventRaw {
  id: string;
  timestamp: string;
  agentName: string;
  agentId: string;
  agentIp: string | null;
  ruleId: string;
  ruleLevel: number;
  ruleDescription: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  eventId: string | null;
  mitreTactic: string | null;
  mitreId: string | null;
  srcIp: string | null;
  user: string | null;
  process: string | null;
  count: number;
  explanation: string | null;
}

export function getConstellationEvents(params: {
  host?: string;
  lookbackHours: number;
  limit?: number;
}): Promise<ConstellationEventRaw[]> {
  const qs = new URLSearchParams();
  qs.set('lookback_hours', String(params.lookbackHours));
  if (params.limit !== undefined) qs.set('limit', String(params.limit));
  if (params.host) qs.set('host', params.host);
  return request<ConstellationEventRaw[]>(`/constellation/events?${qs.toString()}`);
}

// ── Event Map Live Clusters ───────────────────────────────────────────────────

export interface LiveEventCluster {
  id: string;
  kind: 'event_id' | 'rule' | 'mitre_tactic' | 'finding_type';
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  alertCount: number;
  affectedHostCount: number;
  affectedHosts: { hostname: string; agentId?: string; ip?: string; count: number; risk?: number }[];
  users: { name: string; count: number }[];
  processes: { name: string; count: number }[];
  sourceIps: { ip: string; count: number }[];
  ruleIds: string[];
  eventIds: string[];
  mitreTactics: string[];
  mitreIds: string[];
  firstSeen: string;
  lastSeen: string;
  shortExplanation: string;
  recommendedActions: string[];
  // ── Enrichment fields (Phase 2+) ──────────────────────────────────────────
  knowledge?: ClusterKnowledge | null;
  evidence_summary?: ClusterEvidenceSummary;
  playbooks?: ClusterPlaybook[];
  rawPreview?: RawPreview | null;
  // ── Baseline-aware evaluation ─────────────────────────────────────────────
  evaluation?: ClusterEvaluation | null;  // ── Phase 3: unified deterministic pipeline ───────────────────────────
  explanation?:        ClusterExplanation | null;
  unified_evaluation?: UnifiedEventEvaluation | null;
  // ── Wazuh Agent Context ────────────────────────────────────────────────
  wazuh_agent_context?: WazuhAgentContextResult | null;
}

export function getLiveEventClusters(params: {
  lookbackHours: number;
  host?: string;
  limit?: number;
}): Promise<LiveEventCluster[]> {
  const qs = new URLSearchParams({ lookback_hours: String(params.lookbackHours) });
  if (params.host) qs.set('host', params.host);
  if (params.limit != null) qs.set('limit', String(params.limit));
  return request<LiveEventCluster[]>(`/event-map/live?${qs.toString()}`);
}

// ── Unified Host Resolver ─────────────────────────────────────────────────────

export function resolveUnifiedHost(params: {
  hostname?: string;
  agent_id?: string;
  ip?: string;
}): Promise<ResolvedUnifiedHost> {
  const qs = new URLSearchParams();
  if (params.hostname) qs.set('hostname', params.hostname);
  if (params.agent_id) qs.set('agent_id', params.agent_id);
  if (params.ip) qs.set('ip', params.ip);
  return request<ResolvedUnifiedHost>(`/unified-hosts/resolve?${qs.toString()}`);
}

// ── Timeline ──────────────────────────────────────────────────────────────────

export function getTimelineEvents(params: {
  host?: string;
  agent_id?: string;
  user?: string;
  source_ip?: string;
  event_id?: string;
  rule_id?: string;
  from_time?: string;
  to_time?: string;
  minutes_before?: number;
  minutes_after?: number;
  limit?: number;
}): Promise<TimelineItem[]> {
  const qs = new URLSearchParams();
  if (params.host) qs.set('host', params.host);
  if (params.agent_id) qs.set('agent_id', params.agent_id);
  if (params.user) qs.set('user', params.user);
  if (params.source_ip) qs.set('source_ip', params.source_ip);
  if (params.event_id) qs.set('event_id', params.event_id);
  if (params.rule_id) qs.set('rule_id', params.rule_id);
  if (params.from_time) qs.set('from_time', params.from_time);
  if (params.to_time) qs.set('to_time', params.to_time);
  if (params.minutes_before != null) qs.set('minutes_before', String(params.minutes_before));
  if (params.minutes_after != null) qs.set('minutes_after', String(params.minutes_after));
  if (params.limit != null) qs.set('limit', String(params.limit));
  return request<TimelineItem[]>(`/timeline/events?${qs.toString()}`);
}

// ── Script Library ────────────────────────────────────────────────────────────

export function getScripts(params?: {
  platform?: string;
  category?: string;
  dangerous?: boolean;
  enabled?: boolean;
  search?: string;
}): Promise<ScriptEntry[]> {
  const qs = new URLSearchParams();
  if (params?.platform) qs.set('platform', params.platform);
  if (params?.category) qs.set('category', params.category);
  if (params?.dangerous != null) qs.set('dangerous', String(params.dangerous));
  if (params?.enabled != null) qs.set('enabled', String(params.enabled));
  if (params?.search) qs.set('search', params.search);
  const q = qs.toString();
  return request<ScriptEntry[]>(`/scripts${q ? '?' + q : ''}`);
}

export function getScript(scriptId: string): Promise<ScriptEntry> {
  return request<ScriptEntry>(`/scripts/${encodeURIComponent(scriptId)}`);
}

export function createScript(payload: Partial<ScriptEntry>): Promise<ScriptEntry> {
  return request<ScriptEntry>('/scripts', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

export function updateScript(scriptId: string, payload: Partial<ScriptEntry>): Promise<ScriptEntry> {
  return request<ScriptEntry>(`/scripts/${encodeURIComponent(scriptId)}`, {
    method: 'PUT',
    body: JSON.stringify(payload)
  });
}

export function deleteScript(scriptId: string): Promise<{ status: string; script_id: string }> {
  return request(`/scripts/${encodeURIComponent(scriptId)}`, { method: 'DELETE' });
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

export function getAuditActions(params?: {
  action_type?: string;
  host?: string;
  limit?: number;
}): Promise<AuditEntry[]> {
  const qs = new URLSearchParams();
  if (params?.action_type) qs.set('action_type', params.action_type);
  if (params?.host) qs.set('host', params.host);
  if (params?.limit != null) qs.set('limit', String(params.limit));
  const q = qs.toString();
  return request<AuditEntry[]>(`/audit/actions${q ? '?' + q : ''}`);
}

export function logAuditAction(payload: {
  action_type: string;
  source_page?: string;
  host?: string;
  user?: string;
  unified_host_id?: number;
  wazuh_agent_id?: string;
  tactical_agent_id?: string;
  source_event_id?: string;
  source_rule_id?: string;
  action_policy?: string;
  policy_reason?: string;
  details_json?: Record<string, unknown>;
}): Promise<{ status: string; id: number }> {
  return request('/audit/actions', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
}

// ── Action Policy helper ──────────────────────────────────────────────────────

export function getActionPolicyFromUnifiedHost(
  host: { identity_status?: string; action_policy?: string } | null,
  conflicts?: { conflict_type?: string; severity?: string; resolved?: number; is_active?: number }[]
): NormalisedActionPolicy {
  if (!host) {
    return {
      policy: 'blocked',
      reason: 'Host not resolved in SSOT. Wazuh event host could not be mapped to a Unified Host.',
      dangerous_actions_enabled: false,
      read_only_actions_enabled: false,
    };
  }
  const identity = host.identity_status ?? 'unknown';
  const hasBlockingConflict = (conflicts ?? []).some(
    c => !c.resolved && c.is_active && (c.severity === 'critical' || c.conflict_type === 'os_mismatch' || c.conflict_type === 'duplicate_ip')
  );
  if (hasBlockingConflict) {
    return { policy: 'blocked', reason: 'Active critical conflict blocks action.', dangerous_actions_enabled: false, read_only_actions_enabled: false };
  }
  if (identity === 'unknown' || identity === 'uncertain') {
    return { policy: 'blocked', reason: `Host identity is '${identity}'. Cannot confirm host before acting.`, dangerous_actions_enabled: false, read_only_actions_enabled: false };
  }
  if (identity === 'likely') {
    return { policy: 'review_required', reason: "Host matched with 'likely' confidence. Manual review required.", dangerous_actions_enabled: false, read_only_actions_enabled: true };
  }
  if (identity === 'trusted') {
    return { policy: 'review_required', reason: 'Host is trusted. Dangerous actions disabled in Phase 1.', dangerous_actions_enabled: false, read_only_actions_enabled: true };
  }
  const rawPolicy = host.action_policy ?? 'read_only';
  if (rawPolicy === 'blocked') {
    return { policy: 'blocked', reason: 'Host action policy is explicitly blocked.', dangerous_actions_enabled: false, read_only_actions_enabled: false };
  }
  return { policy: 'review_required', reason: 'Host is in read-only / review mode.', dangerous_actions_enabled: false, read_only_actions_enabled: true };
}

// ── Trust Center / Validation ─────────────────────────────────────────────────

export function getValidationStatus(): Promise<import('../types').ValidationStatus> {
  return request<import('../types').ValidationStatus>('/validation/status');
}

// ── Wazuh Manager API ─────────────────────────────────────────────────────────

export interface WazuhPingStep {
  step: 'config' | 'dns' | 'tcp' | 'http' | 'auth';
  ok: boolean;
  detail: string;
  duration_ms: number;
}

export function getWazuhManagerHealth(): Promise<WazuhManagerHealth> {
  return request<WazuhManagerHealth>('/wazuh-manager/health');
}

export function getWazuhManagerPing(): Promise<{ configured: boolean; steps: WazuhPingStep[] }> {
  return request('/wazuh-manager/ping');
}

export function getWazuhAgents(params?: { limit?: number; offset?: number; status?: string }): Promise<{ data: { affected_items: WazuhAgent[]; total_affected_items: number } }> {
  const q = new URLSearchParams();
  if (params?.limit != null) q.set('limit', String(params.limit));
  if (params?.offset != null) q.set('offset', String(params.offset));
  if (params?.status) q.set('status', params.status);
  const qs = q.toString();
  return request<{ data: { affected_items: WazuhAgent[]; total_affected_items: number } }>(`/wazuh-manager/agents${qs ? '?' + qs : ''}`);
}

export function getWazuhAgentsSummary(): Promise<{ status: unknown; os: unknown }> {
  return request<{ status: unknown; os: unknown }>('/wazuh-manager/agents/summary');
}

export function getWazuhAgent(agentId: string): Promise<{ data: { affected_items: WazuhAgent[] } }> {
  return request<{ data: { affected_items: WazuhAgent[] } }>(`/wazuh-manager/agents/${agentId}`);
}

export function getWazuhAgentEnrichment(agentId: string, agentName?: string): Promise<WazuhAgentEnrichment> {
  const q = agentName ? `?agent_name=${encodeURIComponent(agentName)}` : '';
  return request<WazuhAgentEnrichment>(`/wazuh-manager/agents/${agentId}/enrich${q}`);
}

export function getWazuhSyscollectorOS(agentId: string): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/os`);
}

export function getWazuhSyscollectorHardware(agentId: string): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/hardware`);
}

export function getWazuhSyscollectorPackages(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/packages?limit=${limit}`);
}

export function getWazuhSyscollectorPorts(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/ports?limit=${limit}`);
}

export function getWazuhSyscollectorProcesses(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/processes?limit=${limit}`);
}

export function getWazuhSyscollectorServices(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscollector/services?limit=${limit}`);
}

export function getWazuhSCAResults(agentId: string): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/sca`);
}

export function getWazuhSCAChecks(agentId: string, policyId: string, limit = 100, result?: string): Promise<unknown> {
  const q = new URLSearchParams({ limit: String(limit) });
  if (result) q.set('result', result);
  return request<unknown>(`/wazuh-manager/agents/${agentId}/sca/${encodeURIComponent(policyId)}/checks?${q}`);
}

export function getWazuhSyscheckLastScan(agentId: string): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscheck/last-scan`);
}

export function getWazuhSyscheckResults(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/syscheck/results?limit=${limit}`);
}

export function getWazuhRootcheckLastScan(agentId: string): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/rootcheck/last-scan`);
}

export function getWazuhRootcheckResults(agentId: string, limit = 100): Promise<unknown> {
  return request<unknown>(`/wazuh-manager/agents/${agentId}/rootcheck/results?limit=${limit}`);
}

export function getAgentRecentAlerts(agentId: string, agentName?: string, lookbackHours = 24, limit = 50): Promise<{
  agent_id: string; agent_name: string;
  alerts: Array<{ timestamp: string | null; rule_id: string | null; rule_level: number; severity: string; description: string | null; agent_name: string | null; event_id: string | null; mitre_tactic: string | null; mitre_id: string | null }>;
  total: number;
}> {
  const q = new URLSearchParams({ lookback_hours: String(lookbackHours), limit: String(limit) });
  if (agentName) q.set('agent_name', agentName);
  return request(`/wazuh-manager/agents/${agentId}/recent-alerts?${q}`);
}

export function getWazuhCapabilities(params?: { safety?: string; tag?: string }): Promise<WazuhAPICapabilitiesResult> {
  const q = new URLSearchParams();
  if (params?.safety) q.set('safety', params.safety);
  if (params?.tag) q.set('tag', params.tag);
  const qs = q.toString();
  return request<WazuhAPICapabilitiesResult>(`/wazuh-manager/capabilities${qs ? '?' + qs : ''}`);
}

export function runWazuhLogtest(body: { log_format?: string; location?: string; event: string }): Promise<unknown> {
  return request<unknown>('/wazuh-manager/logtest', { method: 'POST', body: JSON.stringify(body) });
}

export function getWazuhPermissions(): Promise<import('../types').WazuhPermissionsResult> {
  return request('/wazuh-manager/permissions');
}

export function getWazuhRecipes(): Promise<{ recipes: import('../types').WazuhAPIRecipe[] }> {
  return request('/wazuh-manager/recipes');
}

export function getWazuhDocSections(): Promise<{ sections: import('../types').WazuhAPIDocSection[] }> {
  return request('/wazuh-manager/docs/sections');
}

export function getWazuhAgentsFiltered(params: {
  limit?: number;
  offset?: number;
  status?: string;
  os_platform?: string;
  group?: string;
  name_contains?: string;
  search?: string;
  q?: string;
}): Promise<{ data: { affected_items: import('../types').WazuhAgent[]; total_affected_items: number } }> {
  const qs = new URLSearchParams();
  if (params.limit)        qs.set('limit', String(params.limit));
  if (params.offset)       qs.set('offset', String(params.offset));
  if (params.status)       qs.set('status', params.status);
  if (params.os_platform)  qs.set('os_platform', params.os_platform);
  if (params.group)        qs.set('group', params.group);
  if (params.name_contains) qs.set('name_contains', params.name_contains);
  if (params.search)       qs.set('search', params.search);
  if (params.q)            qs.set('q', params.q);
  const s = qs.toString();
  return request(`/wazuh-manager/agents${s ? '?' + s : ''}`);
}

export type WazuhReconnectResult = {
  status: 'ok' | 'blocked' | 'denied' | 'error';
  agent_id: string;
  action: string;
  policy: string;
  policy_reason: string | null;
  message: string | null;
  wazuh_response: {
    ok: boolean;
    error_code: number | null;
    message: string | null;
    affected_items: unknown[];
    total_affected_items: number;
    failed_items: unknown[];
    total_failed_items: number;
  } | null;
  audit_id_requested: number | null;
  audit_id_completed: number | null;
};

export function reconnectWazuhAgent(
  agentId: string,
  body?: { wait_for_complete?: boolean; reason?: string; agent_name?: string; source_page?: string },
): Promise<WazuhReconnectResult> {
  return request<WazuhReconnectResult>(
    `/wazuh-manager/agents/${encodeURIComponent(agentId)}/reconnect`,
    { method: 'POST', body: JSON.stringify(body ?? {}) },
  );
}

// ── Local Runner ──────────────────────────────────────────────────────────────

export interface FetchWazuhEventsResult {
  status: string;
  events_fetched: number;
  file_path: string;
  file_size_kb: number;
  agents: string[];
  agent_count: number;
  earliest: string | null;
  latest: string | null;
  parameters_used: { hours: number; limit: number; host_filter: string | null };
}

export function runFetchWazuhEvents(params: {
  hours: number;
  limit: number;
  host_filter?: string | null;
}): Promise<FetchWazuhEventsResult> {
  return request<FetchWazuhEventsResult>('/runner/fetch-wazuh-events', {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

export interface HostFetchResult {
  host: string;
  events_fetched: number;
  file_path: string;
  file_size_kb: number;
  status: string;
  error: string | null;
}

export interface FetchEventsPerHostResult {
  status: string;
  hosts_processed: number;
  total_events: number;
  results: HostFetchResult[];
  output_folder: string;
  timestamp: string;
}

export function runFetchEventsPerHost(params: {
  hours: number;
  limit_per_host: number;
}): Promise<FetchEventsPerHostResult> {
  return request<FetchEventsPerHostResult>('/runner/fetch-events-per-host', {
    method: 'POST',
    body: JSON.stringify(params),
  });
}

// ── Server / Remote Access ────────────────────────────────────────────

type ListConnectionsParams = {
  protocol?: string;
  tag?: string;
  search?: string;
  favorite_only?: boolean;
};

export function getServerConnections(params?: ListConnectionsParams): Promise<{ status: string; count: number; data: ServerConnection[] }> {
  const q = new URLSearchParams();
  if (params?.protocol) q.set('protocol', params.protocol);
  if (params?.tag) q.set('tag', params.tag);
  if (params?.search) q.set('search', params.search);
  if (params?.favorite_only) q.set('favorite_only', 'true');
  const qs = q.toString();
  return request(`/server/connections${qs ? `?${qs}` : ''}`);
}

export function createServerConnection(data: ServerConnectionInput): Promise<ServerActionResult> {
  return request('/server/connections', { method: 'POST', body: JSON.stringify(data) });
}

export function updateServerConnection(id: string, data: Partial<ServerConnectionInput>): Promise<ServerActionResult> {
  return request(`/server/connections/${id}`, { method: 'PUT', body: JSON.stringify(data) });
}

export function deleteServerConnection(id: string): Promise<ServerActionResult> {
  return request(`/server/connections/${id}`, { method: 'DELETE' });
}

export function importLegacyServerConnections(payload: { format: 'json' | 'csv'; data: string; auto_link?: boolean }): Promise<{ status: string; data: LegacyImportReport; audit_id: string }> {
  return request('/server/import/legacy', { method: 'POST', body: JSON.stringify(payload) });
}

export function testServerConnection(id: string): Promise<ServerActionResult> {
  return request(`/server/connections/${id}/test`, { method: 'POST' });
}

export function pingServerConnection(id: string): Promise<ServerActionResult & { data: PingResult }> {
  return request(`/server/connections/${id}/ping`, { method: 'POST' });
}

export function dnsServerConnection(id: string): Promise<ServerActionResult & { data: DnsResult }> {
  return request(`/server/connections/${id}/dns`, { method: 'POST' });
}

export function portCheckServerConnection(id: string, ports?: number[]): Promise<ServerActionResult & { data: PortCheckResult }> {
  return request(`/server/connections/${id}/ports`, { method: 'POST', body: JSON.stringify({ ports: ports ?? [22, 80, 443, 3389, 5985] }) });
}

export function healthCheckServerConnection(id: string): Promise<ServerActionResult & { data: SshHealthResult }> {
  return request(`/server/connections/${id}/health`, { method: 'POST' });
}

export function sshHostInfo(id: string): Promise<ServerActionResult & { data: SshHostInfoResult }> {
  return request(`/server/connections/${id}/ssh/host-info`, { method: 'POST' });
}

export function sshRunReadOnlyCommand(id: string, command_id: string): Promise<ServerActionResult & { data: SshReadOnlyCommandResult }> {
  return request(`/server/connections/${id}/ssh/read-only-command`, { method: 'POST', body: JSON.stringify({ command_id }) });
}

export function sshFileList(id: string, path = '/'): Promise<ServerActionResult & { data: SshFileBrowserResult }> {
  return request(`/server/connections/${id}/ssh/file-list`, { method: 'POST', body: JSON.stringify({ path }) });
}

export function openRdpConnection(id: string): Promise<ServerActionResult> {
  return request(`/server/connections/${id}/rdp/open`, { method: 'POST' });
}

export function wakeOnLanConnection(id: string, mac?: string): Promise<ServerActionResult & { data: WolResult }> {
  return request(`/server/connections/${id}/wol`, { method: 'POST', body: JSON.stringify({ mac: mac ?? undefined }) });
}

export function getServerActivity(limit?: number, connection_id?: string): Promise<{ status: string; count: number; data: ServerActivityLog[] }> {
  const q = new URLSearchParams();
  if (limit) q.set('limit', String(limit));
  if (connection_id) q.set('connection_id', connection_id);
  const qs = q.toString();
  return request(`/server/activity${qs ? `?${qs}` : ''}`);
}

export function getRemoteSessions(limit?: number): Promise<{ status: string; count: number; data: RemoteSession[] }> {
  const q = new URLSearchParams();
  if (limit) q.set('limit', String(limit));
  const qs = q.toString();
  return request(`/server/sessions${qs ? `?${qs}` : ''}`);
}

export function getSshReadOnlyCommands(): Promise<{ status: string; data: SshReadOnlyCommand[] }> {
  return request('/server/ssh/commands');
}

export function standalongPing(host: string): Promise<ServerActionResult & { data: PingResult }> {
  return request('/server/tools/ping', { method: 'POST', body: JSON.stringify({ host }) });
}

export function standalongDns(host: string): Promise<ServerActionResult & { data: DnsResult }> {
  return request('/server/tools/dns', { method: 'POST', body: JSON.stringify({ host }) });
}

export function standalongPortCheck(host: string, ports: number[]): Promise<ServerActionResult & { data: PortCheckResult }> {
  return request('/server/tools/port-check', { method: 'POST', body: JSON.stringify({ host, ports }) });
}

export function standalongTraceroute(host: string): Promise<ServerActionResult> {
  return request('/server/tools/traceroute', { method: 'POST', body: JSON.stringify({ host }) });
}

export function standalongArp(ip: string): Promise<ServerActionResult> {
  return request('/server/tools/arp', { method: 'POST', body: JSON.stringify({ ip }) });
}

export function standalongWol(mac: string, broadcast?: string): Promise<ServerActionResult & { data: WolResult }> {
  return request('/server/tools/wol', { method: 'POST', body: JSON.stringify({ mac, broadcast: broadcast ?? '255.255.255.255' }) });
}

export function getSshConfig(id: string): Promise<{ status: string; data: { config: string } }> {
  return request(`/server/connections/${id}/ssh/config`);
}

export function getServerLegacyFeatures(): Promise<LegacyServerFeatureResponse> {
  return request('/server/legacy-features');
}

export function exportSshConfig(params?: {
  favorites_only?: boolean;
  tag?: string;
}): Promise<SshConfigExportResult> {
  const q = new URLSearchParams();
  if (params?.favorites_only) q.set('favorites_only', 'true');
  if (params?.tag) q.set('tag', params.tag);
  const qs = q.toString();
  return request(`/server/export/ssh-config${qs ? `?${qs}` : ''}`);
}

// ── Host Groups ────────────────────────────────────────────────────────

export function getServerGroups(): Promise<{ status: string; data: ServerHostGroup[] }> {
  return request('/server/groups');
}

export function createServerGroup(data: { name: string; description?: string; color?: string; tags?: string[] }): Promise<{ status: string; data: ServerHostGroup }> {
  return request('/server/groups', { method: 'POST', body: JSON.stringify(data) });
}

export function updateServerGroup(id: string, data: Partial<{ name: string; description: string; color: string; tags: string[] }>): Promise<{ status: string; data: ServerHostGroup }> {
  return request(`/server/groups/${id}`, { method: 'PUT', body: JSON.stringify(data) });
}

export function deleteServerGroup(id: string): Promise<{ status: string }> {
  return request(`/server/groups/${id}`, { method: 'DELETE' });
}

export function getServerGroupMembers(groupId: string): Promise<{ status: string; data: ServerHostGroupMember[] }> {
  return request(`/server/groups/${groupId}/members`);
}

export function addServerGroupMember(groupId: string, connectionId: string): Promise<{ status: string; data: ServerHostGroupMember }> {
  return request(`/server/groups/${groupId}/members`, { method: 'POST', body: JSON.stringify({ connection_id: connectionId }) });
}

export function removeServerGroupMember(groupId: string, connectionId: string): Promise<{ status: string }> {
  return request(`/server/groups/${groupId}/members/${connectionId}`, { method: 'DELETE' });
}

export function runServerGroupHealth(groupId: string, checks?: string[], concurrency?: number): Promise<ServerBatchHealthResponse> {
  return request(`/server/groups/${groupId}/health`, {
    method: 'POST',
    body: JSON.stringify({ connection_ids: [], checks: checks ?? ['ping', 'port'], concurrency: concurrency ?? 5 }),
  });
}

export function runServerBatchHealth(req: ServerBatchHealthRequest): Promise<ServerBatchHealthResponse> {
  return request('/server/batch/health', { method: 'POST', body: JSON.stringify(req) });
}

export function getServerBatchRuns(limit?: number): Promise<{ status: string; data: ServerBatchRun[] }> {
  const q = limit ? `?limit=${limit}` : '';
  return request(`/server/batch/runs${q}`);
}

export function getServerBatchRun(runId: string): Promise<{ status: string; data: ServerBatchRun }> {
  return request(`/server/batch/runs/${runId}`);
}

export function getServerBatchResults(runId: string): Promise<{ status: string; data: ServerBatchResult[] }> {
  return request(`/server/batch/runs/${runId}/results`);
}