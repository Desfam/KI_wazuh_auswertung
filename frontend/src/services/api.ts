import type { AIServiceStatus, AIServiceTestResult, AnalysisJob, AnalysisProfileConfig, BaselineDeviation, BaselineDiff, BaselineFeature, BaselineSnapshot, BaselineSummary, ChatMessage, ChatResponse, Connection, ConnectionTestResult, FindingGroup, HealthResponse, HostCentralDetail, HostCentralListItem, HostOverview, HostProfile, HostProfileAssignment, HostRanking, HostTrendPoint, Report, RunAnalysisPayload, SnipenAIQueryResult, SnipenAnalysisResult, SnipenEvent, SnipenExplainResult, SnipenHostInfo, SnipenHostOverview } from '../types';

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
    throw new Error(text || `Request failed with status ${response.status}`);
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