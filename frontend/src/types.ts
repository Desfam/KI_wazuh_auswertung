export type Connection = {
  id?: number;
  name: string;
  indexer_url: string;
  indexer_username: string;
  indexer_password: string;
  indexer_index_pattern: string;
  manager_url?: string | null;
  manager_username?: string | null;
  manager_password?: string | null;
  ollama_url: string;
  ollama_model: string;
  verify_ssl: boolean;
  lookback_hours: number;
  vm_enabled: boolean;
  vm_host?: string | null;
  vm_port: number;
  vm_username?: string | null;
  vm_password?: string | null;
  vm_script_path: string;
  vm_python_path: string;
  vm_report_txt_path: string;
  vm_report_json_path: string;
  default_analysis_mode: 'local' | 'vm-script';
  default_query_size: number;
  default_only_windows: boolean;
  default_only_linux: boolean;
  default_include_noise: boolean;
  default_run_ai: boolean;
  created_at?: string;
  updated_at?: string;
  is_active?: number;
};

export type AnalysisJob = {
  id: number;
  connection_id: number;
  status: string;
  started_at: string;
  completed_at?: string | null;
  lookback_hours: number;
  total_alerts: number;
  relevant_alerts: number;
  report_markdown?: string | null;
  report_json?: string | null;
  error_message?: string | null;
};

export type FindingGroup = {
  id: number;
  job_id: number;
  host: string;
  platform: string;
  event_id?: string | null;
  rule_id?: string | null;
  rule_description?: string | null;
  count: number;
  group_key: string;
  local_severity: string;
  local_score: number;
  confidence: number;
  suspicious: boolean | number;
  ai_severity?: string | null;
  reason?: string | null;
  recommended_checks?: string[] | string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  raw_summary_json: string;
};

export type HostRanking = {
  host: string;
  findings_count: number;
  alert_count: number;
  avg_score: number;
  top_score: number;
  platforms: string[];
};

export type Report = {
  id: number;
  job_id: number;
  created_at: string;
  markdown: string;
  report_json: string;
};

export type HealthResponse = {
  status: string;
  reachable?: boolean;
  detail?: string;
};

export type RunAnalysisPayload = {
  mode: 'local' | 'vm-script';
  lookback_hours: number;
  query_size: number;
  host_filter?: string | null;
  platform_filter?: string | null;
  severity_filter?: string | null;
  include_noise: boolean;
  run_ai: boolean;
  only_windows: boolean;
  only_linux: boolean;
};

export type ConnectionTestResult = {
  indexer: { ok: boolean; detail: string };
  ollama: { ok: boolean; detail: string };
  vm_script: { ok: boolean; detail: string };
};

export type AnalysisProfile = {
  mode: 'local' | 'vm-script';
  lookback_hours: number;
  query_size: number;
  host_filter: string;
  include_noise: boolean;
  run_ai: boolean;
  only_windows: boolean;
  only_linux: boolean;
};

export type AIServiceStatus = {
  running: boolean;
  pid?: number | null;
  host: string;
  last_error?: string | null;
  logs: string[];
};

export type AIServiceTestResult = {
  ok: boolean;
  detail: string;
  response?: Record<string, unknown> | null;
};

export type ChatMessage = {
  role: 'user' | 'assistant' | 'system';
  content: string;
};

export type ChatResponse = {
  reply: string;
  ran_script: boolean;
  report_context?: string | null;
  script_report?: string | null;
  script_summary?: {
    lookback_hours: number;
    total_alerts: number;
    relevant_alerts: number;
  } | null;
  generated_tasks?: Array<{
    task_id: string;
    host: string;
    severity: string;
    title: string;
    details: string;
    recommended_checks: string[];
  }>;
  report_txt_content?: string | null;
  report_json_content?: string | null;
};

export type AnalysisProfileConfig = {
  event_ids: string[];
  min_rule_level: number;
  max_findings: number;
  max_events_per_host: number;
  include_commandline: boolean;
  include_full_log: boolean;
  include_agent_info: boolean;
  include_mitre_mapping: boolean;
};

export type HostOverview = {
  host: string;
  job_id: number;
  total_grouped_events: number;
  finding_groups: number;
  top_local_score: number;
  top_ai_severity: string;
  suspicious_groups: number;
  severity_counts: Record<string, number>;
  top_findings: FindingGroup[];
};

export type HostTrendPoint = {
  job_id: number;
  completed_at: string;
  total_grouped_events: number;
  finding_groups: number;
  suspicious_groups: number;
  max_local_score: number;
};

// ── Snipen / Threat Hunting types ────────────────────────────────────────────

export type SnipenHostInfo = {
  host: string;
  alert_count: number;
  top_rule_level: number | null;
  last_seen: string | null;
  platforms: string[];
};

export type SnipenSmartEvent = {
  timestamp?: string | null;
  host?: string | null;
  platform?: string | null;
  event_id?: string | null;
  event_explanation?: string | null;
  rule_id?: string | null;
  rule_level?: number | null;
  rule_description?: string | null;
  groups: string[];
  user?: string | null;
  logon_type?: string | null;
  ip_address?: string | null;
  process?: string | null;
  command_line?: string | null;
  service_name?: string | null;
  registry_key?: string | null;
  status?: string | null;
  mitre_id?: string | null;
  mitre_tactic?: string | null;
  decoder?: string | null;
  location?: string | null;
};

export type SnipenEvent = {
  doc_id?: string | null;
  raw: Record<string, unknown>;
  smart: SnipenSmartEvent;
};

export type SnipenAnalysisResult = {
  host: string;
  hours: number;
  total_events: number;
  suspicious_patterns: string[];
  likely_benign: string[];
  recommended_checks: string[];
  host_risk: string;
  top_rule_ids: string[];
  top_event_ids: string[];
  ai_summary: string | null;
  ran_ai: boolean;
};

export type SnipenExplainResult = {
  summary: string;
  why_suspicious: string | null;
  against_it: string | null;
  severity: string;
  suspicious_fields: string[];
  unusual_behavior: string[];
  deviations: string[];
  risk_score: number | null;
  confidence: string | null;
  mitre_techniques: string[];
  remediation: string[];
  next_checks: string[];
  ran_ai: boolean;
};

export type SnipenAIQueryResult = {
  query: string;
  answer: string;
  matched_events: SnipenEvent[];
  ran_ai: boolean;
};
