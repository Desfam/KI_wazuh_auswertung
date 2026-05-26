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
    event_id?: string | null;
    rule_id?: string | null;
    rule_description?: string | null;
    platform?: string | null;
    count?: number;
    reason?: string | null;
    local_score?: number | null;
    mitre_ids?: string[];
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

export type HostCentralListItem = {
  host: string;
  ip?: string | null;
  platforms: string[];
  last_activity?: string | null;
  alerts_24h: number;
  findings_count: number;
  risk_score: number;
  fullscan_status: string;
  last_scan_at?: string | null;
  status: 'online' | 'offline';
  tactical_status?: string | null;
  // ── Access (SSH / RDP) ──────────────────────────────────────────────────────
  ssh_enabled: boolean;
  rdp_enabled: boolean;
  connection_status: 'reachable' | 'unreachable' | 'unknown';
  last_connection?: string | null;
};

export type HostCentralTabPayload = {
  items: unknown[] | Record<string, unknown>;
  ai_assessment: string;
};

export type HostCentralDetail = {
  header: {
    host: string;
    ip?: string | null;
    platforms: string[];
    agent_id?: string | null;
    status: string;
    last_activity?: string | null;
    last_full_scan?: string | null;
  };
  summary: {
    risk_score: number;
    findings_count: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    ti_matches: number;
    last_scan_time?: string | null;
    ai_assessment: string;
  };
  tabs: Record<string, HostCentralTabPayload>;
  overview?: HostOverview | null;
  findings?: FindingGroup[];
  trend?: HostTrendPoint[];
};

// ── Snipen / Threat Hunting types ────────────────────────────────────────────

export type SnipenHostProfileRef = {
  name: string;
  display_name: string;
  risk_tolerance: string;
};

export type SnipenHostInfo = {
  host: string;
  alert_count: number;
  top_rule_level: number | null;
  last_seen: string | null;
  platforms: string[];
  profile?: SnipenHostProfileRef | null;
};

export type SnipenSmartEvent = {
  timestamp?: string | null;
  host?: string | null;
  platform?: string | null;
  event_id?: string | null;
  event_explanation?: string | null;
  system_message?: string | null;
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
  // Extended fields (Phase 1)
  parent_process?: string | null;
  target_user?: string | null;
  subject_user?: string | null;
  workstation?: string | null;
  substatus?: string | null;
  service_type?: string | null;
  start_type?: string | null;
  image_path?: string | null;
  process_id?: string | null;
  new_process_id?: string | null;
  event_family?: string | null;
  summary?: string | null;
  fim_path?: string | null;
  fim_mode?: string | null;
  fim_owner?: string | null;
  fim_group?: string | null;
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

export type TimelinePointDTO = {
  bucket_start: string;
  bucket_end: string;
  event_count: number;
  is_peak: boolean;
  is_anomaly: boolean;
};

export type SnipenHostOverview = {
  host: string;
  hours: number;
  total_events: number;
  severity_distribution: Record<string, number>;
  top_event_ids: string[];
  top_rule_ids: string[];
  top_processes: string[];
  top_users: string[];
  top_ips: string[];
  top_rule_descriptions: string[];
  timeline: TimelinePointDTO[];
};

// ── Host Profile types ────────────────────────────────────────────────────────

export type HostProfile = {
  id: number | null;
  name: string;
  display_name: string;
  description: string;
  risk_tolerance: 'low' | 'medium' | 'high';
  expected_behaviors: Record<string, boolean>;
  allowed_process_patterns: string[];
  suspicious_patterns: string[];
  always_critical_event_ids: string[];
  notes: string[];
  is_builtin: boolean;
  created_at?: string | null;
  updated_at?: string | null;
};

export type HostProfileAssignment = {
  host: string;
  profile_id: number;
  profile_name?: string | null;
  profile_display_name?: string | null;
  risk_tolerance?: string | null;
  assigned_by: string;
  notes?: string | null;
  assigned_at?: string | null;
  updated_at?: string | null;
};

// ── Baseline ──────────────────────────────────────────────────────────────────

export type BaselineFeatureItem = {
  key: string;
  count: number;
};

export type BaselineSnapshot = {
  id: number;
  host: string;
  computed_at: string;
  window_hours: number;
  profile_id: number | null;
  total_events: number;
  high_alerts: number;
  critical_alerts: number;
  top_event_ids: BaselineFeatureItem[];
  top_rule_ids: BaselineFeatureItem[];
  top_processes: BaselineFeatureItem[];
  top_users: BaselineFeatureItem[];
  top_ips: BaselineFeatureItem[];
  top_event_families: BaselineFeatureItem[];
  event_volume_per_hour: Record<string, number>;
  notes: string[];
  deviation_count: number;
};

export type BaselineFeature = {
  id: number;
  host: string;
  feature_type: string;
  feature_key: string;
  count_seen: number;
  first_seen: string;
  last_seen: string;
  stability_score: number;
  is_expected: boolean;
  notes: string | null;
};

export type BaselineDeviation = {
  id: number;
  host: string;
  detected_at: string;
  feature_type: string;
  feature_key: string;
  deviation_type: string;
  severity_hint: string;
  risk_score: number;
  risk_level: string;
  reason: string;
  confidence: number;
  details: Record<string, unknown>;
  resolved: boolean;
  resolved_at: string | null;
  final_classification: string;
};

export type BaselineDiff = {
  host: string;
  computed_at: string;
  new_processes: string[];
  new_users: string[];
  new_services: string[];
  new_ips: string[];
  new_event_ids: string[];
  new_event_families: string[];
  volume_spike: boolean;
  volume_ratio: number;
  open_deviations: number;
  top_risk_deviations: Record<string, unknown>[];
};

export type BaselineSummary = {
  host: string;
  computed_at: string | null;
  window_hours: number;
  total_events: number;
  daily_avg_events: number;
  high_alerts: number;
  critical_alerts: number;
  top_processes: string[];
  top_event_ids: string[];
  top_users: string[];
  top_event_families: string[];
  open_deviations: number;
  deviation_types: string[];
  top_deviations: Array<{
    type: string;
    key: string;
    risk_score: number;
    risk_level: string;
    reason: string;
  }>;
};

// ── Tactical RMM / UnifiedHost types ──────────────────────────────────────

export type TacticalAgent = {
  id: number;
  tactical_agent_id: string;
  hostname: string;
  fqdn?: string | null;
  description?: string | null;
  client_name?: string | null;
  site_name?: string | null;
  os_platform?: string | null;
  os_full?: string | null;
  local_ips?: string | null;
  public_ip?: string | null;
  last_checkin?: string | null;
  status?: string | null;
  agent_version?: string | null;
  logged_user?: string | null;
  mesh_node_id?: string | null;
  checks_failing: number;
  needs_reboot: number;
  synced_at: string;
};

export type IdentityStatus = 'trusted' | 'likely' | 'uncertain' | 'unknown';
export type ActionPolicy = 'full' | 'read_only' | 'blocked';

export type UnifiedHost = {
  id: number;
  display_name: string;
  hostname_short?: string | null;
  fqdn?: string | null;
  tactical_agent_id?: string | null;
  wazuh_agent_id?: string | null;
  mesh_node_id?: string | null;
  match_score: number;
  match_status: string;
  match_source: string;
  identity_status: IdentityStatus;
  tactical_status: string;
  wazuh_status: string;
  mesh_status: string;
  action_policy: ActionPolicy;
  primary_ip?: string | null;
  os_platform?: string | null;
  os_full?: string | null;
  last_seen_tactical?: string | null;
  last_seen_wazuh?: string | null;
  notes?: string | null;
  created_at: string;
  updated_at: string;
  conflict_count?: number;
};

export type HostConflict = {
  id: number;
  unified_host_id: number;
  conflict_type: string;
  severity: 'info' | 'warning' | 'critical';
  field_name?: string | null;
  tactical_value?: string | null;
  wazuh_value?: string | null;
  description: string;
  resolved: number;
  is_active: number;
  detected_at: string;
};

export type TacticalSyncResult = {
  success: boolean;
  agents_pulled: number;
  agents_cached: number;
  hosts_created: number;
  hosts_updated: number;
  conflicts_detected: number;
  errors: string[];
  duration_ms: number;
};

// ── Normalised Action Policy ──────────────────────────────────────────────────

export type NormalisedActionPolicy = {
  policy: 'blocked' | 'review_required' | 'allowed';
  reason: string;
  dangerous_actions_enabled: boolean;
  read_only_actions_enabled: boolean;
};

// ── Unified Host Resolver result ──────────────────────────────────────────────

export type ResolvedUnifiedHost = {
  host: UnifiedHost | null;
  conflicts: HostConflict[];
  action_policy: NormalisedActionPolicy;
};

// ── Event Map knowledge / evidence enrichment types ───────────────────────────

export type ClusterKnowledge = {
  key: string;
  title: string;
  category: string;
  default_severity: string;
  summary: string;
  knowledge_level: string;
  platform: string;
};

export type ClusterEvidenceSummary = {
  top_user?: string;
  top_source_ip?: string;
  top_process?: string;
  file_path?: string;
  file_action?: string;
  service_name?: string;
  command_line?: string;
  sensitive_path?: string;
  sensitive_reason?: string;
  logon_type?: string;
  status?: string;
  sub_status?: string;
};

export type ClusterPlaybook = {
  playbook_id: string;
  title: string;
  description: string;
  recommended_checks: string[];
  recommended_readonly_scripts: string[];
  dangerous_actions: string[];
  blocked_actions_reason?: string | null;
  escalation_conditions: string[];
  false_positive_notes: string[];
};

export type RawPreview = {
  agent?: Record<string, unknown> | null;
  rule?: Record<string, unknown> | null;
  data?: Record<string, unknown> | null;
  syscheck?: Record<string, unknown> | null;
  decoder?: Record<string, unknown> | null;
  location?: string | null;
  full_log?: string | null;
  timestamp?: string | null;
};

// ── Timeline ──────────────────────────────────────────────────────────────────

export type TimelineItem = {
  timestamp: string;
  host?: string | null;
  agent_id?: string | null;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  rule_id?: string | null;
  rule_description?: string | null;
  event_id?: string | null;
  category?: string | null;
  title: string;
  user?: string | null;
  source_ip?: string | null;
  process?: string | null;
  file_path?: string | null;
  command_line?: string | null;
  mitre_tactic?: string | null;
  knowledge_key?: string | null;
  playbook_ids: string[];
  raw_preview?: Record<string, unknown> | null;
};

// ── Script Library ────────────────────────────────────────────────────────────

export type ScriptEntry = {
  id: number;
  script_id: string;
  name: string;
  description?: string | null;
  platform: 'windows' | 'linux' | 'both' | 'network';
  category: string;
  executor: string;
  script_body?: string | null;
  parameters_json?: string | null;
  requires_admin: number;
  risk_level: string;
  dangerous: number;
  enabled: number;
  readonly: number;
  created_at: string;
  updated_at: string;
};

// ── Audit Log ─────────────────────────────────────────────────────────────────

export type AuditEntry = {
  id: number;
  timestamp: string;
  user?: string | null;
  action_type: string;
  action_id?: string | null;
  source_page?: string | null;
  source_event_id?: string | null;
  source_rule_id?: string | null;
  host?: string | null;
  unified_host_id?: number | null;
  wazuh_agent_id?: string | null;
  tactical_agent_id?: string | null;
  action_policy?: string | null;
  policy_reason?: string | null;
  status: string;
  details_json?: string | null;
  result_json?: string | null;
};

// ── Trust Center / Validation ─────────────────────────────────────────────────

export type ValidationTestStatus = 'pass' | 'fail' | 'warning';

export type ValidationTest = {
  id: string;
  name: string;
  category: string;
  status: ValidationTestStatus;
  message: string;
  details?: Record<string, unknown>;
};

export type ValidationSummary = {
  total_tests: number;
  passed: number;
  failed: number;
  warnings: number;
};

export type ValidationKnowledgeStatus = {
  windows_entries: number;
  linux_entries: number;
  playbooks: number;
  scripts: number;
  unknown_events_24h: number;
  fallback_usage_24h: number;
};

export type ValidationApiHealth = {
  backend: string;
  wazuh_indexer: string;
  wazuh_manager: string;
  tactical_rmm: string;
  scripts: string;
  timeline: string;
  audit: string;
};

export type ValidationStatus = {
  timestamp: string;
  summary: ValidationSummary;
  knowledge: ValidationKnowledgeStatus;
  tests: ValidationTest[];
  api_health: ValidationApiHealth;
};

