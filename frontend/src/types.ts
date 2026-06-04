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
  wazuh_status?: string | null;
  wazuh_agent_id?: string | null;
  // ── Access (SSH / RDP) ──────────────────────────────────────────────────────
  ssh_enabled: boolean;
  rdp_enabled: boolean;
  connection_status: 'reachable' | 'unreachable' | 'unknown';
  last_connection?: string | null;
  identity_reason?: string | null;
  policy_reason?: string | null;
  match_confidence_label?: string | null;
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
export type ActionPolicy = 'full' | 'read_only' | 'review_required' | 'blocked';

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
  // ── Trust explanation (computed, not stored) ────────────────────────────────
  identity_reason?: string | null;
  policy_reason?: string | null;
  match_confidence_label?: string | null;
  match_evidence?: string[] | null;
  conflict_evidence?: string[] | null;
  recommended_next_step?: string | null;
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

export type WazuhSyncReport = {
  status: string;
  agents_total: number;
  unified_hosts_before: number;
  matched: number;
  created: number;
  updated: number;
  conflicts: number;
  unmatched_agents: number;
  match_methods: {
    agent_id: number;
    hostname: number;
    fqdn: number;
    ip: number;
    created_new: number;
  };
  conflict_items: Array<{
    unified_host_id: number;
    host_name: string;
    reason: string;
    candidates: Array<{
      agent_id: string;
      agent_name: string;
      agent_ip: string;
      match_reason: string;
    }>;
  }>;
  unmatched_items: Array<{
    agent_id: string;
    agent_name: string;
    agent_ip: string;
    status: string;
  }>;
  warnings: string[];
  duration_ms: number;
  errors: string[];
  // legacy compat keys
  agents_fetched?: number;
  new_hosts?: number;
  conflicts_detected?: number;
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

// ── Baseline-aware cluster evaluation ─────────────────────────────────────────

export type BaselineKnownFeatures = {
  event_id:     boolean | null;
  process:      boolean | null;
  user:         boolean | null;
  ip:           boolean | null;
  service_name: boolean | null;
  event_family: boolean | null;
};

export type BaselineSnapshotInfo = {
  computed_at:     string | null;
  window_hours:    number | null;
  total_events:    number | null;
  high_alerts:     number | null;
  critical_alerts: number | null;
};

export type BaselineDeviationItem = {
  type:        string;
  key:         string;
  risk_score:  number;
  risk_level:  string;
  reason:      string;
  confidence?: number;
};

export type ClusterBaselineContext = {
  host:                     string | null;
  baseline_available:       boolean;
  snapshot:                 BaselineSnapshotInfo;
  known_features:           BaselineKnownFeatures;
  feature_counts:           Record<string, number | null>;
  new_features:             string[];
  rare_features:            string[];
  open_deviations:          number;
  top_risk_deviations:      BaselineDeviationItem[];
  baseline_candidate:       boolean;
  baseline_candidate_reason: string | null;
  host_risk_modifier:       number;
  host_context_reason:      string;
  warnings:                 string[];
};

export type FinalEvaluation = {
  verdict:                string;
  severity:               string;
  risk_score:             number;
  confidence:             string;
  reason:                 string;
  what_to_do:             string[];
  safe_to_baseline:       boolean;
  manual_review_required: boolean;
  warnings:               string[];
};

export type BaseEvaluation = {
  verdict:    string;
  severity:   string;
  risk_score: number;
  confidence: string;
  reason:     string;
  what_to_do: string[];
};

export type ClusterEvaluation = {
  base_evaluation:  BaseEvaluation | null;
  baseline_context: ClusterBaselineContext | null;
  final_evaluation: FinalEvaluation | null;
};

// ── Deterministic event explanation (Phase 3+) ───────────────────────────────
export type ImportantField = {
  field:  string;
  value:  string;
  reason: string;
};

export type ClusterExplanation = {
  title:                 string;
  subtitle:              string;
  verdict:               string;
  severity:              string;
  risk_score:            number;
  confidence:            string;
  explanation_source:    string;
  summary:               string;
  why_visible:           string[];
  why_suspicious:        string[];
  why_likely_benign:     string[];
  not_enough_evidence:   string[];
  important_fields:      ImportantField[];
  recommended_checks:    string[];
  escalation_conditions: string[];
  baseline_notes:        string[];
  wording_warnings:      string[];
};

export type UnifiedEventEvaluation = {
  event_id:          string | null;
  rule_id:           string | null;
  title:             string;
  category:          string;
  platform:          string;
  base_evaluation:   BaseEvaluation | null;
  baseline_context:  ClusterBaselineContext | null;
  final_evaluation:  FinalEvaluation | null;
  explanation:       ClusterExplanation | null;
  trust: {
    source:         string;
    confidence:     string;
    matched_by:     string[];
    missing_fields: string[];
    warnings:       string[];
  } | null;
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

// ── Wazuh Manager API ─────────────────────────────────────────────────────────

export type WazuhManagerHealth = {
  configured: boolean;
  reachable: boolean;
  authenticated: boolean;
  api_version?: string | null;
  manager_version?: string | null;
  hostname?: string | null;
  cluster_enabled?: boolean | null;
  agent_status_summary?: Record<string, number> | null;
  message?: string | null;
  last_checked: string;
};

export type WazuhAgentOS = {
  name?: string | null;
  platform?: string | null;
  version?: string | null;
  arch?: string | null;
  codename?: string | null;
};

export type WazuhAgent = {
  id: string;
  name: string;
  ip?: string | null;
  status: 'active' | 'disconnected' | 'never_connected' | 'pending' | string;
  version?: string | null;
  os?: WazuhAgentOS | null;
  group?: string[] | null;
  node_name?: string | null;
  manager?: string | null;
  lastKeepAlive?: string | null;
};

export type WazuhSCAPolicy = {
  policy_id: string;
  name: string;
  score: number;
  pass: number;
  fail: number;
  invalid: number;
};

export type WazuhAgentEnrichment = {
  agent: {
    id: string | null;
    name: string | null;
    ip: string | null;
    status: string | null;
    version: string | null;
    os: WazuhAgentOS | null;
    groups: string[];
    last_keep_alive: string | null;
    node_name: string | null;
    manager_name: string | null;
  };
  syscollector: {
    os_available: boolean;
    hardware_available: boolean;
    packages_available: boolean;
    ports_available: boolean;
    processes_available: boolean;
    services_available: boolean;
    users_available: boolean;
  };
  sca: {
    available: boolean;
    score: number | null;
    failed_checks: number | null;
    policies: WazuhSCAPolicy[];
  };
  fim: {
    available: boolean;
    last_scan: string | null;
  };
  rootcheck: {
    available: boolean;
    last_scan: string | null;
  };
  source: 'manager_api' | 'cache' | 'event_only';
  source_reason: string;
  cache_age_seconds: number | null;
  warnings: string[];
};

export type WazuhAPICapability = {
  method: string;
  path: string;
  tag: string;
  summary: string;
  operation_id: string;
  safety: 'read_only' | 'safe_test' | 'controlled_action' | 'dangerous';
  implemented: boolean;
  phase: string;
  requires_action_policy: boolean;
};

export type WazuhAPICapabilitiesResult = {
  summary: {
    total: number;
    read_only_total: number;
    read_only_implemented: number;
    controlled_disabled: number;
    dangerous_disabled: number;
    by_safety: Record<string, number>;
  };
  spec_loaded?: boolean;
  spec_search_paths?: string[];
  capabilities: WazuhAPICapability[];
};

export type WazuhPermissionProbe = {
  key: string;
  label: string;
  endpoint: string;
  status: 'ok' | 'denied' | 'unavailable' | 'error' | 'skipped';
  http_status: number | null;
  message: string;
  required_for: string[];
  impact_if_missing: string;
};

export type WazuhControlledActionProbe = {
  key: string;
  label: string;
  endpoint: string;
  safety: string;
  mass_action_allowed: boolean;
  status: 'ok' | 'unknown' | 'denied' | 'unavailable' | 'error';
  message: string;
  required_for: string[];
  impact_if_missing: string;
};

export type WazuhPermissionsResult = {
  checked_at: string;
  overall: 'ok' | 'warning' | 'error';
  sample_agent_id: string | null;
  permissions: WazuhPermissionProbe[];
  controlled_actions: WazuhControlledActionProbe[];
  warnings: string[];
};

export type WazuhAPIRecipe = {
  recipe_id: string;
  title: string;
  purpose: string;
  endpoints: string[];
  safety: 'read_only' | 'safe_test' | 'controlled_action' | 'dangerous';
  required_permissions: string[];
  app_locations: string[];
  implemented: boolean;
  phase: number;
  notes: string;
};

export type WazuhAPIDocSection = {
  key: string;
  title: string;
  url: string;
  purpose: string;
  app_usage: string;
  icon: string;
};

// ── Server / Remote Access ────────────────────────────────────────────

export type ServerProtocol = 'ssh' | 'rdp' | 'winrm';
export type ServerAuthType = 'none' | 'key_ref' | 'agent' | 'credential_ref';
export type ServerActionStatus = 'ok' | 'blocked' | 'review_required' | 'error' | 'unavailable' | 'auth_failed' | 'offline' | 'unreachable';
export type RemoteAccessMode = 'safe' | 'admin' | 'break_glass';

export type RemoteAccessModeConfig = {
  mode: RemoteAccessMode;
  changed_by: string;
  changed_at: string;
  reason: string;
};

export type ServerConnection = {
  id: string;
  name: string;
  hostname: string;
  ip: string;
  protocol: ServerProtocol;
  port: number;
  username: string;
  auth_type: ServerAuthType;
  credential_ref: string;
  key_ref: string;
  os: string;
  platform: string;
  tags: string[];
  favorite: boolean;
  mac: string;
  unified_host_id: string;
  tactical_agent_id: string;
  wazuh_agent_id: string;
  notes: string;
  created_at: string;
  updated_at: string;
};

export type ServerConnectionInput = Partial<Omit<ServerConnection, 'id' | 'created_at' | 'updated_at'>> & { name: string };

export type ServerActionResult = {
  status: ServerActionStatus;
  message: string;
  policy?: string;
  policy_reason?: string;
  data?: Record<string, unknown>;
  audit_id?: string;
  session_id?: string;
};

export type ServerActivityLog = {
  id: string;
  timestamp: string;
  action: string;
  connection_id: string;
  host: string;
  protocol: string;
  status: string;
  message: string;
  metadata: Record<string, unknown>;
};

export type RemoteSession = {
  id: string;
  connection_id: string;
  protocol: string;
  host: string;
  started_at: string;
  ended_at?: string | null;
  status: string;
  audit: Record<string, unknown>;
};

export type LegacyImportReport = {
  total: number;
  imported: number;
  skipped: number;
  conflicts: number;
  warnings: string[];
  items: ServerConnection[];
};

export type ServerPolicyResult = {
  status: ServerActionStatus;
  message: string;
  policy: string;
  policy_reason: string;
};

export type PingResult = {
  host: string;
  reachable: boolean;
  packets_sent?: number;
  elapsed_ms?: number;
  avg_rtt_ms?: number | null;
  raw?: string;
  error?: string;
};

export type DnsResult = {
  host: string;
  resolved: boolean;
  addresses?: string[];
  error?: string;
};

export type PortCheckResult = {
  host: string;
  ports: { port: number; open: boolean; error?: string }[];
  open_count: number;
};

export type SshReadOnlyCommandResult = {
  status: ServerActionStatus;
  command_id: string;
  command?: string;
  output?: string;
  error_output?: string;
  returncode?: number;
  error?: string;
};

export type SshFileBrowserEntry = {
  name: string;
  type: 'file' | 'dir';
  size?: number;
  mtime?: number;
};

export type SshFileBrowserResult = {
  status: ServerActionStatus;
  path: string;
  entries: SshFileBrowserEntry[];
  error?: string;
};

export type SshHostInfoResult = {
  status: ServerActionStatus;
  fields?: Record<string, string>;
  error?: string;
};

export type SshHealthResult = {
  status: ServerActionStatus;
  tcp_ms?: number | null;
  ssh_ms?: number | null;
  uptime?: string | null;
  load?: string | null;
  disk?: string | null;
  error?: string;
};

export type SshReadOnlyCommand = {
  id: string;
  command: string;
};

export type WolResult = {
  status: ServerActionStatus;
  message: string;
};

// ── Legacy Feature Catalog ────────────────────────────────────────────────────

export type LegacyFeatureStatus = 'implemented' | 'planned' | 'disabled' | 'rejected';
export type LegacyFeatureRisk   = 'none' | 'low' | 'medium' | 'high' | 'critical';

export type LegacyServerFeature = {
  id: string;
  name: string;
  description: string;
  source: string;
  risk_level: LegacyFeatureRisk;
  phase1: boolean;
  phase2: boolean;
  status: LegacyFeatureStatus;
  backend: string | null;
  frontend: string | null;
  audit: boolean;
  policy_action: string | null;
  rejection_reason?: string;
};

export type LegacyServerFeatureSummary = {
  total: number;
  phase1: number;
  phase2: number;
  disabled: number;
  rejected: number;
  dangerous: number;
};

export type LegacyServerFeatureResponse = {
  status: string;
  source_repo: string;
  mode: string;
  features: LegacyServerFeature[];
  summary: LegacyServerFeatureSummary;
};

export type SshConfigExportResult = {
  status: string;
  host_count: number;
  config: string;
  warnings: string[];
  audit_id?: string;
};

// ── Host Groups ───────────────────────────────────────────────────────────────

export type ServerHostGroup = {
  id: string;
  name: string;
  description: string;
  color: string;
  tags: string[];
  created_at: string;
  updated_at: string;
  member_count?: number;
};

export type ServerHostGroupMember = {
  id: string;
  group_id: string;
  connection_id: string;
  added_at: string;
  // enriched connection fields
  name?: string;
  hostname?: string;
  ip?: string;
  protocol?: string;
  port?: number;
  username?: string;
  os?: string;
  platform?: string;
  tags?: string[];
  favorite?: boolean;
  unified_host_id?: string;
  wazuh_agent_id?: string;
};

// ── Batch Health ──────────────────────────────────────────────────────────────

export type BatchRunStatus = 'running' | 'done' | 'partial' | 'failed';
export type BatchResultStatus = 'ok' | 'partial' | 'failed' | 'blocked' | 'timeout' | 'pending';

export type ServerBatchSummary = {
  status: BatchRunStatus;
  total: number;
  ok: number;
  failed: number;
  blocked: number;
  duration_ms: number;
};

export type ServerBatchRun = {
  id: string;
  group_id?: string | null;
  action: string;
  status: BatchRunStatus;
  started_at: string;
  finished_at?: string | null;
  summary: ServerBatchSummary;
  created_by?: string;
};

export type ServerBatchResult = {
  id: string;
  batch_run_id: string;
  connection_id: string;
  host: string;
  status: BatchResultStatus;
  duration_ms: number;
  result: Record<string, unknown>;
  error?: string | null;
};

export type ServerBatchHealthRequest = {
  connection_ids: string[];
  checks: ('ping' | 'port' | 'ssh_health')[];
  concurrency?: number;
};

export type ServerBatchHealthResponse = {
  status: string;
  batch_run_id: string | null;
  summary: ServerBatchSummary;
  results: ServerBatchResult[];
};

