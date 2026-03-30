from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class ConnectionBase(BaseModel):
    name: str = "Default Connection"
    indexer_url: str = "https://localhost:9200"
    indexer_username: str = "admin"
    indexer_password: str
    indexer_index_pattern: str = "wazuh-alerts-*"
    manager_url: str | None = "https://wazuh.manager:55000"
    manager_username: str | None = None
    manager_password: str | None = None
    ollama_url: str = "http://172.21.5.111:11434"
    ollama_model: str = "llama3.1:8b"
    verify_ssl: bool = False
    lookback_hours: int = Field(default=24, ge=1, le=168)
    vm_enabled: bool = False
    vm_host: str | None = None
    vm_port: int = Field(default=22, ge=1, le=65535)
    vm_username: str | None = None
    vm_password: str | None = None
    vm_script_path: str = "/home/ai_wazuh_24h_v2.py"
    vm_python_path: str = "python3"
    vm_report_txt_path: str = "/tmp/ai_wazuh_24h_report.txt"
    vm_report_json_path: str = "/tmp/ai_wazuh_24h_report.json"
    default_analysis_mode: Literal["local", "vm-script"] = "local"
    default_query_size: int = Field(default=1000, ge=100, le=10000)
    default_only_windows: bool = False
    default_only_linux: bool = False
    default_include_noise: bool = False
    default_run_ai: bool = True


class ConnectionCreate(ConnectionBase):
    pass


class ConnectionTestRequest(ConnectionBase):
    pass


class ConnectionRecord(ConnectionBase):
    id: int
    created_at: str
    updated_at: str
    is_active: int


class AnalysisRunRequest(BaseModel):
    mode: Literal["local", "vm-script"] = "local"
    lookback_hours: int = Field(default=24, ge=1, le=168)
    query_size: int = Field(default=1000, ge=100, le=10000)
    host_filter: str | None = None
    platform_filter: str | None = None
    severity_filter: str | None = None
    include_noise: bool = False
    run_ai: bool = True
    only_windows: bool = False
    only_linux: bool = False
    event_ids: list[str] | None = None
    min_rule_level: int | None = Field(default=None, ge=0, le=20)
    max_findings: int | None = Field(default=None, ge=10, le=1000)
    max_events_per_host: int | None = Field(default=None, ge=0, le=20000)


class AnalysisProfileConfig(BaseModel):
    event_ids: list[str] = Field(default_factory=list)
    min_rule_level: int = Field(default=0, ge=0, le=20)
    max_findings: int = Field(default=200, ge=10, le=1000)
    max_events_per_host: int = Field(default=0, ge=0, le=20000)
    include_commandline: bool = False
    include_full_log: bool = False
    include_agent_info: bool = True
    include_mitre_mapping: bool = False


class AnalysisJobRecord(BaseModel):
    id: int
    connection_id: int
    status: str
    started_at: str
    completed_at: str | None = None
    lookback_hours: int
    total_alerts: int = 0
    relevant_alerts: int = 0
    report_markdown: str | None = None
    report_json: str | None = None
    error_message: str | None = None


class FindingGroupRecord(BaseModel):
    id: int
    job_id: int
    host: str
    platform: str
    event_id: str | None = None
    rule_id: str | None = None
    rule_description: str | None = None
    count: int
    group_key: str
    local_severity: str
    local_score: int
    confidence: int
    suspicious: int | bool
    ai_severity: str | None = None
    reason: str | None = None
    recommended_checks: list[str] | str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    raw_summary_json: str


class HostRankingRecord(BaseModel):
    host: str
    findings_count: int
    alert_count: int
    avg_score: float
    top_score: int
    platforms: list[str]


class ReportRecord(BaseModel):
    id: int
    job_id: int
    created_at: str
    markdown: str
    report_json: str


class OllamaAssessment(BaseModel):
    suspicious: bool = False
    severity: str = "low"
    reason: str = "No AI assessment available."
    recommended_checks: list[str] = Field(default_factory=list)


class AnalysisSummary(BaseModel):
    total_alerts: int
    relevant_alerts: int
    findings: list[dict[str, Any]]
    report_markdown: str
    report_json: str
    completed_at: str


class ConnectionTestResponse(BaseModel):
    indexer: dict[str, Any]
    ollama: dict[str, Any]
    vm_script: dict[str, Any]


class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str


class ChatRequest(BaseModel):
    message: str = ""
    run_script: bool = False
    lookback_hours: int | None = Field(default=None, ge=1, le=720)
    history: list[ChatMessage] = Field(default_factory=list)
    report_context: str | None = None
    report_json_content: str | None = None
    analysis_profile: AnalysisProfileConfig | None = None


class ChatScriptSummary(BaseModel):
    lookback_hours: int
    total_alerts: int
    relevant_alerts: int


class ChatTaskItem(BaseModel):
    task_id: str
    host: str
    severity: str
    title: str
    details: str
    recommended_checks: list[str] = Field(default_factory=list)


class ChatResponse(BaseModel):
    reply: str
    ran_script: bool = False
    report_context: str | None = None
    script_report: str | None = None
    script_summary: ChatScriptSummary | None = None
    generated_tasks: list[ChatTaskItem] = Field(default_factory=list)
    report_txt_content: str | None = None
    report_json_content: str | None = None


class HostOverviewResponse(BaseModel):
    host: str
    job_id: int
    total_grouped_events: int
    finding_groups: int
    top_local_score: int
    top_ai_severity: str
    suspicious_groups: int
    severity_counts: dict[str, int]
    top_findings: list[dict[str, Any]] = Field(default_factory=list)


class HostTrendPoint(BaseModel):
    job_id: int
    completed_at: str
    total_grouped_events: int
    finding_groups: int
    suspicious_groups: int
    max_local_score: int


# ── Snipen / Threat Hunting models ───────────────────────────────────────────

class SnipenHostInfo(BaseModel):
    host: str
    alert_count: int
    top_rule_level: int | None = None
    last_seen: str | None = None
    platforms: list[str] = Field(default_factory=list)


class SnipenSmartEvent(BaseModel):
    """Normalized/extracted key fields for Smart View."""
    timestamp: str | None = None
    host: str | None = None
    platform: str | None = None
    event_id: str | None = None
    event_explanation: str | None = None
    rule_id: str | None = None
    rule_level: int | None = None
    rule_description: str | None = None
    groups: list[str] = Field(default_factory=list)
    user: str | None = None
    logon_type: str | None = None
    ip_address: str | None = None
    process: str | None = None
    command_line: str | None = None
    service_name: str | None = None
    registry_key: str | None = None
    status: str | None = None
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    decoder: str | None = None
    location: str | None = None


class SnipenEvent(BaseModel):
    """A single Wazuh event with raw + smart fields."""
    doc_id: str | None = None
    raw: dict[str, Any]
    smart: SnipenSmartEvent


class SnipenAnalyzeRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=10, le=500)
    windows_only: bool = False
    linux_only: bool = False
    include_noise: bool = False
    run_ai: bool = True


class SnipenExplainRequest(BaseModel):
    event_raw: dict[str, Any]


class SnipenRemediateRequest(BaseModel):
    event_raw: dict[str, Any]


class SnipenRelatedRequest(BaseModel):
    event_raw: dict[str, Any]
    limit: int = Field(default=20, ge=5, le=100)
    hours: int = Field(default=24, ge=1, le=168)


class SnipenAnalysisResult(BaseModel):
    host: str
    hours: int
    total_events: int
    suspicious_patterns: list[str] = Field(default_factory=list)
    likely_benign: list[str] = Field(default_factory=list)
    recommended_checks: list[str] = Field(default_factory=list)
    host_risk: str = "unknown"
    top_rule_ids: list[str] = Field(default_factory=list)
    top_event_ids: list[str] = Field(default_factory=list)
    ai_summary: str | None = None
    ran_ai: bool = False


class SnipenExplainResult(BaseModel):
    summary: str
    why_suspicious: str | None = None
    against_it: str | None = None
    severity: str = "medium"
    suspicious_fields: list[str] = Field(default_factory=list)
    unusual_behavior: list[str] = Field(default_factory=list)
    deviations: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    next_checks: list[str] = Field(default_factory=list)
    ran_ai: bool = False
    risk_score: float | None = None
    confidence: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)


class SnipenHostOverview(BaseModel):
    host: str
    hours: int
    total_events: int
    high_alerts: int
    critical_alerts: int
    last_activity: str | None = None
    top_event_ids: list[str] = Field(default_factory=list)
    top_processes: list[str] = Field(default_factory=list)
    top_users: list[str] = Field(default_factory=list)
    top_rule_descriptions: list[str] = Field(default_factory=list)


class SnipenAIQueryRequest(BaseModel):
    query: str
    hours: int = Field(default=24, ge=1, le=168)
    limit: int = Field(default=100, ge=10, le=500)


class SnipenAIQueryResult(BaseModel):
    query: str
    answer: str
    matched_events: list[SnipenEvent] = Field(default_factory=list)
    ran_ai: bool = False
