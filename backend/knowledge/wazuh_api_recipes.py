"""
wazuh_api_recipes.py
=====================
A curated catalogue of Wazuh Manager API integration recipes.

Each recipe describes a complete integration pattern: its purpose,
the endpoints it calls, safety classification, required permissions,
and where it is used in this application.

Safety levels:
  read_only        — Safe to call any time; no side effects
  safe_test        — Creates temporary test data, auto-cleaned (e.g. logtest)
  controlled_action — Causes real change; gated behind UI confirmation
  dangerous        — Not implemented; would affect manager or agents broadly

Phase:
  1 — Implemented in Phase 1 (current)
  2 — Planned for Phase 2
  0 — Not planned / documentation only
"""
from __future__ import annotations

WAZUH_API_RECIPES: list[dict] = [
    {
        "recipe_id": "agent_inventory",
        "title": "Agent Inventory",
        "purpose": "Retrieve the full list of registered agents with status, OS, version, "
                   "and last keep-alive. Supports pagination, sorting, and WQL filtering.",
        "endpoints": [
            "GET /agents",
            "GET /agents/summary/status",
        ],
        "safety": "read_only",
        "required_permissions": ["agents:read"],
        "app_locations": [
            "WazuhIntegrationPage → Agents tab",
            "WazuhAgentDetailDrawer → Overview tab",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "Use select= to limit returned fields. Use q= for WQL filtering. "
                 "Single agent: GET /agents?agents_list={id} (no /agents/{id} path in v4.x).",
    },
    {
        "recipe_id": "agent_health",
        "title": "Agent Health & Connectivity Check",
        "purpose": "4-step TCP+auth connectivity probe: DNS resolve → TCP connect → "
                   "HTTP GET /manager/info → JWT auth. Returns per-step timing.",
        "endpoints": [
            "GET /manager/info",
            "POST /security/user/authenticate",
        ],
        "safety": "read_only",
        "required_permissions": ["manager:read"],
        "app_locations": [
            "WazuhIntegrationPage → Overview → Test Connection button",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "Implemented in GET /wazuh-manager/ping.",
    },
    {
        "recipe_id": "syscollector_inventory",
        "title": "Syscollector Inventory",
        "purpose": "Retrieve hardware, OS, packages, ports, processes, users, groups "
                   "and services for a specific agent.",
        "endpoints": [
            "GET /syscollector/{agent_id}/os",
            "GET /syscollector/{agent_id}/hardware",
            "GET /syscollector/{agent_id}/packages",
            "GET /syscollector/{agent_id}/ports",
            "GET /syscollector/{agent_id}/processes",
            "GET /syscollector/{agent_id}/users",
            "GET /syscollector/{agent_id}/groups",
        ],
        "safety": "read_only",
        "required_permissions": ["syscollector:read"],
        "app_locations": [
            "WazuhAgentDetailDrawer → Syscollector tab",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "All syscollector endpoints accept limit/offset/select/sort/q params.",
    },
    {
        "recipe_id": "sca_review",
        "title": "Security Configuration Assessment",
        "purpose": "List SCA policy summaries and individual check results for an agent. "
                   "Each policy shows pass/fail/not-applicable counts.",
        "endpoints": [
            "GET /sca/{agent_id}",
            "GET /sca/{agent_id}/checks/{policy_id}",
        ],
        "safety": "read_only",
        "required_permissions": ["sca:read"],
        "app_locations": [
            "WazuhAgentDetailDrawer → SCA tab",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "SCA checks support q= filter (e.g. q=result=failed for failed checks only).",
    },
    {
        "recipe_id": "fim_review",
        "title": "File Integrity Monitoring (FIM/Syscheck)",
        "purpose": "Review the FIM database: modified, added, deleted files with checksum "
                   "details and last scan timestamp for an agent.",
        "endpoints": [
            "GET /syscheck/{agent_id}",
            "GET /syscheck/{agent_id}/last_scan",
        ],
        "safety": "read_only",
        "required_permissions": ["syscheck:read"],
        "app_locations": [
            "WazuhAgentDetailDrawer → FIM tab",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "Filter by event type: q=type=modified. Supports pagination.",
    },
    {
        "recipe_id": "rootcheck_review",
        "title": "Rootcheck Results",
        "purpose": "Retrieve rootcheck/CIS benchmark scan results for an agent.",
        "endpoints": [
            "GET /rootcheck/{agent_id}",
            "GET /rootcheck/{agent_id}/last_scan",
        ],
        "safety": "read_only",
        "required_permissions": ["rootcheck:read"],
        "app_locations": [
            "WazuhAgentDetailDrawer → Rootcheck tab",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "Results include CIS/trojans categories.",
    },
    {
        "recipe_id": "logtest",
        "title": "Log Test (Decoder + Rule Simulation)",
        "purpose": "Submit a raw log line to Wazuh and receive: matched decoder, fired rule, "
                   "rule ID, level, groups, MITRE IDs, and full output. "
                   "Safe: creates a temporary session, no persistent effects.",
        "endpoints": [
            "PUT /logtest",
            "DELETE /logtest/sessions/{token}",
        ],
        "safety": "safe_test",
        "required_permissions": ["logtest:run"],
        "app_locations": [
            "WazuhIntegrationPage → Capabilities tab → Logtest widget",
        ],
        "implemented": True,
        "phase": 1,
        "notes": "Use PUT not POST. The session token in the response can be reused to "
                 "maintain decoder context across related log lines.",
    },
    {
        "recipe_id": "agent_reconnect_controlled",
        "title": "Agent Reconnect (Single Agent)",
        "purpose": "Force a single disconnected agent to reconnect to the manager. "
                   "Useful when an agent is stuck in 'disconnected' after a network blip.",
        "endpoints": [
            "PUT /agents/{agent_id}/reconnect",
        ],
        "safety": "controlled_action",
        "required_permissions": ["agents:reconnect"],
        "app_locations": [
            "WazuhAgentDetailDrawer → Overview tab → (Phase 2) Reconnect button",
        ],
        "implemented": False,
        "phase": 2,
        "notes": "Must be gated behind an explicit 'Are you sure?' confirmation dialog. "
                 "Never bulk-reconnect all agents without throttling.",
    },
]
