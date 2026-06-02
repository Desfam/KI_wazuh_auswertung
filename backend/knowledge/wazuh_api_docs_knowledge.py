"""
wazuh_api_docs_knowledge.py
============================
Static catalogue of Wazuh Manager REST API documentation sections.

These are used to populate the "Docs" tab in WazuhIntegrationPage
so operators can quickly jump to the relevant documentation.

Based on: https://documentation.wazuh.com/current/user-manual/api/
Version: 4.x (tested against 4.14.5)
"""
from __future__ import annotations

WAZUH_API_DOC_SECTIONS: list[dict] = [
    {
        "key": "getting_started",
        "title": "Getting Started",
        "url": "https://documentation.wazuh.com/current/user-manual/api/getting-started.html",
        "purpose": "Initial configuration and first API calls. Covers authentication, base URL, "
                   "SSL verification, and the standard response envelope.",
        "app_usage": "Reference when setting up the Manager connection in Settings.",
        "icon": "BookOpen",
    },
    {
        "key": "requests_responses",
        "title": "Request & Response Format",
        "url": "https://documentation.wazuh.com/current/user-manual/api/requests.html",
        "purpose": "HTTP verbs, error codes, pagination (offset/limit), field selection (select=), "
                   "sorting (sort=), and search (search=) parameters.",
        "app_usage": "All API proxy calls in wazuh_manager_api.py follow these conventions.",
        "icon": "FileJson",
    },
    {
        "key": "wql",
        "title": "Wazuh Query Language (WQL)",
        "url": "https://documentation.wazuh.com/current/user-manual/api/queries.html",
        "purpose": "Syntax for the q= filter parameter. Supports =, !=, ~, <, > operators "
                   "and AND (;) / OR (,) combinators.",
        "app_usage": "wazuh_wql.py implements build_wql() / parse_wql() for the Agents filter bar.",
        "icon": "Filter",
    },
    {
        "key": "rbac",
        "title": "RBAC — Role-Based Access Control",
        "url": "https://documentation.wazuh.com/current/user-manual/api/rbac/index.html",
        "purpose": "Wazuh RBAC model: users, roles, rules, and policies. Explains which "
                   "permissions each endpoint requires and how to configure the wazuh-wui user.",
        "app_usage": "Required when interpreting 403 errors and configuring permission probes "
                     "in wazuh_api_permissions.py.",
        "icon": "ShieldCheck",
    },
    {
        "key": "security",
        "title": "Security — Authentication",
        "url": "https://documentation.wazuh.com/current/user-manual/api/security/index.html",
        "purpose": "JWT authentication flow: POST /security/user/authenticate, "
                   "token lifetime, refresh, and revocation.",
        "app_usage": "wazuh_manager_api.py caches and auto-refreshes the JWT token.",
        "icon": "KeyRound",
    },
    {
        "key": "configuration",
        "title": "Configuration & Endpoints",
        "url": "https://documentation.wazuh.com/current/user-manual/api/configuration.html",
        "purpose": "ossec.conf API section: bind address, port, SSL cert, max_upload_size, "
                   "rate limiting, logs level, etc.",
        "app_usage": "Consult when diagnosing connection failures or 429 rate-limit errors.",
        "icon": "Settings",
    },
    {
        "key": "use_cases",
        "title": "Use Cases",
        "url": "https://documentation.wazuh.com/current/user-manual/api/use-cases.html",
        "purpose": "Official recipes: listing agents, running logtest, checking SCA, querying "
                   "syscollector. Useful as the authoritative examples for each feature.",
        "app_usage": "Companion to wazuh_api_recipes.py — use-case catalogue maps directly.",
        "icon": "Lightbulb",
    },
    {
        "key": "reference",
        "title": "API Reference (OpenAPI)",
        "url": "https://documentation.wazuh.com/current/user-manual/api/reference.html",
        "purpose": "Full endpoint reference generated from the OpenAPI spec. "
                   "Lists every endpoint with parameters, responses, and RBAC requirements.",
        "app_usage": "Ground truth for endpoint names, HTTP methods, and required parameters.",
        "icon": "Code2",
    },
]
