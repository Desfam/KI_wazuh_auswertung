#!/usr/bin/env python3
"""Simple client for the local Wazuh AI agent API.

Examples:
  python Script/agent_api_client.py chat --message "Was sind die kritischsten Hosts?"
  python Script/agent_api_client.py chat --message "Bitte starte einen 24h Lauf" --run-script --lookback 24
  python Script/agent_api_client.py snipen-query --host SCAN_04_001 --query "zeige suspicious logins" --hours 24 --limit 100
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any


def post_json(url: str, payload: dict[str, Any], timeout: int = 120) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
      with urllib.request.urlopen(req, timeout=timeout) as response:
          return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection failed: {exc}") from exc


def run_chat(args: argparse.Namespace) -> int:
    payload = {
        "message": args.message,
        "run_script": args.run_script,
        "lookback_hours": args.lookback,
        "history": [],
        "report_context": None,
        "report_json_content": None,
        "analysis_profile": None,
    }
    result = post_json(f"{args.base_url.rstrip('/')}/system/chat", payload)

    print("=== Agent Reply ===")
    print(result.get("reply", ""))

    tasks = result.get("generated_tasks") or []
    if tasks:
        print("\n=== Generated Tasks ===")
        for item in tasks[:10]:
            print(f"- {item.get('severity', 'n/a').upper()} | {item.get('host', 'n/a')} | {item.get('title', 'n/a')}")

    if result.get("script_summary"):
        summary = result["script_summary"]
        print("\n=== Script Summary ===")
        print(
            f"lookback={summary.get('lookback_hours')}h, "
            f"total={summary.get('total_alerts')}, relevant={summary.get('relevant_alerts')}"
        )

    return 0


def run_snipen_query(args: argparse.Namespace) -> int:
    payload = {
        "query": args.query,
        "hours": args.hours,
        "limit": args.limit,
    }
    endpoint = f"{args.base_url.rstrip('/')}/snipen/host/{args.host}/ai-query"
    result = post_json(endpoint, payload)

    print("=== Snipen AI Answer ===")
    print(result.get("answer", ""))

    matched = result.get("matched_events") or []
    print(f"\nMatched events: {len(matched)}")
    for ev in matched[:10]:
        smart = ev.get("smart", {})
        print(
            "- "
            f"{smart.get('timestamp', '?')} | "
            f"EID {smart.get('event_id', '?')} | "
            f"Rule {smart.get('rule_id', '?')} | "
            f"{smart.get('rule_description', 'n/a')}"
        )

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Client for local Wazuh AI agent endpoints")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="Backend API base URL")

    sub = parser.add_subparsers(dest="command", required=True)

    chat = sub.add_parser("chat", help="Call /system/chat")
    chat.add_argument("--message", default="", help="User message")
    chat.add_argument("--run-script", action="store_true", help="Trigger VM script run")
    chat.add_argument("--lookback", type=int, default=24, help="Lookback hours")

    snipen = sub.add_parser("snipen-query", help="Call /snipen/host/{host}/ai-query")
    snipen.add_argument("--host", required=True, help="Host name")
    snipen.add_argument("--query", required=True, help="Natural language query")
    snipen.add_argument("--hours", type=int, default=24, help="Lookback hours")
    snipen.add_argument("--limit", type=int, default=100, help="Event limit")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "chat":
        return run_chat(args)
    if args.command == "snipen-query":
        return run_snipen_query(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)
