"""
fetch_example_events.py
=======================
Pulls up to 1000 raw Wazuh alert events from the active connection
and saves them to  <project_root>/Example JSON/

Usage (run from project root):
    python Script/fetch_example_events.py [--hours 72] [--limit 1000] [--host HOSTNAME]

Output:
    Example JSON/events_<timestamp>.json     – all events in one array
    Example JSON/events_split/001.json …     – one file per event
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── path setup ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR  = PROJECT_ROOT / "backend"
OUTPUT_DIR   = PROJECT_ROOT / "Example JSON"
SPLIT_DIR    = OUTPUT_DIR / "events_split"

sys.path.insert(0, str(BACKEND_DIR))

from db.database import get_active_connection
from services.wazuh_indexer import fetch_alerts


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch raw Wazuh events → Example JSON/")
    parser.add_argument("--hours",  type=int,   default=72,    help="Lookback window in hours (default: 72)")
    parser.add_argument("--limit",  type=int,   default=1000,  help="Max events to fetch (default: 1000)")
    parser.add_argument("--host",   type=str,   default=None,  help="Optional: filter by agent hostname (wildcard)")
    parser.add_argument("--split",  action="store_true",       help="Also write one JSON file per event in events_split/")
    args = parser.parse_args()

    # ── active connection ─────────────────────────────────────────────────────
    conn = get_active_connection()
    if not conn:
        print("ERROR: No active Wazuh connection found.\n"
              "       Configure a connection in the app (Settings → Connections) first.",
              file=sys.stderr)
        sys.exit(1)

    print(f"Connection : {conn.get('name', '?')}  →  {conn.get('indexer_url', '?')}")
    print(f"Index      : {conn.get('indexer_index_pattern', 'wazuh-alerts-*')}")
    print(f"Lookback   : {args.hours}h   Limit: {args.limit}   Host filter: {args.host or '(none)'}")
    print("Fetching…")

    # ── fetch ─────────────────────────────────────────────────────────────────
    events = fetch_alerts(
        connection=conn,
        lookback_hours=args.hours,
        query_size=args.limit,
        host_filter=args.host,
    )

    if not events:
        print("WARNING: Server returned 0 events for the given parameters.")
        sys.exit(0)

    print(f"Received   : {len(events)} events")

    # ── output dirs ───────────────────────────────────────────────────────────
    OUTPUT_DIR.mkdir(exist_ok=True)

    # ── bulk file ─────────────────────────────────────────────────────────────
    ts      = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    bulk_path = OUTPUT_DIR / f"events_{ts}.json"

    with bulk_path.open("w", encoding="utf-8") as fh:
        json.dump(events, fh, ensure_ascii=False, indent=2, default=str)

    size_kb = bulk_path.stat().st_size / 1024
    print(f"Saved bulk : {bulk_path.relative_to(PROJECT_ROOT)}  ({size_kb:.1f} KB)")

    # ── split files (optional) ────────────────────────────────────────────────
    if args.split:
        SPLIT_DIR.mkdir(parents=True, exist_ok=True)
        for i, event in enumerate(events, start=1):
            out = SPLIT_DIR / f"{i:04d}.json"
            with out.open("w", encoding="utf-8") as fh:
                json.dump(event, fh, ensure_ascii=False, indent=2, default=str)
        print(f"Saved split: {SPLIT_DIR.relative_to(PROJECT_ROOT)}/  ({len(events)} files)")

    # ── summary ───────────────────────────────────────────────────────────────
    agents   = {e.get("agent", {}).get("name", "?") for e in events if isinstance(e.get("agent"), dict)}
    min_ts   = min((e.get("timestamp", "") for e in events), default="?")
    max_ts   = max((e.get("timestamp", "") for e in events), default="?")

    print(f"\n── Summary ──────────────────────────────────────")
    print(f"  Events   : {len(events)}")
    print(f"  Agents   : {len(agents)}  →  {', '.join(sorted(agents)[:10])}{'…' if len(agents) > 10 else ''}")
    print(f"  Earliest : {min_ts}")
    print(f"  Latest   : {max_ts}")
    print(f"─────────────────────────────────────────────────\n")


if __name__ == "__main__":
    main()
