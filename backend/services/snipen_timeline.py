"""Timeline builder for Snipen host-event analysis."""
from __future__ import annotations

import statistics
from datetime import datetime, timedelta, timezone

from schemas.types import SnipenEvent, TimelinePointDTO


def build_timeline(
    events: list[SnipenEvent],
    hours: int = 24,
    num_buckets: int = 24,
) -> list[TimelinePointDTO]:
    """
    Divide the time window into `num_buckets` equal buckets and count events
    per bucket.  Buckets above mean + 1.5 × stddev are flagged as peaks;
    above mean + 2.5 × stddev as anomalies.
    """
    if not events:
        bucket_duration = timedelta(hours=hours) / num_buckets
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        return [
            TimelinePointDTO(
                bucket_start=(start + bucket_duration * i).isoformat(),
                bucket_end=(start + bucket_duration * (i + 1)).isoformat(),
                event_count=0,
            )
            for i in range(num_buckets)
        ]

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=hours)
    bucket_duration = timedelta(hours=hours) / num_buckets

    bucket_starts = [window_start + bucket_duration * i for i in range(num_buckets)]
    bucket_ends = [window_start + bucket_duration * (i + 1) for i in range(num_buckets)]
    counts: list[int] = [0] * num_buckets

    for ev in events:
        ts_str = ev.smart.timestamp
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except (ValueError, AttributeError):
            continue

        if ts < window_start or ts > now:
            continue
        idx = int((ts - window_start).total_seconds() / bucket_duration.total_seconds())
        idx = max(0, min(num_buckets - 1, idx))
        counts[idx] += 1

    # Peak / anomaly thresholds via mean + k×stddev
    if len(counts) >= 2:
        mean = statistics.mean(counts)
        try:
            stdev = statistics.stdev(counts)
        except statistics.StatisticsError:
            stdev = 0.0
        peak_threshold = mean + max(1.5 * stdev, 1.0)
        anomaly_threshold = mean + max(2.5 * stdev, 2.0)
    else:
        peak_threshold = float(max(counts)) if counts else 1.0
        anomaly_threshold = peak_threshold + 1.0

    result: list[TimelinePointDTO] = []
    for i in range(num_buckets):
        c = counts[i]
        result.append(
            TimelinePointDTO(
                bucket_start=bucket_starts[i].isoformat(),
                bucket_end=bucket_ends[i].isoformat(),
                event_count=c,
                is_peak=c > 0 and c >= peak_threshold,
                is_anomaly=c > 0 and c >= anomaly_threshold,
            )
        )
    return result
