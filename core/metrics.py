"""Paylasilan Prometheus metrik tanimlari (master_prompt.md 3.4
"Gozlemlenebilirlik"). Asama 2'de commit_to_finding_seconds ve
trigger_detection_seconds (bolum 3.5) eklenecek; Asama 1'de henuz anlamli
degil (Hat A/B yok)."""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

JOBS_CLAIMED_TOTAL = Counter("jobs_claimed_total", "Claim edilen is sayisi", ["job_type"])
JOBS_COMPLETED_TOTAL = Counter(
    "jobs_completed_total", "Tamamlanan is sayisi (sonuca gore)", ["job_type", "status"]
)
JOB_DURATION_SECONDS = Histogram("job_duration_seconds", "Is isleme suresi", ["job_type"])
QUEUE_LENGTH = Gauge("queue_length", "Bekleyen (pending) is sayisi", ["job_type"])
LAST_SUCCESSFUL_CYCLE_TIMESTAMP = Gauge(
    "last_successful_cycle_timestamp_seconds", "Son basarili dongu unix zaman damgasi", ["component"]
)
GITHUB_RATE_LIMIT_REMAINING = Gauge("github_rate_limit_remaining", "Kalan GitHub API rate limit butcesi")
