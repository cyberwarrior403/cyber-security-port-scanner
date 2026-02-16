from __future__ import annotations

from dataclasses import dataclass


SEVERITY_POINTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}


@dataclass(frozen=True)
class RiskSummary:
    critical: int
    high: int
    medium: int
    low: int


def compute_risk(services: list[dict]) -> tuple[int, int, str, RiskSummary]:
    """
    Returns:
      - total_points (int)
      - percent (0..100 int)
      - risk_level (string)
      - summary counts by severity
    """
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    total_points = 0

    for svc in services:
        sev = str(svc.get("severity") or "").lower().strip()
        if sev not in SEVERITY_POINTS:
            sev = "low"
        counts[sev] += 1
        total_points += SEVERITY_POINTS[sev]

    # Dynamic max based on number of findings
    max_points = max(1, len(services) * SEVERITY_POINTS["critical"])
    percent = int(round((total_points / max_points) * 100))
    percent = max(0, min(100, percent))

    if percent >= 80:
        risk_level = "critical"
    elif percent >= 55:
        risk_level = "high"
    elif percent >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return (
        total_points,
        percent,
        risk_level,
        RiskSummary(
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
        ),
    )

