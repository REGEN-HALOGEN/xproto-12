"""Statistical algorithms, effect size calculations, and hypothesis testing for XProto-12.

Provides:
- Wilson score confidence intervals for proportions
- Newcombe hybrid score confidence intervals for Risk Differences (RD)
- Katz log-transformed Wald intervals for Risk Ratios (RR)
- McNemar test for paired binary outcomes (exact binomial and continuity-adjusted)
- Holm-Bonferroni step-down multiplicity correction
- Nonparametric bootstrap intervals for latency percentiles (median, p95, p99)
- Simulation-based power analysis routines
"""

from __future__ import annotations

import math
import random
from typing import Sequence


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score confidence interval for a single proportion (default 95% CI)."""
    if n <= 0:
        return 0.0, 0.0
    p = k / n
    denom = 1.0 + (z * z) / n
    center = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + (z * z) / (4.0 * n * n))) / denom
    return max(0.0, center - half), min(1.0, center + half)


def newcombe_risk_difference_interval(
    k1: int, n1: int, k2: int, n2: int, z: float = 1.96
) -> tuple[float, float, float]:
    """Newcombe Hybrid Score confidence interval for the Risk Difference (p1 - p2).

    Returns (rd, lower_bound, upper_bound).
    """
    if n1 <= 0 or n2 <= 0:
        return 0.0, 0.0, 0.0

    p1 = k1 / n1
    p2 = k2 / n2
    rd = p1 - p2

    l1, u1 = wilson_interval(k1, n1, z=z)
    l2, u2 = wilson_interval(k2, n2, z=z)

    lower = rd - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    upper = rd + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)

    return round(rd, 4), max(-1.0, round(lower, 4)), min(1.0, round(upper, 4))


def risk_ratio_interval(
    k1: int, n1: int, k2: int, n2: int, z: float = 1.96
) -> tuple[float | None, float | None, float | None]:
    """Katz log-transformed Wald interval for the Risk Ratio (p1 / p2).

    Returns (rr, lower_bound, upper_bound).
    Uses standard 0.5 continuity adjustment if zero events are observed.
    """
    if n1 <= 0 or n2 <= 0:
        return None, None, None

    # Apply 0.5 continuity correction if either count is 0
    if k1 == 0 or k2 == 0:
        adj_k1, adj_n1 = k1 + 0.5, n1 + 0.5
        adj_k2, adj_n2 = k2 + 0.5, n2 + 0.5
    else:
        adj_k1, adj_n1 = float(k1), float(n1)
        adj_k2, adj_n2 = float(k2), float(n2)

    p1 = adj_k1 / adj_n1
    p2 = adj_k2 / adj_n2

    rr = p1 / p2
    log_rr = math.log(rr)
    se_log = math.sqrt((1.0 - p1) / (adj_n1 * p1) + (1.0 - p2) / (adj_n2 * p2))

    lower = math.exp(log_rr - z * se_log)
    upper = math.exp(log_rr + z * se_log)

    return round(rr, 4), round(lower, 4), round(upper, 4)


def mcnemar_test(b: int, c: int) -> tuple[float, float]:
    """McNemar test for paired discordant binary outcomes.

    b: Number of pairs where (treatment1=Success, treatment2=Failure)
    c: Number of pairs where (treatment1=Failure, treatment2=Success)

    Returns (statistic, p_value).
    Uses exact two-sided binomial test when b + c < 25, continuity-corrected chi2 otherwise.
    """
    n_discordant = b + c
    if n_discordant == 0:
        return 0.0, 1.0

    if n_discordant < 25:
        # Exact two-sided binomial test with p = 0.5
        min_k = min(b, c)
        prob = 0.0
        for i in range(min_k + 1):
            prob += math.comb(n_discordant, i) * (0.5**n_discordant)
        p_val = min(1.0, 2.0 * prob)
        return float(min_k), round(p_val, 6)

    # Continuity-corrected Chi-Square statistic: (|b - c| - 1)^2 / (b + c)
    chi2_stat = ((abs(b - c) - 1.0) ** 2) / n_discordant

    # p-value from chi2 with 1 degree of freedom: erfc(sqrt(x/2))
    p_val = math.erfc(math.sqrt(chi2_stat / 2.0))
    return round(chi2_stat, 4), round(p_val, 6)


def holm_bonferroni(
    p_values: Sequence[float], alpha: float = 0.05
) -> list[dict[str, float | bool | int]]:
    """Apply Holm-Bonferroni step-down procedure to control Family-Wise Error Rate (FWER).

    Returns a list of dicts corresponding to original order with:
    - index: original index
    - raw_p: raw p-value
    - adjusted_p: adjusted p-value
    - threshold: significance threshold
    - significant: boolean decision
    """
    m = len(p_values)
    if m == 0:
        return []

    # Sort p-values with original indices
    indexed = sorted(enumerate(p_values), key=lambda x: x[1])
    results = [None] * m

    cumulative_p = 0.0
    reject = True

    for rank, (orig_idx, p) in enumerate(indexed, start=1):
        threshold = alpha / (m - rank + 1)
        # Holm adjusted p-value
        adj_p = min(1.0, max(cumulative_p, p * (m - rank + 1)))
        cumulative_p = adj_p

        if p > threshold:
            reject = False

        results[orig_idx] = {
            "index": orig_idx,
            "raw_p": round(p, 6),
            "adjusted_p": round(adj_p, 6),
            "threshold": round(threshold, 6),
            "significant": reject,
        }

    return results


def percentile(data: Sequence[float], q: float) -> float:
    """Compute q-th percentile of data (q in [0, 100])."""
    if not data:
        return 0.0
    s = sorted(data)
    n = len(s)
    if n == 1:
        return s[0]
    rank = (q / 100.0) * (n - 1)
    low = int(math.floor(rank))
    high = int(math.ceil(rank))
    weight = rank - low
    return s[low] * (1.0 - weight) + s[high] * weight


def latency_summary(
    latencies: Sequence[float], n_bootstrap: int = 1000, seed: int = 42
) -> dict[str, float | int | list[float]]:
    """Compute distribution statistics and bootstrap intervals for latency data."""
    if not latencies:
        return {
            "count": 0,
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "ci95_mean": [0.0, 0.0],
            "ci95_median": [0.0, 0.0],
        }

    data = list(latencies)
    n = len(data)
    mean_val = sum(data) / n
    median_val = percentile(data, 50.0)
    p95_val = percentile(data, 95.0)
    p99_val = percentile(data, 99.0)

    # Bootstrap intervals for mean and median
    rng = random.Random(seed)
    boot_means = []
    boot_medians = []

    for _ in range(n_bootstrap):
        sample = [rng.choice(data) for _ in range(n)]
        boot_means.append(sum(sample) / n)
        boot_medians.append(percentile(sample, 50.0))

    boot_means.sort()
    boot_medians.sort()

    lower_idx = int(0.025 * n_bootstrap)
    upper_idx = int(0.975 * n_bootstrap)

    return {
        "count": n,
        "mean": round(mean_val, 3),
        "median": round(median_val, 3),
        "p95": round(p95_val, 3),
        "p99": round(p99_val, 3),
        "ci95_mean": [round(boot_means[lower_idx], 3), round(boot_means[upper_idx], 3)],
        "ci95_median": [
            round(boot_medians[lower_idx], 3),
            round(boot_medians[upper_idx], 3),
        ],
    }


def simulate_power(
    n_trials_per_scenario: int,
    n_scenarios: int = 3,
    p_off: float = 1.0,
    p_on: float = 0.0,
    alpha: float = 0.05,
    n_sims: int = 2000,
    seed: int = 42,
) -> float:
    """Monte Carlo simulation to estimate statistical power for detecting ASR reduction.

    n_trials_per_scenario: Number of repeated trials per attack scenario.
    n_scenarios: Number of scenarios in the class (default 3).
    p_off: True probability of success under defense_off.
    p_on: True probability of success under defense_on.
    """
    total_pairs = n_trials_per_scenario * n_scenarios
    if total_pairs <= 0:
        return 0.0

    rng = random.Random(seed)
    rejections = 0

    for _ in range(n_sims):
        # Simulate paired outcomes
        b = 0  # off succeeded, on blocked
        c = 0  # off failed, on bypassed
        for _ in range(total_pairs):
            off_succ = rng.random() < p_off
            on_succ = rng.random() < p_on
            if off_succ and not on_succ:
                b += 1
            elif not off_succ and on_succ:
                c += 1

        _, p_val = mcnemar_test(b, c)
        if p_val < alpha:
            rejections += 1

    return round(rejections / n_sims, 4)
