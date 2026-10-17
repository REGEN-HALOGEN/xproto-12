"""Unit tests for Phase 5 statistical algorithms and hypothesis tests."""

import math
import pytest

from xproto.stats import (
    holm_bonferroni,
    latency_summary,
    mcnemar_test,
    newcombe_risk_difference_interval,
    percentile,
    risk_ratio_interval,
    simulate_power,
    wilson_interval,
)


def test_wilson_interval_bounds():
    lo, hi = wilson_interval(10, 10)
    assert 0.65 < lo < 1.0
    assert hi == 1.0

    lo, hi = wilson_interval(0, 10)
    assert lo == 0.0
    assert 0.0 < hi < 0.35

    lo, hi = wilson_interval(5, 10)
    assert 0.2 < lo < 0.5
    assert 0.5 < hi < 0.8
    assert lo <= 0.5 <= hi


def test_newcombe_risk_difference():
    # Maximum difference: 10/10 vs 0/10
    rd, lo, hi = newcombe_risk_difference_interval(10, 10, 0, 10)
    assert rd == 1.0
    assert lo > 0.5
    assert hi <= 1.0

    # Minimum difference: 0/10 vs 10/10
    rd, lo, hi = newcombe_risk_difference_interval(0, 10, 10, 10)
    assert rd == -1.0
    assert lo >= -1.0
    assert hi < -0.5

    # Zero difference: 5/10 vs 5/10
    rd, lo, hi = newcombe_risk_difference_interval(5, 10, 5, 10)
    assert rd == 0.0
    assert lo < 0.0 < hi


def test_risk_ratio_interval():
    # Regular case without zero
    rr, lo, hi = risk_ratio_interval(8, 10, 2, 10)
    assert rr is not None
    assert rr == 4.0
    assert lo < 4.0 < hi

    # Continuity correction case with 0 events in control
    rr_zero, lo_zero, hi_zero = risk_ratio_interval(10, 10, 0, 10)
    assert rr_zero is not None
    assert rr_zero > 1.0
    assert lo_zero is not None and lo_zero > 1.0


def test_mcnemar_test_exact_and_asymptotic():
    # Small sample (exact binomial): b=10, c=0
    stat, p_val = mcnemar_test(10, 0)
    assert stat == 0.0
    assert p_val < 0.005  # Highly significant

    # Small sample symmetric: b=5, c=5
    stat, p_val = mcnemar_test(5, 5)
    assert p_val > 0.9  # Not significant

    # Large sample (chi-square asymptotic): b=30, c=5
    stat, p_val = mcnemar_test(30, 5)
    assert stat > 10.0
    assert p_val < 0.0001


def test_holm_bonferroni_adjustment():
    raw_p = [0.001, 0.04, 0.015, 0.20]
    res = holm_bonferroni(raw_p, alpha=0.05)

    assert len(res) == 4
    # Check that rank 1 (0.001) is significant
    assert res[0]["raw_p"] == 0.001
    assert res[0]["significant"] is True

    # Check rank 2 (0.015) vs threshold 0.05 / 3 = 0.0167
    assert res[2]["raw_p"] == 0.015
    assert res[2]["significant"] is True

    # Check that 0.20 is not significant
    assert res[3]["raw_p"] == 0.20
    assert res[3]["significant"] is False


def test_latency_summary_and_percentiles():
    data = [10.0, 12.0, 14.0, 15.0, 16.0, 18.0, 20.0, 22.0, 50.0, 100.0]
    p50 = percentile(data, 50.0)
    assert 15.0 <= p50 <= 17.0

    summary = latency_summary(data, n_bootstrap=200, seed=123)
    assert summary["count"] == 10
    assert summary["mean"] > summary["median"]
    assert summary["p95"] > summary["median"]
    assert summary["p99"] >= summary["p95"]
    assert len(summary["ci95_median"]) == 2
    assert summary["ci95_median"][0] <= summary["median"] <= summary["ci95_median"][1]


def test_simulation_power():
    # Power for complete separation (1.0 vs 0.0) should be 1.0 with 10 trials
    power_high = simulate_power(
        n_trials_per_scenario=10,
        n_scenarios=3,
        p_off=1.0,
        p_on=0.0,
        alpha=0.05,
        n_sims=100,
    )
    assert power_high == 1.0

    # Power under null hypothesis (0.5 vs 0.5) should be close to alpha
    power_null = simulate_power(
        n_trials_per_scenario=10,
        n_scenarios=3,
        p_off=0.5,
        p_on=0.5,
        alpha=0.05,
        n_sims=500,
    )
    assert power_null < 0.15


def test_build_summary_paired_hypotheses_and_latency():
    from xproto.config import PlannerConfig
    from xproto.eval import build_summary

    off = {
        "attack": {"A-delegation-to-tool": {"asr": 1.0, "ci95": [0.4, 1.0]}},
        "latency_mean_ms": 1.2,
        "trials": [
            {
                "trial_id": "regex_off_a1_0",
                "scenario_id": "a1",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "defense_on": False,
                "success": True,
                "task_state": "TASK_STATE_COMPLETED",
                "latencies": [1.0, 1.4],
                "planner_telemetry": [],
            },
            {
                "trial_id": "regex_off_a2_0",
                "scenario_id": "a2",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "defense_on": False,
                "success": True,
                "task_state": "TASK_STATE_COMPLETED",
                "latencies": [1.1, 1.3],
                "planner_telemetry": [],
            },
        ],
    }

    on = {
        "attack": {"A-delegation-to-tool": {"asr": 0.0, "ci95": [0.0, 0.6]}},
        "latency_mean_ms": 3.5,
        "trials": [
            {
                "trial_id": "regex_on_a1_0",
                "scenario_id": "a1",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "defense_on": True,
                "success": False,
                "task_state": "TASK_STATE_FAILED",
                "latencies": [3.2, 3.8],
                "planner_telemetry": [],
            },
            {
                "trial_id": "regex_on_a2_0",
                "scenario_id": "a2",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "defense_on": True,
                "success": False,
                "task_state": "TASK_STATE_FAILED",
                "latencies": [3.1, 3.9],
                "planner_telemetry": [],
            },
        ],
    }

    cfg = PlannerConfig(planner_type="regex")
    summary = build_summary(off, on, cfg, n_trials=1, suite="native")

    assert "hypotheses" in summary
    assert len(summary["hypotheses"]) == 4
    h1 = next(h for h in summary["hypotheses"] if h["hypothesis"] == "H1")
    assert h1["pairs"] == 2
    assert h1["defense_off"]["asr"] == 1.0
    assert h1["defense_on"]["asr"] == 0.0
    assert h1["risk_difference"] == 1.0
    assert h1["contingency_table"]["n10_off_only"] == 2

    assert "latency_distribution" in summary
    assert summary["latency_distribution"]["defense_off"]["count"] == 4
    assert summary["latency_distribution"]["defense_on"]["count"] == 4
    assert summary["latency_distribution"]["overhead"]["mean_overhead_ms"] > 0

    assert "exclusions" in summary
    assert summary["exclusions"]["total_trials"] == 4
    assert summary["exclusions"]["excluded_trials"] == 0


def test_build_run_manifest_provenance():
    from xproto.config import PlannerConfig
    from xproto.eval import build_run_manifest, build_summary

    off = {
        "attack": {},
        "latency_mean_ms": 1.0,
        "trials": [
            {
                "trial_id": "regex_off_a1_0",
                "scenario_id": "a1",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "seed": 42,
                "defense_on": False,
                "success": True,
                "task_state": "TASK_STATE_COMPLETED",
                "latencies": [1.0],
                "planner_telemetry": [],
                "log_dir": "results/trials/dummy",
                "attempted_access": True,
                "content_exfiltrated": True,
            }
        ],
    }
    on = {
        "attack": {},
        "latency_mean_ms": 2.0,
        "trials": [
            {
                "trial_id": "regex_on_a1_0",
                "scenario_id": "a1",
                "class": "A-delegation-to-tool",
                "trial_idx": 0,
                "seed": 42,
                "defense_on": True,
                "success": False,
                "task_state": "TASK_STATE_FAILED",
                "latencies": [2.0],
                "planner_telemetry": [],
                "log_dir": "results/trials/dummy",
                "attempted_access": True,
                "content_exfiltrated": False,
            }
        ],
    }
    cfg = PlannerConfig(planner_type="regex")
    summary = build_summary(off, on, cfg, n_trials=1, suite="native")
    manifest = build_run_manifest(off, on, cfg, n_trials=1, suite="native", summary=summary)

    assert manifest["manifest_version"] == "1.0.0"
    assert "git" in manifest and "commit" in manifest["git"]
    assert "protocol" in manifest and manifest["protocol"]["sha256"] != "file_not_found"
    assert "environment" in manifest and "python" in manifest["environment"]
    assert "power_analysis" in manifest
    assert len(manifest["observations"]) == 2
    assert manifest["observations"][0]["seed"] == 42
    assert manifest["observations"][0]["scenario_id"] == "a1"

