"""Simulation-based statistical power analysis for XProto-12 confirmatory study.

Evaluates statistical power as a function of trials per scenario, effect size,
and multiplicity correction (Holm-Bonferroni over 4 hypothesis classes).
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from xproto.stats import holm_bonferroni, mcnemar_test, simulate_power

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_power_analysis(
    sample_sizes: list[int] | None = None,
    effect_sizes: list[float] | None = None,
    alpha: float = 0.05,
    n_sims: int = 2000,
) -> dict:
    sizes = sample_sizes or [1, 2, 3, 5, 10, 15, 20]
    effects = effect_sizes or [0.50, 0.70, 0.80, 0.90, 1.00]
    m_classes = 4  # Classes A, B, C, D

    # For Holm-Bonferroni with 4 hypotheses, the strictest threshold is alpha / 4
    alpha_adjusted = alpha / m_classes

    results_grid: dict[str, dict[str, float]] = {}

    for n in sizes:
        results_grid[str(n)] = {}
        for delta in effects:
            p_off = 1.0
            p_on = 1.0 - delta
            # Power calculated under adjusted alpha to guarantee FWER control
            pwr = simulate_power(
                n_trials_per_scenario=n,
                n_scenarios=3,
                p_off=p_off,
                p_on=p_on,
                alpha=alpha_adjusted,
                n_sims=n_sims,
            )
            results_grid[str(n)][f"delta_{delta:.2f}"] = pwr

    # Determine recommended minimum trials
    recommended_trials = 10
    for n in sizes:
        # Check if power >= 0.80 for target effect delta = 0.80
        if results_grid[str(n)].get("delta_0.80", 0.0) >= 0.80:
            recommended_trials = n
            break

    summary = {
        "alpha": alpha,
        "hypotheses_count": m_classes,
        "alpha_strictest_threshold": alpha_adjusted,
        "simulations_per_point": n_sims,
        "power_grid": results_grid,
        "target_effect_size": 0.80,
        "power_target": 0.80,
        "minimum_trials_for_80_pct_power": recommended_trials,
    }

    out_file = PROJECT_ROOT / "study" / "power_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    return summary


def main():
    parser = argparse.ArgumentParser(description="XProto-12 Simulation Power Analysis")
    parser.add_argument("--sims", type=int, default=2000, help="Number of Monte Carlo simulations per parameter combination")
    parser.add_argument("--alpha", type=float, default=0.05, help="Family-wise significance level")
    args = parser.parse_args()

    print(f"Running simulation power analysis (sims={args.sims}, alpha={args.alpha})...")
    summary = run_power_analysis(alpha=args.alpha, n_sims=args.sims)

    print("\n--- Power Grid (Trials per Scenario vs Effect Size Delta) ---")
    header = f"{'Trials/Scen':<12} | " + " | ".join(f"{d:<10}" for d in ["d=0.50", "d=0.70", "d=0.80", "d=0.90", "d=1.00"])
    print(header)
    print("-" * len(header))

    grid = summary["power_grid"]
    for n, row in grid.items():
        row_str = f"{n:<12} | " + " | ".join(f"{row.get(f'delta_{d:.2f}', 0.0):<10.4f}" for d in [0.50, 0.70, 0.80, 0.90, 1.00])
        print(row_str)

    print(f"\nMinimum trials per scenario for >=80% power at target Delta=0.80: {summary['minimum_trials_for_80_pct_power']}")
    print(f"Results saved to study/power_results.json")


if __name__ == "__main__":
    main()
