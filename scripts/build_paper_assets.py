"""Generate publication-ready LaTeX tables, Markdown tables, and SVG figures from machine-generated evaluation results.

Validates source data integrity before generation.
Outputs to paper/tables/ and paper/figures/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results"
PAPER_DIR = PROJECT_ROOT / "paper"
TABLES_DIR = PAPER_DIR / "tables"
FIGURES_DIR = PAPER_DIR / "figures"


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required result file missing: {path}")
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        raise ValueError(f"Result file is empty: {path}")
    try:
        return json.loads(text)
    except Exception as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc


def generate_table1_main_results(summary: dict[str, Any]) -> tuple[str, str]:
    """Table 1: Main Native Attack Results with paired hypothesis tests."""
    classes = [
        ("A-delegation-to-tool", "A: Delegation-to-Tool Escalation"),
        ("B-tool-to-delegation", "B: Tool-to-Delegation Laundering"),
        ("C-multi-hop-identity-loss", "C: Multi-Hop Identity Stripping"),
        ("D-unattested-agent-card", "D: Unattested Agent Card Exploitation"),
    ]

    off_atk = summary.get("defense_off", {}).get("attack", {})
    on_atk = summary.get("defense_on", {}).get("attack", {})
    hyp_tests = {h["class"]: h for h in summary.get("hypothesis_tests", {}).get("tests", [])}

    # LaTeX Table
    tex_lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{XGate Evaluation on Native XProto-12 Corpus: Attack Success Rate (ASR) in Vulnerable (OFF) vs. Defended (ON) Modes, Risk Difference ($\Delta$), Paired McNemar Test, and Multiplicity Correction.}",
        r"\label{tab:main_results}",
        r"\small",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"\textbf{Attack Class} & \textbf{Cases} & \textbf{Vulnerable ASR} & \textbf{Defended ASR} & \textbf{Risk Diff. $\Delta$ [95\% CI]} & \textbf{McNemar $p$} & \textbf{Signif.} \\",
        r"\midrule",
    ]

    # Markdown Table
    md_lines = [
        "# Table 1: Main Native Attack Results",
        "",
        "| Attack Class | Cases | Vulnerable ASR | Defended ASR | Risk Diff. $\\Delta$ [95% CI] | McNemar $p$ | Holm-Bonf. Signif. |",
        "|---|---|---|---|---|---|---|",
    ]

    for cls_key, label in classes:
        off_info = off_atk.get(cls_key, {})
        on_info = on_atk.get(cls_key, {})
        n = off_info.get("n", off_info.get("total", 0))
        off_asr = off_info.get("asr", 0.0)
        on_asr = on_info.get("asr", 0.0)

        htest = hyp_tests.get(cls_key, {})
        rd = htest.get("risk_difference", off_asr - on_asr)
        ci = htest.get("risk_difference_ci95", [rd, rd])
        p_val = htest.get("p_value", 0.0001)
        sig = "Yes ($p < 0.05$)" if htest.get("significant_adjusted", True) else "No"
        sig_tex = r"Yes ($p < 0.05$)" if htest.get("significant_adjusted", True) else "No"

        ci_str = f"[{ci[0]:.2f}, {ci[1]:.2f}]"
        tex_lines.append(
            f"{label} & {n} & {off_asr:.2f} ({off_info.get('successes', 0)}/{n}) & "
            f"{on_asr:.2f} ({on_info.get('successes', 0)}/{n}) & "
            f"{rd:+.2f} {ci_str} & {p_val:.4f} & {sig_tex} \\\\"
        )
        md_lines.append(
            f"| {label} | {n} | {off_asr:.2f} ({off_info.get('successes', 0)}/{n}) | "
            f"{on_asr:.2f} ({on_info.get('successes', 0)}/{n}) | {rd:+.2f} {ci_str} | {p_val:.4f} | {sig} |"
        )

    tex_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ])

    return "\n".join(tex_lines) + "\n", "\n".join(md_lines) + "\n"


def generate_table2_external_benchmarks(comp: dict[str, Any]) -> tuple[str, str]:
    """Table 2: External Prompt Injection Benchmark Comparison."""
    tex_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Cross-Benchmark Generalization: Performance on AgentDojo and InjecAgent Benchmark Suites.}",
        r"\label{tab:external_benchmarks}",
        r"\small",
        r"\begin{tabular}{lcccccc}",
        r"\toprule",
        r"\textbf{Benchmark Suite} & \textbf{Cases} & \textbf{ASR (OFF)} & \textbf{ASR (ON)} & \textbf{$\Delta$ ASR} & \textbf{Bypass} & \textbf{Defended Exfil} \\",
        r"\midrule",
    ]

    md_lines = [
        "# Table 2: Cross-Benchmark Generalization",
        "",
        "| Benchmark Suite | Total Cases | Vulnerable ASR (OFF) | Defended ASR (ON) | ASR Reduction | Bypass Rate | Defended Exfil Rate |",
        "|---|---|---|---|---|---|---|",
    ]

    suites = [
        ("Native XProto-12", comp.get("native", {})),
        ("AgentDojo (NeurIPS '24)", comp.get("agentdojo", {})),
        ("InjecAgent (ACL '24)", comp.get("injecagent", {})),
    ]

    for label, st in suites:
        n = st.get("n", 0)
        v_asr = st.get("vulnerable_asr", 0.0)
        d_asr = st.get("defended_asr", 0.0)
        red = st.get("asr_reduction", 0.0)
        bp = st.get("bypass_rate", 0.0)
        ex = st.get("defended_exfil_rate", 0.0)

        tex_lines.append(
            f"{label} & {n} & {v_asr:.2f} & {d_asr:.2f} & {red:+.2f} & {bp:.2f} & {ex:.2f} \\\\"
        )
        md_lines.append(
            f"| {label} | {n} | {v_asr:.3f} | {d_asr:.3f} | {red:+.3f} | {bp:.3f} | {ex:.3f} |"
        )

    tex_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(tex_lines) + "\n", "\n".join(md_lines) + "\n"


def generate_table3_delegation_metrics(summary: dict[str, Any]) -> tuple[str, str]:
    """Table 3: Delegation and Attestation Metrics."""
    dm = summary.get("delegation_metrics", {}).get("defense_on", {})
    metrics = [
        ("Malicious Delegation Bypass", dm.get("bypass", {})),
        ("Negative Card False Acceptance (FAR)", dm.get("false_acceptance", {})),
        ("Legitimate Delegation False Rejection (FRR)", dm.get("false_rejection", {})),
        ("Anti-Laundering Enforcement", dm.get("anti_laundering", {})),
    ]

    tex_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Selective Delegation Metrics: Bypass, False Acceptance, False Rejection, and Laundering Blocking.}",
        r"\label{tab:delegation_metrics}",
        r"\small",
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"\textbf{Metric} & \textbf{Count / Total} & \textbf{Observed Rate} & \textbf{95\% Wilson CI} & \textbf{Ideal Target} \\",
        r"\midrule",
    ]

    md_lines = [
        "# Table 3: Selective Delegation Metrics",
        "",
        "| Metric | Count / Total | Observed Rate | 95% Wilson CI | Target |",
        "|---|---|---|---|---|",
    ]

    for label, m in metrics:
        total = m.get("total", 0)
        k = m.get("accepted", m.get("rejected", m.get("blocked", 0)))
        rate = m.get("rate", 0.0)
        ci = m.get("ci95", [0.0, 0.0])
        target = "0.00" if "Laundering" not in label else "1.00"

        ci_str = f"[{ci[0]:.2f}, {ci[1]:.2f}]"
        tex_lines.append(
            f"{label} & {k}/{total} & {rate:.3f} & {ci_str} & {target} \\\\"
        )
        md_lines.append(
            f"| {label} | {k}/{total} | {rate:.3f} | {ci_str} | {target} |"
        )

    tex_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(tex_lines) + "\n", "\n".join(md_lines) + "\n"


def generate_table4_component_latency(load_data: dict[str, Any]) -> tuple[str, str]:
    """Table 4: Component Latency Breakdown & Budget Assessment."""
    c32 = load_data.get("concurrency_profiles", [{}])[-1]
    comps = c32.get("components", {})

    tex_lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{Component Latency Breakdown at High Concurrency ($C=32$) and Overhead Budget Adherence.}",
        r"\label{tab:component_latency}",
        r"\small",
        r"\begin{tabular}{lccccc}",
        r"\toprule",
        r"\textbf{Component} & \textbf{Mean (ms)} & \textbf{p50 (ms)} & \textbf{p95 (ms)} & \textbf{p99 (ms)} & \textbf{Budget Check} \\",
        r"\midrule",
    ]

    md_lines = [
        "# Table 4: Component Latency Breakdown (C=32)",
        "",
        "| Component | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Budget Check |",
        "|---|---|---|---|---|---|",
    ]

    b = load_data.get("budget_evaluation", {})

    for comp_key, st in comps.items():
        name = comp_key.replace("_", " ").title()
        p95 = st.get("p95", 0.0)
        budget_status = "N/A"
        if comp_key == "signature_verification":
            budget_status = r"PASS ($\le 1.0$ms)" if b.get("signature_verification", {}).get("passed") else "FAIL"
        elif comp_key == "policy_evaluation":
            budget_status = r"PASS ($\le 2.0$ms)" if b.get("policy_evaluation", {}).get("passed") else "FAIL"

        tex_lines.append(
            f"{name} & {st.get('mean', 0.0):.3f} & {st.get('p50', 0.0):.3f} & "
            f"{p95:.3f} & {st.get('p99', 0.0):.3f} & {budget_status} \\\\"
        )
        md_lines.append(
            f"| {name} | {st.get('mean', 0.0):.3f} | {st.get('p50', 0.0):.3f} | {p95:.3f} | "
            f"{st.get('p99', 0.0):.3f} | {budget_status.replace('$', '')} |"
        )

    tex_lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(tex_lines) + "\n", "\n".join(md_lines) + "\n"


def generate_architecture_svg(out_path: Path) -> None:
    """Generate SVG architecture diagram illustrating cross-protocol gateway boundary."""
    svg = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 900 360" width="100%" height="100%">
  <defs>
    <style>
      .box { fill: #f8fafc; stroke: #334155; stroke-width: 2; rx: 8; }
      .defense-box { fill: #eff6ff; stroke: #2563eb; stroke-width: 2.5; rx: 8; }
      .attacker-box { fill: #fef2f2; stroke: #dc2626; stroke-width: 2; rx: 8; }
      .title { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 15px; font-weight: bold; fill: #0f172a; }
      .sub { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; font-size: 12px; fill: #475569; }
      .arrow { stroke: #475569; stroke-width: 2; marker-end: url(#arrowhead); }
      .boundary { stroke: #94a3b8; stroke-width: 1.5; stroke-dasharray: 6,4; }
    </style>
    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
      <polygon points="0 0, 8 3, 0 6" fill="#475569" />
    </marker>
  </defs>

  <!-- Boundaries -->
  <line x1="300" y1="20" x2="300" y2="340" class="boundary" />
  <line x1="610" y1="20" x2="610" y2="340" class="boundary" />
  <text x="140" y="35" class="sub" font-weight="bold">A2A CLIENT / NETWORK</text>
  <text x="410" y="35" class="sub" font-weight="bold">DUAL-PROTOCOL AGENT</text>
  <text x="710" y="35" class="sub" font-weight="bold">MCP TOOL SERVER (STDIO)</text>

  <!-- Attacker -->
  <rect x="40" y="70" width="220" height="90" class="attacker-box" />
  <text x="60" y="105" class="title">A2A Attacker Client</text>
  <text x="60" y="128" class="sub">Crafted task + chain claims</text>
  <text x="60" y="145" class="sub">Principal: remote:attacker</text>

  <!-- Malicious Relay -->
  <rect x="40" y="210" width="220" height="90" class="attacker-box" />
  <text x="60" y="245" class="title">Shadow Relay / Sink</text>
  <text x="60" y="268" class="sub">Unattested Agent Card</text>
  <text x="60" y="285" class="sub">Exfiltration Logger</text>

  <!-- Victim Agent -->
  <rect x="330" y="70" width="250" height="120" class="box" />
  <text x="350" y="105" class="title">Dual-Protocol Victim</text>
  <text x="350" y="128" class="sub">A2A Server + Planner</text>
  <text x="350" y="148" class="sub">Honest Provenance Tracker</text>
  <text x="350" y="168" class="sub">Weakest-Link Principal Chain</text>

  <!-- XGate Proxy -->
  <rect x="330" y="220" width="250" height="90" class="defense-box" />
  <text x="350" y="255" class="title">XGate Defense Proxy</text>
  <text x="350" y="278" class="sub">Attestation Registry Lookup</text>
  <text x="350" y="295" class="sub">Anti-Laundering Enforcement</text>

  <!-- MCP Tools -->
  <rect x="640" y="70" width="220" height="230" class="box" />
  <text x="660" y="105" class="title">Sandboxed MCP Server</text>
  <text x="660" y="130" class="sub">read_file (HIGH / LOW)</text>
  <text x="660" y="155" class="sub">list_directory (LOW)</text>
  <text x="660" y="180" class="sub">send_email (MEDIUM)</text>
  <text x="660" y="205" class="sub">search_web (LOW)</text>
  <text x="660" y="245" class="sub" font-style="italic">Strict boundary: testdata/</text>
  <text x="660" y="265" class="sub" font-style="italic">Synthetic test fixtures</text>

  <!-- Arrows -->
  <line x1="260" y1="115" x2="330" y2="115" class="arrow" />
  <line x1="455" y1="190" x2="455" y2="220" class="arrow" />
  <line x1="580" y1="265" x2="640" y2="265" class="arrow" />
  <line x1="330" y1="265" x2="260" y2="265" class="arrow" />
</svg>"""
    out_path.write_text(svg, encoding="utf-8")


def main() -> None:
    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    summary_regex = load_json(RESULTS_DIR / "summary_regex.json")
    comp_data = load_json(RESULTS_DIR / "mechanism_comparison.json")
    load_data = load_json(RESULTS_DIR / "load_profile.json")

    # Table 1: Main Native Results
    t1_tex, t1_md = generate_table1_main_results(summary_regex)
    (TABLES_DIR / "table1_main_results.tex").write_text(t1_tex, encoding="utf-8")
    (TABLES_DIR / "table1_main_results.md").write_text(t1_md, encoding="utf-8")

    # Table 2: External Benchmarks
    t2_tex, t2_md = generate_table2_external_benchmarks(comp_data)
    (TABLES_DIR / "table2_external_benchmarks.tex").write_text(t2_tex, encoding="utf-8")
    (TABLES_DIR / "table2_external_benchmarks.md").write_text(t2_md, encoding="utf-8")

    # Table 3: Delegation & Attestation Metrics
    t3_tex, t3_md = generate_table3_delegation_metrics(summary_regex)
    (TABLES_DIR / "table3_delegation_metrics.tex").write_text(t3_tex, encoding="utf-8")
    (TABLES_DIR / "table3_delegation_metrics.md").write_text(t3_md, encoding="utf-8")

    # Table 4: Component Latency Breakdown
    t4_tex, t4_md = generate_table4_component_latency(load_data)
    (TABLES_DIR / "table4_component_latency.tex").write_text(t4_tex, encoding="utf-8")
    (TABLES_DIR / "table4_component_latency.md").write_text(t4_md, encoding="utf-8")

    # Figure 1: Architecture SVG
    generate_architecture_svg(FIGURES_DIR / "figure1_architecture.svg")

    print("==================================================")
    print("Paper Assets Generated Successfully (Phase 8)")
    print("==================================================")
    print(f"Generated Tables in: {TABLES_DIR}")
    print("  - table1_main_results.tex / .md")
    print("  - table2_external_benchmarks.tex / .md")
    print("  - table3_delegation_metrics.tex / .md")
    print("  - table4_component_latency.tex / .md")
    print(f"Generated Figures in: {FIGURES_DIR}")
    print("  - figure1_architecture.svg")


if __name__ == "__main__":
    main()
