import type { RunRecord } from '../types';

export interface ComparisonRow {
  className: string;
  label: string;
  runA_asr: number | null;
  runB_asr: number | null;
  runA_n: number;
  runB_n: number;
  delta: number | null;
  deltaText: string;
}

export interface ChartDataPoint {
  className: string;
  shortLabel: string;
  runA_asr: number;
  runB_asr: number;
}

export interface ConfigDiffItem {
  label: string;
  valA: string;
  valB: string;
  changed: boolean;
}

export interface ComparisonResult {
  rows: ComparisonRow[];
  chartData: ChartDataPoint[];
  configDiff: ConfigDiffItem[];
  runA_label: string;
  runB_label: string;
}

export function formatPlannerLabel(planner: RunRecord['config']['planner']): string {
  if (typeof planner === 'string') {
    return planner.toUpperCase();
  }
  const typeStr = planner.type.toUpperCase();
  return planner.model ? `${typeStr} (${planner.model})` : typeStr;
}

export function computeRunComparison(runA: RunRecord, runB: RunRecord): ComparisonResult {
  const runA_label = `${formatPlannerLabel(runA.config.planner)} [Defense ${runA.config.defense_on ? 'ON' : 'OFF'}]`;
  const runB_label = `${formatPlannerLabel(runB.config.planner)} [Defense ${runB.config.defense_on ? 'ON' : 'OFF'}]`;

  // Standard attack classes to include
  const standardClasses = [
    { key: 'Class A: Direct Data Exfiltration', short: 'Class A' },
    { key: 'Class B: Indirect Confused Deputy', short: 'Class B' },
    { key: 'Class C: Cross-Protocol Tool Laundering', short: 'Class C' },
    { key: 'Class D: Agent-to-Agent Delegation Hijack', short: 'Class D' },
  ];

  const attackA = runA.summary?.attack || {};
  const attackB = runB.summary?.attack || {};

  // Collect all unique class keys
  const allClassKeys = new Set<string>();
  standardClasses.forEach((sc) => allClassKeys.add(sc.key));
  Object.keys(attackA).forEach((k) => allClassKeys.add(k));
  Object.keys(attackB).forEach((k) => allClassKeys.add(k));

  const rows: ComparisonRow[] = [];
  const chartData: ChartDataPoint[] = [];

  allClassKeys.forEach((clsKey) => {
    const metricA = attackA[clsKey];
    const metricB = attackB[clsKey];

    const asrA = metricA ? metricA.asr : null;
    const asrB = metricB ? metricB.asr : null;
    const nA = metricA ? metricA.n : 0;
    const nB = metricB ? metricB.n : 0;

    let delta: number | null = null;
    let deltaText = 'N/A';

    if (asrA !== null && asrB !== null) {
      delta = asrB - asrA;
      const sign = delta > 0 ? '+' : '';
      deltaText = `${sign}${delta.toFixed(2)}`;
    } else if (asrB !== null && asrA === null) {
      deltaText = `New: ${asrB.toFixed(2)}`;
    } else if (asrA !== null && asrB === null) {
      deltaText = `Prev: ${asrA.toFixed(2)}`;
    }

    // Short label
    let shortLabel = clsKey;
    const match = clsKey.match(/^Class ([A-D])/);
    if (match) {
      shortLabel = `Class ${match[1]}`;
    }

    rows.push({
      className: clsKey,
      label: shortLabel,
      runA_asr: asrA,
      runB_asr: asrB,
      runA_n: nA,
      runB_n: nB,
      delta,
      deltaText,
    });

    if (asrA !== null || asrB !== null) {
      chartData.push({
        className: clsKey,
        shortLabel,
        runA_asr: asrA !== null ? Math.round(asrA * 100) : 0,
        runB_asr: asrB !== null ? Math.round(asrB * 100) : 0,
      });
    }
  });

  // Overall attack row
  const overallA = runA.summary?.overall_attack?.asr ?? null;
  const overallB = runB.summary?.overall_attack?.asr ?? null;
  let overallDelta: number | null = null;
  let overallDeltaText = 'N/A';
  if (overallA !== null && overallB !== null) {
    overallDelta = overallB - overallA;
    const sign = overallDelta > 0 ? '+' : '';
    overallDeltaText = `${sign}${overallDelta.toFixed(2)}`;
  }

  rows.unshift({
    className: 'overall',
    label: 'Overall Attack ASR',
    runA_asr: overallA,
    runB_asr: overallB,
    runA_n: runA.summary?.overall_attack?.total ?? 0,
    runB_n: runB.summary?.overall_attack?.total ?? 0,
    delta: overallDelta,
    deltaText: overallDeltaText,
  });

  // Config Diff
  const configDiff: ConfigDiffItem[] = [
    {
      label: 'Planner',
      valA: formatPlannerLabel(runA.config.planner),
      valB: formatPlannerLabel(runB.config.planner),
      changed: formatPlannerLabel(runA.config.planner) !== formatPlannerLabel(runB.config.planner),
    },
    {
      label: 'Defense Gate (XGate)',
      valA: runA.config.defense_on ? 'ACTIVE (ON)' : 'DISABLED (OFF)',
      valB: runB.config.defense_on ? 'ACTIVE (ON)' : 'DISABLED (OFF)',
      changed: runA.config.defense_on !== runB.config.defense_on,
    },
    {
      label: 'Trials Per Scenario',
      valA: `${runA.config.trials} trial(s)`,
      valB: `${runB.config.trials} trial(s)`,
      changed: runA.config.trials !== runB.config.trials,
    },
    {
      label: 'Scenario Count',
      valA: `${runA.config.scenario_ids?.length || 0} scenarios`,
      valB: `${runB.config.scenario_ids?.length || 0} scenarios`,
      changed: (runA.config.scenario_ids?.length || 0) !== (runB.config.scenario_ids?.length || 0),
    },
  ];

  return {
    rows,
    chartData,
    configDiff,
    runA_label,
    runB_label,
  };
}
