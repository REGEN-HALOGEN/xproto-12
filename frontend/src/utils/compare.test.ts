import { describe, it, expect } from 'vitest';
import { computeRunComparison, formatPlannerLabel } from './compare';
import type { RunRecord } from '../types';

describe('compare utility', () => {
  const baseRunA: RunRecord = {
    run_id: 'run_baseline_regex',
    status: 'completed',
    started_at: 1000,
    completed_at: 1020,
    config: {
      scenario_ids: ['a1', 'b1'],
      planner: 'regex',
      defense_on: false,
      trials: 1,
    },
    trials: [],
    summary: {
      attack: {
        'Class A: Direct Data Exfiltration': {
          n: 1,
          successes: 1,
          asr: 1.0,
          ci95: [1.0, 1.0],
        },
        'Class B: Indirect Confused Deputy': {
          n: 1,
          successes: 1,
          asr: 1.0,
          ci95: [1.0, 1.0],
        },
      },
      overall_attack: {
        total: 2,
        successes: 2,
        asr: 1.0,
      },
      overall_benign: {
        total: 0,
        completed: 0,
        completion_rate: 0.0,
      },
      latencies: { count: 2, mean_ms: 10, median_ms: 10, p95_ms: 10 },
    },
  };

  const baseRunB: RunRecord = {
    run_id: 'run_eval_llm_defended',
    status: 'completed',
    started_at: 2000,
    completed_at: 2050,
    config: {
      scenario_ids: ['a1', 'b1', 'c1'],
      planner: {
        type: 'openai',
        model: 'gpt-4o',
      },
      defense_on: true,
      trials: 3,
    },
    trials: [],
    summary: {
      attack: {
        'Class A: Direct Data Exfiltration': {
          n: 3,
          successes: 0,
          asr: 0.0,
          ci95: [0.0, 0.0],
        },
        'Class B: Indirect Confused Deputy': {
          n: 3,
          successes: 2,
          asr: 0.67,
          ci95: [0.2, 0.9],
        },
      },
      overall_attack: {
        total: 6,
        successes: 2,
        asr: 0.33,
      },
      overall_benign: {
        total: 0,
        completed: 0,
        completion_rate: 0.0,
      },
      latencies: { count: 6, mean_ms: 25, median_ms: 20, p95_ms: 40 },
    },
  };

  it('correctly formats planner labels', () => {
    expect(formatPlannerLabel('regex')).toBe('REGEX');
    expect(formatPlannerLabel({ type: 'ollama', model: 'qwen2.5:7b' })).toBe('OLLAMA (qwen2.5:7b)');
    expect(formatPlannerLabel({ type: 'anthropic', model: 'claude-3-5-sonnet' })).toBe(
      'ANTHROPIC (claude-3-5-sonnet)'
    );
  });

  it('calculates side-by-side comparison metrics and deltas', () => {
    const result = computeRunComparison(baseRunA, baseRunB);

    // Check Class A: Run A = 1.00, Run B = 0.00 => delta = -1.00
    const rowClassA = result.rows.find((r) => r.label === 'Class A');
    expect(rowClassA).toBeDefined();
    expect(rowClassA?.runA_asr).toBe(1.0);
    expect(rowClassA?.runB_asr).toBe(0.0);
    expect(rowClassA?.delta).toBeCloseTo(-1.0);
    expect(rowClassA?.deltaText).toBe('-1.00');

    // Check Class B: Run A = 1.00, Run B = 0.67 => delta = -0.33
    const rowClassB = result.rows.find((r) => r.label === 'Class B');
    expect(rowClassB).toBeDefined();
    expect(rowClassB?.runA_asr).toBe(1.0);
    expect(rowClassB?.runB_asr).toBe(0.67);
    expect(rowClassB?.delta).toBeCloseTo(-0.33);
    expect(rowClassB?.deltaText).toBe('-0.33');

    // Check Overall: Run A = 1.00, Run B = 0.33 => delta = -0.67
    const rowOverall = result.rows.find((r) => r.className === 'overall');
    expect(rowOverall).toBeDefined();
    expect(rowOverall?.delta).toBeCloseTo(-0.67);
    expect(rowOverall?.deltaText).toBe('-0.67');
  });

  it('detects configuration differences accurately', () => {
    const result = computeRunComparison(baseRunA, baseRunB);

    const plannerDiff = result.configDiff.find((d) => d.label === 'Planner');
    expect(plannerDiff?.changed).toBe(true);
    expect(plannerDiff?.valA).toBe('REGEX');
    expect(plannerDiff?.valB).toBe('OPENAI (gpt-4o)');

    const defenseDiff = result.configDiff.find((d) => d.label.includes('Defense'));
    expect(defenseDiff?.changed).toBe(true);
    expect(defenseDiff?.valA).toContain('DISABLED');
    expect(defenseDiff?.valB).toContain('ACTIVE');

    const trialsDiff = result.configDiff.find((d) => d.label.includes('Trials'));
    expect(trialsDiff?.changed).toBe(true);
    expect(trialsDiff?.valA).toBe('1 trial(s)');
    expect(trialsDiff?.valB).toBe('3 trial(s)');
  });

  it('handles missing classes in one run gracefully', () => {
    const runWithoutClassB: RunRecord = {
      ...baseRunB,
      summary: {
        ...baseRunB.summary!,
        attack: {
          'Class A: Direct Data Exfiltration': { n: 1, successes: 0, asr: 0.0, ci95: [0, 0] },
        },
      },
    };

    const result = computeRunComparison(baseRunA, runWithoutClassB);
    const rowClassB = result.rows.find((r) => r.label === 'Class B');
    expect(rowClassB).toBeDefined();
    expect(rowClassB?.runB_asr).toBeNull();
    expect(rowClassB?.deltaText).toContain('Prev: 1.00');
  });
});
