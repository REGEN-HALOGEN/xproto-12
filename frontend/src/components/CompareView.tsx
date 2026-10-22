import React, { useState } from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import { GitCompare, ArrowRight, ShieldCheck, ShieldAlert, Cpu, Layers } from 'lucide-react';
import type { RunRecord } from '../types';
import { computeRunComparison } from '../utils/compare';

interface CompareViewProps {
  runs: RunRecord[];
  onSelectRunForView?: (runId: string) => void;
}

export const CompareView: React.FC<CompareViewProps> = ({ runs }) => {
  // Default to comparing the latest two runs if available
  const [selectedAId, setSelectedAId] = useState<string>(
    runs.length > 1 ? runs[1].run_id : runs[0]?.run_id || ''
  );
  const [selectedBId, setSelectedBId] = useState<string>(
    runs.length > 0 ? runs[0].run_id : ''
  );

  const runA = runs.find((r) => r.run_id === selectedAId);
  const runB = runs.find((r) => r.run_id === selectedBId);

  if (runs.length < 2) {
    return (
      <div className="max-w-4xl mx-auto py-12 px-4 text-center">
        <div className="w-16 h-16 rounded-2xl bg-zinc-900 border border-zinc-800 flex items-center justify-center mx-auto mb-4 text-zinc-500">
          <GitCompare className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-semibold text-zinc-100 mb-2">Insufficient Runs for Comparison</h2>
        <p className="text-zinc-400 text-sm max-w-md mx-auto mb-6">
          At least two evaluation runs are required to perform comparative analysis and delta calculations. Run a baseline and a defended trial to compare ASR.
        </p>
      </div>
    );
  }

  const comparison = runA && runB ? computeRunComparison(runA, runB) : null;

  return (
    <div className="space-y-6">
      {/* Header & Run Selectors */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4 pb-3 border-b border-zinc-800/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <GitCompare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold text-zinc-100">Comparative Evaluation</h2>
              <p className="text-xs text-zinc-400">
                Side-by-side ASR delta, configuration divergence, and per-class attack resilience
              </p>
            </div>
          </div>

          {/* Quick preset comparisons */}
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                if (runs.length >= 2) {
                  setSelectedAId(runs[1].run_id);
                  setSelectedBId(runs[0].run_id);
                }
              }}
              className="text-xs px-2.5 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-medium transition"
            >
              Latest 2 Runs
            </button>
          </div>
        </div>

        {/* Dual Selectors */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Run A (Baseline) */}
          <div className="bg-zinc-950/60 border border-cyan-500/30 rounded-lg p-3.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400"></span> Run A (Baseline)
              </span>
              <span className="text-[11px] text-zinc-400 font-mono">
                {runA ? new Date(runA.started_at * 1000).toLocaleTimeString() : ''}
              </span>
            </div>
            <select
              value={selectedAId}
              onChange={(e) => setSelectedAId(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700/80 rounded-md px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.run_id} — {typeof r.config.planner === 'string' ? r.config.planner.toUpperCase() : `${r.config.planner.type} (${r.config.planner.model})`} (Defense: {r.config.defense_on ? 'ON' : 'OFF'})
                </option>
              ))}
            </select>
          </div>

          {/* Run B (Comparison Target) */}
          <div className="bg-zinc-950/60 border border-amber-500/30 rounded-lg p-3.5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-amber-400"></span> Run B (Evaluated / Target)
              </span>
              <span className="text-[11px] text-zinc-400 font-mono">
                {runB ? new Date(runB.started_at * 1000).toLocaleTimeString() : ''}
              </span>
            </div>
            <select
              value={selectedBId}
              onChange={(e) => setSelectedBId(e.target.value)}
              className="w-full bg-zinc-900 border border-zinc-700/80 rounded-md px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-amber-500"
            >
              {runs.map((r) => (
                <option key={r.run_id} value={r.run_id}>
                  {r.run_id} — {typeof r.config.planner === 'string' ? r.config.planner.toUpperCase() : `${r.config.planner.type} (${r.config.planner.model})`} (Defense: {r.config.defense_on ? 'ON' : 'OFF'})
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {comparison && (
        <>
          {/* Config Diff Card */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-zinc-400" /> Configuration Divergence
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {comparison.configDiff.map((item, i) => (
                <div
                  key={i}
                  className={`p-3 rounded-lg border text-xs ${
                    item.changed
                      ? 'bg-amber-500/5 border-amber-500/30 text-amber-300'
                      : 'bg-zinc-950/40 border-zinc-800/80 text-zinc-400'
                  }`}
                >
                  <div className="font-medium text-zinc-400 mb-1 flex items-center justify-between">
                    <span>{item.label}</span>
                    {item.changed && (
                      <span className="text-[10px] uppercase font-bold text-amber-400 bg-amber-400/10 px-1.5 py-0.5 rounded">
                        Diff
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 font-mono text-[11px] mt-1.5">
                    <span className="text-cyan-400 truncate">{item.valA}</span>
                    <ArrowRight className="w-3 h-3 text-zinc-600 shrink-0" />
                    <span className="text-amber-400 truncate">{item.valB}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Grouped Bar Chart */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                  <Layers className="w-4 h-4 text-zinc-400" /> ASR Delta Breakdown by Attack Class
                </h3>
                <p className="text-xs text-zinc-400">
                  Attack Success Rate (%) comparison: Lower is more secure
                </p>
              </div>
              <div className="flex items-center gap-4 text-xs font-mono">
                <span className="flex items-center gap-1.5 text-cyan-400">
                  <span className="w-2.5 h-2.5 rounded-sm bg-cyan-400"></span> Run A
                </span>
                <span className="flex items-center gap-1.5 text-amber-400">
                  <span className="w-2.5 h-2.5 rounded-sm bg-amber-400"></span> Run B
                </span>
              </div>
            </div>

            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={comparison.chartData} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" vertical={false} />
                  <XAxis dataKey="shortLabel" stroke="#71717a" fontSize={11} tickLine={false} />
                  <YAxis
                    stroke="#71717a"
                    fontSize={11}
                    domain={[0, 100]}
                    tickFormatter={(v) => `${v}%`}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#18181b',
                      borderColor: '#27272a',
                      borderRadius: '8px',
                      color: '#fafafa',
                      fontSize: '12px',
                    }}
                    formatter={(val: any, name: any) => [
                      `${val}%`,
                      name === 'runA_asr' ? comparison.runA_label : comparison.runB_label,
                    ]}
                  />
                  <Legend verticalAlign="top" height={0} />
                  <Bar dataKey="runA_asr" fill="#38bdf8" name="Run A" radius={[4, 4, 0, 0]} maxBarSize={36} />
                  <Bar dataKey="runB_asr" fill="#f59e0b" name="Run B" radius={[4, 4, 0, 0]} maxBarSize={36} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Side-by-Side ASR Table with Delta Column */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-5 py-4 border-b border-zinc-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-zinc-200">Side-by-Side Metrics Matrix</h3>
              <span className="text-xs font-mono text-zinc-400">Delta = Run B ASR − Run A ASR</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 bg-zinc-950/60 text-zinc-400 font-mono">
                    <th className="py-3 px-4 font-medium">Attack Class</th>
                    <th className="py-3 px-4 font-medium text-cyan-400">
                      Run A ({comparison.runA_label})
                    </th>
                    <th className="py-3 px-4 font-medium text-amber-400">
                      Run B ({comparison.runB_label})
                    </th>
                    <th className="py-3 px-4 font-medium">ASR Delta</th>
                    <th className="py-3 px-4 font-medium">Security Impact</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {comparison.rows.map((row, idx) => {
                    const isOverall = row.className === 'overall';
                    const deltaVal = row.delta;
                    let deltaBadge = 'bg-zinc-800 text-zinc-300';
                    let impactText = 'Identical ASR';
                    let ImpactIcon = ShieldCheck;

                    if (deltaVal !== null) {
                      if (deltaVal < 0) {
                        deltaBadge = 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
                        impactText = `Improved resilience (${Math.abs(Math.round(deltaVal * 100))}% ASR reduction)`;
                        ImpactIcon = ShieldCheck;
                      } else if (deltaVal > 0) {
                        deltaBadge = 'bg-rose-500/10 text-rose-400 border border-rose-500/20';
                        impactText = `Increased vulnerability (+${Math.round(deltaVal * 100)}% ASR increase)`;
                        ImpactIcon = ShieldAlert;
                      }
                    }

                    return (
                      <tr
                        key={idx}
                        className={`hover:bg-zinc-800/40 transition ${
                          isOverall ? 'bg-zinc-800/30 font-semibold' : ''
                        }`}
                      >
                        <td className="py-3 px-4 text-zinc-200">
                          <div className="flex items-center gap-2">
                            <span>{row.label}</span>
                            {isOverall && (
                              <span className="text-[10px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded uppercase font-bold">
                                Primary Metric
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300">
                          {row.runA_asr !== null ? `${(row.runA_asr * 100).toFixed(1)}%` : '—'}
                          {row.runA_n > 0 && (
                            <span className="text-zinc-500 text-[11px] ml-1.5">
                              (n={row.runA_n})
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-300">
                          {row.runB_asr !== null ? `${(row.runB_asr * 100).toFixed(1)}%` : '—'}
                          {row.runB_n > 0 && (
                            <span className="text-zinc-500 text-[11px] ml-1.5">
                              (n={row.runB_n})
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 font-mono">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold ${deltaBadge}`}
                          >
                            {row.deltaText}
                          </span>
                        </td>
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-1.5 text-xs text-zinc-300">
                            <ImpactIcon className="w-3.5 h-3.5 text-zinc-400" />
                            <span>{impactText}</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
