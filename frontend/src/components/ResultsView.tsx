import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts';
import {
  Download,
  Layers,
} from 'lucide-react';
import type { RunRecord } from '../types';

interface ResultsViewProps {
  run: RunRecord | null;
  onExportJson: () => void;
}

export const ResultsView: React.FC<ResultsViewProps> = ({ run, onExportJson }) => {
  if (!run) {
    return (
      <div className="h-[calc(100vh-3.5rem)] flex flex-col items-center justify-center text-slate-400 p-8 text-center space-y-3">
        <Layers className="w-10 h-10 text-slate-400" />
        <h3 className="text-base font-semibold text-white">No Evaluation Run Selected</h3>
        <p className="text-xs max-w-sm">
          Select a completed run from the sidebar history or launch a new run in the Setup tab.
        </p>
      </div>
    );
  }

  const summary = run.summary;
  const attackClasses = Object.entries(summary?.attack || {});

  // Chart data format
  const chartData = attackClasses.map(([clsName, metrics]) => {
    // Shorten class label for chart X-axis
    let shortName = clsName;
    if (clsName.includes('Class A')) shortName = 'Class A (Direct)';
    else if (clsName.includes('Class B')) shortName = 'Class B (Confused)';
    else if (clsName.includes('Class C')) shortName = 'Class C (Laundering)';
    else if (clsName.includes('Class D')) shortName = 'Class D (A2A Hijack)';

    return {
      name: shortName,
      fullName: clsName,
      ASR: Number((metrics.asr * 100).toFixed(1)),
      attemptedRate: Number(((metrics.attempted_access?.rate || 0) * 100).toFixed(1)),
      exfilRate: Number(((metrics.content_exfiltrated?.rate || 0) * 100).toFixed(1)),
      total: metrics.n,
    };
  });

  return (
    <div className="max-w-6xl mx-auto p-8 space-y-8 overflow-y-auto">
      {/* Header & Export */}
      <div className="flex items-center justify-between border-b border-[#21262d] pb-5">
        <div>
          <div className="flex items-center space-x-2">
            <h2 className="text-xl font-bold text-white tracking-tight">Evaluation Results & Telemetry</h2>
            <span
              className={`text-xs px-2 py-0.5 rounded-full font-bold uppercase ${
                run.config.defense_on
                  ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-950/80 text-rose-400 border border-rose-500/30'
              }`}
            >
              {run.config.defense_on ? 'Defense Enforcing (ON)' : 'Defense Permissive (OFF)'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 font-mono">
            Run ID: {run.run_id} | Planner:{' '}
            {typeof run.config.planner === 'string' ? run.config.planner : run.config.planner.type}
          </p>
        </div>

        <button
          onClick={onExportJson}
          className="text-xs px-3.5 py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 border border-[#30363d] flex items-center space-x-2 transition-all font-medium shadow-sm"
        >
          <Download className="w-4 h-4 text-sky-400" />
          <span>Export Run JSON</span>
        </button>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* ASR Card */}
        <div className="p-4 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-1">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Overall Attack Success Rate
          </span>
          <div className="text-2xl font-bold font-mono text-white">
            {summary ? `${(summary.overall_attack.asr * 100).toFixed(1)}%` : '0.0%'}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            {summary?.overall_attack.successes || 0} / {summary?.overall_attack.total || 0} bypassed
          </div>
        </div>

        {/* Benign Task Completion */}
        <div className="p-4 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-1">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Benign Task Completion
          </span>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {summary ? `${(summary.overall_benign.completion_rate * 100).toFixed(1)}%` : '100.0%'}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            {summary?.overall_benign.completed || 0} / {summary?.overall_benign.total || 0} completed
          </div>
        </div>

        {/* Median Latency */}
        <div className="p-4 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-1">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Median Gateway Latency
          </span>
          <div className="text-2xl font-bold font-mono text-sky-400">
            {summary?.latencies.median_ms || 0} ms
          </div>
          <div className="text-[11px] text-slate-400 font-mono">p95: {summary?.latencies.p95_ms || 0} ms</div>
        </div>

        {/* Total Trials */}
        <div className="p-4 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-1">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Observation Count
          </span>
          <div className="text-2xl font-bold font-mono text-white">{run.trials.length}</div>
          <div className="text-[11px] text-slate-400 font-mono">
            {run.config.trials} trial(s) per scenario
          </div>
        </div>
      </div>

      {/* Chart: ASR per Attack Class */}
      {chartData.length > 0 && (
        <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Attack Success Rate (ASR) by Attack Class
            </h3>
            <span className="text-[10px] text-slate-400 font-mono">Lower is better</span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 20, left: -10, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                <YAxis stroke="#64748b" domain={[0, 100]} tick={{ fontSize: 11 }} unit="%" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#161b22',
                    border: '1px solid #30363d',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#e2e8f0',
                  }}
                  formatter={(value: any) => [`${value}%`, 'ASR']}
                />
                <Bar
                  dataKey="ASR"
                  fill={run.config.defense_on ? '#10b981' : '#f43f5e'}
                  radius={[4, 4, 0, 0]}
                  barSize={32}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Per-Class Breakdown Table */}
      <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
          Class-Level Authorization Metrics
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#21262d] text-slate-400 font-mono text-[11px]">
                <th className="py-2 px-3">Attack Class</th>
                <th className="py-2 px-3">Observations (N)</th>
                <th className="py-2 px-3">Bypasses</th>
                <th className="py-2 px-3">ASR</th>
                <th className="py-2 px-3">95% Wilson CI</th>
                <th className="py-2 px-3">Exfiltrated Content</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#21262d] font-mono">
              {attackClasses.map(([cls, m]) => (
                <tr key={cls} className="hover:bg-[#161b22]/50 transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-slate-200">{cls}</td>
                  <td className="py-2.5 px-3 text-slate-400">{m.n}</td>
                  <td className="py-2.5 px-3 text-slate-300">{m.successes}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold ${
                        m.asr === 0 ? 'bg-emerald-950 text-emerald-400' : 'bg-rose-950 text-rose-400'
                      }`}
                    >
                      {(m.asr * 100).toFixed(1)}%
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400">
                    [{m.ci95[0].toFixed(2)}, {m.ci95[1].toFixed(2)}]
                  </td>
                  <td className="py-2.5 px-3 text-slate-300">
                    {m.content_exfiltrated?.count || 0} event(s)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Trial Observations Log */}
      <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
          Trial Execution Observations ({run.trials.length})
        </h3>
        <div className="overflow-x-auto max-h-80">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#21262d] text-slate-400 font-mono text-[11px]">
                <th className="py-2 px-3">Trial ID</th>
                <th className="py-2 px-3">Scenario</th>
                <th className="py-2 px-3">Class</th>
                <th className="py-2 px-3">State</th>
                <th className="py-2 px-3">Outcome</th>
                <th className="py-2 px-3">Latency</th>
                <th className="py-2 px-3">Response Preview</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#21262d] font-mono text-[11px]">
              {run.trials.map((t) => (
                <tr key={t.trial_id} className="hover:bg-[#161b22]/50 transition-colors">
                  <td className="py-2 px-3 text-slate-400">{t.trial_id}</td>
                  <td className="py-2 px-3 font-semibold text-white">{t.scenario_id}</td>
                  <td className="py-2 px-3 text-slate-400">{t.class}</td>
                  <td className="py-2 px-3 text-slate-300">{t.task_state}</td>
                  <td className="py-2 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        t.success
                          ? 'bg-rose-950 text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-950 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {t.success ? 'BYPASSED' : 'BLOCKED'}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-sky-400">{t.mean_latency_ms.toFixed(1)} ms</td>
                  <td className="py-2 px-3 text-slate-400 truncate max-w-xs">
                    {t.response_text || 'None'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
