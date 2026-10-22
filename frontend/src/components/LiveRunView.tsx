import { useState, useEffect, useRef, useMemo } from 'react';
import {
  MessageSquare,
  Wrench,
  ShieldCheck,
  ShieldAlert,
  ArrowRightCircle,
  Clock,
  RotateCcw,
} from 'lucide-react';
import type { EngineEvent, RunRecord } from '../types';
import { ChainDiagram } from './ChainDiagram';

interface LiveRunViewProps {
  activeRun: RunRecord | null;
  events: EngineEvent[];
  defenseOn: boolean;
  onRestartRun: () => void;
  onViewResults: () => void;
}

export const LiveRunView: React.FC<LiveRunViewProps> = ({
  activeRun,
  events,
  defenseOn,
  onRestartRun,
  onViewResults,
}) => {
  const [autoScroll, setAutoScroll] = useState(true);
  const feedEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom of event feed
  useEffect(() => {
    if (autoScroll && feedEndRef.current) {
      feedEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, autoScroll]);

  // Compute live trial progress and running ASR
  const stats = useMemo(() => {
    const trials = activeRun?.trials || [];
    const attackTrials = trials.filter(
      (t) => t.class !== 'benign' && t.class !== 'benign-delegation'
    );
    const benignTrials = trials.filter(
      (t) => t.class === 'benign' || t.class === 'benign-delegation'
    );

    const attackTotal = attackTrials.length;
    const attackSuccesses = attackTrials.filter((t) => t.success).length; // attack success = vulnerability bypassed
    const attackBlocked = attackTotal - attackSuccesses;
    const runningAsr = attackTotal > 0 ? attackSuccesses / attackTotal : 0.0;

    const benignTotal = benignTrials.length;
    const benignCompleted = benignTrials.filter(
      (t) => t.task_state === 'TASK_STATE_COMPLETED'
    ).length;
    const benignRate = benignTotal > 0 ? benignCompleted / benignTotal : 1.0;

    return {
      attackTotal,
      attackSuccesses,
      attackBlocked,
      runningAsr,
      benignTotal,
      benignCompleted,
      benignRate,
    };
  }, [activeRun]);

  return (
    <div className="flex flex-col h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Top Banner / Status Strip */}
      <div className="h-11 border-b border-[#21262d] bg-[#0d1117] px-4 flex items-center justify-between text-xs">
        <div className="flex items-center space-x-3">
          <span className="font-mono text-slate-400">
            Run ID: <span className="text-white font-semibold">{activeRun?.run_id || 'Waiting for run...'}</span>
          </span>
          <div className="h-3 w-px bg-[#21262d]" />
          <div className="flex items-center space-x-1.5">
            <span
              className={`w-2 h-2 rounded-full ${
                activeRun?.status === 'running'
                  ? 'bg-sky-400 animate-ping'
                  : activeRun?.status === 'completed'
                  ? 'bg-emerald-400'
                  : 'bg-slate-400'
              }`}
            />
            <span className="capitalize font-medium text-slate-300">
              {activeRun?.status || 'idle'}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          {activeRun?.status === 'completed' && (
            <button
              onClick={onViewResults}
              className="px-3 py-1 rounded bg-sky-600 hover:bg-sky-500 text-white font-medium text-xs transition-all flex items-center space-x-1.5 shadow-sm"
            >
              <span>View Full Results →</span>
            </button>
          )}
        </div>
      </div>

      {/* Main 3-Panel Grid */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Panel: Auto-scrolling Event Feed */}
        <div className="w-[420px] border-r border-[#21262d] flex flex-col bg-[#090a0f] overflow-hidden">
          <div className="p-3 border-b border-[#21262d] bg-[#0d1117] flex items-center justify-between text-xs">
            <div className="flex items-center space-x-1.5 font-semibold text-slate-200">
              <Clock className="w-3.5 h-3.5 text-sky-400" />
              <span>Event Timeline</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#161b22] text-slate-400">
                {events.length}
              </span>
            </div>
            <button
              onClick={() => setAutoScroll(!autoScroll)}
              className={`text-[10px] px-2 py-0.5 rounded border transition-all ${
                autoScroll
                  ? 'bg-sky-950 text-sky-300 border-sky-500/30'
                  : 'bg-[#161b22] text-slate-400 border-[#21262d]'
              }`}
            >
              {autoScroll ? 'Auto-scroll ON' : 'Auto-scroll OFF'}
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-3 space-y-2 font-mono">
            {events.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-slate-400 text-xs text-center space-y-2">
                <Clock className="w-6 h-6 animate-pulse" />
                <p>Waiting for engine events to stream...</p>
              </div>
            ) : (
              events.map((ev) => {
                const isAllow = ev.event === 'xgate_decision' && ev.data.allowed;
                const isDeny = ev.event === 'xgate_decision' && !ev.data.allowed;

                return (
                  <div
                    key={ev.seq}
                    className={`p-2.5 rounded-lg border text-xs transition-all ${
                      isDeny
                        ? 'bg-rose-950/30 border-rose-500/50 text-rose-200 shadow-[0_0_12px_rgba(244,63,94,0.15)]'
                        : isAllow
                        ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
                        : ev.event === 'tool_call'
                        ? 'bg-[#131c2e] border-sky-500/30 text-sky-200'
                        : 'bg-[#0d1117] border-[#21262d] text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1 border-b border-[#21262d] pb-1">
                      <div className="flex items-center space-x-1.5">
                        <span className="font-bold text-slate-300">#{ev.seq}</span>
                        <span className="uppercase text-[9px] px-1 py-0.2 rounded bg-[#161b22]">
                          {ev.event}
                        </span>
                      </div>
                      <span className="font-mono text-[9px]">
                        {new Date(ev.ts * 1000).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </span>
                    </div>

                    {/* A2A Message */}
                    {ev.event === 'a2a_message' && (
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1 text-sky-400 font-semibold text-[11px]">
                          <MessageSquare className="w-3 h-3" />
                          <span>Task Arrival (A2A)</span>
                        </div>
                        <div className="text-[11px] text-slate-300 line-clamp-2">
                          {String(ev.data.text || '')}
                        </div>
                        {Boolean(ev.data.delegator) && (
                          <div className="text-[10px] text-amber-400">
                            Delegator: {String(ev.data.delegator)}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Tool Call */}
                    {ev.event === 'tool_call' && (
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1.5 text-sky-400 font-semibold text-[11px]">
                          <Wrench className="w-3 h-3" />
                          <span>Tool Invocation:</span>
                          <span className="text-white font-bold">{String(ev.data.tool)}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 bg-[#090a0f] p-1.5 rounded font-mono truncate">
                          Args: {JSON.stringify(ev.data.args)}
                        </div>
                        {Array.isArray(ev.data.principal_chain) && (
                          <div className="text-[9px] text-slate-400">
                            Chain: {ev.data.principal_chain.join(' → ')}
                          </div>
                        )}
                      </div>
                    )}

                    {/* XGate Decision */}
                    {ev.event === 'xgate_decision' && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-1 font-bold text-[11px]">
                            {isAllow ? (
                              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                            )}
                            <span className={isAllow ? 'text-emerald-400' : 'text-rose-400'}>
                              {isAllow ? 'ALLOWED' : 'DENIED BY XGATE'}
                            </span>
                          </div>
                          <span className="text-[9px] px-1.5 py-0.2 rounded font-bold bg-[#161b22]">
                            Req: {String(ev.data.required_authority)} | Chain: {String(ev.data.chain_authority)}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono leading-tight">
                          {String(ev.data.reason)}
                        </div>
                      </div>
                    )}

                    {/* Delegation */}
                    {ev.event === 'delegation' && (
                      <div className="space-y-1">
                        <div className="flex items-center space-x-1 text-sky-300 font-semibold text-[11px]">
                          <ArrowRightCircle className="w-3 h-3" />
                          <span>Delegation Request</span>
                        </div>
                        <div className="text-[10px] text-slate-300">
                          Target: {String(ev.data.target_url)}
                        </div>
                        {Boolean(ev.data.capability) && (
                          <div className="text-[9px] text-slate-400">
                            Capability: {String(ev.data.capability)}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Trial Complete */}
                    {ev.event === 'trial_complete' && (
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-bold">
                          <span className="text-white">Trial Finished</span>
                          <span
                            className={
                              ev.data.success ? 'text-emerald-400' : 'text-rose-400'
                            }
                          >
                            {ev.data.success ? '✓ Target Met' : '✗ Failed/Blocked'}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-400">
                          Scenario: {String(ev.data.scenario_id)}
                        </div>
                      </div>
                    )}

                    {/* Run Complete */}
                    {ev.event === 'run_complete' && (
                      <div className="text-center py-1">
                        <span className="font-bold text-emerald-400 text-xs">
                          ★ RUN EXECUTION COMPLETE
                        </span>
                      </div>
                    )}
                  </div>
                );
              })
            )}
            <div ref={feedEndRef} />
          </div>
        </div>

        {/* Center Panel: React Flow Principal Chain Graph */}
        <div className="flex-1 flex flex-col border-r border-[#21262d] bg-[#090a0f] relative">
          <ChainDiagram events={events} defenseOn={defenseOn} />
        </div>

        {/* Right Panel: Trial Progress and Running Metrics */}
        <div className="w-80 bg-[#0d1117] p-5 flex flex-col justify-between overflow-y-auto">
          <div className="space-y-6">
            <div>
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Live Trial Progress
              </h3>
              <p className="text-[11px] text-slate-400 mt-0.5">
                Real-time security metrics calculated from active stream.
              </p>
            </div>

            {/* Running ASR Metric Card */}
            <div className={`p-4 rounded-xl border ${
              stats.runningAsr === 0
                ? 'bg-emerald-950/30 border-emerald-500/40'
                : 'bg-rose-950/30 border-rose-500/40'
            }`}>
              <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                Attack Success Rate (ASR)
              </div>
              <div className="flex items-baseline space-x-2 mt-1">
                <span
                  className={`text-3xl font-extrabold font-mono ${
                    stats.runningAsr === 0 ? 'text-emerald-400' : 'text-rose-400'
                  }`}
                >
                  {(stats.runningAsr * 100).toFixed(1)}%
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  ({stats.attackSuccesses}/{stats.attackTotal} bypassed)
                </span>
              </div>
              <div className="text-[10px] text-slate-400 mt-2">
                {stats.runningAsr === 0
                  ? 'All attacks successfully neutralized by XGate.'
                  : `${stats.attackSuccesses} attack(s) breached authorization bounds.`}
              </div>
            </div>

            {/* Running Benign Completion */}
            <div className="p-4 rounded-xl border border-[#21262d] bg-[#161b22]/50">
              <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                Benign Task Completion
              </div>
              <div className="flex items-baseline space-x-2 mt-1">
                <span className="text-2xl font-bold font-mono text-white">
                  {(stats.benignRate * 100).toFixed(1)}%
                </span>
                <span className="text-xs text-slate-400 font-mono">
                  ({stats.benignCompleted}/{stats.benignTotal} completed)
                </span>
              </div>
              <div className="text-[10px] text-slate-400 mt-1">
                Verifies legitimate tasks execute without false rejections.
              </div>
            </div>

            {/* Scenario Progress List */}
            <div className="space-y-2">
              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Scenario Observations ({activeRun?.trials.length || 0})
              </div>
              <div className="space-y-1.5 max-h-60 overflow-y-auto">
                {(activeRun?.trials || []).map((t, i) => (
                  <div
                    key={i}
                    className="p-2 rounded bg-[#161b22] border border-[#21262d] text-xs flex items-center justify-between"
                  >
                    <span className="font-mono text-slate-200">{t.scenario_id}</span>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                        t.success
                          ? 'bg-emerald-950 text-emerald-400'
                          : 'bg-rose-950 text-rose-400'
                      }`}
                    >
                      {t.success ? 'PASSED' : 'BLOCKED/FAIL'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="border-t border-[#21262d] pt-4 space-y-2">
            <button
              onClick={onRestartRun}
              className="w-full py-2 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-200 text-xs font-medium border border-[#30363d] transition-all flex items-center justify-center space-x-2"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Configure New Run</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
