import React from 'react';
import {
  Shield,
  ShieldAlert,
  Play,
  Layers,
  Activity,
  BarChart3,
  Edit3,
  GitCompare,
  CheckCircle2,
  XCircle,
  Clock,
} from 'lucide-react';
import type { RunRecord } from '../types';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  runs: RunRecord[];
  activeRunId: string | null;
  onSelectRun: (runId: string) => void;
  defenseOn: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  runs,
  activeRunId,
  onSelectRun,
  defenseOn,
}) => {
  const navItems = [
    { id: 'setup', label: 'Setup & Run', icon: Play },
    { id: 'scenarios', label: 'Scenarios', icon: Layers },
    { id: 'live', label: 'Live Run', icon: Activity },
    { id: 'results', label: 'Results & Metrics', icon: BarChart3 },
    { id: 'editor', label: 'Scenario Editor', icon: Edit3 },
    { id: 'compare', label: 'Compare Runs', icon: GitCompare },
  ];

  return (
    <aside className="w-64 bg-[#0d1117] border-r border-[#21262d] flex flex-col h-screen select-none">
      {/* Brand */}
      <div className="p-4 border-b border-[#21262d] flex items-center space-x-3">
        <div className={`p-2 rounded-lg ${defenseOn ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30' : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'}`}>
          <Shield className="w-5 h-5" />
        </div>
        <div>
          <div className="font-semibold text-white tracking-wide text-sm flex items-center space-x-1.5">
            <span>XProto-12</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#21262d] text-slate-300 font-mono">BETA</span>
          </div>
          <p className="text-[11px] text-slate-400 font-medium">Agent Security Gateway</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="p-2 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center space-x-3 px-3 py-2 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? 'bg-[#1f293d] text-sky-400 shadow-sm border border-sky-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{item.label}</span>
              {item.id === 'live' && activeRunId && (
                <span className="ml-auto w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              )}
            </button>
          );
        })}
      </nav>

      {/* Run History */}
      <div className="flex-1 flex flex-col min-h-0 border-t border-[#21262d] mt-2">
        <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
          <span>Run History</span>
          <span className="text-[10px] font-mono text-slate-400">({runs.length})</span>
        </div>
        <div className="flex-1 overflow-y-auto px-2 space-y-1.5">
          {runs.length === 0 ? (
            <div className="p-4 text-center text-xs text-slate-400">
              No runs executed yet.
            </div>
          ) : (
            runs.map((r) => {
              const isSelected = activeRunId === r.run_id;
              const dateStr = new Date(r.started_at * 1000).toLocaleTimeString([], {
                hour: '2-digit',
                minute: '2-digit',
              });
              const plannerTag =
                typeof r.config.planner === 'string'
                  ? r.config.planner
                  : r.config.planner.type;

              return (
                <div
                  key={r.run_id}
                  onClick={() => onSelectRun(r.run_id)}
                  className={`p-2 rounded-md text-xs cursor-pointer border transition-all ${
                    isSelected
                      ? 'bg-[#161b22] border-sky-500/40 text-slate-200'
                      : 'bg-[#090a0f]/50 border-[#21262d] text-slate-400 hover:border-slate-700 hover:text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between font-mono text-[11px]">
                    <span className="text-slate-200 truncate">{r.run_id.replace('run-', '')}</span>
                    <span className="text-[10px] text-slate-400">{dateStr}</span>
                  </div>
                  <div className="flex items-center space-x-1.5 mt-1 text-[10px]">
                    <span className="px-1.5 py-0.2 rounded bg-[#21262d] text-slate-300 capitalize">
                      {plannerTag}
                    </span>
                    <span
                      className={`px-1 py-0.2 rounded text-[9px] font-semibold ${
                        r.config.defense_on
                          ? 'bg-emerald-950/80 text-emerald-400'
                          : 'bg-rose-950/80 text-rose-400'
                      }`}
                    >
                      {r.config.defense_on ? 'ON' : 'OFF'}
                    </span>
                    <span className="ml-auto">
                      {r.status === 'completed' ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      ) : r.status === 'failed' ? (
                        <XCircle className="w-3.5 h-3.5 text-rose-400" />
                      ) : (
                        <Clock className="w-3.5 h-3.5 text-sky-400 animate-spin" />
                      )}
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>
    </aside>
  );
};

interface HeaderProps {
  defenseOn: boolean;
  onToggleDefense: () => void;
  activeRunId: string | null;
  onRunActive: () => void;
  onStartDemo: () => void;
  demoStep?: number | null;
}

export const Header: React.FC<HeaderProps> = ({
  defenseOn,
  onToggleDefense,
  activeRunId,
  onRunActive,
  onStartDemo,
  demoStep,
}) => {
  return (
    <header className="h-14 border-b border-[#21262d] bg-[#0d1117] px-6 flex items-center justify-between">
      {/* Title / Status */}
      <div className="flex items-center space-x-4">
        <h1 className="text-sm font-semibold text-white tracking-wide">
          XGate Security Gateway
        </h1>
        <div className="h-4 w-px bg-[#21262d]" />
        
        {/* Big Defense Status Indicator */}
        <button
          onClick={onToggleDefense}
          className={`flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-semibold border transition-all ${
            defenseOn
              ? 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40 shadow-[0_0_12px_rgba(16,185,129,0.2)]'
              : 'bg-rose-950/70 text-rose-300 border-rose-500/40 shadow-[0_0_12px_rgba(244,63,94,0.2)]'
          }`}
          title="Toggle XGate Enforcement Mode"
        >
          {defenseOn ? (
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          )}
          <span>{defenseOn ? 'DEFENSE ENFORCING (ON)' : 'DEFENSE PERMISSIVE (OFF)'}</span>
        </button>

        {demoStep && (
          <div className="flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
            <span>⚡ DEMO STEP {demoStep}/2:</span>
            <span>{demoStep === 1 ? 'BASELINE (DEFENSE OFF)' : 'PROTECTED (DEFENSE ON)'}</span>
          </div>
        )}
      </div>

      {/* Header Actions */}
      <div className="flex items-center space-x-3">
        <button
          onClick={onStartDemo}
          className="text-xs px-3 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-amber-300 font-medium border border-amber-500/30 transition-all flex items-center space-x-1.5 shadow-sm"
        >
          <span>⚡ Demo Mode (Viva Preset)</span>
        </button>

        <button
          onClick={onRunActive}
          disabled={Boolean(activeRunId)}
          className={`text-xs px-4 py-1.5 rounded-md font-semibold transition-all flex items-center space-x-1.5 ${
            activeRunId
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-sky-600 hover:bg-sky-500 text-white shadow-sm hover:shadow-sky-500/20'
          }`}
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>{activeRunId ? 'Run in Progress...' : 'Run Selected'}</span>
        </button>
      </div>
    </header>
  );
};
