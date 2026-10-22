import React, { useState } from 'react';
import {
  Cpu,
  Server,
  Zap,
  Flame,
  ShieldCheck,
  ShieldAlert,
  Play,
  CheckCircle,
  AlertCircle,
  Loader2,
  Lock,
} from 'lucide-react';
import type { PlannerType, ProviderConfig } from '../types';
import { testProvider } from '../api';

interface SetupViewProps {
  plannerType: PlannerType;
  onChangePlannerType: (type: PlannerType) => void;
  providerConfig: ProviderConfig;
  onChangeProviderConfig: (config: ProviderConfig) => void;
  defenseOn: boolean;
  onToggleDefense: (val: boolean) => void;
  trials: number;
  onChangeTrials: (trials: number) => void;
  temperature: number;
  onChangeTemperature: (temp: number) => void;
  selectedScenariosCount: number;
  onGoToScenarios: () => void;
  onStartRun: () => void;
  isStarting: boolean;
}

export const SetupView: React.FC<SetupViewProps> = ({
  plannerType,
  onChangePlannerType,
  providerConfig,
  onChangeProviderConfig,
  defenseOn,
  onToggleDefense,
  trials,
  onChangeTrials,
  temperature,
  onChangeTemperature,
  selectedScenariosCount,
  onGoToScenarios,
  onStartRun,
  isStarting,
}) => {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);

  const planners: Array<{
    id: PlannerType;
    title: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    tag: string;
  }> = [
    {
      id: 'regex',
      title: 'Regex Control',
      description: 'Deterministic rule-based control baseline without LLM variance.',
      icon: Cpu,
      tag: 'Deterministic Baseline',
    },
    {
      id: 'ollama',
      title: 'Local Ollama',
      description: 'Self-hosted local models (e.g. Qwen 2.5 7B, Llama 3.1 8B).',
      icon: Server,
      tag: 'Local Offline',
    },
    {
      id: 'openai',
      title: 'OpenAI-Compatible',
      description: 'OpenAI, Groq, Together, LM Studio, vLLM endpoints.',
      icon: Zap,
      tag: 'Cloud / Local Endpoints',
    },
    {
      id: 'anthropic',
      title: 'Anthropic Claude',
      description: 'Anthropic Claude 3.5 Sonnet / Haiku messages API.',
      icon: Flame,
      tag: 'Claude Models',
    },
  ];

  const handleTestConnection = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testProvider({
        ...providerConfig,
        type: plannerType,
      });
      if (res.success) {
        setTestResult({ success: true, message: res.message || 'Connection verified successfully!' });
      } else {
        setTestResult({ success: false, message: res.error || 'Connection failed' });
      }
    } catch (err: unknown) {
      setTestResult({ success: false, message: err instanceof Error ? err.message : String(err) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto p-8 space-y-8">
      {/* View Title */}
      <div>
        <h2 className="text-xl font-bold text-white tracking-tight">Run Configuration & Environment</h2>
        <p className="text-xs text-slate-400 mt-1">
          Configure the victim agent planner, authority enforcement model, and benchmark parameters.
        </p>
      </div>

      {/* Planner Selector Cards */}
      <div className="space-y-3">
        <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          1. Select Agent Planner
        </label>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {planners.map((p) => {
            const Icon = p.icon;
            const isSelected = plannerType === p.id;
            return (
              <div
                key={p.id}
                onClick={() => {
                  onChangePlannerType(p.id);
                  setTestResult(null);
                }}
                className={`p-4 rounded-xl border cursor-pointer transition-all flex flex-col justify-between ${
                  isSelected
                    ? 'bg-[#121d33] border-sky-500 shadow-[0_0_15px_rgba(14,165,233,0.15)] text-white'
                    : 'bg-[#0d1117] border-[#21262d] text-slate-400 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between">
                    <div className={`p-2 rounded-lg ${isSelected ? 'bg-sky-500/20 text-sky-400' : 'bg-[#161b22] text-slate-400'}`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#161b22] text-slate-400">
                      {p.tag}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold mt-3 text-slate-100">{p.title}</h3>
                  <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{p.description}</p>
                </div>
                <div className="mt-4 flex items-center text-[10px] font-semibold text-sky-400">
                  {isSelected ? '● Active Selection' : 'Click to select'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Dynamic Provider Configuration Panel */}
      {plannerType !== 'regex' && (
        <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
          <div className="flex items-center justify-between border-b border-[#21262d] pb-3">
            <div>
              <h4 className="text-xs font-semibold text-slate-200 capitalize">
                {plannerType} Provider Settings
              </h4>
              <p className="text-[11px] text-slate-400">
                Credentials are fed per-session in volatile memory; never persisted to disk or localStorage.
              </p>
            </div>
            <button
              onClick={handleTestConnection}
              disabled={testing}
              className="text-xs px-3 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-sky-400 border border-sky-500/30 flex items-center space-x-1.5 transition-all font-medium disabled:opacity-50"
            >
              {testing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
              <span>{testing ? 'Testing...' : 'Test Connection'}</span>
            </button>
          </div>

          {testResult && (
            <div
              className={`p-3 rounded-lg text-xs flex items-center space-x-2 border ${
                testResult.success
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
              }`}
            >
              {testResult.success ? (
                <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
              )}
              <span className="font-mono">{testResult.message}</span>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {plannerType === 'ollama' && (
              <>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">Base URL</label>
                  <input
                    type="text"
                    value={providerConfig.base_url || 'http://127.0.0.1:11434'}
                    onChange={(e) =>
                      onChangeProviderConfig({ ...providerConfig, base_url: e.target.value })
                    }
                    placeholder="http://127.0.0.1:11434"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">Model Name</label>
                  <input
                    type="text"
                    value={providerConfig.model || 'qwen2.5:7b'}
                    onChange={(e) =>
                      onChangeProviderConfig({ ...providerConfig, model: e.target.value })
                    }
                    placeholder="qwen2.5:7b"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
              </>
            )}

            {plannerType === 'openai' && (
              <>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">Base URL</label>
                  <input
                    type="text"
                    value={providerConfig.base_url || 'https://api.openai.com/v1'}
                    onChange={(e) =>
                      onChangeProviderConfig({ ...providerConfig, base_url: e.target.value })
                    }
                    placeholder="https://api.openai.com/v1"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">
                    API Key (Volatile Memory Only)
                  </label>
                  <div className="relative">
                    <input
                      type="password"
                      value={providerConfig.api_key || ''}
                      onChange={(e) =>
                        onChangeProviderConfig({ ...providerConfig, api_key: e.target.value })
                      }
                      placeholder="sk-..."
                      className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono pl-8"
                    />
                    <Lock className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                  </div>
                </div>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">Model Name</label>
                  <input
                    type="text"
                    value={providerConfig.model || 'gpt-4o'}
                    onChange={(e) =>
                      onChangeProviderConfig({ ...providerConfig, model: e.target.value })
                    }
                    placeholder="gpt-4o or llama-3.3-70b-versatile"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
              </>
            )}

            {plannerType === 'anthropic' && (
              <>
                <div className="md:col-span-2">
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">
                    Anthropic API Key (Volatile Memory Only)
                  </label>
                  <div className="relative">
                    <input
                      type="password"
                      value={providerConfig.api_key || ''}
                      onChange={(e) =>
                        onChangeProviderConfig({ ...providerConfig, api_key: e.target.value })
                      }
                      placeholder="sk-ant-..."
                      className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono pl-8"
                    />
                    <Lock className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                  </div>
                </div>
                <div>
                  <label className="text-[11px] font-medium text-slate-400 block mb-1">Model Name</label>
                  <input
                    type="text"
                    value={providerConfig.model || 'claude-3-5-sonnet-20241022'}
                    onChange={(e) =>
                      onChangeProviderConfig({ ...providerConfig, model: e.target.value })
                    }
                    placeholder="claude-3-5-sonnet-20241022"
                    className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 text-xs text-white focus:outline-none focus:border-sky-500 font-mono"
                  />
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Defense Mode and Execution Parameters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Defense Enforcement Toggle */}
        <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
          <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
            2. XGate Defense Policy
          </label>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-white">
                {defenseOn ? 'Enforcing Mode (Defense ON)' : 'Permissive Mode (Defense OFF)'}
              </div>
              <p className="text-[11px] text-slate-400 mt-1 max-w-sm">
                {defenseOn
                  ? 'Enforces weakest-link authority checks across principal chains and blocks unauthenticated cross-protocol laundering.'
                  : 'Vulnerable baseline: agent executes tasks using full owner authority regardless of remote untrusted callers.'}
              </p>
            </div>
            <button
              onClick={() => onToggleDefense(!defenseOn)}
              className={`p-3 rounded-xl border flex items-center space-x-2 transition-all ${
                defenseOn
                  ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]'
                  : 'bg-rose-950/60 border-rose-500/50 text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.2)]'
              }`}
            >
              {defenseOn ? <ShieldCheck className="w-6 h-6" /> : <ShieldAlert className="w-6 h-6" />}
              <span className="font-bold text-xs">{defenseOn ? 'DEFENSE ON' : 'DEFENSE OFF'}</span>
            </button>
          </div>
        </div>

        {/* Sampling and Trials */}
        <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] space-y-4">
          <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider block">
            3. Sampling & Repetitions
          </label>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Temperature</span>
                <span className="font-mono text-sky-400">{temperature.toFixed(2)}</span>
              </div>
              <input
                type="range"
                min="0.0"
                max="1.0"
                step="0.05"
                value={temperature}
                onChange={(e) => onChangeTemperature(parseFloat(e.target.value))}
                className="w-full accent-sky-500 cursor-pointer"
              />
              <span className="text-[10px] text-slate-400 block mt-1">0.0 = Deterministic</span>
            </div>

            <div>
              <div className="text-xs text-slate-300 mb-1">Trials per Scenario</div>
              <div className="flex space-x-2">
                {[1, 3, 5, 10].map((num) => (
                  <button
                    key={num}
                    onClick={() => onChangeTrials(num)}
                    className={`flex-1 py-1.5 rounded-md text-xs font-mono font-medium border transition-all ${
                      trials === num
                        ? 'bg-sky-500/20 text-sky-400 border-sky-500/40'
                        : 'bg-[#161b22] text-slate-400 border-[#30363d] hover:text-slate-200'
                    }`}
                  >
                    {num}x
                  </button>
                ))}
              </div>
              <span className="text-[10px] text-slate-400 block mt-1">Repeated observations</span>
            </div>
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="p-5 rounded-xl border border-[#21262d] bg-[#0d1117] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="text-xs text-slate-300">
            Selected Scenarios:{' '}
            <span className="font-mono font-bold text-sky-400">{selectedScenariosCount}</span>
          </div>
          <button
            onClick={onGoToScenarios}
            className="text-xs text-slate-400 hover:text-sky-300 underline font-medium"
          >
            Manage Scenarios →
          </button>
        </div>

        <button
          onClick={onStartRun}
          disabled={selectedScenariosCount === 0 || isStarting}
          className={`px-6 py-2.5 rounded-lg text-sm font-semibold flex items-center space-x-2 shadow-lg transition-all ${
            selectedScenariosCount === 0 || isStarting
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-sky-600 hover:bg-sky-500 text-white shadow-sky-500/20 hover:scale-[1.01]'
          }`}
        >
          {isStarting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
          <span>{isStarting ? 'Initiating Run...' : 'Start Evaluation Run'}</span>
        </button>
      </div>
    </div>
  );
};
