import { useState, useMemo } from 'react';
import {
  Search,
  CheckSquare,
  Square,
  Trash2,
  ChevronRight,
  Info,
} from 'lucide-react';
import type { Scenario } from '../types';

interface ScenariosViewProps {
  scenarioSets: Record<string, Scenario[]>;
  selectedIds: string[];
  onToggleScenario: (id: string) => void;
  onSelectAllAttacks: () => void;
  onSelectAllBenign: () => void;
  onClearAll: () => void;
  onSelectSet: (setName: string) => void;
  onDeleteCustomScenario?: (id: string) => Promise<void>;
}

export const ScenariosView: React.FC<ScenariosViewProps> = ({
  scenarioSets,
  selectedIds,
  onToggleScenario,
  onSelectAllAttacks,
  onSelectAllBenign,
  onClearAll,
  onSelectSet,
  onDeleteCustomScenario,
}) => {
  const [activeSet, setActiveSet] = useState<string>('native');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [inspectedScenario, setInspectedScenario] = useState<Scenario | null>(null);

  const setNames = Object.keys(scenarioSets);

  // Filter scenarios in the active set by search query
  const displayedScenarios = useMemo(() => {
    const list = scenarioSets[activeSet] || [];
    if (!searchQuery.trim()) return list;
    const q = searchQuery.toLowerCase();
    return list.filter(
      (s) =>
        s.id.toLowerCase().includes(q) ||
        s.title.toLowerCase().includes(q) ||
        (s.attacker?.text || '').toLowerCase().includes(q) ||
        (s.class || '').toLowerCase().includes(q)
    );
  }, [scenarioSets, activeSet, searchQuery]);

  return (
    <div className="flex h-[calc(100vh-3.5rem)] overflow-hidden">
      {/* Left/Middle Content Area */}
      <div className="flex-1 flex flex-col border-r border-[#21262d] overflow-hidden">
        {/* Controls Bar */}
        <div className="p-4 border-b border-[#21262d] bg-[#0d1117] space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white tracking-tight">Benchmark Scenarios</h2>
              <p className="text-xs text-slate-400">
                Select scenarios to include in the evaluation run.
              </p>
            </div>
            {/* Quick Action Shortcuts */}
            <div className="flex items-center space-x-2">
              <button
                onClick={onSelectAllAttacks}
                className="text-xs px-2.5 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-rose-300 border border-rose-500/30 transition-all font-medium"
              >
                Select All Attacks
              </button>
              <button
                onClick={onSelectAllBenign}
                className="text-xs px-2.5 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-emerald-300 border border-emerald-500/30 transition-all font-medium"
              >
                Select Benign Controls
              </button>
              <button
                onClick={onClearAll}
                className="text-xs px-2.5 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-400 border border-[#30363d] transition-all font-medium"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Search Input and Set Selection */}
          <div className="flex items-center space-x-3">
            <div className="relative flex-1">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scenarios by id, title, or injected payload..."
                className="w-full bg-[#161b22] border border-[#30363d] rounded-md px-3 py-1.5 pl-9 text-xs text-white focus:outline-none focus:border-sky-500"
              />
              <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2" />
            </div>
          </div>

          {/* Set Tabs */}
          <div className="flex space-x-1.5 overflow-x-auto pb-1">
            {setNames.map((sName) => {
              const count = scenarioSets[sName]?.length || 0;
              const isCurrent = activeSet === sName;
              return (
                <button
                  key={sName}
                  onClick={() => setActiveSet(sName)}
                  className={`text-xs px-3 py-1.5 rounded-md font-medium whitespace-nowrap border transition-all flex items-center space-x-1.5 ${
                    isCurrent
                      ? 'bg-[#1f293d] text-sky-400 border-sky-500/30'
                      : 'bg-[#161b22] text-slate-400 border-[#21262d] hover:text-slate-200'
                  }`}
                >
                  <span className="capitalize">{sName.replace('_', ' ')}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#0d1117] text-slate-400">
                    {count}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Scenarios Table / List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          <div className="flex items-center justify-between text-[11px] text-slate-400 px-2 py-1">
            <span>
              Showing {displayedScenarios.length} scenarios in {activeSet}
            </span>
            <button
              onClick={() => onSelectSet(activeSet)}
              className="text-sky-400 hover:underline"
            >
              Select entire set
            </button>
          </div>

          {displayedScenarios.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-400">
              No matching scenarios found.
            </div>
          ) : (
            displayedScenarios.map((sc) => {
              const isSelected = selectedIds.includes(sc.id);
              const isInspected = inspectedScenario?.id === sc.id;
              const isBenign = sc.class === 'benign' || sc.class === 'benign-delegation';

              return (
                <div
                  key={sc.id}
                  className={`p-3 rounded-lg border transition-all flex items-start space-x-3 cursor-pointer ${
                    isInspected
                      ? 'bg-[#161b22] border-sky-500/50'
                      : isSelected
                      ? 'bg-[#0f172a]/60 border-slate-700'
                      : 'bg-[#0d1117] border-[#21262d] hover:border-slate-700'
                  }`}
                  onClick={() => setInspectedScenario(sc)}
                >
                  {/* Selection Checkbox */}
                  <div
                    onClick={(e) => {
                      e.stopPropagation();
                      onToggleScenario(sc.id);
                    }}
                    className="pt-0.5"
                  >
                    {isSelected ? (
                      <CheckSquare className="w-4 h-4 text-sky-400" />
                    ) : (
                      <Square className="w-4 h-4 text-slate-400 hover:text-slate-200" />
                    )}
                  </div>

                  {/* Scenario Information */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center space-x-2">
                      <span className="font-mono text-xs font-semibold text-slate-200">{sc.id}</span>
                      <span
                        className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
                          isBenign
                            ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                            : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {sc.class}
                      </span>
                      {sc.is_custom && (
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-amber-950/50 text-amber-400 border border-amber-500/30">
                          Custom
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-slate-300 font-medium mt-1 truncate">{sc.title}</div>
                    <div className="text-[11px] text-slate-400 font-mono mt-0.5 truncate">
                      {sc.attacker?.text}
                    </div>
                  </div>

                  {/* Inspect Chevron */}
                  <ChevronRight className="w-4 h-4 text-slate-400 shrink-0 self-center" />
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Detail Drawer (Right side) */}
      <div className="w-96 bg-[#0d1117] p-5 flex flex-col justify-between overflow-y-auto">
        {inspectedScenario ? (
          <div className="space-y-5">
            <div className="border-b border-[#21262d] pb-4">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-mono text-sky-400">{inspectedScenario.id}</span>
                {inspectedScenario.is_custom && onDeleteCustomScenario && (
                  <button
                    onClick={() => onDeleteCustomScenario(inspectedScenario.id)}
                    className="text-[11px] text-rose-400 hover:text-rose-300 flex items-center space-x-1"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete</span>
                  </button>
                )}
              </div>
              <h3 className="text-sm font-bold text-white mt-1">{inspectedScenario.title}</h3>
              <div className="mt-2 text-[11px] px-2 py-0.5 rounded bg-[#161b22] text-slate-300 inline-block">
                {inspectedScenario.class}
              </div>
            </div>

            {/* Attacker Request */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Attacker / Client Request
              </label>
              <div className="p-3 rounded-md bg-[#161b22] border border-[#21262d] text-xs font-mono text-slate-200 whitespace-pre-wrap leading-relaxed">
                {inspectedScenario.attacker?.text}
              </div>
            </div>

            {/* Delegator & Metadata */}
            {inspectedScenario.attacker?.metadata && (
              <div className="space-y-1.5">
                <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Origin Context & Delegator
                </label>
                <div className="p-2.5 rounded-md bg-[#161b22] border border-[#21262d] text-xs font-mono text-slate-300 space-y-1">
                  <div>
                    Delegator:{' '}
                    <span className="text-amber-400">
                      {inspectedScenario.attacker.metadata.delegator || 'unspecified'}
                    </span>
                  </div>
                  {inspectedScenario.attacker.metadata.claimed_authority && (
                    <div>
                      Claimed Authority:{' '}
                      <span className="text-sky-400">
                        {inspectedScenario.attacker.metadata.claimed_authority}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Expected Unauthorized Effect */}
            {inspectedScenario.expected_unauthorized_effect && (
              <div className="space-y-1.5">
                <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Expected Unauthorized Effect
                </label>
                <div className="p-3 rounded-md bg-rose-950/20 border border-rose-500/20 text-xs text-rose-300 leading-relaxed">
                  {inspectedScenario.expected_unauthorized_effect}
                </div>
              </div>
            )}

            {/* Validation Criteria */}
            <div className="space-y-1.5">
              <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Success Verification Rules
              </label>
              <div className="p-3 rounded-md bg-[#161b22] border border-[#21262d] text-xs font-mono text-slate-300 space-y-2">
                {inspectedScenario.expect.map((rule, idx) => (
                  <div key={idx} className="border-b border-[#21262d] last:border-b-0 pb-1.5 last:pb-0">
                    {rule.file ? (
                      <div>
                        <span className="text-sky-400">Log: {rule.file}</span>
                        <div className="text-[11px] text-slate-400 pl-2 mt-0.5">
                          {JSON.stringify(rule.match)}
                        </div>
                      </div>
                    ) : (
                      <div>State: {rule.task_state}</div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-center text-slate-400 space-y-2">
            <Info className="w-8 h-8 text-slate-400" />
            <p className="text-xs">Click on any scenario to inspect its authorization rules and expected effects.</p>
          </div>
        )}
      </div>
    </div>
  );
};
