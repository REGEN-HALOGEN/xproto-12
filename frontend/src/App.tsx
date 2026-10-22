import { useState, useEffect, useRef } from 'react';
import {
  fetchScenarios,
  fetchRuns,
  fetchRun,
  createRun,
  deleteCustomScenario,
  openRunWebSocket,
} from './api';
import type {
  EngineEvent,
  PlannerType,
  ProviderConfig,
  RunRecord,
  Scenario,
} from './types';
import { Sidebar, Header } from './components/Navigation';
import { SetupView } from './components/SetupView';
import { ScenariosView } from './components/ScenariosView';
import { LiveRunView } from './components/LiveRunView';
import { ResultsView } from './components/ResultsView';
import { ScenarioEditor } from './components/ScenarioEditor';
import { CompareView } from './components/CompareView';

export function App() {
  const [currentTab, setCurrentTab] = useState<string>('setup');
  const [scenarioSets, setScenarioSets] = useState<Record<string, Scenario[]>>({});
  const [selectedIds, setSelectedIds] = useState<string[]>(['a1']);
  const [editingScenario, setEditingScenario] = useState<Scenario | null>(null);
  const [defenseOn, setDefenseOn] = useState<boolean>(true);
  const [plannerType, setPlannerType] = useState<PlannerType>('regex');
  const [providerConfig, setProviderConfig] = useState<ProviderConfig>({
    type: 'regex',
    base_url: 'https://api.openai.com/v1',
    api_key: '', // In-memory only!
    model: 'gpt-4o',
    temperature: 0.0,
  });
  const [trials, setTrials] = useState<number>(1);
  const [temperature, setTemperature] = useState<number>(0.0);

  const [runs, setRuns] = useState<RunRecord[]>([]);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [liveEvents, setLiveEvents] = useState<EngineEvent[]>([]);
  const [selectedRun, setSelectedRun] = useState<RunRecord | null>(null);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [demoStep, setDemoStep] = useState<number | null>(null);

  const activeWsRef = useRef<WebSocket | null>(null);
  const demoStepRef = useRef<number | null>(null);
  demoStepRef.current = demoStep;

  // Load scenarios on mount
  useEffect(() => {
    fetchScenarios()
      .then((data) => setScenarioSets(data.sets || {}))
      .catch((err) => console.error('Failed to load scenarios', err));

    fetchRuns()
      .then((data) => {
        setRuns(data.runs || []);
        if (data.runs?.length > 0 && !selectedRun) {
          setSelectedRun(data.runs[0]);
        }
      })
      .catch((err) => console.error('Failed to load runs', err));
  }, []);

  // Manage WebSocket connection whenever activeRunId changes
  useEffect(() => {
    if (!activeRunId) {
      if (activeWsRef.current) {
        activeWsRef.current.close();
        activeWsRef.current = null;
      }
      return;
    }

    setLiveEvents([]);
    const ws = openRunWebSocket(activeRunId);
    activeWsRef.current = ws;

    const handleRunCompletion = async (runId: string) => {
      try {
        const completedRun = await fetchRun(runId);
        setSelectedRun(completedRun);
        setRuns((prev) => [completedRun, ...prev.filter((p) => p.run_id !== completedRun.run_id)]);

        if (demoStepRef.current === 1) {
          // Step 1 (Defense OFF) completed -> Automatically start Step 2 (Defense ON)
          setDemoStep(2);
          setDefenseOn(true);
          try {
            const res2 = await createRun({
              scenario_ids: ['a1', 'b1'],
              planner: 'regex',
              defense_on: true,
              trials: 1,
            });
            setActiveRunId(res2.run_id);
          } catch (e) {
            console.error('Failed to start demo step 2', e);
            setDemoStep(null);
            setActiveRunId(null);
          }
        } else if (demoStepRef.current === 2) {
          // Step 2 (Defense ON) completed -> Transition to Compare View
          setDemoStep(null);
          setActiveRunId(null);
          setCurrentTab('compare');
        } else {
          setActiveRunId(null);
        }
      } catch (err) {
        console.error('Failed to fetch completed run', err);
        setActiveRunId(null);
      }
    };

    ws.onmessage = (event) => {
      try {
        const ev: EngineEvent = JSON.parse(event.data);
        setLiveEvents((prev) => {
          if (prev.some((e) => e.seq === ev.seq)) return prev;
          return [...prev, ev];
        });

        if (ev.event === 'run_complete') {
          handleRunCompletion(activeRunId);
        }
      } catch (err) {
        console.error('Failed to parse WebSocket event', err);
      }
    };

    ws.onerror = (err) => console.error('WebSocket error', err);

    ws.onclose = () => {
      // Hardening: if connection dropped while run was active, poll HTTP until complete
      if (activeRunId) {
        const poller = setInterval(async () => {
          try {
            const r = await fetchRun(activeRunId);
            if (r.status === 'completed' || r.status === 'failed') {
              clearInterval(poller);
              handleRunCompletion(activeRunId);
            }
          } catch {
            clearInterval(poller);
          }
        }, 1500);
      }
    };

    return () => {
      ws.close();
      activeWsRef.current = null;
    };
  }, [activeRunId]);

  // Scenario selection handlers
  const handleToggleScenario = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleSelectAllAttacks = () => {
    const attackIds: string[] = [];
    Object.entries(scenarioSets).forEach(([setName, list]) => {
      if (setName !== 'benign' && setName !== 'benign_delegation') {
        list.forEach((s) => attackIds.push(s.id));
      }
    });
    setSelectedIds(Array.from(new Set(attackIds)));
  };

  const handleSelectAllBenign = () => {
    const benignIds: string[] = [];
    (scenarioSets.benign || []).forEach((s) => benignIds.push(s.id));
    (scenarioSets.benign_delegation || []).forEach((s) => benignIds.push(s.id));
    setSelectedIds(Array.from(new Set(benignIds)));
  };

  const handleClearAll = () => setSelectedIds([]);

  const handleSelectSet = (setName: string) => {
    const ids = (scenarioSets[setName] || []).map((s) => s.id);
    setSelectedIds((prev) => Array.from(new Set([...prev, ...ids])));
  };

  const handleDeleteCustomScenario = async (scenarioId: string) => {
    await deleteCustomScenario(scenarioId);
    const data = await fetchScenarios();
    setScenarioSets(data.sets || {});
    setSelectedIds((prev) => prev.filter((id) => id !== scenarioId));
  };

  // Run start handler
  const handleStartRun = async () => {
    if (selectedIds.length === 0 || isStarting) return;
    setIsStarting(true);

    try {
      const plannerPayload =
        plannerType === 'regex'
          ? 'regex'
          : {
              ...providerConfig,
              type: plannerType,
              temperature,
            };

      const res = await createRun({
        scenario_ids: selectedIds,
        planner: plannerPayload,
        defense_on: defenseOn,
        trials,
      });

      setActiveRunId(res.run_id);
      setCurrentTab('live');
    } catch (err: unknown) {
      alert(`Failed to start run: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsStarting(false);
    }
  };

  // Demo mode (Viva preset): load a1 + b1, regex planner, runs defense OFF then ON back-to-back
  const handleStartDemo = async () => {
    setSelectedIds(['a1', 'b1']);
    setPlannerType('regex');
    setTrials(1);
    setDefenseOn(false);
    setDemoStep(1);
    setIsStarting(true);
    try {
      const res = await createRun({
        scenario_ids: ['a1', 'b1'],
        planner: 'regex',
        defense_on: false,
        trials: 1,
      });
      setActiveRunId(res.run_id);
      setCurrentTab('live');
    } catch (err: unknown) {
      alert(`Demo mode failed: ${err instanceof Error ? err.message : String(err)}`);
      setDemoStep(null);
    } finally {
      setIsStarting(false);
    }
  };

  const handleSelectRunFromHistory = async (runId: string) => {
    try {
      const r = await fetchRun(runId);
      setSelectedRun(r);
      setCurrentTab('results');
    } catch (err) {
      console.error('Failed to fetch run', err);
    }
  };

  const handleExportJson = () => {
    if (!selectedRun) return;
    const blob = new Blob([JSON.stringify(selectedRun, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedRun.run_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Active run object for live run view
  const activeRunRecord: RunRecord | null =
    runs.find((r) => r.run_id === activeRunId) ||
    (activeRunId
      ? {
          run_id: activeRunId,
          status: 'running',
          started_at: Date.now() / 1000,
          config: {
            scenario_ids: selectedIds,
            planner: plannerType === 'regex' ? 'regex' : providerConfig,
            defense_on: defenseOn,
            trials,
          },
          trials: [],
        }
      : selectedRun);

  return (
    <div className="flex h-screen bg-[#090a0f] text-slate-200 overflow-hidden font-sans">
      {/* Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        runs={runs}
        activeRunId={activeRunId}
        onSelectRun={handleSelectRunFromHistory}
        defenseOn={defenseOn}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          defenseOn={defenseOn}
          onToggleDefense={() => setDefenseOn(!defenseOn)}
          activeRunId={activeRunId}
          onRunActive={handleStartRun}
          onStartDemo={handleStartDemo}
          demoStep={demoStep}
        />

        <main className="flex-1 overflow-y-auto">
          {currentTab === 'setup' && (
            <SetupView
              plannerType={plannerType}
              onChangePlannerType={setPlannerType}
              providerConfig={providerConfig}
              onChangeProviderConfig={setProviderConfig}
              defenseOn={defenseOn}
              onToggleDefense={setDefenseOn}
              trials={trials}
              onChangeTrials={setTrials}
              temperature={temperature}
              onChangeTemperature={setTemperature}
              selectedScenariosCount={selectedIds.length}
              onGoToScenarios={() => setCurrentTab('scenarios')}
              onStartRun={handleStartRun}
              isStarting={isStarting}
              onStartDemo={handleStartDemo}
            />
          )}

          {currentTab === 'scenarios' && (
            <ScenariosView
              scenarioSets={scenarioSets}
              selectedIds={selectedIds}
              onToggleScenario={handleToggleScenario}
              onSelectAllAttacks={handleSelectAllAttacks}
              onSelectAllBenign={handleSelectAllBenign}
              onClearAll={handleClearAll}
              onSelectSet={handleSelectSet}
              onDeleteCustomScenario={handleDeleteCustomScenario}
              onCreateScenario={() => {
                setEditingScenario(null);
                setCurrentTab('editor');
              }}
              onEditCustomScenario={(sc) => {
                setEditingScenario(sc);
                setCurrentTab('editor');
              }}
            />
          )}

          {currentTab === 'live' && (
            <LiveRunView
              activeRun={activeRunRecord}
              events={liveEvents}
              defenseOn={defenseOn}
              onRestartRun={() => setCurrentTab('setup')}
              onViewResults={() => setCurrentTab('results')}
            />
          )}

          {currentTab === 'results' && (
            <ResultsView run={selectedRun} onExportJson={handleExportJson} />
          )}

          {currentTab === 'editor' && (
            <div className="p-6">
              <ScenarioEditor
                initialScenario={editingScenario}
                existingIds={Object.values(scenarioSets).flatMap((set) => set.map((s) => s.id))}
                onSaved={async (saved) => {
                  const data = await fetchScenarios();
                  setScenarioSets(data.sets || {});
                  if (!selectedIds.includes(saved.id)) {
                    setSelectedIds((prev) => [...prev, saved.id]);
                  }
                  setEditingScenario(null);
                  setCurrentTab('scenarios');
                }}
                onCancel={() => {
                  setEditingScenario(null);
                  setCurrentTab('scenarios');
                }}
              />
            </div>
          )}

          {currentTab === 'compare' && (
            <div className="p-6 max-w-7xl mx-auto">
              <CompareView
                runs={runs}
                onSelectRunForView={(runId) => {
                  const r = runs.find((x) => x.run_id === runId);
                  if (r) {
                    setSelectedRun(r);
                    setCurrentTab('results');
                  }
                }}
              />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
