/** Type definitions for XProto-12 Security Evaluation UI. */

export type AttackClass =
  | 'Class A: Direct Data Exfiltration'
  | 'Class B: Indirect Confused Deputy'
  | 'Class C: Cross-Protocol Tool Laundering'
  | 'Class D: Agent-to-Agent Delegation Hijack'
  | 'benign'
  | string;

export interface ScenarioAttacker {
  target?: string;
  text: string;
  metadata?: {
    delegator?: string;
    claimed_authority?: string;
    [key: string]: unknown;
  };
}

export interface ScenarioExpectation {
  file?: string;
  match?: Record<string, unknown>;
  task_state?: string;
}

export interface Scenario {
  id: string;
  title: string;
  class: AttackClass;
  set?: string;
  is_custom?: boolean;
  attacker: ScenarioAttacker;
  expected_unauthorized_effect?: string;
  expect: ScenarioExpectation[];
}

export interface ScenarioSetsResponse {
  sets: Record<string, Scenario[]>;
  total: number;
}

export type PlannerType = 'regex' | 'ollama' | 'openai' | 'anthropic';

export interface ProviderConfig {
  type: PlannerType;
  base_url?: string;
  api_key?: string; // Kept in component memory only! Never persisted to localStorage!
  model?: string;
  temperature?: number;
  max_tokens?: number;
}

export interface RunPayload {
  scenario_ids: string[];
  planner: 'regex' | ProviderConfig;
  defense_on: boolean;
  trials: number;
}

export interface EngineEvent {
  seq: number;
  run_id: string;
  event:
    | 'a2a_message'
    | 'tool_call'
    | 'xgate_decision'
    | 'delegation'
    | 'trial_complete'
    | 'run_complete';
  data: Record<string, unknown>;
  ts: number;
}

export interface TrialResult {
  trial_id: string;
  scenario_id: string;
  class: string;
  defense_on: boolean;
  trial_idx: number;
  success: boolean;
  failures: string[];
  task_state: string;
  response_text?: string;
  attempted_access: boolean;
  content_exfiltrated: boolean;
  mean_latency_ms: number;
  planner_telemetry?: Array<Record<string, unknown>>;
  delegations?: Array<Record<string, unknown>>;
}

export interface ClassMetric {
  n: number;
  successes: number;
  asr: number;
  ci95: [number, number];
  attempted_access?: { count: number; rate: number };
  content_exfiltrated?: { count: number; rate: number };
  scenarios?: string[];
}

export interface RunSummary {
  attack: Record<string, ClassMetric>;
  overall_attack: {
    total: number;
    successes: number;
    asr: number;
  };
  benign?: Record<string, unknown>;
  overall_benign: {
    total: number;
    completed: number;
    completion_rate: number;
  };
  latencies: {
    count: number;
    mean_ms: number;
    median_ms: number;
    p95_ms: number;
  };
}

export interface RunRecord {
  run_id: string;
  status: 'running' | 'completed' | 'failed';
  started_at: number;
  completed_at?: number | null;
  config: RunPayload;
  summary?: RunSummary | null;
  trials: TrialResult[];
  error?: string | null;
}
