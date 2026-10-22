/** API client for XProto-12 backend. */

import type {
  ProviderConfig,
  RunPayload,
  RunRecord,
  Scenario,
  ScenarioSetsResponse,
} from './types';

const BASE_URL = '';

export async function fetchScenarios(): Promise<ScenarioSetsResponse> {
  const res = await fetch(`${BASE_URL}/api/scenarios`);
  if (!res.ok) {
    throw new Error(`Failed to fetch scenarios: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRuns(): Promise<{ runs: RunRecord[]; total: number }> {
  const res = await fetch(`${BASE_URL}/api/runs`);
  if (!res.ok) {
    throw new Error(`Failed to fetch runs: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchRun(runId: string): Promise<RunRecord> {
  const res = await fetch(`${BASE_URL}/api/runs/${runId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch run ${runId}: ${res.statusText}`);
  }
  return res.json();
}

export async function createRun(payload: RunPayload): Promise<{ run_id: string; status: string }> {
  const res = await fetch(`${BASE_URL}/api/runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to start run: ${res.statusText}`);
  }
  return res.json();
}

export async function testProvider(
  config: ProviderConfig
): Promise<{ success: boolean; message?: string; error?: string }> {
  const res = await fetch(`${BASE_URL}/api/providers/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    return { success: false, error: `HTTP ${res.status}: ${res.statusText}` };
  }
  return res.json();
}

export async function createCustomScenario(data: Partial<Scenario>): Promise<Scenario> {
  const res = await fetch(`${BASE_URL}/api/scenarios/custom`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to create custom scenario: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCustomScenario(
  scenarioId: string,
  data: Partial<Scenario>
): Promise<Scenario> {
  const res = await fetch(`${BASE_URL}/api/scenarios/custom/${scenarioId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to update custom scenario: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCustomScenario(scenarioId: string): Promise<{ deleted: boolean; id: string }> {
  const res = await fetch(`${BASE_URL}/api/scenarios/custom/${scenarioId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Failed to delete custom scenario: ${res.statusText}`);
  }
  return res.json();
}

export function openRunWebSocket(runId: string): WebSocket {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return new WebSocket(`${protocol}//${host}/api/runs/${runId}/events`);
}
