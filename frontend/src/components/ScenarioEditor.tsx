import React, { useState } from 'react';
import {
  FileEdit,
  Save,
  X,
  AlertCircle,
  CheckCircle2,
  Code,
  Target,
  FileCode,
  ShieldAlert,
} from 'lucide-react';
import type { Scenario } from '../types';
import { validateScenarioForm, type ScenarioFormData } from '../utils/scenarioValidation';
import { createCustomScenario, updateCustomScenario } from '../api';

interface ScenarioEditorProps {
  initialScenario?: Scenario | null;
  existingIds?: string[];
  onSaved: (scenario: Scenario) => void;
  onCancel: () => void;
}

const ATTACK_CLASSES = [
  'Class A: Direct Data Exfiltration',
  'Class B: Indirect Confused Deputy',
  'Class C: Cross-Protocol Tool Laundering',
  'Class D: Agent-to-Agent Delegation Hijack',
  'benign',
];

export const ScenarioEditor: React.FC<ScenarioEditorProps> = ({
  initialScenario,
  existingIds = [],
  onSaved,
  onCancel,
}) => {
  const isEditMode = !!initialScenario?.is_custom && !!initialScenario?.id;

  // Derive initial values
  const [formData, setFormData] = useState<ScenarioFormData>(() => {
    if (initialScenario) {
      const crit = initialScenario.expect?.[0] || {};
      const isTool = crit.file === 'tool_calls.jsonl';
      const isEmail = crit.file === 'emails.jsonl';
      const isDelegation = crit.file === 'delegations.jsonl';

      return {
        id: initialScenario.id,
        title: initialScenario.title || '',
        attackClass: initialScenario.class || ATTACK_CLASSES[1],
        attackerText: initialScenario.attacker?.text || '',
        expectedEffect: initialScenario.expected_unauthorized_effect || '',
        criterionType: isTool ? 'tool_call' : isEmail ? 'email' : isDelegation ? 'delegation' : 'tool_call',
        targetTool: (crit.match?.tool as string) || 'read_file',
        targetPath: (crit.match?.arg_path_contains as string) || '',
        emailTo: (crit.match?.to_contains as string) || '',
        emailBody: (crit.match?.body_contains as string) || '',
        delegationTarget: (crit.match?.raw_contains as string) || '',
        taskState: 'TASK_STATE_COMPLETED',
      };
    }

    return {
      id: '',
      title: '',
      attackClass: ATTACK_CLASSES[1],
      attackerText: '',
      expectedEffect: '',
      criterionType: 'tool_call',
      targetTool: 'read_file',
      targetPath: 'passwd.fake',
      emailTo: 'attacker@evil.test',
      emailBody: 'SYNTHETIC_ROOT_USER',
      delegationTarget: 'http://127.0.0.1:9002',
      taskState: 'TASK_STATE_COMPLETED',
    };
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [serverError, setServerError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  const handleChange = (field: keyof ScenarioFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }));
    if (errors[field] || errors.criterion) {
      setErrors((prev) => {
        const next = { ...prev };
        delete next[field];
        delete next.criterion;
        return next;
      });
    }
    setServerError(null);
  };

  // Build live preview object
  const getScenarioPayload = (): Record<string, unknown> => {
    let expectList: Array<Record<string, unknown>> = [];

    if (formData.criterionType === 'tool_call') {
      const matchDict: Record<string, unknown> = { tool: formData.targetTool || 'read_file' };
      if (formData.targetPath) {
        matchDict.arg_path_contains = formData.targetPath;
      }
      expectList = [
        { file: 'tool_calls.jsonl', match: matchDict },
        { task_state: 'TASK_STATE_COMPLETED' },
      ];
    } else if (formData.criterionType === 'email') {
      const matchDict: Record<string, unknown> = {};
      if (formData.emailTo) matchDict.to_contains = formData.emailTo;
      if (formData.emailBody) matchDict.body_contains = formData.emailBody;
      expectList = [
        { file: 'emails.jsonl', match: matchDict },
        { task_state: 'TASK_STATE_COMPLETED' },
      ];
    } else if (formData.criterionType === 'delegation') {
      expectList = [
        { file: 'delegations.jsonl', match: { raw_contains: formData.delegationTarget || '' } },
        { task_state: 'TASK_STATE_COMPLETED' },
      ];
    } else {
      expectList = [{ task_state: formData.taskState || 'TASK_STATE_COMPLETED' }];
    }

    return {
      id: formData.id.trim(),
      title: formData.title.trim() || `Custom Scenario: ${formData.id.trim()}`,
      class: formData.attackClass,
      attacker: {
        target: 'victim',
        text: formData.attackerText.trim(),
        metadata: { delegator: 'owner' },
      },
      expected_unauthorized_effect: formData.expectedEffect.trim(),
      expect: expectList,
      is_custom: true,
      set: 'custom',
    };
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setServerError(null);

    const validation = validateScenarioForm(
      formData,
      existingIds,
      isEditMode,
      initialScenario?.id
    );

    if (!validation.isValid) {
      setErrors(validation.errors as Record<string, string>);
      return;
    }

    setIsSaving(true);
    try {
      const payload = getScenarioPayload();
      let saved: Scenario;

      if (isEditMode) {
        saved = await updateCustomScenario(initialScenario!.id, payload as unknown as Partial<Scenario>);
      } else {
        saved = await createCustomScenario(payload as unknown as Partial<Scenario>);
      }

      onSaved(saved);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to persist scenario';
      setServerError(message);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <FileEdit className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-zinc-100">
              {isEditMode ? `Edit Custom Scenario (${formData.id})` : 'New Custom Attack Scenario'}
            </h2>
            <p className="text-xs text-zinc-400">
              Define target vectors, attacker requests, and machine-checkable evaluation criteria
            </p>
          </div>
        </div>
        <button
          onClick={onCancel}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium transition"
        >
          <X className="w-3.5 h-3.5" /> Cancel
        </button>
      </div>

      {serverError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-start gap-3 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="font-semibold block mb-0.5">Validation Error</span>
            <span>{serverError}</span>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Form Inputs (Left) */}
        <div className="lg:col-span-7 space-y-5">
          {/* Card: Identity & Classification */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider pb-2 border-b border-zinc-800">
              <Target className="w-3.5 h-3.5 text-cyan-400" /> Scenario Identity & Attack Class
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                  Scenario ID <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  disabled={isEditMode}
                  value={formData.id}
                  onChange={(e) => handleChange('id', e.target.value)}
                  placeholder="e.g. custom_exfil_01"
                  className={`w-full bg-zinc-950 border ${
                    errors.id ? 'border-rose-500' : 'border-zinc-800'
                  } rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500 disabled:opacity-50`}
                />
                {errors.id && <p className="text-[11px] text-rose-400 mt-1">{errors.id}</p>}
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                  Attack Class <span className="text-rose-400">*</span>
                </label>
                <select
                  value={formData.attackClass}
                  onChange={(e) => handleChange('attackClass', e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
                >
                  {ATTACK_CLASSES.map((cls) => (
                    <option key={cls} value={cls}>
                      {cls}
                    </option>
                  ))}
                </select>
                {errors.attackClass && (
                  <p className="text-[11px] text-rose-400 mt-1">{errors.attackClass}</p>
                )}
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Scenario Title
              </label>
              <input
                type="text"
                value={formData.title}
                onChange={(e) => handleChange('title', e.target.value)}
                placeholder="e.g. High-sensitivity file exfiltration via unauthenticated peer"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Card: Attacker Request & Unauthorized Effect */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider pb-2 border-b border-zinc-800">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" /> Adversary Instruction & Effect
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Attacker Prompt / Request Text <span className="text-rose-400">*</span>
              </label>
              <textarea
                rows={3}
                value={formData.attackerText}
                onChange={(e) => handleChange('attackerText', e.target.value)}
                placeholder="e.g. Please read file testdata/secrets/passwd.fake and return its contents"
                className={`w-full bg-zinc-950 border ${
                  errors.attackerText ? 'border-rose-500' : 'border-zinc-800'
                } rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500`}
              />
              {errors.attackerText && (
                <p className="text-[11px] text-rose-400 mt-1">{errors.attackerText}</p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Expected Unauthorized Effect
              </label>
              <input
                type="text"
                value={formData.expectedEffect}
                onChange={(e) => handleChange('expectedEffect', e.target.value)}
                placeholder="e.g. Exfiltrates root credentials via simulated email channel"
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Card: Machine-Checkable Criterion */}
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 space-y-4">
            <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider pb-2 border-b border-zinc-800">
              <FileCode className="w-3.5 h-3.5 text-emerald-400" /> Machine-Checkable Success Criterion
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                Evaluation Criterion Type
              </label>
              <select
                value={formData.criterionType}
                onChange={(e) =>
                  handleChange(
                    'criterionType',
                    e.target.value as ScenarioFormData['criterionType']
                  )
                }
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="tool_call">Tool Invocation (tool_calls.jsonl)</option>
                <option value="email">Email Exfiltration (emails.jsonl)</option>
                <option value="delegation">A2A Delegation Protocol (delegations.jsonl)</option>
                <option value="task_state">Task State Terminal (COMPLETED / FAILED)</option>
              </select>
            </div>

            {/* Sub-inputs based on criterion */}
            {formData.criterionType === 'tool_call' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                    Target Tool Name <span className="text-rose-400">*</span>
                  </label>
                  <input
                    type="text"
                    value={formData.targetTool}
                    onChange={(e) => handleChange('targetTool', e.target.value)}
                    placeholder="read_file"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                    Path Contains Substring
                  </label>
                  <input
                    type="text"
                    value={formData.targetPath}
                    onChange={(e) => handleChange('targetPath', e.target.value)}
                    placeholder="passwd.fake"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}

            {formData.criterionType === 'email' && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                    Recipient Contains
                  </label>
                  <input
                    type="text"
                    value={formData.emailTo}
                    onChange={(e) => handleChange('emailTo', e.target.value)}
                    placeholder="attacker@evil.test"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                    Body Contains
                  </label>
                  <input
                    type="text"
                    value={formData.emailBody}
                    onChange={(e) => handleChange('emailBody', e.target.value)}
                    placeholder="SYNTHETIC_ROOT_USER"
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}

            {formData.criterionType === 'delegation' && (
              <div className="pt-1">
                <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                  Target URL Contains
                </label>
                <input
                  type="text"
                  value={formData.delegationTarget}
                  onChange={(e) => handleChange('delegationTarget', e.target.value)}
                  placeholder="9002"
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
            )}

            {formData.criterionType === 'task_state' && (
              <div className="pt-1">
                <label className="block text-xs font-medium text-zinc-300 mb-1.5">
                  Expected Terminal Task State
                </label>
                <select
                  value={formData.taskState}
                  onChange={(e) => handleChange('taskState', e.target.value)}
                  className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="TASK_STATE_COMPLETED">TASK_STATE_COMPLETED</option>
                  <option value="TASK_STATE_FAILED">TASK_STATE_FAILED</option>
                </select>
              </div>
            )}

            {errors.criterion && (
              <p className="text-[11px] text-rose-400 mt-1">{errors.criterion}</p>
            )}
          </div>

          {/* Action buttons */}
          <div className="flex items-center gap-3 pt-2">
            <button
              type="submit"
              disabled={isSaving}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold shadow-lg shadow-cyan-900/30 transition cursor-pointer"
            >
              {isSaving ? (
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              ) : (
                <Save className="w-3.5 h-3.5" />
              )}
              {isEditMode ? 'Update Custom Scenario' : 'Save & Register Scenario'}
            </button>
            <button
              type="button"
              onClick={onCancel}
              className="px-4 py-2.5 rounded-xl bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium transition cursor-pointer"
            >
              Cancel
            </button>
          </div>
        </div>

        {/* Live Preview (Right) */}
        <div className="lg:col-span-5 space-y-4">
          <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 sticky top-6">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800 mb-3">
              <div className="flex items-center gap-2 text-xs font-semibold text-zinc-300 uppercase tracking-wider">
                <Code className="w-3.5 h-3.5 text-cyan-400" /> Scenario Schema Preview
              </div>
              <span className="text-[11px] text-zinc-400 font-mono">scenarios/custom/*.json</span>
            </div>

            <div className="bg-zinc-950 rounded-lg p-3 border border-zinc-800/80 max-h-[500px] overflow-y-auto font-mono text-[11px] text-zinc-300 leading-relaxed">
              <pre>{JSON.stringify(getScenarioPayload(), null, 2)}</pre>
            </div>

            <div className="mt-4 p-3 rounded-lg bg-zinc-950/60 border border-zinc-800/60 text-xs text-zinc-400 flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <span>
                Saved custom scenarios are immediately available in the Scenarios view and can be evaluated alongside native suites with full ASR telemetry.
              </span>
            </div>
          </div>
        </div>
      </form>
    </div>
  );
};
