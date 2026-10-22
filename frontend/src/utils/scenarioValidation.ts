export interface ScenarioFormData {
  id: string;
  title: string;
  attackClass: string;
  attackerText: string;
  expectedEffect: string;
  criterionType: 'tool_call' | 'email' | 'task_state' | 'delegation';
  targetTool: string;
  targetPath: string;
  emailTo: string;
  emailBody: string;
  delegationTarget: string;
  taskState: string;
}

export interface ValidationErrors {
  id?: string;
  attackClass?: string;
  attackerText?: string;
  criterion?: string;
}

export function validateScenarioForm(
  data: ScenarioFormData,
  existingIds: string[] = [],
  isEditMode: boolean = false,
  originalId?: string
): { isValid: boolean; errors: ValidationErrors } {
  const errors: ValidationErrors = {};

  // 1. ID Validation
  const trimmedId = data.id.trim();
  if (!trimmedId) {
    errors.id = 'Scenario ID is required';
  } else if (!/^[a-zA-Z0-9_\-]+$/.test(trimmedId)) {
    errors.id = 'ID can only contain letters, numbers, underscores, and hyphens';
  } else if (!isEditMode || (originalId && trimmedId !== originalId)) {
    if (existingIds.includes(trimmedId)) {
      errors.id = `Scenario ID "${trimmedId}" already exists`;
    }
  }

  // 2. Attack Class Validation
  if (!data.attackClass.trim()) {
    errors.attackClass = 'Attack class is required';
  }

  // 3. Attacker Text Validation
  if (!data.attackerText.trim()) {
    errors.attackerText = 'Attacker request prompt text is required';
  }

  // 4. Criterion validation
  if (data.criterionType === 'tool_call') {
    if (!data.targetTool.trim()) {
      errors.criterion = 'Target tool name (e.g. read_file) is required for tool call criterion';
    }
  } else if (data.criterionType === 'email') {
    if (!data.emailTo.trim() && !data.emailBody.trim()) {
      errors.criterion = 'Either recipient or body match substring is required for email criterion';
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
}
