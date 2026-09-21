// lib/scanners/rules/index.ts
export { AWS_RULES } from './aws';
export { GCP_RULES } from './gcp';

import { AWS_RULES } from './aws';
import { GCP_RULES } from './gcp';
import type { SecurityRule, CloudProvider } from '../types';

export function getRule(provider: CloudProvider, ruleId: string): SecurityRule | undefined {
  const rules = provider === 'aws' ? AWS_RULES : GCP_RULES;
  return rules[ruleId];
}

export function getAllRules(provider: CloudProvider): SecurityRule[] {
  const rules = provider === 'aws' ? AWS_RULES : GCP_RULES;
  return Object.values(rules);
}
