// lib/scanners/gcp/gcpiam.ts — GCP IAM scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface ServiceAccount { name: string; email: string; displayName?: string }
interface SAKey { name: string; keyType: string; validAfterTime: string }
interface IAMPolicy { bindings?: { role: string; members: string[] }[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);

    // Service account user-managed keys
    const { accounts = [] } = await gcpFetch<{ accounts?: ServiceAccount[] }>(
      `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts`, token
    );
    for (const sa of accounts) {
      try {
        const { keys = [] } = await gcpFetch<{ keys?: SAKey[] }>(
          `https://iam.googleapis.com/v1/${sa.name}/keys`, token
        );
        const userKeys = keys.filter(k => k.keyType === 'USER_MANAGED');
        if (userKeys.length > 0) {
          const rule = GCP_RULES['gcp-iam-service-account-key'];
          if (rule) findings.push({ id: `${rule.id}::${sa.email}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: sa.email, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Service account ${sa.email} has ${userKeys.length} user-managed key(s) that must be manually rotated.`, potentialImpact: 'Leaked service account keys provide persistent access to GCP resources and are difficult to detect if compromised.', remediation: rule.getRemediation(sa.email), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
        }
      } catch (e) { console.error(`[GCPIAM:${sa.email}]`, (e as Error).message); }
    }

    // Primitive roles at project level
    try {
      const policy = await gcpFetch<IAMPolicy>(
        `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`,
        token
      );
      const primitiveRoles = ['roles/owner', 'roles/editor'];
      for (const binding of (policy.bindings ?? [])) {
        if (!primitiveRoles.includes(binding.role)) continue;
        const humanMembers = binding.members.filter(m => m.startsWith('user:') || m.startsWith('group:'));
        if (humanMembers.length > 0) {
          const rule = GCP_RULES['gcp-iam-primitive-roles'];
          if (rule) findings.push({ id: `${rule.id}::${project}::${binding.role}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: project, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Role ${binding.role} is granted to: ${humanMembers.join(', ')} at the project level.`, potentialImpact: 'Primitive roles grant overly broad access. An Owner can delete the entire project; an Editor can modify all resources.', remediation: rule.getRemediation(project), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
        }
      }
    } catch (e) { console.error('[GCPIAM:policy]', (e as Error).message); }
  } catch (err) { console.error('[GCPIAM]', (err as Error).message); }
  return findings;
}
