// lib/scanners/gcp/gcs.ts — Google Cloud Storage scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface GCSBucket { name: string; iamConfiguration?: { uniformBucketLevelAccess?: { enabled: boolean } }; encryption?: { defaultKmsKeyName?: string } }
interface IAMPolicy { bindings?: { role: string; members: string[] }[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const { items: buckets = [] } = await gcpFetch<{ items?: GCSBucket[] }>(
      `https://storage.googleapis.com/storage/v1/b?project=${project}&fields=items(name,iamConfiguration,encryption)`, token
    );
    for (const bucket of buckets) {
      const id = bucket.name;
      // Uniform bucket access
      if (!bucket.iamConfiguration?.uniformBucketLevelAccess?.enabled) {
        const rule = GCP_RULES['gcs-uniform-access-disabled'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Bucket ${id} does not have Uniform Bucket-Level Access enabled, allowing legacy ACLs.`, potentialImpact: 'Legacy ACLs can inadvertently grant public access, bypassing IAM policies and leading to data exposure.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
      }
      // CMEK
      if (!bucket.encryption?.defaultKmsKeyName) {
        const rule = GCP_RULES['gcs-encryption-no-cmek'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Bucket ${id} uses Google-managed keys instead of a customer-managed KMS key.`, potentialImpact: 'Without CMEK, you cannot revoke encryption access, audit key usage, or control key rotation independently.', remediation: rule.getRemediation(id), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
      }
      // Public IAM
      try {
        const policy = await gcpFetch<IAMPolicy>(`https://storage.googleapis.com/storage/v1/b/${id}/iam`, token);
        const publicMembers = ['allUsers', 'allAuthenticatedUsers'];
        const isPublic = (policy.bindings ?? []).some(b => b.members.some(m => publicMembers.includes(m)));
        if (isPublic) {
          const rule = GCP_RULES['gcs-bucket-public'];
          if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Bucket ${id} has IAM bindings granting access to allUsers or allAuthenticatedUsers.`, potentialImpact: 'Any person on the internet can read, list, or potentially write objects in this bucket without authentication.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
        }
      } catch (e) { console.error(`[GCS:${id}:iam]`, (e as Error).message); }
    }
  } catch (err) { console.error('[GCS]', (err as Error).message); }
  return findings;
}
