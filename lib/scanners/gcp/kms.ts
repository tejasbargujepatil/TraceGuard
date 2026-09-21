// lib/scanners/gcp/kms.ts — Cloud KMS scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface KeyRing { name: string }
interface CryptoKey { name: string; purpose: string; nextRotationTime?: string; rotationPeriod?: string }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const { keyRings = [] } = await gcpFetch<{ keyRings?: KeyRing[] }>(
      `https://cloudkms.googleapis.com/v1/projects/${project}/locations/-/keyRings`, token
    );
    for (const ring of keyRings) {
      try {
        const { cryptoKeys = [] } = await gcpFetch<{ cryptoKeys?: CryptoKey[] }>(
          `https://cloudkms.googleapis.com/v1/${ring.name}/cryptoKeys`, token
        );
        for (const key of cryptoKeys) {
          if (key.purpose !== 'ENCRYPT_DECRYPT') continue;
          const shortName = key.name.split('/').pop() ?? key.name;
          const location = key.name.split('/')[3] ?? 'global';
          const needsRotation = !key.rotationPeriod || !key.nextRotationTime;
          if (needsRotation) {
            const rule = GCP_RULES['gcp-kms-rotation-disabled'];
            if (rule) findings.push({ id: `${rule.id}::${shortName}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: shortName, region: location, accountId: project, provider: 'gcp', observedCondition: `KMS key ${shortName} in key ring ${ring.name.split('/').pop()} does not have automatic rotation configured.`, potentialImpact: 'Without rotation, long-lived key material that is compromised can decrypt any data encrypted with this key indefinitely.', remediation: rule.getRemediation(shortName), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
          }
        }
      } catch (e) { console.error(`[KMS:${ring.name}]`, (e as Error).message); }
    }
  } catch (err) { console.error('[KMS]', (err as Error).message); }
  return findings;
}
