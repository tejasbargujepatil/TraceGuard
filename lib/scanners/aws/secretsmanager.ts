import { SecretsManagerClient, ListSecretsCommand } from '@aws-sdk/client-secrets-manager';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new SecretsManagerClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListSecretsCommand({}));
      for (const sec of resp.SecretList || []) {
        const id = sec.Name || sec.ARN;
        if (!id) continue;
        if (!sec.RotationEnabled) {
          const rule = AWS_RULES['secretsmanager-rotation-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Secret ${id} does not have rotation enabled.`,
              potentialImpact: `Stale secrets increase risk if leaked.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:SecretsManager:${region}]`, err.message); }
  }
  return findings;
}