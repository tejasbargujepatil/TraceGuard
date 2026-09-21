import { KMSClient, ListKeysCommand, DescribeKeyCommand, GetKeyRotationStatusCommand } from '@aws-sdk/client-kms';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new KMSClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListKeysCommand({}));
      for (const key of resp.Keys || []) {
        const id = key.KeyId;
        if (!id) continue;
        try {
          const desc = await client.send(new DescribeKeyCommand({ KeyId: id }));
          if (desc.KeyMetadata?.KeyManager === 'AWS') continue;

          const rot = await client.send(new GetKeyRotationStatusCommand({ KeyId: id }));
          if (!rot.KeyRotationEnabled) {
            const rule = AWS_RULES['kms-key-rotation-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `KMS Key ${id} does not have automatic rotation enabled.`,
                potentialImpact: `Compromised keys can be used indefinitely.`,
                remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:KMS:${id}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:KMS:${region}]`, err.message); }
  }
  return findings;
}