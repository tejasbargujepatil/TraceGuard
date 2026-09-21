import { SecurityHubClient, GetFindingsCommand } from '@aws-sdk/client-securityhub';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new SecurityHubClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new GetFindingsCommand({ Filters: { RecordState: [{ Value: 'ACTIVE', Comparison: 'EQUALS' }], ComplianceStatus: [{ Value: 'FAILED', Comparison: 'EQUALS' }] } }));
      for (const f of resp.Findings || []) {
        let severity: 'critical' | 'high' | 'medium' | 'low' | 'info' = 'info';
        if (f.Severity?.Label === 'CRITICAL') severity = 'critical';
        else if (f.Severity?.Label === 'HIGH') severity = 'high';
        else if (f.Severity?.Label === 'MEDIUM') severity = 'medium';
        else if (f.Severity?.Label === 'LOW') severity = 'low';

        findings.push({
          id: `securityhub-${f.Id}`, ruleId: `securityhub-${f.Types?.[0]?.replace(/[^a-zA-Z0-9-]/g, '-') || 'finding'}`,
          title: f.Title || 'SecurityHub Finding', severity, category: 'SecurityHub', service: 'securityhub',
          resourceId: f.Resources?.[0]?.Id || 'unknown', resourceArn: f.Resources?.[0]?.Id,
          region, accountId: job.cloudAccountId, provider: 'aws',
          observedCondition: f.Description || '', potentialImpact: 'See SecurityHub for details.',
          remediation: { summary: f.Remediation?.Recommendation?.Text ?? 'Review in AWS Security Hub console.', steps: [f.Remediation?.Recommendation?.Text ?? 'See Security Hub for remediation guidance.'], consoleUrl: f.Remediation?.Recommendation?.Url, estimatedEffort: 'hours', operationalImpact: 'medium' },
          compliance: [], mitre: [], discoveredAt: new Date().toISOString()
        });
      }
    } catch (err: any) { console.error(`[AWS:SecurityHub:${region}]`, err.message); }
  }
  return findings;
}