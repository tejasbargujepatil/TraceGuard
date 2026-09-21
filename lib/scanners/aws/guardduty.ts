import { GuardDutyClient, ListDetectorsCommand, GetDetectorCommand } from '@aws-sdk/client-guardduty';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new GuardDutyClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListDetectorsCommand({}));
      if (!resp.DetectorIds || resp.DetectorIds.length === 0) {
        const rule = AWS_RULES['guardduty-not-enabled'];
        if (rule) {
          findings.push({
            id: `${rule.id}::${region}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
            resourceId: 'region-guardduty', region, accountId: job.cloudAccountId, provider: 'aws',
            observedCondition: `GuardDuty is not enabled in ${region}.`,
            potentialImpact: `Malicious activity goes undetected.`,
            remediation: rule.getRemediation('region', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
          });
        }
      } else {
        let active = false;
        for (const id of resp.DetectorIds) {
          const det = await client.send(new GetDetectorCommand({ DetectorId: id }));
          if (det.Status === 'ENABLED') active = true;
        }
        if (!active) {
          const rule = AWS_RULES['guardduty-not-enabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${region}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: 'region-guardduty', region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `GuardDuty is disabled in ${region}.`,
              potentialImpact: `Malicious activity goes undetected.`,
              remediation: rule.getRemediation('region', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:GuardDuty:${region}]`, err.message); }
  }
  return findings;
}