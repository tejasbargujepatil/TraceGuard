import { CloudTrailClient, DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new CloudTrailClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new DescribeTrailsCommand({}));
      const trails = resp.trailList || [];
      if (trails.length === 0 || !trails.some(t => t.IsMultiRegionTrail)) {
        const rule = AWS_RULES['cloudtrail-not-enabled'];
        if (rule) {
          findings.push({
            id: `${rule.id}::account`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
            resourceId: 'account-cloudtrail', region, accountId: job.cloudAccountId, provider: 'aws',
            observedCondition: `No multi-region CloudTrail enabled.`,
            potentialImpact: `No comprehensive audit logging for the account.`,
            remediation: rule.getRemediation('account', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
          });
        }
      }

      for (const t of trails) {
        if (!t.LogFileValidationEnabled && t.Name) {
          const rule = AWS_RULES['cloudtrail-log-validation-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${t.Name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: t.Name, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `CloudTrail ${t.Name} does not have log file validation enabled.`,
              potentialImpact: `Attackers can tamper with log files undetected.`,
              remediation: rule.getRemediation(t.Name, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:CloudTrail:${region}]`, err.message); }
  }
  return findings;
}