import { RDSClient, DescribeDBInstancesCommand } from '@aws-sdk/client-rds';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new RDSClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new DescribeDBInstancesCommand({}));
      for (const inst of resp.DBInstances || []) {
        const id = inst.DBInstanceIdentifier;
        if (!id) continue;

        if (inst.PubliclyAccessible) {
          const rule = AWS_RULES['rds-publicly-accessible'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `RDS instance ${id} is publicly accessible.`,
              potentialImpact: `Database is exposed to the internet, increasing risk of brute-force or exploitation.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }

        if (!inst.StorageEncrypted) {
          const rule = AWS_RULES['rds-encryption-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `RDS instance ${id} is unencrypted.`,
              potentialImpact: `Data at rest is vulnerable if physical media is compromised.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }

        if ((inst.BackupRetentionPeriod || 0) === 0) {
          const rule = AWS_RULES['rds-backup-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `RDS instance ${id} has no backups enabled.`,
              potentialImpact: `Data cannot be recovered in case of deletion or corruption.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:RDS:${region}]`, err.message); }
  }
  return findings;
}