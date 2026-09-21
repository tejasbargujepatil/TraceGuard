import { DynamoDBClient, ListTablesCommand, DescribeTableCommand, DescribeContinuousBackupsCommand } from '@aws-sdk/client-dynamodb';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new DynamoDBClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListTablesCommand({}));
      for (const tName of resp.TableNames || []) {
        try {
          const desc = await client.send(new DescribeTableCommand({ TableName: tName }));
          const table = desc.Table;
          if (table?.SSEDescription?.Status !== 'ENABLED') {
            const rule = AWS_RULES['dynamodb-encryption-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${tName}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: tName, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `DynamoDB table ${tName} does not have SSE enabled.`,
                potentialImpact: `Data at rest is not protected by customer-managed keys.`,
                remediation: rule.getRemediation(tName, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:DynamoDB:${tName}]`, err.message); }

        try {
          const backup = await client.send(new DescribeContinuousBackupsCommand({ TableName: tName }));
          if (backup.ContinuousBackupsDescription?.PointInTimeRecoveryDescription?.PointInTimeRecoveryStatus !== 'ENABLED') {
            const rule = AWS_RULES['dynamodb-pitr-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${tName}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: tName, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `DynamoDB table ${tName} does not have PITR enabled.`,
                potentialImpact: `Accidental deletions cannot be precisely recovered.`,
                remediation: rule.getRemediation(tName, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:DynamoDB:PITR:${tName}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:DynamoDB:${region}]`, err.message); }
  }
  return findings;
}