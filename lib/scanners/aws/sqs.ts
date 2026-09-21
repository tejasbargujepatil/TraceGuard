import { SQSClient, ListQueuesCommand, GetQueueAttributesCommand } from '@aws-sdk/client-sqs';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new SQSClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListQueuesCommand({}));
      for (const url of resp.QueueUrls || []) {
        try {
          const attr = await client.send(new GetQueueAttributesCommand({ QueueUrl: url, AttributeNames: ['All'] }));
          if (!attr.Attributes || (!attr.Attributes.KmsMasterKeyId && !attr.Attributes.SqsManagedSseEnabled)) {
            const rule = AWS_RULES['sqs-encryption-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${url}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: url, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `SQS queue ${url} is unencrypted.`,
                potentialImpact: `Messages at rest are exposed if infrastructure is compromised.`,
                remediation: rule.getRemediation(url, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:SQS:${url}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:SQS:${region}]`, err.message); }
  }
  return findings;
}