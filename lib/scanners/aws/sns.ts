import { SNSClient, ListTopicsCommand, GetTopicAttributesCommand } from '@aws-sdk/client-sns';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new SNSClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListTopicsCommand({}));
      for (const t of resp.Topics || []) {
        const arn = t.TopicArn;
        if (!arn) continue;
        try {
          const attr = await client.send(new GetTopicAttributesCommand({ TopicArn: arn }));
          if (!attr.Attributes || !attr.Attributes.KmsMasterKeyId) {
            const rule = AWS_RULES['sns-encryption-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${arn}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: arn, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `SNS topic ${arn} is unencrypted.`,
                potentialImpact: `Messages at rest are exposed if infrastructure is compromised.`,
                remediation: rule.getRemediation(arn, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:SNS:${arn}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:SNS:${region}]`, err.message); }
  }
  return findings;
}