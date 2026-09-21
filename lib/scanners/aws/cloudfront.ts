import { CloudFrontClient, ListDistributionsCommand } from '@aws-sdk/client-cloudfront';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;
  const region = 'us-east-1';
  const client = new CloudFrontClient({
    region,
    credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
  });

  try {
    const resp = await client.send(new ListDistributionsCommand({}));
    for (const dist of resp.DistributionList?.Items || []) {
      const id = dist.Id;
      if (!id) continue;
      const policy = dist.DefaultCacheBehavior?.ViewerProtocolPolicy;
      if (policy !== 'redirect-to-https' && policy !== 'https-only') {
        const rule = AWS_RULES['cloudfront-https-not-enforced'];
        if (rule) {
          findings.push({
            id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
            resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
            observedCondition: `CloudFront distribution ${id} does not enforce HTTPS.`,
            potentialImpact: `Traffic can be intercepted in transit.`,
            remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
          });
        }
      }
    }
  } catch (err: any) { console.error(`[AWS:CloudFront]`, err.message); }
  return findings;
}