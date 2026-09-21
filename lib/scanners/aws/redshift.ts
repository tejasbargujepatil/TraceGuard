import { RedshiftClient, DescribeClustersCommand } from '@aws-sdk/client-redshift';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new RedshiftClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new DescribeClustersCommand({}));
      for (const c of resp.Clusters || []) {
        const id = c.ClusterIdentifier;
        if (!id) continue;
        if (c.PubliclyAccessible) {
          const rule = AWS_RULES['redshift-publicly-accessible'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Redshift cluster ${id} is publicly accessible.`,
              potentialImpact: `Data is exposed to the internet.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:Redshift:${region}]`, err.message); }
  }
  return findings;
}