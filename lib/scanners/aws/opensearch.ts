import { OpenSearchClient, ListDomainNamesCommand, DescribeDomainCommand } from '@aws-sdk/client-opensearch';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new OpenSearchClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListDomainNamesCommand({}));
      for (const d of resp.DomainNames || []) {
        const name = d.DomainName;
        if (!name) continue;
        try {
          const desc = await client.send(new DescribeDomainCommand({ DomainName: name }));
          if (!desc.DomainStatus?.VPCOptions) {
            const rule = AWS_RULES['opensearch-publicly-accessible'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: name, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `OpenSearch domain ${name} is not in a VPC.`,
                potentialImpact: `Data is exposed to the internet.`,
                remediation: rule.getRemediation(name, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:OpenSearch:${name}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:OpenSearch:${region}]`, err.message); }
  }
  return findings;
}