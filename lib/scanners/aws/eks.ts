import { EKSClient, ListClustersCommand, DescribeClusterCommand } from '@aws-sdk/client-eks';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new EKSClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListClustersCommand({}));
      for (const name of resp.clusters || []) {
        try {
          const desc = await client.send(new DescribeClusterCommand({ name }));
          const cluster = desc.cluster;
          if (cluster?.resourcesVpcConfig?.endpointPublicAccess && cluster.resourcesVpcConfig.publicAccessCidrs?.includes('0.0.0.0/0')) {
            const rule = AWS_RULES['eks-public-endpoint'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: name, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `EKS cluster ${name} has a fully public API endpoint.`,
                potentialImpact: `API server is exposed to the internet, increasing attack surface.`,
                remediation: rule.getRemediation(name, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:EKS:${name}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:EKS:${region}]`, err.message); }
  }
  return findings;
}