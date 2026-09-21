import { EC2Client, DescribeVpcsCommand, DescribeFlowLogsCommand } from '@aws-sdk/client-ec2';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new EC2Client({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const vpcResp = await client.send(new DescribeVpcsCommand({}));
      for (const vpc of vpcResp.Vpcs || []) {
        if (!vpc.VpcId) continue;
        if (vpc.IsDefault) {
          const rule = AWS_RULES['vpc-default-in-use'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${vpc.VpcId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: vpc.VpcId, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Default VPC ${vpc.VpcId} is present.`,
              potentialImpact: `Using default VPCs can lead to broader exposure than custom-configured VPCs.`,
              remediation: rule.getRemediation(vpc.VpcId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }

        try {
          const flowResp = await client.send(new DescribeFlowLogsCommand({ Filter: [{ Name: 'resource-id', Values: [vpc.VpcId] }] }));
          if (!flowResp.FlowLogs || flowResp.FlowLogs.length === 0) {
            const rule = AWS_RULES['vpc-flow-logs-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${vpc.VpcId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: vpc.VpcId, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `VPC ${vpc.VpcId} does not have flow logs enabled.`,
                potentialImpact: `Lack of network traffic visibility hampers incident investigation.`,
                remediation: rule.getRemediation(vpc.VpcId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:VPC:FlowLogs:${vpc.VpcId}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:VPC:${region}]`, err.message); }
  }
  return findings;
}