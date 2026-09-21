import { EC2Client, DescribeSecurityGroupsCommand, DescribeInstancesCommand, DescribeVolumesCommand } from '@aws-sdk/client-ec2';
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
      const sgResp = await client.send(new DescribeSecurityGroupsCommand({}));
      for (const sg of sgResp.SecurityGroups || []) {
        if (!sg.GroupId) continue;
        for (const perm of sg.IpPermissions || []) {
          const fromPort = perm.FromPort;
          const toPort = perm.ToPort;
          const ranges = perm.IpRanges || [];
          const ipv6Ranges = perm.Ipv6Ranges || [];
          const isOpen = ranges.some(r => r.CidrIp === '0.0.0.0/0') || ipv6Ranges.some(r => r.CidrIpv6 === '::/0');
          if (isOpen) {
            if (fromPort && toPort && fromPort <= 22 && toPort >= 22) {
              const rule = AWS_RULES['ec2-sg-unrestricted-ssh'];
              if (rule) {
                findings.push({
                  id: `${rule.id}::${sg.GroupId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                  resourceId: sg.GroupId, region, accountId: job.cloudAccountId, provider: 'aws',
                  observedCondition: `Security group ${sg.GroupId} has unrestricted SSH access.`,
                  potentialImpact: `Allows attackers to attempt brute-force login to instances.`,
                  remediation: rule.getRemediation(sg.GroupId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
                });
              }
            }
            if (fromPort && toPort && fromPort <= 3389 && toPort >= 3389) {
              const rule = AWS_RULES['ec2-sg-unrestricted-rdp'];
              if (rule) {
                findings.push({
                  id: `${rule.id}::${sg.GroupId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                  resourceId: sg.GroupId, region, accountId: job.cloudAccountId, provider: 'aws',
                  observedCondition: `Security group ${sg.GroupId} has unrestricted RDP access.`,
                  potentialImpact: `Allows attackers to attempt brute-force login to instances.`,
                  remediation: rule.getRemediation(sg.GroupId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
                });
              }
            }
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:EC2:SG:${region}]`, err.message); }

    try {
      const instResp = await client.send(new DescribeInstancesCommand({}));
      for (const res of instResp.Reservations || []) {
        for (const inst of res.Instances || []) {
          if (!inst.InstanceId) continue;
          if (inst.MetadataOptions?.HttpTokens !== 'required') {
            const rule = AWS_RULES['ec2-imdsv2-not-enforced'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${inst.InstanceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: inst.InstanceId, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `Instance ${inst.InstanceId} does not enforce IMDSv2.`,
                potentialImpact: `Vulnerable to SSRF attacks extracting instance metadata.`,
                remediation: rule.getRemediation(inst.InstanceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:EC2:Instances:${region}]`, err.message); }

    try {
      const volResp = await client.send(new DescribeVolumesCommand({}));
      for (const vol of volResp.Volumes || []) {
        if (!vol.VolumeId) continue;
        if (!vol.Encrypted) {
          const rule = AWS_RULES['ec2-ebs-unencrypted'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${vol.VolumeId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: vol.VolumeId, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `EBS Volume ${vol.VolumeId} is unencrypted.`,
              potentialImpact: `Data is exposed if storage media is compromised.`,
              remediation: rule.getRemediation(vol.VolumeId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:EC2:Volumes:${region}]`, err.message); }
  }

  return findings;
}