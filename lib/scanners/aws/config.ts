import { ConfigServiceClient, DescribeConfigurationRecordersCommand, DescribeComplianceByConfigRuleCommand } from '@aws-sdk/client-config-service';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new ConfigServiceClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const recs = await client.send(new DescribeConfigurationRecordersCommand({}));
      if (!recs.ConfigurationRecorders || recs.ConfigurationRecorders.length === 0) {
        const rule = AWS_RULES['config-not-enabled'];
        if (rule) {
          findings.push({
            id: `${rule.id}::${region}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
            resourceId: 'region-config', region, accountId: job.cloudAccountId, provider: 'aws',
            observedCondition: `AWS Config is not enabled in ${region}.`,
            potentialImpact: `Resource changes are not tracked.`,
            remediation: rule.getRemediation('region', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
          });
        }
      }

      const comp = await client.send(new DescribeComplianceByConfigRuleCommand({ ComplianceTypes: ['NON_COMPLIANT'] }));
      for (const ruleConf of comp.ComplianceByConfigRules || []) {
        if (ruleConf.ConfigRuleName) {
           findings.push({
            id: `config-rule-${ruleConf.ConfigRuleName}::${region}`, ruleId: 'config-rule-failed', title: `Config Rule Failed: ${ruleConf.ConfigRuleName}`,
            severity: 'medium', category: 'Compliance', service: 'config',
            resourceId: ruleConf.ConfigRuleName, region, accountId: job.cloudAccountId, provider: 'aws',
            observedCondition: `AWS Config rule ${ruleConf.ConfigRuleName} is NON_COMPLIANT.`,
            potentialImpact: 'Non-compliant resources exist.',
            remediation: { summary: `AWS Config rule ${ruleConf.ConfigRuleName} is non-compliant. Review affected resources in the AWS Config console.`, steps: ['Open AWS Config → Rules → select the rule', 'View non-compliant resources', 'Follow the remediation guidance for each resource'], consoleUrl: `https://console.aws.amazon.com/config/home?region=${region}#/rules/details?configRuleName=${ruleConf.ConfigRuleName}`, estimatedEffort: 'hours', operationalImpact: 'medium' }, compliance: [], mitre: [], discoveredAt: new Date().toISOString()
          });
        }
      }
    } catch (err: any) { console.error(`[AWS:Config:${region}]`, err.message); }
  }
  return findings;
}