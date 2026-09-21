import { ACMClient, ListCertificatesCommand, DescribeCertificateCommand } from '@aws-sdk/client-acm';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;
  const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

  for (const region of job.regions) {
    const client = new ACMClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListCertificatesCommand({}));
      for (const cert of resp.CertificateSummaryList || []) {
        const arn = cert.CertificateArn;
        if (!arn) continue;
        try {
          const desc = await client.send(new DescribeCertificateCommand({ CertificateArn: arn }));
          const c = desc.Certificate;
          if (c?.NotAfter && c.NotAfter.getTime() < Date.now() + THIRTY_DAYS) {
            const rule = AWS_RULES['acm-cert-expiring'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${arn}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: arn, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `Certificate ${arn} expires within 30 days.`,
                potentialImpact: `Service outage or browser warnings due to expired TLS certs.`,
                remediation: rule.getRemediation(arn, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:ACM:${arn}]`, err.message); }
      }
    } catch (err: any) { console.error(`[AWS:ACM:${region}]`, err.message); }
  }
  return findings;
}