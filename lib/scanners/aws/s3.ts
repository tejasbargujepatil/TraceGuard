import { S3Client, ListBucketsCommand, GetBucketLocationCommand, GetPublicAccessBlockCommand, GetBucketVersioningCommand, GetBucketEncryptionCommand, GetBucketLoggingCommand } from '@aws-sdk/client-s3';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;
  const client = new S3Client({
    region: job.regions[0] || 'us-east-1',
    credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
  });

  try {
    const listResponse = await client.send(new ListBucketsCommand({}));
    const buckets = listResponse.Buckets || [];

    for (const bucket of buckets) {
      if (!bucket.Name) continue;
      const resourceId = bucket.Name;

      let region = 'us-east-1';
      try {
        const locResponse = await client.send(new GetBucketLocationCommand({ Bucket: resourceId }));
        region = locResponse.LocationConstraint || 'us-east-1';
      } catch (err) {
        console.error(`[AWS:S3:Location:${resourceId}]`, (err as Error).message);
      }
      
      const regionalClient = new S3Client({
        region,
        credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
      });

      try {
        const bpaResponse = await regionalClient.send(new GetPublicAccessBlockCommand({ Bucket: resourceId }));
        const conf = bpaResponse.PublicAccessBlockConfiguration;
        if (!conf || !conf.BlockPublicAcls || !conf.IgnorePublicAcls || !conf.BlockPublicPolicy || !conf.RestrictPublicBuckets) {
          const rule = AWS_RULES['s3-block-public-access-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId, resourceArn: `arn:aws:s3:::${resourceId}`, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Bucket ${resourceId} has Block Public Access settings disabled.`,
              potentialImpact: `Objects may be publicly readable from the internet.`,
              remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      } catch (err: any) {
        if (err.name === 'NoSuchPublicAccessBlockConfiguration') {
          const rule = AWS_RULES['s3-block-public-access-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId, resourceArn: `arn:aws:s3:::${resourceId}`, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Bucket ${resourceId} has no Block Public Access config.`,
              potentialImpact: `Objects may be publicly readable.`,
              remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        } else { console.error(`[AWS:S3:BPA:${resourceId}]`, err.message); }
      }

      try {
        const verResponse = await regionalClient.send(new GetBucketVersioningCommand({ Bucket: resourceId }));
        if (verResponse.Status !== 'Enabled') {
          const rule = AWS_RULES['s3-versioning-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId, resourceArn: `arn:aws:s3:::${resourceId}`, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Bucket ${resourceId} does not have versioning enabled.`,
              potentialImpact: `Accidental deletions cannot be recovered.`,
              remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      } catch (err: any) { console.error(`[AWS:S3:Versioning:${resourceId}]`, err.message); }

      try {
        await regionalClient.send(new GetBucketEncryptionCommand({ Bucket: resourceId }));
      } catch (err: any) {
        if (err.name === 'ServerSideEncryptionConfigurationNotFoundError') {
          const rule = AWS_RULES['s3-encryption-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId, resourceArn: `arn:aws:s3:::${resourceId}`, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Bucket ${resourceId} does not have encryption enabled.`,
              potentialImpact: `Data is unencrypted at rest.`,
              remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        } else { console.error(`[AWS:S3:Encryption:${resourceId}]`, err.message); }
      }

      try {
        const logResponse = await regionalClient.send(new GetBucketLoggingCommand({ Bucket: resourceId }));
        if (!logResponse.LoggingEnabled) {
          const rule = AWS_RULES['s3-logging-disabled'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId, resourceArn: `arn:aws:s3:::${resourceId}`, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Bucket ${resourceId} does not have logging enabled.`,
              potentialImpact: `Lack of audit logs.`,
              remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }
      } catch (err: any) { console.error(`[AWS:S3:Logging:${resourceId}]`, err.message); }
    }
  } catch (err: any) { console.error(`[AWS:S3:ListBuckets]`, err.message); }

  return findings;
}