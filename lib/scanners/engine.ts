// lib/scanners/engine.ts
// Scanner engine — registers all service scanners and runs chunked scans.
// Each service scan is called individually (chunked) so Vercel free tier doesn't time out.

import type { ScanFinding, ScanJob, ServiceScanResult, CloudProvider } from './types';
import { sanityClient } from '../sanity/client';

// ─── Scanner Registry ─────────────────────────────────────────────────────────

export interface RegisteredScanner {
  key: string;           // e.g. 's3'
  displayName: string;   // e.g. 'S3 Buckets'
  provider: CloudProvider;
  scan: (job: ScanJob) => Promise<ScanFinding[]>;
}

const AWS_SCANNER_KEYS = [
  's3', 'iam', 'ec2', 'vpc', 'rds', 'lambda', 'eks',
  'cloudtrail', 'kms', 'secretsmanager', 'acm', 'dynamodb',
  'sqs', 'sns', 'cloudfront', 'guardduty', 'securityhub',
  'config', 'redshift', 'opensearch',
];

const GCP_SCANNER_KEYS = [
  'gcs', 'gcpiam', 'compute', 'cloudsql', 'bigquery',
  'functions', 'gke', 'kms', 'logging',
];

/** Returns the ordered list of service keys for a provider */
export function getServiceKeys(provider: CloudProvider): string[] {
  return provider === 'aws' ? AWS_SCANNER_KEYS : GCP_SCANNER_KEYS;
}

/** Display names for services */
const SERVICE_DISPLAY_NAMES: Record<string, string> = {
  // AWS
  s3: 'S3 Buckets',
  iam: 'IAM Users & Roles',
  ec2: 'EC2 & Security Groups',
  vpc: 'VPC & Networking',
  rds: 'RDS Databases',
  lambda: 'Lambda Functions',
  eks: 'EKS Clusters',
  cloudtrail: 'CloudTrail',
  kms: 'KMS Keys',
  secretsmanager: 'Secrets Manager',
  acm: 'ACM Certificates',
  dynamodb: 'DynamoDB Tables',
  sqs: 'SQS Queues',
  sns: 'SNS Topics',
  cloudfront: 'CloudFront',
  guardduty: 'GuardDuty',
  securityhub: 'Security Hub',
  config: 'AWS Config',
  redshift: 'Redshift',
  opensearch: 'OpenSearch',
  // GCP
  gcs: 'Cloud Storage',
  gcpiam: 'GCP IAM',
  compute: 'Compute Engine',
  cloudsql: 'Cloud SQL',
  bigquery: 'BigQuery',
  functions: 'Cloud Functions',
  gke: 'GKE Clusters',
  kms_gcp: 'Cloud KMS',
  logging: 'Cloud Logging',
};

export function getDisplayName(key: string): string {
  return SERVICE_DISPLAY_NAMES[key] ?? key.toUpperCase();
}

// ─── Dynamic scanner loader ───────────────────────────────────────────────────

async function loadScanner(provider: CloudProvider, serviceKey: string) {
  try {
    if (provider === 'aws') {
      const mod = await import(`./aws/${serviceKey}`);
      return mod.scan as (job: ScanJob) => Promise<ScanFinding[]>;
    } else {
      const mod = await import(`./gcp/${serviceKey}`);
      return mod.scan as (job: ScanJob) => Promise<ScanFinding[]>;
    }
  } catch {
    return null;
  }
}

// ─── Run a single service scan (called per-service from the API route) ────────

export async function runServiceScan(
  job: ScanJob,
  serviceKey: string
): Promise<ServiceScanResult> {
  const start = Date.now();
  const displayName = getDisplayName(serviceKey);

  try {
    const scanFn = await loadScanner(job.provider, serviceKey);
    if (!scanFn) {
      return {
        service: serviceKey,
        displayName,
        status: 'skipped',
        findingCount: 0,
        findings: [],
        durationMs: Date.now() - start,
        error: `No scanner implemented for ${serviceKey}`,
      };
    }

    const findings = await scanFn(job);

    // Write findings to Sanity (best-effort)
    await persistFindings(job, findings);

    return {
      service: serviceKey,
      displayName,
      status: 'complete',
      findingCount: findings.length,
      findings,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    console.error(`[Scanner:${serviceKey}]`, err);
    return {
      service: serviceKey,
      displayName,
      status: 'error',
      findingCount: 0,
      findings: [],
      durationMs: Date.now() - start,
      error: (err as Error).message,
    };
  }
}

// ─── Persist findings to Sanity ───────────────────────────────────────────────

async function persistFindings(job: ScanJob, findings: ScanFinding[]) {
  if (!findings.length) return;

  const docs = findings.map((f) => ({
    _id: `scan-finding-${f.id.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 200)}`,
    _type: 'finding',
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    category: f.category,
    status: 'open',
    observedCondition: f.observedCondition,
    potentialImpact: f.potentialImpact,
    discoveredAt: f.discoveredAt,
    // Cloud-specific metadata
    cloudProvider: f.provider,
    cloudAccountId: f.accountId,
    resourceId: f.resourceId,
    resourceArn: f.resourceArn,
    resourceName: f.resourceName,
    region: f.region,
    service: f.service,
    compliance: f.compliance,
    mitre: f.mitre,
    remediationSummary: f.remediation.summary,
    remediationSteps: f.remediation.steps,
    remediationAwsCli: f.remediation.awsCli,
    remediationGcpCli: f.remediation.gcpCli,
    remediationTerraform: f.remediation.terraform,
    remediationConsoleUrl: f.remediation.consoleUrl,
    remediationEffort: f.remediation.estimatedEffort,
    operationalImpact: f.remediation.operationalImpact,
    autoDetected: true,
    scanTimestamp: new Date().toISOString(),
  }));

  try {
    const tx = sanityClient.transaction();
    for (const doc of docs) {
      tx.createOrReplace(doc);
    }
    await tx.commit({ visibility: 'async' });
  } catch (err) {
    console.error('[Engine] Failed to persist findings:', err);
  }
}

// ─── Update cloud account scan status ────────────────────────────────────────

export async function updateAccountScanStatus(
  accountSanityId: string,
  status: 'scanning' | 'connected' | 'error',
  stats?: { total: number; critical: number; high: number },
  errorMessage?: string
) {
  try {
    const patch = sanityClient.patch(accountSanityId).set({
      status,
      ...(stats && {
        lastScannedAt: new Date().toISOString(),
        lastScanFindingCount: stats.total,
        lastScanCriticalCount: stats.critical,
        lastScanHighCount: stats.high,
      }),
      ...(errorMessage && { errorMessage }),
    });
    await patch.commit({ visibility: 'async' });
  } catch (err) {
    console.error('[Engine] Failed to update account status:', err);
  }
}
