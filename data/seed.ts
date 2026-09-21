// TraceGuard — ACME Corporation Synthetic Security Dataset
// 
// This file contains all seed data for the demonstration environment.
// IMPORTANT: This is entirely synthetic data for demonstration purposes.
// No real AWS accounts are accessed or represented.
//
// Organization: ACME Corporation (fictional)
// Environment: Production + Development
// Scenario: A compound security misconfiguration investigation

import { createClient } from '@sanity/client';
import * as dotenv from 'dotenv';
import * as path from 'path';
import * as fs from 'fs';

// Load env
const envPath = path.resolve(process.cwd(), '.env.local');
if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else {
  dotenv.config({ path: path.resolve(process.cwd(), '.env') });
}

const client = createClient({
  projectId: process.env.SANITY_PROJECT_ID || process.env.NEXT_PUBLIC_SANITY_PROJECT_ID || '',
  dataset: process.env.SANITY_DATASET || 'production',
  apiVersion: '2024-01-01',
  token: process.env.SANITY_API_TOKEN,
  useCdn: false,
});

// ─── Seed Document Definitions ────────────────────────────────────────────────

const SOURCES = [
  {
    _id: 'source-aws-s3-block-public-access',
    _type: 'source',
    title: 'Configuring block public access settings for your S3 bucket',
    organization: 'Amazon Web Services',
    url: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-bucket.html',
    authority: 'aws',
    publicationDate: '2024-01-15',
    version: '2024',
    sourceType: 'documentation',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'AWS documentation on S3 Block Public Access settings that operate at account, bucket, and access-point levels. Describes how BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets settings interact.',
  },
  {
    _id: 'source-aws-iam-least-privilege',
    _type: 'source',
    title: 'AWS IAM Security Best Practices — Least Privilege',
    organization: 'Amazon Web Services',
    url: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    authority: 'aws',
    publicationDate: '2024-03-01',
    version: '2024',
    sourceType: 'documentation',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'AWS IAM best practices covering least privilege access, use of conditions in policies, regular review of permissions, and avoiding use of wildcard (*) in resource or action fields.',
  },
  {
    _id: 'source-mitre-t1530',
    _type: 'source',
    title: 'MITRE ATT&CK: T1530 — Data from Cloud Storage',
    organization: 'MITRE Corporation',
    url: 'https://attack.mitre.org/techniques/T1530/',
    authority: 'mitre',
    publicationDate: '2024-01-01',
    version: 'v15',
    sourceType: 'threat_intel',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'Adversaries may access data objects from improperly secured cloud storage. Cloud service providers often provide storage services that allow users to store large amounts of data. Misconfigured cloud storage may expose this data directly or allow adversaries to exfiltrate it via legitimate means.',
  },
  {
    _id: 'source-mitre-t1078-004',
    _type: 'source',
    title: 'MITRE ATT&CK: T1078.004 — Valid Accounts: Cloud Accounts',
    organization: 'MITRE Corporation',
    url: 'https://attack.mitre.org/techniques/T1078/004/',
    authority: 'mitre',
    publicationDate: '2024-01-01',
    version: 'v15',
    sourceType: 'threat_intel',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'Adversaries may obtain and abuse credentials of cloud accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and managed by an organization for use by users, remote support, integration, etc.',
  },
  {
    _id: 'source-cis-aws-2-1-2',
    _type: 'source',
    title: 'CIS Amazon Web Services Foundations Benchmark v3.0.0 — Control 2.1.2',
    organization: 'Center for Internet Security',
    url: 'https://www.cisecurity.org/cis-benchmarks',
    authority: 'cis',
    publicationDate: '2023-11-01',
    version: '3.0.0',
    sourceType: 'standard',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'CIS AWS Foundations Benchmark Control 2.1.2: Ensure S3 Bucket Policy is set to deny HTTP requests and that Block Public Access is enabled. Rationale: Enabling Block Public Access prevents the accidental or intentional exposure of data stored in S3 to the public internet.',
  },
  {
    _id: 'source-nist-csf-pr-ds',
    _type: 'source',
    title: 'NIST Cybersecurity Framework 2.0 — PR.DS (Data Security)',
    organization: 'National Institute of Standards and Technology',
    url: 'https://www.nist.gov/cyberframework',
    authority: 'nist',
    publicationDate: '2024-02-26',
    version: '2.0',
    sourceType: 'standard',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'NIST CSF 2.0 Protect function — Data Security subcategory. PR.DS-1: Data-at-rest is protected. PR.DS-2: Data-in-transit is protected. PR.DS-10: The confidentiality, integrity, and availability of data-at-rest are protected.',
  },
  {
    _id: 'source-internal-policy-v2',
    _type: 'source',
    title: 'ACME Corp Information Security Policy v2.0',
    organization: 'ACME Corporation (Internal)',
    url: null,
    authority: 'internal',
    publicationDate: '2024-01-01',
    version: '2.0',
    sourceType: 'policy',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'current',
    summary:
      'Current ACME Corporation information security policy requiring that all production data storage must enforce access controls. Public access to production data storage containing customer information is explicitly prohibited.',
  },
  {
    _id: 'source-internal-legacy-arch',
    _type: 'source',
    title: 'ACME Corp Cloud Architecture Document — Legacy Distribution Architecture',
    organization: 'ACME Corporation (Internal)',
    url: null,
    authority: 'internal',
    publicationDate: '2022-06-01',
    version: '1.0',
    sourceType: 'architecture_doc',
    retrievedAt: '2024-09-01T00:00:00Z',
    status: 'historical',
    summary:
      'Original architecture document from 2022 describing the external distribution architecture where the prod-customer-backups bucket was intentionally configured for public access to support a third-party distribution service that has since been decommissioned.',
  },
];

const THREAT_TECHNIQUES = [
  {
    _id: 'threat-t1530',
    _type: 'threatTechnique',
    techniqueId: 'T1530',
    name: 'Data from Cloud Storage',
    description:
      'Adversaries may access data objects from improperly secured cloud storage. Cloud service providers often provide storage services that allow users to store large amounts of data, such as messages, attachments, contacts, financial records, and user preferences. If cloud storage is misconfigured, adversaries may be able to directly retrieve the data without requiring credentials, or they may be able to abuse legitimate cloud APIs to retrieve data.',
    tactics: ['Collection'],
    affectedServices: ['S3', 'CloudStorage', 'Blob'],
    relevantConditions: ['PublicAccessBlock', 'BucketPolicy', 'ACL', 'public-read'],
    cloudContext:
      'In AWS environments, this technique is enabled when S3 Block Public Access is disabled at the bucket or account level, or when bucket ACLs grant public read permissions. The technique allows unauthenticated retrieval of all objects in the bucket without any AWS credentials.',
    severity: 'high',
    mitigations: [
      'Enable S3 Block Public Access at account and bucket level',
      'Audit bucket ACLs and remove public-read permissions',
      'Enable S3 Object Ownership controls',
      'Use S3 access logging to detect unauthorized access',
      'Implement SCPs to prevent public bucket creation organization-wide',
    ],
    externalUrl: 'https://attack.mitre.org/techniques/T1530/',
    source: { _type: 'reference', _ref: 'source-mitre-t1530' },
  },
  {
    _id: 'threat-t1078-004',
    _type: 'threatTechnique',
    techniqueId: 'T1078.004',
    name: 'Valid Accounts: Cloud Accounts',
    description:
      'Adversaries may obtain and abuse credentials of cloud accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Overly permissive IAM roles and policies can allow adversaries who gain access to one service or account to pivot to other resources, access sensitive data, or establish persistence.',
    tactics: ['Initial Access', 'Persistence', 'Privilege Escalation', 'Defense Evasion'],
    affectedServices: ['IAM', 'STS', 'EC2', 'Lambda', 'S3'],
    relevantConditions: ['MFAEnabled', 'WildcardPermissions', 'CrossAccountAccess', 'OverlyPermissive'],
    cloudContext:
      'In AWS environments, overly permissive IAM roles (particularly those with wildcard action/resource permissions) enable lateral movement and privilege escalation once an attacker gains a foothold. Roles without MFA requirements are particularly vulnerable.',
    severity: 'critical',
    mitigations: [
      'Enforce IAM least privilege — avoid wildcards in Action and Resource',
      'Enable MFA for all human and privileged accounts',
      'Use IAM Access Analyzer to identify overly permissive policies',
      'Implement SCPs to restrict dangerous actions organization-wide',
      'Rotate access keys regularly',
    ],
    externalUrl: 'https://attack.mitre.org/techniques/T1078/004/',
    source: { _type: 'reference', _ref: 'source-mitre-t1078-004' },
  },
];

const SECURITY_CONTROLS = [
  {
    _id: 'control-cis-2-1-2',
    _type: 'securityControl',
    controlId: 'CIS-2.1.2',
    name: 'Ensure S3 Block Public Access is Enabled',
    description:
      'CIS AWS Foundations Benchmark Control 2.1.2 requires that S3 Block Public Access settings be enabled at the account level and that individual buckets do not override these settings. This prevents accidental or intentional public exposure of S3 data.',
    framework: 'CIS',
    requirements: [
      'BlockPublicAcls must be enabled at account and bucket level',
      'IgnorePublicAcls must be enabled at account and bucket level',
      'BlockPublicPolicy must be enabled at account and bucket level',
      'RestrictPublicBuckets must be enabled at account and bucket level',
    ],
    applicableServices: ['S3'],
    remediationGuidance:
      'Enable Block Public Access for the bucket using the AWS Console, CLI, or CloudFormation. For the CLI: aws s3api put-public-access-block --bucket BUCKET_NAME --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true. Also enable at the account level.',
    version: '3.0.0',
    severity: 'high',
    relevantThreatTechniques: [{ _type: 'reference', _ref: 'threat-t1530' }],
    source: { _type: 'reference', _ref: 'source-cis-aws-2-1-2' },
  },
  {
    _id: 'control-cis-1-16',
    _type: 'securityControl',
    controlId: 'CIS-1.16',
    name: 'Ensure IAM Policies Are Attached Only to Groups or Roles',
    description:
      'IAM policies should not be attached directly to users. Policies should be attached to groups or roles, and users should be added to groups. This ensures consistent permission management and makes it easier to audit access.',
    framework: 'CIS',
    requirements: [
      'No IAM policies directly attached to users',
      'Users access resources through group or role memberships',
      'IAM Access Analyzer enabled',
    ],
    applicableServices: ['IAM', 'STS'],
    remediationGuidance:
      'Use IAM Access Analyzer to identify and remove direct user policies. Move permissions to IAM groups or roles. Review with: aws iam list-users and aws iam list-user-policies.',
    version: '3.0.0',
    severity: 'medium',
    relevantThreatTechniques: [{ _type: 'reference', _ref: 'threat-t1078-004' }],
    source: { _type: 'reference', _ref: 'source-cis-aws-2-1-2' },
  },
  {
    _id: 'control-nist-pr-ds-1',
    _type: 'securityControl',
    controlId: 'NIST-PR.DS-1',
    name: 'Data-at-Rest Protection',
    description:
      'NIST CSF 2.0 PR.DS-1: Data-at-rest is protected. This includes encrypting sensitive data stored in cloud services and ensuring access controls prevent unauthorized retrieval.',
    framework: 'NIST',
    requirements: [
      'All sensitive data at rest must be encrypted',
      'Access controls must restrict data retrieval to authorized parties',
      'Public access to sensitive data storage must be prohibited',
    ],
    applicableServices: ['S3', 'RDS', 'EBS', 'DynamoDB'],
    remediationGuidance:
      'Enable server-side encryption on all S3 buckets. Disable public access. Implement bucket policies that explicitly deny unauthorized access. Audit with AWS Config rules: s3-bucket-public-read-prohibited, s3-bucket-public-write-prohibited.',
    version: '2.0',
    severity: 'high',
    relevantThreatTechniques: [{ _type: 'reference', _ref: 'threat-t1530' }],
    source: { _type: 'reference', _ref: 'source-nist-csf-pr-ds' },
  },
];

const POLICIES = [
  {
    _id: 'policy-storage-access-v1',
    _type: 'policy',
    name: 'Cloud Storage Access Policy',
    policyId: 'POL-S3-001',
    version: '1.0',
    isCurrentVersion: false,
    requirement:
      'Production data storage may be configured for public access where explicitly required for external distribution workflows. Such configurations must be documented and approved by the Engineering Lead.',
    appliesTo: ['production', 's3', 'cloud_storage'],
    effectiveFrom: '2022-01-01',
    effectiveTo: '2023-12-31',
    exceptions: ['prod-customer-backups: approved for external distribution (legacy)'],
    notes:
      'This policy was created in 2022 to support an external data distribution workflow. The prod-customer-backups bucket was originally configured as publicly readable to support a third-party data distribution service. This policy was superseded in 2024 when the distribution service was decommissioned.',
    approvedBy: 'Engineering Lead, 2022',
    source: { _type: 'reference', _ref: 'source-internal-legacy-arch' },
    supersededBy: { _type: 'reference', _ref: 'policy-storage-access-v2' },
  },
  {
    _id: 'policy-storage-access-v2',
    _type: 'policy',
    name: 'Cloud Storage Access Policy',
    policyId: 'POL-S3-001',
    version: '2.0',
    isCurrentVersion: true,
    requirement:
      'All production cloud storage containing customer data must enforce restricted access controls. Public access to production storage is explicitly prohibited. Block Public Access must be enabled at both account and bucket levels. Any exceptions require CISO approval and must be time-limited.',
    appliesTo: ['production', 's3', 'cloud_storage', 'customer_data', 'all_environments'],
    effectiveFrom: '2024-01-01',
    exceptions: [],
    notes:
      'This policy supersedes v1.0 following the decommission of the external distribution service in Q4 2023. All production storage must now enforce restricted access with no public access exceptions.',
    approvedBy: 'CISO, January 2024',
    source: { _type: 'reference', _ref: 'source-internal-policy-v2' },
  },
  {
    _id: 'policy-iam-least-privilege',
    _type: 'policy',
    name: 'IAM Least Privilege Policy',
    policyId: 'POL-IAM-001',
    version: '1.0',
    isCurrentVersion: true,
    requirement:
      'All IAM roles and policies must follow the principle of least privilege. Wildcard (*) permissions in Action or Resource fields are prohibited without explicit CISO approval. All roles must be scoped to the minimum permissions required for their function.',
    appliesTo: ['iam', 'production', 'development', 'all_environments'],
    effectiveFrom: '2023-06-01',
    exceptions: [],
    notes:
      'Applies to all IAM roles, policies, and service accounts across all environments. Use IAM Access Analyzer to continuously validate.',
    approvedBy: 'Security Team, June 2023',
    source: { _type: 'reference', _ref: 'source-aws-iam-least-privilege' },
  },
];

const SECURITY_ASSETS = [
  // ── Production Assets ────────────────────────────────────────────────────
  {
    _id: 'asset-prod-s3-backups',
    _type: 'securityAsset',
    name: 'prod-customer-backups',
    assetId: 'arn:aws:s3:::prod-customer-backups',
    provider: 'aws',
    service: 'S3',
    environment: 'production',
    description:
      'Production S3 bucket containing daily database backups of the customer data warehouse. Contains PII and financial records.',
    sensitivity: 'restricted',
    owner: 'Platform Engineering Team',
    tags: ['production', 'backup', 'customer-data', 'pii'],
    region: 'us-east-1',
    accountId: '123456789012',
    source: { _type: 'reference', _ref: 'source-aws-s3-block-public-access' },
  },
  {
    _id: 'asset-prod-rds',
    _type: 'securityAsset',
    name: 'customer-db',
    assetId: 'arn:aws:rds:us-east-1:123456789012:db:customer-db-prod',
    provider: 'aws',
    service: 'RDS',
    environment: 'production',
    description: 'Production RDS PostgreSQL instance containing the customer data warehouse.',
    sensitivity: 'restricted',
    owner: 'Platform Engineering Team',
    tags: ['production', 'database', 'customer-data'],
    region: 'us-east-1',
    accountId: '123456789012',
    relatedAssets: [{ _type: 'reference', _ref: 'asset-prod-s3-backups' }],
  },
  {
    _id: 'asset-prod-ec2-api',
    _type: 'securityAsset',
    name: 'api-server',
    assetId: 'arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456789',
    provider: 'aws',
    service: 'EC2',
    environment: 'production',
    description: 'Production API server handling customer-facing requests.',
    sensitivity: 'confidential',
    owner: 'Backend Engineering Team',
    tags: ['production', 'api', 'public-facing'],
    region: 'us-east-1',
    accountId: '123456789012',
  },
  {
    _id: 'asset-prod-iam-role',
    _type: 'securityAsset',
    name: 'api-service-role',
    assetId: 'arn:aws:iam::123456789012:role/api-service-role',
    provider: 'aws',
    service: 'IAM',
    environment: 'production',
    description: 'IAM role assumed by the production API server. Has excessive permissions including S3 wildcards.',
    sensitivity: 'confidential',
    owner: 'Security Team',
    tags: ['production', 'iam', 'service-role'],
    region: 'global',
    accountId: '123456789012',
    relatedAssets: [
      { _type: 'reference', _ref: 'asset-prod-ec2-api' },
      { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    ],
    source: { _type: 'reference', _ref: 'source-aws-iam-least-privilege' },
  },
  {
    _id: 'asset-prod-cloudtrail',
    _type: 'securityAsset',
    name: 'production-trail',
    assetId: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/production-trail',
    provider: 'aws',
    service: 'CloudTrail',
    environment: 'production',
    description: 'CloudTrail log trail for the production account. Has logging gaps for S3 data events.',
    sensitivity: 'internal',
    owner: 'Security Team',
    tags: ['production', 'logging', 'audit'],
    region: 'us-east-1',
    accountId: '123456789012',
  },
  // ── Development Assets ───────────────────────────────────────────────────
  {
    _id: 'asset-dev-s3',
    _type: 'securityAsset',
    name: 'dev-assets',
    assetId: 'arn:aws:s3:::dev-assets-acme',
    provider: 'aws',
    service: 'S3',
    environment: 'development',
    description: 'Development S3 bucket for testing assets.',
    sensitivity: 'internal',
    owner: 'Engineering Team',
    tags: ['development', 'assets'],
    region: 'us-east-1',
    accountId: '123456789012',
  },
  {
    _id: 'asset-dev-iam-role',
    _type: 'securityAsset',
    name: 'dev-service-role',
    assetId: 'arn:aws:iam::123456789012:role/dev-service-role',
    provider: 'aws',
    service: 'IAM',
    environment: 'development',
    description:
      'Development IAM role with incorrectly scoped permissions that include access to production RDS.',
    sensitivity: 'confidential',
    owner: 'Engineering Team',
    tags: ['development', 'iam', 'service-role'],
    region: 'global',
    accountId: '123456789012',
    relatedAssets: [
      { _type: 'reference', _ref: 'asset-prod-rds' }, // cross-env access violation
    ],
    source: { _type: 'reference', _ref: 'source-aws-iam-least-privilege' },
  },
];

const DATA_ASSETS = [
  {
    _id: 'data-customer-pii',
    _type: 'dataAsset',
    name: 'Customer PII Backup Files',
    classification: 'restricted',
    sensitivity: 'restricted',
    contains: ['customer_pii', 'email_addresses', 'full_names', 'billing_addresses', 'phone_numbers'],
    storedIn: { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    owner: 'Data Engineering Team',
    description:
      'Daily backup exports from the customer database. Files follow the pattern daily-prod-backup-YYYY-MM-DD.sql.gz. Each backup file contains full customer profiles including PII as defined under GDPR and CCPA.',
    regulatoryScope: ['GDPR', 'CCPA'],
    estimatedRecordCount: '>500k',
  },
  {
    _id: 'data-customer-financial',
    _type: 'dataAsset',
    name: 'Customer Financial Records',
    classification: 'restricted',
    sensitivity: 'restricted',
    contains: ['subscription_history', 'payment_method_tokens', 'invoice_records'],
    storedIn: { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    owner: 'Finance Team',
    description:
      'Subscription and billing records included in daily backup exports. Contains payment method tokens (not raw card numbers) and full billing history.',
    regulatoryScope: ['PCI-DSS', 'GDPR'],
    estimatedRecordCount: '>500k',
  },
];

const CONFIGURATIONS = [
  // F001: Public S3
  {
    _id: 'config-s3-block-public-access',
    _type: 'configuration',
    asset: { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    setting: 'BlockPublicAccess',
    observedValue: 'DISABLED',
    expectedValue: 'ENABLED',
    status: 'non_compliant',
    observedAt: '2024-09-15T08:00:00Z',
    environment: 'production',
    notes:
      'Block Public Access is disabled at the bucket level. The bucket has no bucket policy restricting public access. ACL grants public-read to AllUsers.',
    configPath: 'S3.PublicAccessBlockConfiguration.BlockPublicAcls',
    source: { _type: 'reference', _ref: 'source-aws-s3-block-public-access' },
  },
  {
    _id: 'config-s3-bucket-acl',
    _type: 'configuration',
    asset: { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    setting: 'BucketACL',
    observedValue: 'public-read (AllUsers)',
    expectedValue: 'private',
    status: 'non_compliant',
    observedAt: '2024-09-15T08:00:00Z',
    environment: 'production',
    configPath: 'S3.BucketAcl.Grants[].Grantee',
    source: { _type: 'reference', _ref: 'source-aws-s3-block-public-access' },
  },
  // F002: IAM wildcard
  {
    _id: 'config-iam-wildcard',
    _type: 'configuration',
    asset: { _type: 'reference', _ref: 'asset-prod-iam-role' },
    setting: 'PolicyActions',
    observedValue: 's3:* (wildcard on all S3 actions)',
    expectedValue: 's3:GetObject, s3:PutObject (scoped actions only)',
    status: 'non_compliant',
    observedAt: '2024-09-15T08:00:00Z',
    environment: 'production',
    notes: 'The api-service-role IAM role has a policy granting s3:* on all resources (*). This allows the role to perform any S3 action including GetObject on the production backup bucket.',
    source: { _type: 'reference', _ref: 'source-aws-iam-least-privilege' },
  },
  // F003: Security group unrestricted
  {
    _id: 'config-sg-unrestricted-ssh',
    _type: 'configuration',
    asset: { _type: 'reference', _ref: 'asset-prod-ec2-api' },
    setting: 'InboundSSH',
    observedValue: '0.0.0.0/0:22 (open to all)',
    expectedValue: '10.0.0.0/8:22 (internal only)',
    status: 'non_compliant',
    observedAt: '2024-09-15T08:00:00Z',
    environment: 'production',
    notes: 'SSH port 22 is open to the public internet on the production API server security group.',
    source: { _type: 'reference', _ref: 'source-cis-aws-2-1-2' },
  },
  // F004: CloudTrail logging gaps
  {
    _id: 'config-cloudtrail-s3-events',
    _type: 'configuration',
    asset: { _type: 'reference', _ref: 'asset-prod-cloudtrail' },
    setting: 'S3DataEventsLogging',
    observedValue: 'DISABLED',
    expectedValue: 'ENABLED (for production buckets)',
    status: 'non_compliant',
    observedAt: '2024-09-15T08:00:00Z',
    environment: 'production',
    notes: 'CloudTrail S3 data event logging is not enabled for the production-trail. This means GetObject, PutObject, and DeleteObject operations on prod-customer-backups are not being logged.',
  },
];

const FINDINGS = [
  {
    _id: 'finding-f001',
    _type: 'finding',
    title: 'S3 Bucket Publicly Accessible',
    findingId: 'F001',
    severity: 'critical',
    category: 'data_exposure',
    affectedAsset: { _type: 'reference', _ref: 'asset-prod-s3-backups' },
    observedCondition:
      'S3 bucket "prod-customer-backups" has Block Public Access disabled and grants public-read permission to AllUsers via bucket ACL. The bucket is directly accessible from the internet without authentication.',
    evidence: [
      'BlockPublicAccess: DISABLED at bucket level',
      'BucketACL: public-read granted to AllUsers',
      'No bucket policy restricting access',
      'Bucket contains production backup files',
      'Files follow naming convention: daily-prod-backup-YYYY-MM-DD.sql.gz',
    ],
    relatedConfigurations: [
      { _type: 'reference', _ref: 'config-s3-block-public-access' },
      { _type: 'reference', _ref: 'config-s3-bucket-acl' },
    ],
    relatedFindings: [
      { _type: 'reference', _ref: 'finding-f002' },
      { _type: 'reference', _ref: 'finding-f004' },
    ],
    potentialImpact:
      'An unauthenticated external party can list and download all objects from this bucket. The bucket contains daily production database backups including customer PII (names, email addresses, billing information) for 500k+ customers. This constitutes a potential GDPR and CCPA reportable breach.',
    status: 'open',
    discoveredAt: '2024-09-15T08:00:00Z',
  },
  {
    _id: 'finding-f002',
    _type: 'finding',
    title: 'Overly Permissive IAM Role',
    findingId: 'F002',
    severity: 'high',
    category: 'iam',
    affectedAsset: { _type: 'reference', _ref: 'asset-prod-iam-role' },
    observedCondition:
      'IAM role "api-service-role" has a policy granting s3:* on resource *.  This allows any service assuming this role to perform any S3 operation, including listing and downloading objects from the production backup bucket.',
    evidence: [
      'Policy grants s3:* on Resource: *',
      'Role is assumed by api-server EC2 instance',
      'api-server is internet-facing',
      'Role has no S3 resource scoping',
    ],
    relatedConfigurations: [{ _type: 'reference', _ref: 'config-iam-wildcard' }],
    relatedFindings: [
      { _type: 'reference', _ref: 'finding-f001' },
      { _type: 'reference', _ref: 'finding-f003' },
    ],
    potentialImpact:
      'If the api-server is compromised through any vulnerability (including F003), the attacker inherits full S3 access across all buckets in the account, including prod-customer-backups. Combined with F001, this creates two independent paths to customer PII exposure.',
    status: 'open',
    discoveredAt: '2024-09-15T08:00:00Z',
  },
  {
    _id: 'finding-f003',
    _type: 'finding',
    title: 'Unrestricted SSH Inbound on Production EC2',
    findingId: 'F003',
    severity: 'high',
    category: 'network',
    affectedAsset: { _type: 'reference', _ref: 'asset-prod-ec2-api' },
    observedCondition:
      'Security group attached to api-server allows inbound SSH (TCP/22) from 0.0.0.0/0 (all IPs). This exposes the SSH service to brute-force and credential-stuffing attacks from the public internet.',
    evidence: [
      'Security Group inbound rule: TCP/22 from 0.0.0.0/0',
      'Instance is internet-facing (has public IP)',
      'No IP allowlisting in place',
    ],
    relatedConfigurations: [{ _type: 'reference', _ref: 'config-sg-unrestricted-ssh' }],
    relatedFindings: [{ _type: 'reference', _ref: 'finding-f002' }],
    potentialImpact:
      'Successful SSH brute-force or credential compromise of the api-server would give an attacker shell access. Combined with F002 (overly permissive IAM role), this becomes a path to full S3 data exfiltration.',
    status: 'open',
    discoveredAt: '2024-09-15T08:00:00Z',
  },
  {
    _id: 'finding-f004',
    _type: 'finding',
    title: 'CloudTrail S3 Data Event Logging Disabled',
    findingId: 'F004',
    severity: 'medium',
    category: 'logging',
    affectedAsset: { _type: 'reference', _ref: 'asset-prod-cloudtrail' },
    observedCondition:
      'CloudTrail production-trail does not have S3 data event logging enabled. This means GetObject, PutObject, and DeleteObject operations on S3 buckets — including prod-customer-backups — are not being captured in the audit trail.',
    evidence: [
      'S3 data events not configured in production-trail',
      'Management events are logged but not data events',
      'No alternative logging mechanism (e.g., S3 server access logging) confirmed active',
    ],
    relatedConfigurations: [{ _type: 'reference', _ref: 'config-cloudtrail-s3-events' }],
    relatedFindings: [{ _type: 'reference', _ref: 'finding-f001' }],
    potentialImpact:
      'If unauthorized data retrieval is occurring from prod-customer-backups (possible due to F001), there is no audit trail to detect, investigate, or quantify the exposure. This significantly impairs incident response capability.',
    status: 'open',
    discoveredAt: '2024-09-15T08:00:00Z',
  },
  {
    _id: 'finding-f005',
    _type: 'finding',
    title: 'Development Role Has Production Database Access',
    findingId: 'F005',
    severity: 'high',
    category: 'iam',
    affectedAsset: { _type: 'reference', _ref: 'asset-dev-iam-role' },
    observedCondition:
      'IAM role "dev-service-role" used in the development environment has permissions to access the production RDS instance "customer-db". Development roles should not have access to production resources.',
    evidence: [
      'dev-service-role policy allows rds:* on production RDS ARN',
      'Role is used in development environment',
      'Production RDS contains customer PII',
      'No network-level segregation between dev and prod in this account',
    ],
    relatedFindings: [{ _type: 'reference', _ref: 'finding-f002' }],
    potentialImpact:
      'A compromise of any development system using dev-service-role would grant the attacker access to the production customer database. This violates environment separation principles and could result in unauthorized access to 500k+ customer records.',
    status: 'open',
    discoveredAt: '2024-09-15T08:00:00Z',
  },
];

const REMEDIATIONS = [
  {
    _id: 'remediation-f001',
    _type: 'remediation',
    title: 'Enable S3 Block Public Access on prod-customer-backups',
    finding: { _type: 'reference', _ref: 'finding-f001' },
    proposedChange:
      '1. Enable Block Public Access at the account level for the production AWS account.\n2. Enable Block Public Access at the bucket level for prod-customer-backups (set all four settings: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets = true).\n3. Remove the public-read ACL grant from the bucket.\n4. Add a bucket policy explicitly denying s3:GetObject for Principal: * unless explicitly authorized.',
    rationale:
      'Enabling Block Public Access removes unauthenticated internet access to the bucket contents. Combined with removing the public-read ACL, this closes the primary exposure path for customer PII. This is aligned with CIS-2.1.2 and the current Cloud Storage Access Policy v2.0.',
    prerequisites: [
      'Verify that no legitimate external services currently depend on public bucket access',
      'Check for any public distribution workflows still active (legacy system decommissioned in 2023)',
      'Confirm with Data Engineering that backup restore procedures do not rely on public access',
      'Enable CloudTrail S3 data event logging before making changes (to capture baseline)',
    ],
    operationalImpact:
      'If any service is still using the legacy public distribution workflow (originally documented in the 2022 architecture doc), enabling Block Public Access will break it. Based on current documentation, this service was decommissioned in Q4 2023, but this should be verified before applying the change. No other operational impact expected.',
    risk: 'medium',
    verificationSteps: [
      'Attempt to retrieve an object from the bucket without credentials — should return 403 Forbidden',
      'Check AWS Console: S3 bucket → Permissions → Block Public Access — all four settings should show ON',
      'Verify bucket policy includes explicit deny for Principal: *',
      'Confirm CloudTrail shows the configuration change was applied',
      'Run CIS benchmark check to confirm control CIS-2.1.2 is now passing',
    ],
    requiredApproval: 'Cloud Security Owner',
    automationAvailable: true,
    affectedControls: [
      { _type: 'reference', _ref: 'control-cis-2-1-2' },
      { _type: 'reference', _ref: 'control-nist-pr-ds-1' },
    ],
  },
];

// ─── Seeding Script ──────────────────────────────────────────────────────────

// Strip cross-document references from a document for first-pass seeding.
// This prevents "references non-existent document" errors.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function stripRefs(doc: any): any {
  const stripped = { ...doc };

  // Fields that contain cross-doc references we'll patch in pass 2
  const refArrayFields = [
    'relatedFindings',
    'relatedAssets',
    'affectedControls',
    'relevantThreatTechniques',
    'relatedConfigurations',
  ];
  const refFields = ['supersededBy', 'storedIn', 'affectedAsset', 'finding', 'asset', 'source'];

  for (const f of refArrayFields) {
    if (stripped[f]) delete stripped[f];
  }
  for (const f of refFields) {
    if (stripped[f]) delete stripped[f];
  }

  return stripped;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function upsert(doc: any) {
  return client.createOrReplace(doc as Parameters<typeof client.createOrReplace>[0]);
}

async function seed() {
  console.log('\n🔒 TraceGuard — ACME Corp Synthetic Dataset Seeder');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('⚠️  SYNTHETIC DATA — FOR DEMONSTRATION PURPOSES ONLY');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  if (!process.env.SANITY_PROJECT_ID && !process.env.NEXT_PUBLIC_SANITY_PROJECT_ID) {
    console.error('❌ SANITY_PROJECT_ID is not set. Please configure .env.local first.\n');
    process.exit(1);
  }

  const allDocuments = [
    ...SOURCES,
    ...THREAT_TECHNIQUES,
    ...SECURITY_CONTROLS,
    ...POLICIES,
    ...SECURITY_ASSETS,
    ...DATA_ASSETS,
    ...CONFIGURATIONS,
    ...FINDINGS,
    ...REMEDIATIONS,
  ];

  // ── Pass 1: Create all documents without cross-references ──────────────────
  console.log(`📦 Pass 1 — Creating ${allDocuments.length} documents (without cross-refs)...\n`);

  for (const doc of allDocuments) {
    const stripped = stripRefs(doc);
    try {
      await upsert(stripped);
      const label = ('name' in doc ? doc.name : '') || ('title' in doc ? doc.title : '') || ('findingId' in doc ? (doc as { findingId: string }).findingId : doc._id);
      console.log(`  ✅ ${doc._type}: ${label}`);
    } catch (err) {
      console.error(`  ❌ Failed: ${doc._id}`, (err as Error).message?.split('\n')[0]);
    }
  }

  // ── Pass 2: Patch cross-references ────────────────────────────────────────
  console.log('\n🔗 Pass 2 — Patching cross-references...\n');

  // Patch: policy v1 supersededBy v2
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const policyV1 = (POLICIES as any[]).find((p) => p._id === 'policy-storage-access-v1');
  if (policyV1?.supersededBy) {
    try {
      await client.patch('policy-storage-access-v1').set({ supersededBy: policyV1.supersededBy }).commit();
      console.log('  ✅ policy-storage-access-v1 → supersededBy patched');
    } catch (e) { console.error('  ❌ policy-storage-access-v1 supersededBy:', (e as Error).message?.split('\n')[0]); }
  }

  // Patch: findings with relatedFindings and relatedConfigurations
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const finding of FINDINGS as any[]) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const patch: Record<string, any> = {};
    if (finding.relatedFindings) patch.relatedFindings = finding.relatedFindings;
    if (finding.relatedConfigurations) patch.relatedConfigurations = finding.relatedConfigurations;
    if (Object.keys(patch).length === 0) continue;
    try {
      await client.patch(finding._id).set(patch).commit();
      console.log(`  ✅ ${finding._id} → refs patched`);
    } catch (e) { console.error(`  ❌ ${finding._id} refs:`, (e as Error).message?.split('\n')[0]); }
  }

  // Patch: remediation → finding reference
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const rem of REMEDIATIONS as any[]) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const patch: Record<string, any> = {};
    if (rem.finding) patch.finding = rem.finding;
    if (rem.affectedControls) patch.affectedControls = rem.affectedControls;
    if (Object.keys(patch).length === 0) continue;
    try {
      await client.patch(rem._id).set(patch).commit();
      console.log(`  ✅ ${rem._id} → refs patched`);
    } catch (e) { console.error(`  ❌ ${rem._id} refs:`, (e as Error).message?.split('\n')[0]); }
  }

  // Patch: security controls → relevantThreatTechniques
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const ctrl of SECURITY_CONTROLS as any[]) {
    if (!ctrl.relevantThreatTechniques) continue;
    try {
      await client.patch(ctrl._id).set({ relevantThreatTechniques: ctrl.relevantThreatTechniques }).commit();
      console.log(`  ✅ ${ctrl._id} → relevantThreatTechniques patched`);
    } catch (e) { console.error(`  ❌ ${ctrl._id}:`, (e as Error).message?.split('\n')[0]); }
  }

  // Patch: source references on all docs
  for (const docGroup of [THREAT_TECHNIQUES, SECURITY_CONTROLS, POLICIES, SECURITY_ASSETS, CONFIGURATIONS]) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    for (const doc of docGroup as any[]) {
      if (!doc.source) continue;
      try {
        await client.patch(doc._id).set({ source: doc.source }).commit();
      } catch (e) { console.error(`  ❌ ${doc._id} source:`, (e as Error).message?.split('\n')[0]); }
    }
  }
  console.log('  ✅ Source references patched');

  // Patch: securityAsset.storedIn for data assets
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const da of DATA_ASSETS as any[]) {
    if (!da.storedIn) continue;
    try {
      await client.patch(da._id).set({ storedIn: da.storedIn }).commit();
      console.log(`  ✅ ${da._id} → storedIn patched`);
    } catch (e) { console.error(`  ❌ ${da._id} storedIn:`, (e as Error).message?.split('\n')[0]); }
  }

  // Patch: configuration.asset references
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const cfg of CONFIGURATIONS as any[]) {
    if (!cfg.asset) continue;
    try {
      await client.patch(cfg._id).set({ asset: cfg.asset }).commit();
    } catch (e) { console.error(`  ❌ ${cfg._id} asset:`, (e as Error).message?.split('\n')[0]); }
  }
  console.log('  ✅ Configuration asset references patched');

  // Patch: finding.affectedAsset references
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  for (const f of FINDINGS as any[]) {
    if (!f.affectedAsset) continue;
    try {
      await client.patch(f._id).set({ affectedAsset: f.affectedAsset }).commit();
    } catch (e) { console.error(`  ❌ ${f._id} affectedAsset:`, (e as Error).message?.split('\n')[0]); }
  }
  console.log('  ✅ Finding affectedAsset references patched');

  console.log('\n✨ Seeding complete!');
  console.log('\n📋 Summary:');
  console.log(`  Sources:           ${SOURCES.length}`);
  console.log(`  Threat Techniques: ${THREAT_TECHNIQUES.length}`);
  console.log(`  Security Controls: ${SECURITY_CONTROLS.length}`);
  console.log(`  Policies:          ${POLICIES.length} (incl. v1 legacy + v2 current)`);
  console.log(`  Security Assets:   ${SECURITY_ASSETS.length}`);
  console.log(`  Data Assets:       ${DATA_ASSETS.length}`);
  console.log(`  Configurations:    ${CONFIGURATIONS.length}`);
  console.log(`  Findings:          ${FINDINGS.length}`);
  console.log(`  Remediations:      ${REMEDIATIONS.length}`);
  console.log('\n🚀 Open the TraceGuard dashboard at http://localhost:3000');
}

seed().catch((err) => {
  console.error('Seeding failed:', err);
  process.exit(1);
});
