// lib/scanners/rules/aws.ts
// Comprehensive AWS security rules with remediation guidance.
// Each rule maps a check ID to severity, compliance mappings, MITRE ATT&CK, and remediation.

import type { SecurityRule } from '../types';

export const AWS_RULES: Record<string, SecurityRule> = {

  // ─── S3 ─────────────────────────────────────────────────────────────────────

  's3-block-public-access-disabled': {
    id: 's3-block-public-access-disabled',
    service: 'S3',
    title: 'S3 Bucket Block Public Access Not Fully Enabled',
    description: 'One or more Block Public Access settings are disabled on the S3 bucket, potentially allowing public access.',
    severity: 'critical',
    category: 'data_exposure',
    compliance: ['CIS AWS 2.1.2', 'NIST PR.DS-1', 'PCI DSS 6.4.1', 'SOC 2 CC6.1', 'ISO 27001 A.13.1'],
    mitre: ['T1530'],
    getRemediation: (resourceId, region, accountId) => ({
      summary: 'Enable all four S3 Block Public Access settings on the bucket to prevent any public exposure.',
      steps: [
        `Open the AWS Console → S3 → ${resourceId} → Permissions tab`,
        'Click "Block public access (bucket settings)" → Edit',
        'Enable all four checkboxes: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets',
        'Save changes and confirm',
        'Verify by attempting an anonymous GET request — it should return 403 Forbidden',
      ],
      awsCli: `aws s3api put-public-access-block --bucket ${resourceId} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true" --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_s3_bucket_public_access_block" "${resourceId.replace(/-/g, '_')}" {\n  bucket = "${resourceId}"\n  block_public_acls       = true\n  ignore_public_acls      = true\n  block_public_policy     = true\n  restrict_public_buckets = true\n}`,
      consoleUrl: `https://s3.console.aws.amazon.com/s3/buckets/${resourceId}?tab=permissions`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
      operationalNotes: 'If the bucket previously served public content (static website, public assets), those will become inaccessible. Use CloudFront with Origin Access Control instead.',
    }),
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html'],
  },

  's3-versioning-disabled': {
    id: 's3-versioning-disabled',
    service: 'S3',
    title: 'S3 Bucket Versioning Disabled',
    description: 'Versioning is not enabled on the S3 bucket. Without versioning, deleted or overwritten objects cannot be recovered.',
    severity: 'medium',
    category: 'data_exposure',
    compliance: ['CIS AWS 2.1.3', 'NIST PR.IP-4', 'PCI DSS 12.3.4', 'SOC 2 A1.2'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable versioning on the S3 bucket to protect against accidental deletion or overwrites.',
      steps: [
        `Navigate to S3 → ${resourceId} → Properties tab`,
        'Under "Bucket Versioning", click Edit',
        'Select "Enable" and save',
        'Optionally configure a lifecycle rule to expire old versions after N days to control costs',
      ],
      awsCli: `aws s3api put-bucket-versioning --bucket ${resourceId} --versioning-configuration Status=Enabled --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_s3_bucket_versioning" "${resourceId.replace(/-/g, '_')}_versioning" {\n  bucket = "${resourceId}"\n  versioning_configuration {\n    status = "Enabled"\n  }\n}`,
      consoleUrl: `https://s3.console.aws.amazon.com/s3/buckets/${resourceId}?tab=properties`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html'],
  },

  's3-encryption-disabled': {
    id: 's3-encryption-disabled',
    service: 'S3',
    title: 'S3 Bucket Default Encryption Not Configured',
    description: 'The S3 bucket does not have default server-side encryption enabled. New objects may be stored unencrypted.',
    severity: 'high',
    category: 'encryption',
    compliance: ['CIS AWS 2.1.1', 'NIST PR.DS-1', 'PCI DSS 3.5', 'HIPAA § 164.312(a)(2)(iv)', 'SOC 2 CC6.1'],
    mitre: ['T1530'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable SSE-S3 or SSE-KMS default encryption on the bucket.',
      steps: [
        `Go to S3 → ${resourceId} → Properties`,
        'Under "Default encryption", click Edit',
        'Select SSE-S3 (Amazon S3 managed keys) or SSE-KMS for stricter control',
        'If using SSE-KMS, select or create a KMS key',
        'Save changes',
      ],
      awsCli: `aws s3api put-bucket-encryption --bucket ${resourceId} --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_s3_bucket_server_side_encryption_configuration" "${resourceId.replace(/-/g, '_')}_sse" {\n  bucket = "${resourceId}"\n  rule {\n    apply_server_side_encryption_by_default {\n      sse_algorithm = "AES256"\n    }\n  }\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html'],
  },

  's3-logging-disabled': {
    id: 's3-logging-disabled',
    service: 'S3',
    title: 'S3 Bucket Access Logging Disabled',
    description: 'Server access logging is not enabled. Without logging, it is impossible to audit who accessed objects in this bucket.',
    severity: 'medium',
    category: 'logging',
    compliance: ['CIS AWS 2.1.4', 'NIST DE.AE-1', 'PCI DSS 10.2', 'SOC 2 CC7.2'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable S3 server access logging to a dedicated log bucket.',
      steps: [
        'Create or identify a target S3 bucket for access logs',
        `Go to S3 → ${resourceId} → Properties → Server access logging`,
        'Click Edit → Enable',
        'Select your log bucket as the target',
        'Set a prefix like "s3-access-logs/" for easy filtering',
      ],
      awsCli: `aws s3api put-bucket-logging --bucket ${resourceId} --bucket-logging-status '{"LoggingEnabled":{"TargetBucket":"YOUR_LOG_BUCKET","TargetPrefix":"${resourceId}/"}}' --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html'],
  },

  // ─── IAM ─────────────────────────────────────────────────────────────────────

  'iam-root-access-key': {
    id: 'iam-root-access-key',
    service: 'IAM',
    title: 'Root Account Has Active Access Keys',
    description: 'The AWS root account has active access keys. Root keys bypass all IAM policies and represent the highest risk credential.',
    severity: 'critical',
    category: 'iam',
    compliance: ['CIS AWS 1.4', 'NIST PR.AC-4', 'PCI DSS 7.1', 'SOC 2 CC6.3', 'ISO 27001 A.9.2'],
    mitre: ['T1078.004'],
    getRemediation: (resourceId) => ({
      summary: 'Delete all root account access keys immediately. Use IAM roles and users for all programmatic access.',
      steps: [
        'Sign in to the AWS Console as root',
        'Go to IAM → Security credentials (top-right account menu)',
        'Under "Access keys", delete ALL root access keys',
        'Create an IAM user with appropriate permissions for any automation that was using root keys',
        'Enable MFA on the root account if not already enabled',
      ],
      consoleUrl: 'https://us-east-1.console.aws.amazon.com/iam/home#/security_credentials',
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
      operationalNotes: 'Any automation using root access keys will break and must be updated to use IAM roles or users.',
    }),
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials'],
  },

  'iam-mfa-disabled': {
    id: 'iam-mfa-disabled',
    service: 'IAM',
    title: 'IAM User Without MFA Enabled',
    description: 'This IAM user has console access but does not have Multi-Factor Authentication (MFA) enabled.',
    severity: 'high',
    category: 'iam',
    compliance: ['CIS AWS 1.10', 'NIST PR.AC-7', 'PCI DSS 8.4', 'SOC 2 CC6.1', 'ISO 27001 A.9.4'],
    mitre: ['T1078.004'],
    getRemediation: (resourceId) => ({
      summary: 'Enable MFA for the IAM user to add a second factor of authentication.',
      steps: [
        `Go to IAM → Users → ${resourceId}`,
        'Click the "Security credentials" tab',
        'Under "Multi-factor authentication (MFA)", click "Assign MFA device"',
        'Choose Virtual MFA device (e.g., Google Authenticator, Authy) or Hardware key',
        'Follow the setup instructions and verify two consecutive codes',
        'Enforce MFA via IAM policy: deny all actions if aws:MultiFactorAuthPresent is false',
      ],
      awsCli: `aws iam create-virtual-mfa-device --virtual-mfa-device-name ${resourceId}-mfa --outfile /tmp/${resourceId}-mfa.png --bootstrap-method QRCodePNG`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html'],
  },

  'iam-password-policy-weak': {
    id: 'iam-password-policy-weak',
    service: 'IAM',
    title: 'IAM Password Policy Does Not Meet Security Requirements',
    description: 'The IAM password policy does not enforce sufficient complexity, length, or rotation requirements.',
    severity: 'medium',
    category: 'iam',
    compliance: ['CIS AWS 1.8', 'CIS AWS 1.9', 'NIST PR.AC-1', 'PCI DSS 8.3', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region, accountId) => ({
      summary: 'Configure a strong IAM account password policy.',
      steps: [
        'Go to IAM → Account settings → Password policy',
        'Click "Edit"',
        'Set: Minimum length = 14, Require uppercase, lowercase, numbers, symbols',
        'Enable: Prevent password reuse (remember 24 passwords)',
        'Enable: Password expiry (90 days max)',
        'Save changes',
      ],
      awsCli: `aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --allow-users-to-change-password --max-password-age 90 --password-reuse-prevention 24`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html'],
  },

  'iam-access-key-old': {
    id: 'iam-access-key-old',
    service: 'IAM',
    title: 'IAM Access Key Older Than 90 Days',
    description: 'An IAM access key has not been rotated in over 90 days, increasing the risk of compromised credentials being used undetected.',
    severity: 'high',
    category: 'iam',
    compliance: ['CIS AWS 1.14', 'NIST PR.AC-1', 'PCI DSS 8.3.9', 'SOC 2 CC6.1'],
    mitre: ['T1078.004'],
    getRemediation: (resourceId) => ({
      summary: 'Rotate the IAM access key and delete the old one.',
      steps: [
        `Go to IAM → Users → ${resourceId} → Security credentials`,
        'Click "Create access key" to generate a new key',
        'Update all applications/scripts using the old key with the new credentials',
        'Test that all integrations work with the new key',
        'Click "Deactivate" on the old key, wait 24 hours, then delete it',
      ],
      awsCli: `# Create new key\naws iam create-access-key --user-name ${resourceId}\n# List keys to find old key ID\naws iam list-access-keys --user-name ${resourceId}\n# Delete old key (replace AKID with actual key ID)\naws iam delete-access-key --user-name ${resourceId} --access-key-id AKIDXXXXXXXXXXXXXXXX`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey'],
  },

  'iam-wildcard-policy': {
    id: 'iam-wildcard-policy',
    service: 'IAM',
    title: 'IAM Policy Grants Wildcard (*) Permissions',
    description: 'An IAM policy contains Action: * or Resource: *, granting excessive permissions violating least-privilege principle.',
    severity: 'critical',
    category: 'iam',
    compliance: ['CIS AWS 1.16', 'NIST PR.AC-4', 'PCI DSS 7.1', 'SOC 2 CC6.3', 'ISO 27001 A.9.4'],
    mitre: ['T1078.004'],
    getRemediation: (resourceId) => ({
      summary: 'Replace wildcard permissions with specific actions and resources following least-privilege principle.',
      steps: [
        `Go to IAM → Policies → ${resourceId}`,
        'Click "Edit policy" → JSON editor',
        'Replace "Action": "*" with specific actions (e.g., ["s3:GetObject", "s3:PutObject"])',
        'Replace "Resource": "*" with specific ARNs',
        'Use IAM Access Analyzer to generate least-privilege policies based on access activity',
        'Review and attach the refined policy',
      ],
      awsCli: `# Use IAM Access Analyzer to generate least-privilege policy based on CloudTrail\naws accessanalyzer create-policy-generation --policy-generation-details "principalArn=arn:aws:iam::ACCOUNT_ID:policy/${resourceId}"`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
      operationalNotes: 'Removing wildcard permissions may break existing applications. Test thoroughly in a non-production environment first.',
    }),
    references: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege'],
  },

  // ─── EC2 ─────────────────────────────────────────────────────────────────────

  'ec2-sg-unrestricted-ssh': {
    id: 'ec2-sg-unrestricted-ssh',
    service: 'EC2',
    title: 'Security Group Allows Unrestricted SSH (Port 22) from 0.0.0.0/0',
    description: 'A security group allows inbound SSH access from any IP address (0.0.0.0/0 or ::/0), exposing instances to brute-force and exploitation.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS AWS 5.2', 'NIST PR.AC-5', 'PCI DSS 1.3.1', 'SOC 2 CC6.6', 'ISO 27001 A.13.1.3'],
    mitre: ['T1133', 'T1021.004'],
    getRemediation: (resourceId, region) => ({
      summary: 'Restrict SSH access to specific trusted IP ranges or use AWS Systems Manager Session Manager instead.',
      steps: [
        `Go to EC2 → Security Groups → ${resourceId} → Inbound rules`,
        'Delete the rule that allows 0.0.0.0/0 or ::/0 on port 22',
        'If SSH is required: add a rule restricting to your corporate IP range only',
        'Better alternative: Enable AWS Systems Manager Session Manager (no open ports needed)',
        'Update your instances to use SSM Agent and remove SSH inbound rules entirely',
      ],
      awsCli: `# Remove unrestricted SSH rule\naws ec2 revoke-security-group-ingress --group-id ${resourceId} --protocol tcp --port 22 --cidr 0.0.0.0/0 --region ${region ?? 'us-east-1'}\n\n# Add restricted rule (replace with your IP)\naws ec2 authorize-security-group-ingress --group-id ${resourceId} --protocol tcp --port 22 --cidr YOUR.IP.ADDRESS/32 --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_security_group_rule" "ssh_restricted" {\n  type              = "ingress"\n  from_port         = 22\n  to_port           = 22\n  protocol          = "tcp"\n  cidr_blocks       = ["YOUR_IP/32"]  # Replace with actual IP range\n  security_group_id = "${resourceId}"\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/authorizing-access-to-an-instance.html'],
  },

  'ec2-sg-unrestricted-rdp': {
    id: 'ec2-sg-unrestricted-rdp',
    service: 'EC2',
    title: 'Security Group Allows Unrestricted RDP (Port 3389) from 0.0.0.0/0',
    description: 'A security group allows inbound RDP access from any IP, exposing Windows instances to brute-force attacks.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS AWS 5.3', 'NIST PR.AC-5', 'PCI DSS 1.3.1', 'SOC 2 CC6.6'],
    mitre: ['T1133', 'T1021.001'],
    getRemediation: (resourceId, region) => ({
      summary: 'Restrict RDP to specific IP ranges or use AWS Systems Manager Fleet Manager.',
      steps: [
        `Go to EC2 → Security Groups → ${resourceId} → Inbound rules`,
        'Delete the rule allowing 0.0.0.0/0 on port 3389',
        'Add a rule restricted to your corporate VPN/IP range',
        'Consider using AWS Systems Manager Fleet Manager for browser-based RDP — no port 3389 needed',
      ],
      awsCli: `aws ec2 revoke-security-group-ingress --group-id ${resourceId} --protocol tcp --port 3389 --cidr 0.0.0.0/0 --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/AWSEC2/latest/WindowsGuide/connecting_to_windows_instance.html'],
  },

  'ec2-imdsv2-not-enforced': {
    id: 'ec2-imdsv2-not-enforced',
    service: 'EC2',
    title: 'EC2 Instance Does Not Enforce IMDSv2',
    description: 'The instance allows IMDSv1, which is vulnerable to SSRF attacks that can steal instance credentials via the metadata service.',
    severity: 'high',
    category: 'iam',
    compliance: ['CIS AWS 5.6', 'NIST PR.AC-4', 'AWS Well-Architected Security Pillar'],
    mitre: ['T1552.005'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enforce IMDSv2 (token-required) on the EC2 instance to prevent SSRF-based credential theft.',
      steps: [
        `Go to EC2 → Instances → ${resourceId} → Actions → Modify instance metadata options`,
        'Set "IMDSv2" to "Required"',
        'Save changes (no reboot required)',
        'Update any applications using the instance metadata to use IMDSv2 with session-oriented tokens',
      ],
      awsCli: `aws ec2 modify-instance-metadata-options --instance-id ${resourceId} --http-tokens required --http-endpoint enabled --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_instance" "example" {\n  # ... existing config ...\n  metadata_options {\n    http_endpoint               = "enabled"\n    http_tokens                 = "required"\n    http_put_response_hop_limit = 1\n  }\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html'],
  },

  'ec2-ebs-unencrypted': {
    id: 'ec2-ebs-unencrypted',
    service: 'EC2',
    title: 'EBS Volume Not Encrypted',
    description: 'An EBS volume is not encrypted at rest, risking data exposure if the physical disk is compromised.',
    severity: 'high',
    category: 'encryption',
    compliance: ['CIS AWS 2.2.1', 'NIST PR.DS-1', 'PCI DSS 3.5', 'HIPAA § 164.312(a)(2)(iv)', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Create an encrypted snapshot and replace the volume with an encrypted copy.',
      steps: [
        `Go to EC2 → Volumes → ${resourceId} → Actions → Create snapshot`,
        'Once snapshot is created, right-click it → Copy',
        'Enable "Encrypt this snapshot" and select a KMS key',
        'Create a new volume from the encrypted snapshot',
        'Stop the instance, detach the old volume, attach the new encrypted volume',
        'Start the instance and verify everything works',
        'Delete the unencrypted volume and original snapshot',
        'Enable account-level EBS encryption by default to prevent future unencrypted volumes',
      ],
      awsCli: `# Enable EBS encryption by default for new volumes\naws ec2 enable-ebs-encryption-by-default --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html'],
  },

  // ─── RDS ─────────────────────────────────────────────────────────────────────

  'rds-publicly-accessible': {
    id: 'rds-publicly-accessible',
    service: 'RDS',
    title: 'RDS Instance Publicly Accessible',
    description: 'The RDS database instance is configured with PubliclyAccessible=true, making it reachable from the internet.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS AWS 2.3.2', 'NIST PR.AC-5', 'PCI DSS 1.3.2', 'SOC 2 CC6.6', 'HIPAA § 164.312(e)(1)'],
    mitre: ['T1190'],
    getRemediation: (resourceId, region) => ({
      summary: 'Disable public accessibility and restrict database access to your VPC only.',
      steps: [
        `Go to RDS → Databases → ${resourceId} → Modify`,
        'Under "Connectivity", expand "Additional configuration"',
        'Set "Public access" to "No"',
        'Click "Continue" → apply immediately or during next maintenance window',
        'Ensure your application connects via private IP within the VPC',
        'Update security groups to only allow access from application server IPs',
      ],
      awsCli: `aws rds modify-db-instance --db-instance-identifier ${resourceId} --no-publicly-accessible --apply-immediately --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_db_instance" "${resourceId.replace(/-/g, '_')}" {\n  # ... existing config ...\n  publicly_accessible = false\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'high',
      operationalNotes: 'Applications connecting from outside the VPC will lose access. Ensure connectivity through VPN, Direct Connect, or bastion host.',
    }),
    references: ['https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html'],
  },

  'rds-encryption-disabled': {
    id: 'rds-encryption-disabled',
    service: 'RDS',
    title: 'RDS Instance Storage Not Encrypted',
    description: 'The RDS instance does not have storage encryption enabled.',
    severity: 'high',
    category: 'encryption',
    compliance: ['CIS AWS 2.3.1', 'NIST PR.DS-1', 'PCI DSS 3.5', 'HIPAA § 164.312(a)(2)(iv)', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Create an encrypted snapshot and restore to a new encrypted RDS instance.',
      steps: [
        `Go to RDS → Databases → ${resourceId} → Actions → Take snapshot`,
        'Once complete, click the snapshot → Actions → Copy snapshot',
        'Enable "Enable Encryption", choose a KMS key, and copy',
        'Restore a new DB instance from the encrypted snapshot',
        'Update your application connection string to point to the new instance',
        'Verify the new instance works, then delete the old unencrypted instance',
      ],
      estimatedEffort: 'hours',
      operationalImpact: 'high',
      operationalNotes: 'This requires migrating to a new instance. Plan a maintenance window.',
    }),
    references: ['https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html'],
  },

  'rds-backup-disabled': {
    id: 'rds-backup-disabled',
    service: 'RDS',
    title: 'RDS Instance Automated Backups Disabled',
    description: 'Automated backups are disabled (BackupRetentionPeriod=0), meaning the database cannot be restored to a previous point in time.',
    severity: 'high',
    category: 'data_exposure',
    compliance: ['CIS AWS 2.3.3', 'NIST PR.IP-4', 'PCI DSS 12.3.4', 'SOC 2 A1.2'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable automated backups with at least 7 days retention.',
      steps: [
        `Go to RDS → Databases → ${resourceId} → Modify`,
        'Under "Backup", set "Backup retention period" to 7 (or more) days',
        'Set a preferred backup window during low-traffic hours',
        'Apply immediately',
      ],
      awsCli: `aws rds modify-db-instance --db-instance-identifier ${resourceId} --backup-retention-period 7 --apply-immediately --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html'],
  },

  // ─── Lambda ──────────────────────────────────────────────────────────────────

  'lambda-env-secrets': {
    id: 'lambda-env-secrets',
    service: 'Lambda',
    title: 'Lambda Function Has Plaintext Secrets in Environment Variables',
    description: 'The Lambda function environment variables contain strings that resemble credentials or secrets (keys, tokens, passwords).',
    severity: 'critical',
    category: 'iam',
    compliance: ['NIST PR.DS-2', 'PCI DSS 3.5', 'SOC 2 CC6.1', 'CWE-312'],
    mitre: ['T1552.001'],
    getRemediation: (resourceId, region) => ({
      summary: 'Move secrets from environment variables to AWS Secrets Manager or Parameter Store.',
      steps: [
        'Create secrets in AWS Secrets Manager for each credential',
        `Update the Lambda function role (IAM) to allow secretsmanager:GetSecretValue`,
        `In ${resourceId}, remove the plaintext environment variables`,
        'Update the function code to fetch secrets at runtime using the AWS SDK',
        'Use Lambda Powertools SecretsManager for efficient caching',
      ],
      awsCli: `# Store secret\naws secretsmanager create-secret --name "/${resourceId}/database-password" --secret-string "YOUR_SECRET" --region ${region ?? 'us-east-1'}\n# Remove env var from function\naws lambda update-function-configuration --function-name ${resourceId} --environment "Variables={}" --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html#configuration-envvars-encryption'],
  },

  'lambda-deprecated-runtime': {
    id: 'lambda-deprecated-runtime',
    service: 'Lambda',
    title: 'Lambda Function Uses Deprecated Runtime',
    description: 'The Lambda function uses a runtime that has reached end-of-life and no longer receives security patches.',
    severity: 'high',
    category: 'compliance',
    compliance: ['AWS Well-Architected', 'NIST SI-2', 'SOC 2 CC7.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Update the Lambda function to a supported runtime version.',
      steps: [
        'Review the AWS Lambda supported runtimes page for the current list',
        `Go to Lambda → Functions → ${resourceId} → Configuration → General configuration`,
        'Click Edit, select an updated runtime (e.g., python3.12, nodejs20.x, java21)',
        'Test the function thoroughly after the runtime upgrade',
        'Deploy the updated function',
      ],
      awsCli: `aws lambda update-function-configuration --function-name ${resourceId} --runtime python3.12 --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html'],
  },

  // ─── CloudTrail ──────────────────────────────────────────────────────────────

  'cloudtrail-not-enabled': {
    id: 'cloudtrail-not-enabled',
    service: 'CloudTrail',
    title: 'CloudTrail Not Enabled or Missing Multi-Region Trail',
    description: 'AWS CloudTrail is not configured or does not have a multi-region trail, leaving API activity unlogged.',
    severity: 'critical',
    category: 'logging',
    compliance: ['CIS AWS 3.1', 'NIST DE.CM-3', 'PCI DSS 10.2', 'SOC 2 CC7.2', 'ISO 27001 A.12.4'],
    mitre: ['T1562.008'],
    getRemediation: (resourceId, region) => ({
      summary: 'Create a multi-region CloudTrail trail writing to an S3 bucket with log validation enabled.',
      steps: [
        'Go to CloudTrail → Create trail',
        'Name the trail (e.g., "acme-all-regions-trail")',
        'Enable "Apply trail to all regions" (multi-region)',
        'Create a new S3 bucket for CloudTrail logs (with MFA delete enabled)',
        'Enable log file validation',
        'Enable CloudWatch Logs integration for real-time monitoring',
        'Create SNS notifications for trail delivery',
      ],
      awsCli: `aws cloudtrail create-trail --name all-regions-trail --s3-bucket-name YOUR_CLOUDTRAIL_BUCKET --is-multi-region-trail --enable-log-file-validation --region us-east-1\naws cloudtrail start-logging --name all-regions-trail`,
      terraform: `resource "aws_cloudtrail" "main" {\n  name                          = "all-regions-trail"\n  s3_bucket_name                = aws_s3_bucket.cloudtrail.id\n  include_global_service_events = true\n  is_multi_region_trail         = true\n  enable_log_file_validation    = true\n}`,
      estimatedEffort: 'hours',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html'],
  },

  'cloudtrail-log-validation-disabled': {
    id: 'cloudtrail-log-validation-disabled',
    service: 'CloudTrail',
    title: 'CloudTrail Log File Validation Disabled',
    description: 'Log file validation is not enabled on the CloudTrail trail. Tampered or deleted log files cannot be detected.',
    severity: 'medium',
    category: 'logging',
    compliance: ['CIS AWS 3.2', 'NIST DE.CM-3', 'PCI DSS 10.5', 'SOC 2 CC7.2'],
    getRemediation: (resourceId) => ({
      summary: 'Enable log file validation on the CloudTrail trail.',
      steps: [
        `Go to CloudTrail → Trails → ${resourceId} → Edit`,
        'Enable "Log file validation"',
        'Save changes',
        'Use aws cloudtrail validate-logs to periodically verify log integrity',
      ],
      awsCli: `aws cloudtrail update-trail --name ${resourceId} --enable-log-file-validation`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html'],
  },

  // ─── KMS ─────────────────────────────────────────────────────────────────────

  'kms-key-rotation-disabled': {
    id: 'kms-key-rotation-disabled',
    service: 'KMS',
    title: 'KMS Key Automatic Rotation Disabled',
    description: 'Automatic key rotation is not enabled for this KMS customer-managed key, increasing the risk from key exposure.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['CIS AWS 3.7', 'NIST PR.DS-1', 'PCI DSS 3.7', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable automatic annual key rotation for the KMS key.',
      steps: [
        `Go to KMS → Customer managed keys → ${resourceId}`,
        'Click "Key rotation" tab → Enable automatic key rotation',
        'This rotates the key material annually; old material is retained for decryption',
      ],
      awsCli: `aws kms enable-key-rotation --key-id ${resourceId} --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_kms_key" "example" {\n  # ... existing config ...\n  enable_key_rotation = true\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html'],
  },

  // ─── VPC ─────────────────────────────────────────────────────────────────────

  'vpc-flow-logs-disabled': {
    id: 'vpc-flow-logs-disabled',
    service: 'VPC',
    title: 'VPC Flow Logs Not Enabled',
    description: 'VPC Flow Logs are not enabled. Network traffic metadata is not being captured, making it impossible to investigate network-based incidents.',
    severity: 'medium',
    category: 'logging',
    compliance: ['CIS AWS 3.9', 'NIST DE.CM-1', 'PCI DSS 10.3', 'SOC 2 CC7.2'],
    mitre: ['T1562.008'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable VPC Flow Logs to capture network traffic metadata.',
      steps: [
        `Go to VPC → Your VPCs → ${resourceId} → Flow logs tab`,
        'Click "Create flow log"',
        'Choose: Filter = All, Maximum aggregation interval = 1 minute',
        'Select or create a CloudWatch Log Group or S3 bucket for destination',
        'Create an IAM role if using CloudWatch',
        'Create the flow log',
      ],
      awsCli: `aws ec2 create-flow-logs --resource-type VPC --resource-ids ${resourceId} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn arn:aws:iam::ACCOUNT_ID:role/VPCFlowLogsRole --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html'],
  },

  'vpc-default-in-use': {
    id: 'vpc-default-in-use',
    service: 'VPC',
    title: 'Default VPC Is Being Used for Production Resources',
    description: 'Resources are deployed in the default VPC. Default VPCs are pre-configured with permissive settings and should not be used for production.',
    severity: 'medium',
    category: 'network',
    compliance: ['CIS AWS 5.1', 'NIST PR.AC-5', 'AWS Well-Architected'],
    getRemediation: (resourceId, region) => ({
      summary: 'Migrate resources to a custom VPC and delete the default VPC.',
      steps: [
        'Create a new custom VPC with appropriate CIDR block, subnets, and routing',
        'Migrate EC2, RDS, and other resources to the new VPC',
        'Update security groups and NACLs for the new VPC',
        `Delete the default VPC in each region: aws ec2 delete-vpc --vpc-id ${resourceId} --region REGION`,
        'Repeat for all regions',
      ],
      awsCli: `# List default VPCs\naws ec2 describe-vpcs --filters "Name=isDefault,Values=true" --region ${region ?? 'us-east-1'}\n# Delete default VPC (migrate resources first!)\naws ec2 delete-vpc --vpc-id ${resourceId} --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'days',
      operationalImpact: 'high',
    }),
    references: ['https://docs.aws.amazon.com/vpc/latest/userguide/default-vpc.html'],
  },

  // ─── EKS ─────────────────────────────────────────────────────────────────────

  'eks-public-endpoint': {
    id: 'eks-public-endpoint',
    service: 'EKS',
    title: 'EKS Cluster API Server Endpoint Is Public',
    description: 'The EKS cluster Kubernetes API server endpoint is accessible from the internet. This increases the attack surface for unauthenticated probing.',
    severity: 'high',
    category: 'network',
    compliance: ['CIS EKS 1.2.1', 'NIST PR.AC-5', 'SOC 2 CC6.6'],
    mitre: ['T1190'],
    getRemediation: (resourceId, region) => ({
      summary: 'Disable the public endpoint or restrict access to known CIDR blocks.',
      steps: [
        `Go to EKS → Clusters → ${resourceId} → Configuration → Networking`,
        'Click "Manage networking"',
        'Set "Cluster endpoint access" to "Private only" (preferred)',
        'Or: Keep public but add allowed CIDR ranges (e.g., your corporate IPs)',
        'If switching to private-only, ensure your kubectl clients are within the VPC or connected via VPN',
      ],
      awsCli: `aws eks update-cluster-config --name ${resourceId} --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
    }),
    references: ['https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html'],
  },

  // ─── Secrets Manager ─────────────────────────────────────────────────────────

  'secretsmanager-rotation-disabled': {
    id: 'secretsmanager-rotation-disabled',
    service: 'SecretsManager',
    title: 'Secrets Manager Secret Has No Automatic Rotation',
    description: 'Automatic rotation is not configured for this secret, meaning credentials are never rotated and must be manually updated.',
    severity: 'medium',
    category: 'iam',
    compliance: ['CIS AWS 2.1', 'NIST PR.AC-1', 'PCI DSS 8.3.9', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Configure automatic rotation for the secret using a Lambda rotation function.',
      steps: [
        `Go to Secrets Manager → ${resourceId} → Rotation configuration`,
        'Click "Edit rotation"',
        'Enable automatic rotation, set schedule (e.g., every 30 days)',
        'Select or create a Lambda rotation function matching the secret type',
        'Test rotation to ensure it works',
      ],
      awsCli: `aws secretsmanager rotate-secret --secret-id ${resourceId} --rotation-rules "AutomaticallyAfterDays=30" --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html'],
  },

  // ─── ACM ─────────────────────────────────────────────────────────────────────

  'acm-cert-expiring': {
    id: 'acm-cert-expiring',
    service: 'ACM',
    title: 'ACM Certificate Expiring Within 30 Days',
    description: 'An ACM certificate is expiring within 30 days. If not renewed, HTTPS connections will fail for associated resources.',
    severity: 'critical',
    category: 'compliance',
    compliance: ['NIST PR.MA-1', 'PCI DSS 6.3.3', 'SOC 2 CC7.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Renew or re-request the ACM certificate before it expires.',
      steps: [
        'ACM-managed certificates (DNS or email validation) renew automatically — check if auto-renewal is pending',
        `Go to ACM → Certificates → ${resourceId}`,
        'Check "Renewal status" — if "Pending validation", complete the validation step',
        'For DNS validation: add/verify the CNAME record in Route53',
        'For manually imported certificates: upload a new certificate from your CA',
        'Ensure all associated resources (ALB, CloudFront, API Gateway) are updated if certificate ARN changes',
      ],
      consoleUrl: `https://${region ?? 'us-east-1'}.console.aws.amazon.com/acm/home?region=${region ?? 'us-east-1'}#/certificates/${resourceId}`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
      operationalNotes: 'Expired certificates cause immediate HTTPS failures for end users.',
    }),
    references: ['https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html'],
  },

  // ─── DynamoDB ─────────────────────────────────────────────────────────────────

  'dynamodb-encryption-disabled': {
    id: 'dynamodb-encryption-disabled',
    service: 'DynamoDB',
    title: 'DynamoDB Table Not Encrypted with KMS',
    description: 'The DynamoDB table uses default (AWS-owned) encryption instead of a customer-managed KMS key, limiting key control and audit capabilities.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['NIST PR.DS-1', 'PCI DSS 3.5', 'HIPAA § 164.312(a)(2)(iv)', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Update the DynamoDB table to use a customer-managed KMS key.',
      steps: [
        `Go to DynamoDB → Tables → ${resourceId} → Additional settings → Encryption`,
        'Click "Manage encryption" → Select "Stored at rest encryption: KMS - Customer managed key"',
        'Choose or create a KMS key',
        'Apply changes',
      ],
      awsCli: `aws dynamodb update-table --table-name ${resourceId} --sse-specification "Enabled=true,SSEType=KMS,KMSMasterKeyId=YOUR_KMS_KEY_ARN" --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html'],
  },

  'dynamodb-pitr-disabled': {
    id: 'dynamodb-pitr-disabled',
    service: 'DynamoDB',
    title: 'DynamoDB Point-in-Time Recovery (PITR) Disabled',
    description: 'PITR is not enabled, meaning you cannot restore the table to any point in the last 35 days.',
    severity: 'medium',
    category: 'data_exposure',
    compliance: ['NIST PR.IP-4', 'PCI DSS 12.3.4', 'SOC 2 A1.2'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable Point-in-Time Recovery for the DynamoDB table.',
      steps: [
        `Go to DynamoDB → Tables → ${resourceId} → Backups`,
        'Click "Manage PITR" → Enable',
        'Save changes',
      ],
      awsCli: `aws dynamodb update-continuous-backups --table-name ${resourceId} --point-in-time-recovery-specification "PointInTimeRecoveryEnabled=true" --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery.html'],
  },

  // ─── SQS ─────────────────────────────────────────────────────────────────────

  'sqs-encryption-disabled': {
    id: 'sqs-encryption-disabled',
    service: 'SQS',
    title: 'SQS Queue Not Encrypted with KMS',
    description: 'The SQS queue does not use SSE-KMS encryption, meaning messages at rest are not protected with a customer-managed key.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['NIST PR.DS-1', 'PCI DSS 3.5', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable SSE-KMS on the SQS queue.',
      steps: [
        `Go to SQS → Queues → ${resourceId} → Encryption tab`,
        'Click "Edit" → Enable SSE-KMS',
        'Select or create a KMS key',
        'Save',
      ],
      awsCli: `aws sqs set-queue-attributes --queue-url https://sqs.${region ?? 'us-east-1'}.amazonaws.com/ACCOUNT/${resourceId} --attributes "KmsMasterKeyId=alias/aws/sqs" --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html'],
  },

  // ─── CloudFront ───────────────────────────────────────────────────────────────

  'cloudfront-https-not-enforced': {
    id: 'cloudfront-https-not-enforced',
    service: 'CloudFront',
    title: 'CloudFront Distribution Allows HTTP (Not HTTPS-Only)',
    description: 'The CloudFront distribution does not redirect HTTP to HTTPS, allowing unencrypted traffic and potential MITM attacks.',
    severity: 'high',
    category: 'encryption',
    compliance: ['CIS AWS 2.5', 'NIST PR.DS-2', 'PCI DSS 4.2.1', 'SOC 2 CC6.7'],
    mitre: ['T1557'],
    getRemediation: (resourceId) => ({
      summary: 'Configure CloudFront to redirect HTTP to HTTPS.',
      steps: [
        `Go to CloudFront → Distributions → ${resourceId} → Behaviors tab`,
        'Edit the default cache behavior',
        'Set "Viewer protocol policy" to "Redirect HTTP to HTTPS"',
        'Save changes and wait for deployment to complete',
      ],
      terraform: `resource "aws_cloudfront_distribution" "example" {\n  default_cache_behavior {\n    viewer_protocol_policy = "redirect-to-https"\n  }\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html'],
  },

  // ─── GuardDuty ───────────────────────────────────────────────────────────────

  'guardduty-not-enabled': {
    id: 'guardduty-not-enabled',
    service: 'GuardDuty',
    title: 'AWS GuardDuty Not Enabled',
    description: 'GuardDuty threat detection is not enabled in this region. Malicious activity, compromised instances, and reconnaissance will go undetected.',
    severity: 'high',
    category: 'logging',
    compliance: ['CIS AWS 2.6', 'NIST DE.CM-1', 'PCI DSS 11.6', 'SOC 2 CC7.2'],
    mitre: ['T1562.001'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable GuardDuty in all regions.',
      steps: [
        `Go to GuardDuty → Get Started → Enable GuardDuty in ${region ?? 'all regions'}`,
        'Enable optional protection plans: S3 Protection, EKS Protection, RDS Protection, Lambda Protection',
        'Set up SNS notifications for High-severity findings',
        'Consider enabling GuardDuty in all regions via Organizations',
      ],
      awsCli: `aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES --region ${region ?? 'us-east-1'}`,
      terraform: `resource "aws_guardduty_detector" "main" {\n  enable = true\n  finding_publishing_frequency = "FIFTEEN_MINUTES"\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html'],
  },

  // ─── SNS ─────────────────────────────────────────────────────────────────────

  'sns-encryption-disabled': {
    id: 'sns-encryption-disabled',
    service: 'SNS',
    title: 'SNS Topic Not Encrypted with KMS',
    description: 'The SNS topic does not have server-side encryption enabled, leaving message content unprotected at rest.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['NIST PR.DS-1', 'PCI DSS 3.5', 'SOC 2 CC6.1'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable KMS encryption on the SNS topic.',
      steps: [
        `Go to SNS → Topics → ${resourceId} → Edit`,
        'Under "Encryption", enable SSE',
        'Select a KMS key (or use aws/sns managed key)',
        'Save',
      ],
      awsCli: `aws sns set-topic-attributes --topic-arn arn:aws:sns:${region ?? 'us-east-1'}:ACCOUNT_ID:${resourceId} --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html'],
  },

  // ─── Redshift ────────────────────────────────────────────────────────────────

  'redshift-publicly-accessible': {
    id: 'redshift-publicly-accessible',
    service: 'Redshift',
    title: 'Redshift Cluster Publicly Accessible',
    description: 'The Redshift cluster is publicly accessible from the internet, exposing the data warehouse to unauthorized access attempts.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS AWS 2.4', 'NIST PR.AC-5', 'PCI DSS 1.3.2', 'SOC 2 CC6.6'],
    mitre: ['T1190'],
    getRemediation: (resourceId, region) => ({
      summary: 'Disable public accessibility and restrict access within your VPC.',
      steps: [
        `Go to Redshift → Clusters → ${resourceId} → Properties`,
        'Click "Modify cluster" → Under Network and security, disable "Publicly accessible"',
        'Apply changes (requires cluster reboot)',
        'Access the cluster through the VPC using the cluster endpoint',
      ],
      awsCli: `aws redshift modify-cluster --cluster-identifier ${resourceId} --no-publicly-accessible --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'high',
    }),
    references: ['https://docs.aws.amazon.com/redshift/latest/mgmt/managing-clusters-vpc.html'],
  },

  // ─── OpenSearch ──────────────────────────────────────────────────────────────

  'opensearch-publicly-accessible': {
    id: 'opensearch-publicly-accessible',
    service: 'OpenSearch',
    title: 'OpenSearch Domain Publicly Accessible Without Fine-Grained Control',
    description: 'The OpenSearch domain is accessible from the public internet without VPC or fine-grained access control.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS AWS 2.7', 'NIST PR.AC-5', 'PCI DSS 1.3.2', 'SOC 2 CC6.6'],
    mitre: ['T1190'],
    getRemediation: (resourceId, region) => ({
      summary: 'Place the OpenSearch domain in a VPC and enable fine-grained access control.',
      steps: [
        'OpenSearch cannot move to a VPC after creation — a new domain must be created',
        `Create a new domain at OpenSearch Service → Create domain`,
        'Choose VPC access, select subnets and security groups',
        'Enable Fine-grained access control (FGAC)',
        'Migrate data from the public domain to the new VPC domain',
        'Delete the old public domain',
      ],
      estimatedEffort: 'days',
      operationalImpact: 'high',
    }),
    references: ['https://docs.aws.amazon.com/opensearch-service/latest/developerguide/vpc.html'],
  },

  // ─── Config ──────────────────────────────────────────────────────────────────

  'config-not-enabled': {
    id: 'config-not-enabled',
    service: 'Config',
    title: 'AWS Config Not Enabled',
    description: 'AWS Config is not enabled. Configuration changes to AWS resources are not recorded, making compliance auditing and change tracking impossible.',
    severity: 'high',
    category: 'logging',
    compliance: ['CIS AWS 3.3', 'NIST DE.CM-3', 'PCI DSS 10.2', 'SOC 2 CC7.2'],
    getRemediation: (resourceId, region) => ({
      summary: 'Enable AWS Config with all resources recording and a managed rules baseline.',
      steps: [
        'Go to AWS Config → Get started (or Settings)',
        'Enable recording for "All resources" including global resources',
        'Set an S3 bucket for configuration snapshots',
        'Enable SNS topic for configuration change notifications',
        'Add AWS Config managed rules for compliance (e.g., encrypted-volumes, root-mfa-enabled)',
      ],
      awsCli: `aws configservice put-configuration-recorder --configuration-recorder "name=default,roleARN=arn:aws:iam::ACCOUNT_ID:role/ConfigRole,recordingGroup={allSupported=true,includeGlobalResourceTypes=true}" --region ${region ?? 'us-east-1'}\naws configservice start-configuration-recorder --configuration-recorder-name default --region ${region ?? 'us-east-1'}`,
      estimatedEffort: 'hours',
      operationalImpact: 'none',
    }),
    references: ['https://docs.aws.amazon.com/config/latest/developerguide/getting-started.html'],
  },
};
