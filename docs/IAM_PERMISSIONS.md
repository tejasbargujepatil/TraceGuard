# AWS Minimum IAM Policy for TraceGuard Scanning

This policy grants the **minimum read-only permissions** required for TraceGuard to scan all 20 AWS services. Attach this to an IAM user or role used for scanning.

> **Recommendation**: Create a dedicated IAM user named `traceguard-scanner` with no console access, only programmatic access.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TraceGuardS3",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketLogging",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardIAM",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardEC2",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeVolumes",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeRegions",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardRDS",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSnapshots"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardLambda",
      "Effect": "Allow",
      "Action": [
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "lambda:GetFunctionConfiguration"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardEKS",
      "Effect": "Allow",
      "Action": [
        "eks:ListClusters",
        "eks:DescribeCluster"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardCloudTrail",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardKMS",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardSecretsManager",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardACM",
      "Effect": "Allow",
      "Action": [
        "acm:ListCertificates",
        "acm:DescribeCertificate"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardDynamoDB",
      "Effect": "Allow",
      "Action": [
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardSQSSNS",
      "Effect": "Allow",
      "Action": [
        "sqs:ListQueues",
        "sqs:GetQueueAttributes",
        "sns:ListTopics",
        "sns:GetTopicAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardCloudFront",
      "Effect": "Allow",
      "Action": [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardGuardDuty",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardSecurityHub",
      "Effect": "Allow",
      "Action": [
        "securityhub:GetFindings",
        "securityhub:DescribeHub"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardConfig",
      "Effect": "Allow",
      "Action": [
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeComplianceByConfigRule",
        "config:DescribeConfigRules"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardRedshift",
      "Effect": "Allow",
      "Action": [
        "redshift:DescribeClusters"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardOpenSearch",
      "Effect": "Allow",
      "Action": [
        "es:ListDomainNames",
        "es:DescribeDomain",
        "es:DescribeDomains"
      ],
      "Resource": "*"
    },
    {
      "Sid": "TraceGuardSTS",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Creating the IAM User (AWS CLI)

```bash
# 1. Create the policy
aws iam create-policy \
  --policy-name TraceGuardScannerPolicy \
  --policy-document file://iam-policy.json \
  --description "Read-only scanning policy for TraceGuard"

# 2. Create the user
aws iam create-user --user-name traceguard-scanner

# 3. Attach the policy
aws iam attach-user-policy \
  --user-name traceguard-scanner \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/TraceGuardScannerPolicy

# 4. Create access keys
aws iam create-access-key --user-name traceguard-scanner
# → Save the AccessKeyId and SecretAccessKey
```

## GCP Service Account Setup

```bash
# 1. Create service account
gcloud iam service-accounts create traceguard-scanner \
  --display-name="TraceGuard Security Scanner" \
  --project=YOUR_PROJECT_ID

# 2. Bind read-only roles
for ROLE in \
  roles/viewer \
  roles/iam.securityReviewer \
  roles/cloudkms.viewer \
  roles/logging.viewer \
  roles/container.viewer; do
  gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:traceguard-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="$ROLE"
done

# 3. Create and download JSON key
gcloud iam service-accounts keys create traceguard-key.json \
  --iam-account=traceguard-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com

# 4. Paste the contents of traceguard-key.json when adding a GCP account in TraceGuard
```

## GCP IAM Roles Required

| Role | Purpose |
|---|---|
| `roles/viewer` | Base read access to all resources |
| `roles/iam.securityReviewer` | Read IAM policies, service account keys |
| `roles/cloudkms.viewer` | Read KMS key metadata and rotation settings |
| `roles/logging.viewer` | Read Cloud Logging sinks and audit configs |
| `roles/container.viewer` | Read GKE cluster configuration |
| `roles/cloudsql.viewer` | Read Cloud SQL instance settings |
| `roles/bigquery.metadataViewer` | Read BigQuery dataset IAM policies |

> **Note**: `roles/viewer` covers most services. The additional roles are needed for services that have stricter default access controls.
