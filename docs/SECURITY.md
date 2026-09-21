# TraceGuard Security Documentation

Security is the core feature of TraceGuard. This document outlines the threat model, compliance mappings, required permissions, and our responsible disclosure policy.

---

## 1. Credential Storage Security

TraceGuard is designed with a zero-trust approach to credential storage.

### AES-256-GCM Encryption
- All cloud credentials (AWS Access Keys, GCP Service Account JSONs) are encrypted in the application layer using **AES-256-GCM** via the Node.js native `crypto` module (`lib/scanners/credentials.ts`).
- An initialization vector (IV) and authentication tag are generated for every encryption operation to prevent tampering and replay attacks.

### Key Derivation
- The primary encryption key is provided via the `ENCRYPTION_KEY` environment variable.
- This key is **never** committed to version control, embedded in code, or stored in the Sanity database.

### Storage Boundary
- **Sanity Database**: Stores only the encrypted ciphertext, IV, and auth tag.
- **Environment**: Holds the decryption key.
- **Runtime**: Credentials are decrypted only in memory for the duration of an API request to AWS/GCP and are subject to immediate garbage collection once the HTTP request completes.

---

## 2. Threat Model

TraceGuard's threat modeling considers the following scenarios:

### Threat Actors
- **External Attackers**: Attempting to breach the web interface or API endpoints.
- **Compromised Infrastructure**: An attacker gaining access to the Sanity database.
- **Insider Threat**: An analyst misusing the dashboard.

### Attack Vectors & Mitigations
- **Database Breach**: If the Sanity database is compromised, cloud credentials remain secure because the AES encryption key resides only on the application server (e.g., Vercel).
- **Server Side Request Forgery (SSRF)**: Scanners strictly define target endpoints (AWS SDK and GCP REST APIs). Custom URLs cannot be passed to the scanner engine.
- **Prompt Injection**: LLM queries are bounded by rigid Zod schemas, mitigating the impact of malicious data parsed from cloud resource tags or names.

### Trust Boundaries
- Vercel Serverless Functions ↔ Sanity CMS
- Vercel Serverless Functions ↔ AWS/GCP Endpoints
- Client Browser ↔ Vercel API

---

## 3. Compliance Mappings

TraceGuard maps findings to multiple industry frameworks using rule definitions in `lib/scanners/rules/aws.ts` and `lib/scanners/rules/gcp.ts`.

| Framework | Coverage Area | Rule Map Example |
| :--- | :--- | :--- |
| **CIS AWS Foundations** | IAM, Logging, Networking | `CIS-1.2`, `CIS-2.1`, `CIS-4.3` |
| **CIS GCP** | IAM, Storage, Compute | `CIS-GCP-1.1`, `CIS-GCP-2.0` |
| **NIST CSF v2.0** | PR.AC, DE.CM, RS.AN | Evaluates KMS rotation and public S3 buckets |
| **PCI DSS 4.0** | Req 3, Req 4, Req 7 | Scans encryption at rest/transit and IAM strictness |
| **SOC 2 Type II** | Security, Confidentiality | Validates GuardDuty/Security Hub activation |
| **ISO 27001** | A.8, A.9, A.12 | Asset management, access control, ops security |
| **HIPAA** | Technical Safeguards | Ensures ePHI environments have audit logging |
| **MITRE ATT&CK** | Cloud Matrix | Maps open SG ports to Initial Access / Persistence |

---

## 4. IAM Permissions Required

TraceGuard operates strictly in **Read-Only** mode.

### AWS Minimum IAM Policy
To scan the 20 AWS services, attach this minimum policy to the TraceGuard IAM User/Role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:Get*", "s3:List*",
        "iam:Get*", "iam:List*", "iam:GenerateCredentialReport",
        "ec2:Describe*",
        "vpc:Describe*",
        "rds:Describe*", "rds:ListTagsForResource",
        "lambda:List*", "lambda:GetFunction*",
        "eks:Describe*", "eks:List*",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "kms:List*", "kms:Describe*", "kms:GetKeyPolicy",
        "secretsmanager:List*", "secretsmanager:Describe*",
        "acm:List*", "acm:Describe*",
        "dynamodb:List*", "dynamodb:Describe*",
        "sqs:List*", "sqs:GetQueueAttributes",
        "sns:List*", "sns:GetTopicAttributes",
        "cloudfront:List*", "cloudfront:GetDistributionConfig",
        "guardduty:List*", "guardduty:Get*",
        "securityhub:Get*", "securityhub:List*",
        "config:Describe*", "config:Get*",
        "redshift:Describe*",
        "es:Describe*", "es:List*"
      ],
      "Resource": "*"
    }
  ]
}
```

### GCP IAM Roles
Create a Service Account and assign the following roles:
- `roles/viewer` (Grants read access to most resources)
- `roles/iam.securityReviewer` (Required for evaluating IAM policies)

---

## 5. Security Best Practices for Deployment

When deploying TraceGuard, ensure the following practices:
1. **Environment Variables**: Use Vercel's secure environment variable storage. Do not check `.env.local` into Git.
2. **Sanity API Token Scoping**: Ensure the `SANITY_API_TOKEN` has the minimum necessary privileges (Editor role) rather than full Admin rights.
3. **Key Rotation**: Rotate your `ENCRYPTION_KEY` periodically. Note: You must run a migration script to decrypt/re-encrypt existing cloudAccount entries when rotating keys.
4. **Network Isolation**: If self-hosting, place the Next.js server behind a WAF (like Cloudflare) and restrict database access to the application's IP block.

---

## 6. Responsible Disclosure

If you find a vulnerability in TraceGuard:
- **DO NOT** create a public GitHub issue.
- Please email **security@traceguard.com** with details of the vulnerability, steps to reproduce, and potential impact.
- We will acknowledge receipt within 48 hours and work with you to patch the issue before public disclosure.
