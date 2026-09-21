# TraceGuard — Data Flow & Scanning Reference

## Scan Data Flow (Chunked Architecture)

```mermaid
sequenceDiagram
    participant User as 👤 Analyst
    participant UI as Next.js UI
    participant AccountAPI as /api/accounts
    participant ScanAPI as /api/accounts/[id]/scan
    participant Engine as Scanner Engine
    participant Crypto as AES-256-GCM
    participant Sanity as Sanity CMS
    participant Cloud as AWS / GCP APIs

    User->>UI: Click "Add Account" + enter credentials
    UI->>AccountAPI: POST /api/accounts {provider, credentials, regions}
    AccountAPI->>Crypto: encryptCredentials(credentials)
    Crypto-->>AccountAPI: {iv, tag, data} (encrypted blob)
    AccountAPI->>Sanity: create cloudAccount document
    Sanity-->>AccountAPI: {_id, name, status: "connected"}
    AccountAPI-->>UI: Account created ✓

    User->>UI: Click "Scan Now"
    UI->>ScanAPI: POST /api/accounts/{id}/scan {service: "s3"}
    ScanAPI->>Sanity: fetch cloudAccount by _id
    Sanity-->>ScanAPI: {encryptedCredential, regions, provider}
    ScanAPI->>Crypto: decryptCredentials(encryptedBlob)
    Crypto-->>ScanAPI: plaintext credentials (in-memory only)
    ScanAPI->>Engine: runServiceScan(job, "s3")
    Engine->>Cloud: AWS/GCP API calls
    Cloud-->>Engine: resource list + config data
    Engine->>Engine: evaluate rules → findings[]
    Engine->>Sanity: createOrReplace finding documents
    ScanAPI-->>UI: {findings, findingCount, durationMs}

    Note over UI: Repeat for each of 20/9 services sequentially
    UI->>UI: Accumulate findings, show live progress
```

---

## AI Investigation Pipeline

```mermaid
flowchart TD
    A[Finding selected by analyst] --> B[POST /api/investigate SSE]
    B --> C[Step 1: Load finding context]
    C --> D[Step 2: Fetch affected asset]
    D --> E[Step 3: Load data assets on asset]
    E --> F[Step 4: Load configurations]
    F --> G[Step 5: Fetch relevant policies]
    G --> H[Step 6: Load security controls]
    H --> I[Step 7: Find threat techniques]
    I --> J[Step 8: Search similar findings]
    J --> K[Step 9: Correlate MITRE ATT&CK]
    K --> L[Step 10: Assess compliance impact]
    L --> M[Step 11: Generate risk score]
    M --> N{generateObject - Gemini 3.6 Flash}
    N --> O[Step 12: Synthesize investigation report]
    O --> P[Step 13: Generate remediation steps]
    P --> Q[Step 14: Create Sanity investigation doc]
    Q --> R[Step 15: Stream completion event]
    R --> S[UI renders EvidenceChainGraph + RemediationWorkflow]
```

---

## Credential Encryption Flow

```mermaid
flowchart LR
    subgraph Server["Server-side only (never client)"]
        KEY["CREDENTIAL_ENCRYPTION_KEY\n(env var, 32-byte hex)"]
        ENCRYPT["AES-256-GCM\nencryptCredentials()"]
        DECRYPT["AES-256-GCM\ndecryptCredentials()"]
    end

    subgraph Sanity["Sanity Content Lake"]
        DOC["cloudAccount document\n{iv, tag, data} as JSON string"]
    end

    subgraph Memory["In-memory only (scan time)"]
        PLAIN["Plaintext credentials\nGarbage collected after scan"]
    end

    KEY --> ENCRYPT
    ENCRYPT --> DOC
    DOC --> DECRYPT
    KEY --> DECRYPT
    DECRYPT --> Memory
```

**Security properties:**
- The master key **never touches Sanity** — only the encrypted blob does
- The encrypted blob uses a **fresh random 12-byte IV per encryption** — same credentials encrypted twice produce different ciphertext
- AES-256-GCM provides **authenticated encryption** — the tag prevents tampering
- Plaintext credentials exist **in Node.js process memory only** during the scan call and are garbage-collected immediately after

---

## Sanity Schema Relationships

```mermaid
erDiagram
    SOURCE ||--o{ SECURITY_ASSET : "discovered via"
    SECURITY_ASSET ||--o{ DATA_ASSET : "hosts"
    SECURITY_ASSET ||--o{ CONFIGURATION : "has"
    SECURITY_ASSET ||--o{ FINDING : "generates"
    FINDING }o--o{ THREAT_TECHNIQUE : "maps to"
    FINDING }o--o{ POLICY : "violates"
    FINDING ||--o| REMEDIATION : "has"
    FINDING ||--o| INVESTIGATION : "triggers"
    INVESTIGATION }o--o{ SECURITY_CONTROL : "relates to"
    CLOUD_ACCOUNT ||--o{ FINDING : "produces"

    SOURCE {
        string name
        string type
        string region
        string accountId
        string provider
    }
    SECURITY_ASSET {
        string name
        string assetType
        string criticality
        string environment
        string[] tags
    }
    FINDING {
        string title
        string severity
        string category
        string status
        string cloudProvider
        string resourceId
        string[] compliance
        string[] mitre
    }
    CLOUD_ACCOUNT {
        string name
        string provider
        string cloudAccountId
        string[] regions
        string credentialMode
        string encryptedCredential
        string status
    }
    INVESTIGATION {
        string status
        string riskScore
        string aiModel
        object synthesisResult
    }
```

---

## Security Rule Evaluation Logic

```mermaid
flowchart TD
    START["scan(job) called"] --> LOOP["For each region in job.regions"]
    LOOP --> API["Call cloud API\ne.g. DescribeInstances"]
    API --> RESOURCES["For each resource"]
    RESOURCES --> CHECK["Evaluate rule conditions\ne.g. MetadataOptions.HttpTokens !== 'required'"]
    CHECK --> FAIL{Condition\nviolated?}
    FAIL -->|Yes| BUILD["Build ScanFinding\n{id, ruleId, severity, remediation, ...}"]
    BUILD --> PUSH["Push to findings[]"]
    PUSH --> NEXT["Next resource"]
    FAIL -->|No| NEXT
    NEXT --> MORE_RESOURCES{More\nresources?}
    MORE_RESOURCES -->|Yes| RESOURCES
    MORE_RESOURCES -->|No| MORE_REGIONS{More\nregions?}
    MORE_REGIONS -->|Yes| LOOP
    MORE_REGIONS -->|No| PERSIST["persistFindings() → Sanity"]
    PERSIST --> RETURN["Return ServiceScanResult"]
```

---

## Finding Severity Taxonomy

| Severity | Score | Examples |
|---|---|---|
| **Critical** | 9–10 | S3 public access, root access keys, SSH open to 0.0.0.0/0, RDS publicly accessible |
| **High** | 7–8 | IAM user without MFA, unencrypted EBS, Lambda with deprecated runtime, EKS public endpoint |
| **Medium** | 4–6 | S3 versioning disabled, KMS rotation disabled, VPC flow logs missing, weak password policy |
| **Low** | 1–3 | Logging configuration gaps, tagging standards |
| **Info** | 0 | Informational observations from Security Hub |

---

## Compliance Framework Coverage

| Framework | Version | Checks Covered |
|---|---|---|
| CIS AWS Foundations | v3.0 | 1.4, 1.8, 1.9, 1.10, 1.14, 1.16, 2.1.1–2.1.4, 2.2.1, 2.3.1–2.3.3, 2.4, 2.5, 2.6, 2.7, 3.1–3.3, 3.7, 3.9, 5.1–5.3, 5.6 |
| CIS GCP | v1.3 | 1.1, 1.4, 1.10, 2.1, 2.2, 3.6, 4.4, 4.9, 5.1–5.3, 6.4, 6.6, 6.7, 7.1 |
| NIST CSF | v2.0 | PR.AC-1/4/5/7, PR.DS-1/2, PR.IP-4, PR.MA-1, DE.AE-1, DE.CM-1/3, SI-2 |
| PCI DSS | v4.0 | 1.3.1/2, 3.5, 3.7, 4.2.1, 6.3.3, 6.4.1, 7.1, 8.3, 8.3.9, 8.4, 10.2/3/5/7, 11.6, 12.3.4 |
| SOC 2 | Type II | CC6.1/3/6/7, CC7.1/2, A1.2 |
| ISO 27001 | 2022 | A.9.2, A.9.4, A.12.4, A.13.1/3 |
| HIPAA | 2013 | §164.312(a)(2)(iv), §164.312(e)(1) |
| MITRE ATT&CK | v14 | T1078, T1078.004, T1133, T1190, T1021, T1530, T1552, T1557, T1562 |

---

## AWS Scanner Coverage Matrix

| Service | Scanner | Checks | Key Rules |
|---|---|---|---|
| S3 | `aws/s3.ts` | 4 | Public access block, versioning, SSE, logging |
| IAM | `aws/iam.ts` | 5 | Root keys, MFA, password policy, access key age, wildcard policies |
| EC2 | `aws/ec2.ts` | 4 | SSH/RDP open, IMDSv2, EBS encryption |
| VPC | `aws/vpc.ts` | 2 | Flow logs, default VPC |
| RDS | `aws/rds.ts` | 3 | Public access, encryption, backups |
| Lambda | `aws/lambda.ts` | 2 | Secrets in env, deprecated runtime |
| EKS | `aws/eks.ts` | 1 | Public API endpoint |
| CloudTrail | `aws/cloudtrail.ts` | 2 | Enabled + multi-region, log validation |
| KMS | `aws/kms.ts` | 1 | Key rotation |
| Secrets Manager | `aws/secretsmanager.ts` | 1 | Auto-rotation |
| ACM | `aws/acm.ts` | 1 | Expiry < 30 days |
| DynamoDB | `aws/dynamodb.ts` | 2 | KMS encryption, PITR |
| SQS | `aws/sqs.ts` | 1 | KMS encryption |
| SNS | `aws/sns.ts` | 1 | KMS encryption |
| CloudFront | `aws/cloudfront.ts` | 1 | HTTPS enforcement |
| GuardDuty | `aws/guardduty.ts` | 1 | Enabled per region |
| Security Hub | `aws/securityhub.ts` | * | All active failed findings |
| Config | `aws/config.ts` | * | Recording status + non-compliant rules |
| Redshift | `aws/redshift.ts` | 1 | Public accessibility |
| OpenSearch | `aws/opensearch.ts` | 1 | Public endpoint |

---

## GCP Scanner Coverage Matrix

| Service | Scanner | Checks | Key Rules |
|---|---|---|---|
| Cloud Storage | `gcp/gcs.ts` | 3 | Public IAM, uniform access, CMEK |
| IAM | `gcp/gcpiam.ts` | 2 | SA user-managed keys, primitive roles |
| Compute Engine | `gcp/compute.ts` | 3 | External IP, OS Login, SSH firewall |
| Cloud SQL | `gcp/cloudsql.ts` | 3 | Public IP, SSL required, backups |
| BigQuery | `gcp/bigquery.ts` | 1 | Public dataset access |
| Cloud Functions | `gcp/functions.ts` | 2 | Secrets in env, deprecated runtime |
| GKE | `gcp/gke.ts` | 2 | Public control plane, Workload Identity |
| Cloud KMS | `gcp/kms.ts` | 1 | Key rotation |
| Cloud Logging | `gcp/logging.ts` | 2 | Audit log types, log sinks |
