// lib/scanners/rules/gcp.ts
// GCP security rules with remediation guidance.

import type { SecurityRule } from '../types';

export const GCP_RULES: Record<string, SecurityRule> = {

  // ─── GCS ─────────────────────────────────────────────────────────────────────

  'gcs-bucket-public': {
    id: 'gcs-bucket-public',
    service: 'GCS',
    title: 'GCS Bucket Is Publicly Accessible',
    description: 'The Cloud Storage bucket has IAM bindings for allUsers or allAuthenticatedUsers, making it readable by anyone on the internet.',
    severity: 'critical',
    category: 'data_exposure',
    compliance: ['CIS GCP 5.1', 'NIST PR.DS-1', 'PCI DSS 6.4.1', 'SOC 2 CC6.1'],
    mitre: ['T1530'],
    getRemediation: (resourceId) => ({
      summary: 'Remove allUsers and allAuthenticatedUsers IAM bindings from the bucket.',
      steps: [
        `Go to Cloud Storage → Buckets → ${resourceId} → Permissions tab`,
        'Click "View by role" or "View by principal"',
        'Remove any entries for "allUsers" or "allAuthenticatedUsers"',
        'Enable Uniform Bucket-Level Access to prevent ACL-based public access',
        'Verify with: gsutil iam get gs://BUCKET_NAME',
      ],
      gcpCli: `# Remove public access\ngsutil iam ch -d allUsers gs://${resourceId}\ngsutil iam ch -d allAuthenticatedUsers gs://${resourceId}\n# Enable uniform access\ngsutil uniformbucketlevelaccess set on gs://${resourceId}`,
      terraform: `resource "google_storage_bucket_iam_binding" "public" {\n  # Remove allUsers binding\n  # Ensure no binding exists for allUsers or allAuthenticatedUsers\n}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'high',
      operationalNotes: 'Applications relying on public access will break. Use signed URLs for time-limited access.',
    }),
    references: ['https://cloud.google.com/storage/docs/access-control/making-data-public'],
  },

  'gcs-uniform-access-disabled': {
    id: 'gcs-uniform-access-disabled',
    service: 'GCS',
    title: 'GCS Bucket Does Not Use Uniform Bucket-Level Access',
    description: 'The bucket allows legacy ACLs which can conflict with IAM policies and lead to unintended public access.',
    severity: 'medium',
    category: 'data_exposure',
    compliance: ['CIS GCP 5.2', 'NIST PR.DS-1', 'SOC 2 CC6.1'],
    getRemediation: (resourceId) => ({
      summary: 'Enable Uniform Bucket-Level Access to enforce IAM-only access control.',
      steps: [
        `Go to Cloud Storage → ${resourceId} → Configuration`,
        'Under "Access control", click "Switch to Uniform"',
        'Confirm',
      ],
      gcpCli: `gsutil uniformbucketlevelaccess set on gs://${resourceId}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'low',
    }),
    references: ['https://cloud.google.com/storage/docs/uniform-bucket-level-access'],
  },

  'gcs-encryption-no-cmek': {
    id: 'gcs-encryption-no-cmek',
    service: 'GCS',
    title: 'GCS Bucket Not Using Customer-Managed Encryption Key (CMEK)',
    description: 'The bucket uses Google-managed encryption keys instead of customer-managed keys (CMEK), limiting control and audit capability over encryption.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['CIS GCP 5.3', 'NIST PR.DS-1', 'PCI DSS 3.5', 'HIPAA § 164.312(a)(2)(iv)'],
    getRemediation: (resourceId) => ({
      summary: 'Configure a Cloud KMS customer-managed key for the GCS bucket.',
      steps: [
        'Create a Cloud KMS key ring and key in the same region as the bucket',
        `Go to Cloud Storage → ${resourceId} → Configuration → Encryption`,
        'Change to "Customer-managed key (Cloud KMS)"',
        'Select your KMS key',
        'Grant the Cloud Storage service account "Cloud KMS CryptoKey Encrypter/Decrypter" role on the key',
      ],
      gcpCli: `# Create key\ngcloud kms keyrings create traceguard-ring --location us-east1\ngcloud kms keys create bucket-key --location us-east1 --keyring traceguard-ring --purpose encryption\n# Set bucket default KMS key\ngsutil kms encryption -k projects/PROJECT_ID/locations/us-east1/keyRings/traceguard-ring/cryptoKeys/bucket-key gs://${resourceId}`,
      estimatedEffort: 'hours',
      operationalImpact: 'none',
    }),
    references: ['https://cloud.google.com/storage/docs/encryption/customer-managed-keys'],
  },

  // ─── GCP IAM ─────────────────────────────────────────────────────────────────

  'gcp-iam-service-account-key': {
    id: 'gcp-iam-service-account-key',
    service: 'GCP IAM',
    title: 'Service Account Has User-Managed Keys',
    description: 'A service account has user-managed keys which must be manually rotated. Unrotated keys are a persistent risk if leaked.',
    severity: 'high',
    category: 'iam',
    compliance: ['CIS GCP 1.4', 'NIST PR.AC-1', 'PCI DSS 8.3.9', 'SOC 2 CC6.1'],
    mitre: ['T1078.004'],
    getRemediation: (resourceId) => ({
      summary: 'Migrate to Workload Identity Federation or ensure keys are rotated and unused keys are deleted.',
      steps: [
        `Go to IAM → Service Accounts → ${resourceId} → Keys tab`,
        'Delete any keys older than 90 days',
        'For GKE workloads: configure Workload Identity — no service account keys needed',
        'For Cloud Run / Cloud Functions: use the service account directly — no key needed',
        'For external applications: consider Workload Identity Federation with your IdP',
      ],
      gcpCli: `# List keys\ngcloud iam service-accounts keys list --iam-account=${resourceId}\n# Delete old key (replace KEY_ID)\ngcloud iam service-accounts keys delete KEY_ID --iam-account=${resourceId}`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
    }),
    references: ['https://cloud.google.com/iam/docs/service-account-creds#key-types'],
  },

  'gcp-iam-primitive-roles': {
    id: 'gcp-iam-primitive-roles',
    service: 'GCP IAM',
    title: 'Primitive (Owner/Editor/Viewer) Roles Assigned at Project Level',
    description: 'Primitive roles (roles/owner, roles/editor) grant overly broad permissions and should be replaced with predefined or custom roles.',
    severity: 'high',
    category: 'iam',
    compliance: ['CIS GCP 1.1', 'NIST PR.AC-4', 'SOC 2 CC6.3', 'ISO 27001 A.9.2'],
    mitre: ['T1078'],
    getRemediation: (resourceId) => ({
      summary: 'Replace primitive roles with specific predefined or custom roles.',
      steps: [
        'Go to IAM → View all principals',
        `Find the principal with primitive role on project ${resourceId}`,
        'Identify what services they actually use (check Cloud Audit Logs)',
        'Replace "Editor" with specific roles (e.g., roles/compute.instanceAdmin, roles/storage.objectAdmin)',
        'Remove the primitive role after confirming the specific roles work',
      ],
      gcpCli: `# Remove primitive role from user\ngcloud projects remove-iam-policy-binding PROJECT_ID --member="user:EMAIL" --role="roles/editor"\n# Add specific role instead\ngcloud projects add-iam-policy-binding PROJECT_ID --member="user:EMAIL" --role="roles/compute.instanceAdmin.v1"`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
    }),
    references: ['https://cloud.google.com/iam/docs/understanding-roles#primitive_roles'],
  },

  // ─── GCE ─────────────────────────────────────────────────────────────────────

  'gce-firewall-ssh-open': {
    id: 'gce-firewall-ssh-open',
    service: 'GCE',
    title: 'Firewall Rule Allows SSH (Port 22) from 0.0.0.0/0',
    description: 'A GCE firewall rule allows inbound SSH from any IP address, exposing instances to brute force attacks.',
    severity: 'critical',
    category: 'network',
    compliance: ['CIS GCP 3.6', 'NIST PR.AC-5', 'PCI DSS 1.3.1', 'SOC 2 CC6.6'],
    mitre: ['T1133', 'T1021.004'],
    getRemediation: (resourceId) => ({
      summary: 'Restrict SSH access to specific IP ranges or use IAP for TCP Forwarding.',
      steps: [
        `Go to VPC Network → Firewall → ${resourceId} → Edit`,
        'Change source IP ranges from 0.0.0.0/0 to your specific corporate IP',
        'Save',
        'Better: Delete this rule and use Cloud IAP for TCP Forwarding (zero open ports)',
        'Enable OS Login for centralized SSH key management',
      ],
      gcpCli: `# Update firewall rule to restrict source\ngcloud compute firewall-rules update ${resourceId} --source-ranges=YOUR_IP/32\n\n# Or delete and use IAP\ngcloud compute firewall-rules delete ${resourceId}\ngcloud compute firewall-rules create allow-ssh-iap --direction=INGRESS --priority=1000 --network=default --action=allow --rules=tcp:22 --source-ranges=35.235.240.0/20`,
      estimatedEffort: 'minutes',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/iap/docs/using-tcp-forwarding'],
  },

  'gce-public-ip': {
    id: 'gce-public-ip',
    service: 'GCE',
    title: 'GCE Instance Has External (Public) IP Address',
    description: 'The Compute Engine instance has a public IP, increasing its attack surface unnecessarily.',
    severity: 'medium',
    category: 'network',
    compliance: ['CIS GCP 4.9', 'NIST PR.AC-5', 'SOC 2 CC6.6'],
    getRemediation: (resourceId) => ({
      summary: 'Remove the external IP and use Cloud NAT or IAP for outbound traffic and SSH access.',
      steps: [
        `Go to Compute Engine → VM instances → ${resourceId} → Edit`,
        'Under "Network interfaces", change external IP from "Ephemeral" to "None"',
        'Save (requires instance stop/start)',
        'Set up Cloud NAT for outbound internet access',
        'Use IAP TCP forwarding for SSH access without a public IP',
      ],
      gcpCli: `# Remove external IP (must stop first)\ngcloud compute instances stop ${resourceId} --zone=ZONE\ngcloud compute instances delete-access-config ${resourceId} --access-config-name="External NAT" --zone=ZONE\ngcloud compute instances start ${resourceId} --zone=ZONE`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address'],
  },

  'gce-os-login-disabled': {
    id: 'gce-os-login-disabled',
    service: 'GCE',
    title: 'OS Login Not Enabled for GCE Instances',
    description: 'OS Login is not enabled, meaning SSH access is managed via project-level SSH keys which are harder to audit and revoke.',
    severity: 'medium',
    category: 'iam',
    compliance: ['CIS GCP 4.4', 'NIST PR.AC-4', 'SOC 2 CC6.1'],
    getRemediation: (resourceId) => ({
      summary: 'Enable OS Login at project or instance level for centralized SSH key management.',
      steps: [
        'Go to Compute Engine → Metadata → Edit',
        'Add key: "enable-oslogin", value: "TRUE" (project level)',
        'Or set on individual instance: Compute Engine → VM → Edit → Custom metadata',
        'Remove project-wide SSH keys after enabling OS Login',
      ],
      gcpCli: `gcloud compute instances add-metadata ${resourceId} --metadata enable-oslogin=TRUE --zone=ZONE`,
      estimatedEffort: 'minutes',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/compute/docs/oslogin'],
  },

  // ─── Cloud SQL ────────────────────────────────────────────────────────────────

  'cloudsql-public-ip': {
    id: 'cloudsql-public-ip',
    service: 'Cloud SQL',
    title: 'Cloud SQL Instance Has Public IP Configured',
    description: 'The Cloud SQL instance has a public IP, making it accessible from the internet subject to authorized network restrictions.',
    severity: 'high',
    category: 'network',
    compliance: ['CIS GCP 6.6', 'NIST PR.AC-5', 'PCI DSS 1.3.2', 'SOC 2 CC6.6'],
    mitre: ['T1190'],
    getRemediation: (resourceId) => ({
      summary: 'Disable the public IP and use Cloud SQL Auth Proxy with private IP.',
      steps: [
        `Go to Cloud SQL → ${resourceId} → Edit`,
        'Under "Connectivity", disable "Public IP"',
        'Enable "Private IP" and select your VPC',
        'Use Cloud SQL Auth Proxy in your applications instead of direct connections',
        'Add Authorized Networks only if you must keep public IP',
      ],
      gcpCli: `gcloud sql instances patch ${resourceId} --no-assign-ip`,
      estimatedEffort: 'hours',
      operationalImpact: 'high',
    }),
    references: ['https://cloud.google.com/sql/docs/mysql/configure-ip'],
  },

  'cloudsql-ssl-not-required': {
    id: 'cloudsql-ssl-not-required',
    service: 'Cloud SQL',
    title: 'Cloud SQL Does Not Require SSL for Connections',
    description: 'SSL is not required for database connections, allowing plaintext transmission of database credentials and data.',
    severity: 'high',
    category: 'encryption',
    compliance: ['CIS GCP 6.4', 'NIST PR.DS-2', 'PCI DSS 4.2.1', 'SOC 2 CC6.7'],
    mitre: ['T1557'],
    getRemediation: (resourceId) => ({
      summary: 'Enforce SSL for all Cloud SQL connections.',
      steps: [
        `Go to Cloud SQL → ${resourceId} → Edit → Connections`,
        'Under "SSL", select "Allow only SSL connections"',
        'Download the SSL certificates and update your application connection strings',
        'Test connections with SSL before saving',
      ],
      gcpCli: `gcloud sql instances patch ${resourceId} --require-ssl`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/sql/docs/postgres/configure-ssl-instance'],
  },

  'cloudsql-backup-disabled': {
    id: 'cloudsql-backup-disabled',
    service: 'Cloud SQL',
    title: 'Cloud SQL Automated Backups Disabled',
    description: 'Automated backups are not enabled for this Cloud SQL instance.',
    severity: 'high',
    category: 'data_exposure',
    compliance: ['CIS GCP 6.7', 'NIST PR.IP-4', 'PCI DSS 12.3.4', 'SOC 2 A1.2'],
    getRemediation: (resourceId) => ({
      summary: 'Enable automated backups with point-in-time recovery.',
      steps: [
        `Go to Cloud SQL → ${resourceId} → Edit → Data Protection`,
        'Enable "Automated backups"',
        'Set retention to 7 days or more',
        'Enable "Point-in-time recovery" (requires binary logging for MySQL)',
      ],
      gcpCli: `gcloud sql instances patch ${resourceId} --backup-start-time=02:00 --enable-bin-log`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://cloud.google.com/sql/docs/postgres/backup-recovery/backups'],
  },

  // ─── BigQuery ─────────────────────────────────────────────────────────────────

  'bigquery-dataset-public': {
    id: 'bigquery-dataset-public',
    service: 'BigQuery',
    title: 'BigQuery Dataset Is Publicly Accessible',
    description: 'The BigQuery dataset grants access to allUsers or allAuthenticatedUsers, making all its tables and views readable without authentication.',
    severity: 'critical',
    category: 'data_exposure',
    compliance: ['CIS GCP 7.1', 'NIST PR.DS-1', 'PCI DSS 6.4.1', 'SOC 2 CC6.1'],
    mitre: ['T1530'],
    getRemediation: (resourceId) => ({
      summary: 'Remove public access from the BigQuery dataset.',
      steps: [
        `Go to BigQuery → ${resourceId} → Sharing → Permissions`,
        'Remove entries for allUsers and allAuthenticatedUsers',
        'Replace with specific user, group, or service account email addresses',
        'Consider using VPC Service Controls to restrict BigQuery access to your network',
      ],
      gcpCli: `bq update --clear_all_permissions ${resourceId}`,
      estimatedEffort: 'minutes',
      operationalImpact: 'high',
    }),
    references: ['https://cloud.google.com/bigquery/docs/dataset-access-controls'],
  },

  // ─── GKE ─────────────────────────────────────────────────────────────────────

  'gke-public-endpoint': {
    id: 'gke-public-endpoint',
    service: 'GKE',
    title: 'GKE Cluster Has Public Control Plane Endpoint',
    description: 'The GKE cluster control plane is accessible from the internet. This increases the attack surface for the Kubernetes API server.',
    severity: 'high',
    category: 'network',
    compliance: ['CIS GKE 1.2.1', 'NIST PR.AC-5', 'SOC 2 CC6.6'],
    mitre: ['T1190'],
    getRemediation: (resourceId) => ({
      summary: 'Enable private clusters or restrict master authorized networks.',
      steps: [
        `Go to GKE → Clusters → ${resourceId} → Networking`,
        'Add "Master authorized networks" to restrict access to your corporate IP ranges',
        'For stronger isolation: enable Private cluster (cannot be changed after creation)',
        'Use Cloud IAP or VPN for kubectl access to a private cluster',
      ],
      gcpCli: `gcloud container clusters update ${resourceId} --enable-master-authorized-networks --master-authorized-networks=YOUR_IP/32 --zone=ZONE`,
      estimatedEffort: 'hours',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters'],
  },

  'gke-workload-identity-disabled': {
    id: 'gke-workload-identity-disabled',
    service: 'GKE',
    title: 'GKE Workload Identity Not Enabled',
    description: 'Workload Identity is not enabled. Applications in the cluster may be using service account JSON keys, which are harder to manage and rotate.',
    severity: 'medium',
    category: 'iam',
    compliance: ['CIS GKE 6.2.1', 'NIST PR.AC-4', 'SOC 2 CC6.1'],
    getRemediation: (resourceId) => ({
      summary: 'Enable Workload Identity on the cluster to allow pods to use GCP service accounts without JSON keys.',
      steps: [
        `Enable Workload Identity on the cluster:\ngcloud container clusters update ${resourceId} --workload-pool=PROJECT_ID.svc.id.goog --zone=ZONE`,
        'Update each node pool to use Workload Identity',
        'Create a KSA (Kubernetes Service Account) for each workload',
        'Bind KSA to a GCP Service Account via IAM annotation',
        'Remove service account JSON key files from Kubernetes secrets',
      ],
      gcpCli: `gcloud container clusters update ${resourceId} --workload-pool=PROJECT_ID.svc.id.goog --zone=ZONE`,
      estimatedEffort: 'days',
      operationalImpact: 'medium',
    }),
    references: ['https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity'],
  },

  // ─── Cloud KMS ────────────────────────────────────────────────────────────────

  'gcp-kms-rotation-disabled': {
    id: 'gcp-kms-rotation-disabled',
    service: 'Cloud KMS',
    title: 'Cloud KMS Key Does Not Have Automatic Rotation Configured',
    description: 'Automatic key rotation is not configured for this Cloud KMS key, increasing risk from key material exposure over time.',
    severity: 'medium',
    category: 'encryption',
    compliance: ['CIS GCP 1.10', 'NIST PR.DS-1', 'PCI DSS 3.7', 'SOC 2 CC6.1'],
    getRemediation: (resourceId) => ({
      summary: 'Enable automatic rotation with a 90-day rotation period.',
      steps: [
        `Go to Security → Key Management → ${resourceId}`,
        'Click the key → Edit (pencil icon)',
        'Set "Rotation period" to 90 days',
        'Save',
      ],
      gcpCli: `gcloud kms keys update ${resourceId} --keyring=KEY_RING --location=LOCATION --rotation-period=7776000s --next-rotation-time=$(date -v+90d -u +%Y-%m-%dT%H:%M:%SZ)`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://cloud.google.com/kms/docs/key-rotation'],
  },

  // ─── Cloud Logging ────────────────────────────────────────────────────────────

  'gcp-logging-admin-activity-disabled': {
    id: 'gcp-logging-admin-activity-disabled',
    service: 'Cloud Logging',
    title: 'Cloud Audit Logs: Admin Activity Not Enabled for All Services',
    description: 'Admin Activity audit logs are not enabled for all services, leaving gaps in the audit trail for critical API calls.',
    severity: 'high',
    category: 'logging',
    compliance: ['CIS GCP 2.1', 'NIST DE.CM-3', 'PCI DSS 10.2', 'SOC 2 CC7.2'],
    getRemediation: (resourceId) => ({
      summary: 'Enable Admin Activity and Data Access audit logs for all GCP services.',
      steps: [
        'Go to IAM & Admin → Audit Logs',
        'Select "All Services" at the top',
        'Enable "Admin Read", "Data Read", "Data Write" log types',
        'Click "Save"',
        'Create a log sink to BigQuery or GCS for long-term retention',
      ],
      gcpCli: `gcloud projects get-iam-policy PROJECT_ID --format=json > policy.json\n# Edit policy.json to add auditLogConfigs for allServices\ngcloud projects set-iam-policy PROJECT_ID policy.json`,
      estimatedEffort: 'minutes',
      operationalImpact: 'none',
    }),
    references: ['https://cloud.google.com/logging/docs/audit'],
  },
};
