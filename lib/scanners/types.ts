// lib/scanners/types.ts
// Shared types for the TraceGuard cloud scanning engine.
// All scanner implementations must conform to these interfaces.

export type CloudProvider = 'aws' | 'gcp';
export type ScanSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type EffortLevel = 'minutes' | 'hours' | 'days';
export type ImpactLevel = 'none' | 'low' | 'medium' | 'high';

// ─── Credentials ─────────────────────────────────────────────────────────────

export interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  region: string;
  accountId?: string;
}

export interface GCPCredentials {
  type: 'service_account';
  project_id: string;
  private_key_id: string;
  private_key: string;
  client_email: string;
  client_id: string;
  token_uri: string;
}

export type CloudCredentials = AWSCredentials | GCPCredentials;

// ─── Remediation ─────────────────────────────────────────────────────────────

export interface RemediationInfo {
  summary: string;
  steps: string[];
  awsCli?: string;
  gcpCli?: string;
  terraform?: string;
  consoleUrl?: string;
  estimatedEffort: EffortLevel;
  operationalImpact: ImpactLevel;
  operationalNotes?: string;
}

// ─── Security Rule ────────────────────────────────────────────────────────────

export interface SecurityRule {
  id: string;
  service: string;
  title: string;
  description: string;
  severity: ScanSeverity;
  category: string;
  compliance: string[];
  mitre?: string[];
  getRemediation: (resourceId: string, region?: string, accountId?: string) => RemediationInfo;
  references: string[];
}

// ─── Scan Finding ─────────────────────────────────────────────────────────────

export interface ScanFinding {
  id: string;                        // `${ruleId}::${resourceId}`
  ruleId: string;
  title: string;
  severity: ScanSeverity;
  category: string;
  service: string;
  resourceId: string;
  resourceArn?: string;
  resourceName?: string;
  region: string;
  accountId: string;
  provider: CloudProvider;
  observedCondition: string;
  potentialImpact: string;
  remediation: RemediationInfo;
  compliance: string[];
  mitre?: string[];
  rawMetadata?: Record<string, unknown>;
  discoveredAt: string;
}

// ─── Scanner Interface ────────────────────────────────────────────────────────

export interface ServiceScanner {
  service: string;
  displayName: string;
  provider: CloudProvider;
  scan(credentials: CloudCredentials, regions: string[]): Promise<ScanFinding[]>;
}

// ─── Scan Job ─────────────────────────────────────────────────────────────────

export interface ScanJob {
  accountId: string;            // Sanity cloudAccount _id
  provider: CloudProvider;
  cloudAccountId: string;       // AWS account ID / GCP project ID
  credentials: CloudCredentials;
  regions: string[];
  services: string[];           // which service keys to scan
}

export interface ServiceScanResult {
  service: string;
  displayName: string;
  status: 'running' | 'complete' | 'error' | 'skipped';
  findingCount: number;
  findings: ScanFinding[];
  durationMs: number;
  error?: string;
}

// ─── Cloud Account (UI type, mirrors Sanity doc) ─────────────────────────────

export interface CloudAccount {
  _id: string;
  name: string;
  provider: CloudProvider;
  cloudAccountId: string;
  regions: string[];
  credentialMode: 'encrypted' | 'env';
  status: 'connected' | 'scanning' | 'error' | 'disconnected';
  lastScannedAt?: string;
  lastScanFindingCount?: number;
  lastScanCriticalCount?: number;
  lastScanHighCount?: number;
  errorMessage?: string;
  createdAt: string;
}

// ─── Credential Payload ───────────────────────────────────────────────────────

export interface EncryptedCredential {
  iv: string;
  tag: string;
  data: string;
}
