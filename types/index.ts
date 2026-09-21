// TraceGuard — Core TypeScript Types
// All types used across the investigation pipeline

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Environment = 'production' | 'staging' | 'development' | 'unknown';
export type DataSensitivity = 'restricted' | 'confidential' | 'internal' | 'public';
export type InvestigationStatus =
  | 'investigating'
  | 'analysis_complete'
  | 'remediation_proposed'
  | 'pending_review'
  | 'approved'
  | 'rejected'
  | 'verified'
  | 'closed';

export type WorkflowStatus = InvestigationStatus;

export type ConflictType = 'policy_version' | 'source_contradiction' | 'config_drift' | 'permission_escalation';
export type EvidenceType = 'configuration' | 'asset_metadata' | 'data_classification' | 'policy' | 'threat_intel' | 'control' | 'source_doc';
export type ChainNodeType = 'finding' | 'asset' | 'environment' | 'data' | 'control' | 'threat' | 'impact' | 'remediation' | 'policy';

// ─── Sanity Reference ────────────────────────────────────────────────────────

export interface SanityRef {
  _ref: string;
  _type: 'reference';
}

// ─── Source Document ──────────────────────────────────────────────────────────

export interface Source {
  _id: string;
  _type: 'source';
  title: string;
  organization: string;
  url: string;
  authority: 'aws' | 'mitre' | 'cis' | 'nist' | 'internal' | 'vendor' | 'other';
  publicationDate: string;
  version?: string;
  sourceType: 'documentation' | 'standard' | 'threat_intel' | 'policy' | 'architecture_doc';
  retrievedAt: string;
  status: 'current' | 'historical' | 'deprecated' | 'unknown';
}

// ─── Security Asset ───────────────────────────────────────────────────────────

export interface SecurityAsset {
  _id: string;
  _type: 'securityAsset';
  name: string;
  assetId: string;
  provider: 'aws' | 'gcp' | 'azure' | 'on-prem';
  service: string;
  environment: Environment;
  description: string;
  sensitivity: DataSensitivity;
  owner: string;
  tags: string[];
  relatedAssets?: SanityRef[];
  source?: Source;
}

// ─── Data Asset ───────────────────────────────────────────────────────────────

export interface DataAsset {
  _id: string;
  _type: 'dataAsset';
  name: string;
  classification: DataSensitivity;
  sensitivity: DataSensitivity;
  contains: string[];
  storedIn?: SanityRef; // → SecurityAsset
  owner: string;
  description: string;
  regulatoryScope?: string[];
}

// ─── Configuration ────────────────────────────────────────────────────────────

export interface Configuration {
  _id: string;
  _type: 'configuration';
  asset: SanityRef; // → SecurityAsset
  setting: string;
  observedValue: string;
  expectedValue: string;
  status: 'compliant' | 'non_compliant' | 'unknown';
  observedAt: string;
  environment: Environment;
  source?: Source;
  notes?: string;
}

// ─── Finding ──────────────────────────────────────────────────────────────────

export interface Finding {
  _id: string;
  _type: 'finding';
  title: string;
  findingId: string;
  severity: Severity;
  category: string;
  affectedAsset: SanityRef; // → SecurityAsset
  observedCondition: string;
  evidence: string[];
  relatedConfigurations?: SanityRef[]; // → Configuration[]
  potentialImpact: string;
  status: 'open' | 'investigating' | 'remediated' | 'accepted' | 'false_positive';
  discoveredAt: string;
}

// ─── Security Control ─────────────────────────────────────────────────────────

export interface SecurityControl {
  _id: string;
  _type: 'securityControl';
  controlId: string;
  name: string;
  description: string;
  framework: 'CIS' | 'NIST' | 'SOC2' | 'PCI-DSS' | 'ISO27001' | 'internal';
  requirements: string[];
  applicableServices: string[];
  remediationGuidance: string;
  source?: Source;
  version?: string;
}

// ─── Threat Technique ─────────────────────────────────────────────────────────

export interface ThreatTechnique {
  _id: string;
  _type: 'threatTechnique';
  techniqueId: string;
  name: string;
  description: string;
  tactics: string[];
  affectedServices: string[];
  relevantConditions: string[];
  cloudContext: string;
  source?: Source;
  severity: Severity;
  externalUrl?: string;
  mitigations?: string[];
}

// ─── Policy ───────────────────────────────────────────────────────────────────

export interface Policy {
  _id: string;
  _type: 'policy';
  name: string;
  policyId: string;
  requirement: string;
  appliesTo: string[];
  effectiveFrom: string;
  effectiveTo?: string;
  version: string;
  isCurrentVersion: boolean;
  exceptions?: string[];
  source?: Source;
  supersededBy?: SanityRef; // → Policy
  notes?: string;
}

// ─── Remediation ──────────────────────────────────────────────────────────────

export interface Remediation {
  _id: string;
  _type: 'remediation';
  title: string;
  finding: SanityRef; // → Finding
  proposedChange: string;
  rationale: string;
  prerequisites: string[];
  operationalImpact: string;
  risk: 'low' | 'medium' | 'high';
  verificationSteps: string[];
  requiredApproval: string;
  automationAvailable: boolean;
}

// ─── Investigation ────────────────────────────────────────────────────────────

export interface Investigation {
  _id: string;
  _type: 'investigation';
  investigationId: string;
  finding: SanityRef; // → Finding
  status: InvestigationStatus;
  evidence: EvidenceItem[];
  claims: Claim[];
  relationships: Relationship[];
  conflicts: ConflictItem[];
  reasoningSummary: string;
  nextChecks: string[];
  remediation?: SanityRef; // → Remediation
  approvalStatus?: 'pending' | 'approved' | 'rejected';
  approvedBy?: string;
  approvedAt?: string;
  rejectionReason?: string;
  createdAt: string;
  updatedAt: string;
}

// ─── Investigation Result (Agent Output) ──────────────────────────────────────

export interface EvidenceItem {
  type: EvidenceType;
  label: string;
  value: string;
  sourceId?: string;
  sourceTitle?: string;
  sourceUrl?: string;
  sourceVersion?: string;
  sourceDate?: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface Claim {
  statement: string;
  supportedBy: string[]; // evidence IDs or descriptions
  confidence: 'high' | 'medium' | 'low';
}

export interface Relationship {
  from: string;
  to: string;
  type: string;
  label: string;
}

export interface ConflictItem {
  type: ConflictType;
  description: string;
  sourceA: string;
  sourceB: string;
  recommendation: string;
  severity: Severity;
}

export interface ChainNode {
  id: string;
  type: ChainNodeType;
  label: string;
  sublabel?: string;
  severity?: Severity;
  evidence?: EvidenceItem[];
  data?: Record<string, unknown>;
}

export interface ChainEdge {
  from: string;
  to: string;
  label?: string;
}

export interface PolicyAnalysis {
  currentPolicyId: string;
  currentPolicyName: string;
  currentPolicyVersion: string;
  currentPolicyStatus: 'compliant' | 'violated' | 'unknown';
  historicalPolicies: {
    policyId: string;
    name: string;
    version: string;
    status: 'compliant' | 'violated' | 'unknown';
    effectiveTo?: string;
  }[];
  driftDetected: boolean;
  driftDescription?: string;
  conflictsDetected: boolean;
}

// ─── Full Investigation Result (returned by agent) ────────────────────────────

export interface InvestigationResult {
  investigationId: string;
  finding: Finding;
  status: InvestigationStatus;
  observations: string[];
  affectedAssets: SecurityAsset[];
  dataExposure: DataAsset[];
  securityControls: SecurityControl[];
  threatTechniques: ThreatTechnique[];
  policyAnalysis: PolicyAnalysis;
  conflicts: ConflictItem[];
  evidence: EvidenceItem[];
  investigationChain: ChainNode[];
  chainEdges: ChainEdge[];
  nextChecks: string[];
  remediation: Remediation | null;
  operationalImpact: string;
  confidence: {
    overall: 'high' | 'medium' | 'low';
    dataExposure: 'high' | 'medium' | 'low';
    policyViolation: 'high' | 'medium' | 'low';
  };
  limitations: string[];
  reasoningSummary: string;
  createdAt: string;
}

// ─── Investigation Step (for activity feed streaming) ────────────────────────

export interface InvestigationStep {
  stepIndex: number;
  stepId: string;
  label: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  detail?: string;
  timestamp: string;
  durationMs?: number;
}

export interface InvestigationProgress {
  investigationId: string;
  currentStep: number;
  totalSteps: number;
  steps: InvestigationStep[];
  isComplete: boolean;
  result?: InvestigationResult;
  error?: string;
}

// ─── Dashboard Types ─────────────────────────────────────────────────────────

export interface SecurityPosture {
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  criticalPaths: number;
  policyConflicts: number;
  assetsAffected: number;
  evidenceSources: number;
  openInvestigations: number;
}
