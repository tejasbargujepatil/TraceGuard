// TraceGuard Investigation Agent
// 
// This is the core AI agent that investigates security findings.
// It follows a structured 15-step pipeline using Sanity GROQ queries
// as tools to retrieve and correlate structured security knowledge.
//
// The agent does NOT perform keyword search — it traverses the Sanity
// content graph using structured GROQ queries to build the evidence chain.
//
// Architecture:
// - Each step is a discrete tool call / knowledge retrieval
// - Progress is emitted as events for streaming to the UI
// - Output is a validated InvestigationResult (not free-form prose)
// - The LLM synthesizes only the reasoning summary and next checks
//   from structured evidence — not from raw text retrieval

import { generateObject } from 'ai';
import { openai } from '@ai-sdk/openai';
import { anthropic } from '@ai-sdk/anthropic';
import { google } from '@ai-sdk/google';
import { z } from 'zod';
import {
  getFindingById,
  getConfigurationsForAsset,
  getDataAssetsForAsset,
  getPoliciesForService,
  getAllPolicies,
  getControlsForService,
  getThreatTechniquesForService,
  getThreatTechniquesByCondition,
  getRemediationForFinding,
  createInvestigationDocument,
} from '../sanity/queries';
import type {
  InvestigationResult,
  InvestigationStep,
  ConflictItem,
  EvidenceItem,
  ChainNode,
  ChainEdge,
  PolicyAnalysis,
} from '../../types';

// ─── Provider selection ───────────────────────────────────────────────────────

function getModel() {
  const provider = process.env.AI_PROVIDER || 'openai';
  const modelName = process.env.AI_MODEL || 'gpt-4o';

  if (provider === 'anthropic') {
    return anthropic(modelName as Parameters<typeof anthropic>[0]);
  }
  if (provider === 'google') {
    return google(modelName as Parameters<typeof google>[0]);
  }
  // Default to OpenAI
  return openai(modelName as Parameters<typeof openai>[0]);
}

// ─── Step event emitter ──────────────────────────────────────────────────────

export type StepCallback = (step: InvestigationStep) => void;

function makeStep(index: number, label: string): InvestigationStep {
  return {
    stepIndex: index,
    stepId: `step-${index}`,
    label,
    status: 'running',
    timestamp: new Date().toISOString(),
  };
}

function completeStep(step: InvestigationStep, detail?: string): InvestigationStep {
  return {
    ...step,
    status: 'complete',
    detail,
    durationMs: Date.now() - new Date(step.timestamp).getTime(),
  };
}

function errorStep(step: InvestigationStep, error: string): InvestigationStep {
  return { ...step, status: 'error', detail: error };
}

// ─── Conflict detection ──────────────────────────────────────────────────────

function detectPolicyConflicts(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  allPolicies: any[],
  service: string,
  environment: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  configurations: any[]
): ConflictItem[] {
  const conflicts: ConflictItem[] = [];

  // Group policies by policyId
  const policyGroups: Record<string, typeof allPolicies> = {};
  for (const p of allPolicies) {
    if (!policyGroups[p.policyId]) policyGroups[p.policyId] = [];
    policyGroups[p.policyId].push(p);
  }

  for (const [, versions] of Object.entries(policyGroups)) {
    if (versions.length < 2) continue;
    const current = versions.find((v) => v.isCurrentVersion);
    const historical = versions.find((v) => !v.isCurrentVersion);

    if (!current || !historical) continue;

    // Check if the historical policy has different requirements
    const currentReq = current.requirement?.toLowerCase() || '';
    const historicalReq = historical.requirement?.toLowerCase() || '';

    const currentForbidsPublic =
      currentReq.includes('not') || currentReq.includes('prohibit') || currentReq.includes('restrict');
    const historicalAllowsPublic =
      historicalReq.includes('allow') || historicalReq.includes('permit') || historicalReq.includes('public');

    if (currentForbidsPublic && historicalAllowsPublic) {
      conflicts.push({
        type: 'policy_version',
        description: `Policy "${current.name}" has conflicting requirements across versions.`,
        sourceA: `${current.name} v${current.version} (CURRENT, effective ${current.effectiveFrom}): ${current.requirement}`,
        sourceB: `${historical.name} v${historical.version} (HISTORICAL, effective ${historical.effectiveFrom}): ${historical.requirement}`,
        recommendation:
          'Verify whether any legacy exceptions are still authorized. Current policy prohibits the configuration, but historical documentation permitted it.',
        severity: 'high',
      });
    }
  }

  // Check for config drift — does observed config match legacy policy?
  const nonCompliantConfigs = configurations.filter((c) => c.status === 'non_compliant');
  for (const config of nonCompliantConfigs) {
    // Check if any historical policy might have allowed this
    const legacyPolicies = allPolicies.filter((p) => !p.isCurrentVersion);
    const potentialLegacyMatch = legacyPolicies.some((p) => {
      const req = p.requirement?.toLowerCase() || '';
      return req.includes('allow') || req.includes('permit');
    });

    if (potentialLegacyMatch) {
      conflicts.push({
        type: 'config_drift',
        description: `Configuration "${config.setting}" appears consistent with a superseded policy but violates the current policy.`,
        sourceA: `Current configuration: ${config.setting} = ${config.observedValue}`,
        sourceB: `Expected per current policy: ${config.expectedValue}`,
        recommendation:
          'This may indicate security drift — the configuration may not have been updated when the policy changed. Verify the change window and update the configuration.',
        severity: 'high',
      });
    }
  }

  return conflicts;
}

// ─── Evidence chain builder ──────────────────────────────────────────────────

function buildEvidenceChain(data: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  finding: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  asset: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dataAssets: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controls: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  threats: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  configurations: any[];
}): { nodes: ChainNode[]; edges: ChainEdge[] } {
  const nodes: ChainNode[] = [];
  const edges: ChainEdge[] = [];

  // Node: Finding
  const findingNode: ChainNode = {
    id: 'finding',
    type: 'finding',
    label: data.finding.title,
    sublabel: data.finding.findingId,
    severity: data.finding.severity,
    data: {
      observedCondition: data.finding.observedCondition,
      potentialImpact: data.finding.potentialImpact,
    },
  };
  nodes.push(findingNode);

  // Node: Asset
  if (data.asset) {
    const assetNode: ChainNode = {
      id: 'asset',
      type: 'asset',
      label: data.asset.name,
      sublabel: `${data.asset.service} · ${data.asset.provider?.toUpperCase()}`,
      severity: data.asset.sensitivity === 'restricted' ? 'critical' : 'medium',
      data: {
        environment: data.asset.environment,
        sensitivity: data.asset.sensitivity,
        owner: data.asset.owner,
        region: data.asset.region,
      },
    };
    nodes.push(assetNode);
    edges.push({ from: 'finding', to: 'asset', label: 'affects' });

    // Node: Environment
    const envNode: ChainNode = {
      id: 'environment',
      type: 'environment',
      label: data.asset.environment?.toUpperCase() || 'UNKNOWN',
      sublabel: 'Environment classification',
      severity: data.asset.environment === 'production' ? 'critical' : 'medium',
    };
    nodes.push(envNode);
    edges.push({ from: 'asset', to: 'environment', label: 'runs in' });
  }

  // Nodes: Data Assets
  if (data.dataAssets.length > 0) {
    const primaryData = data.dataAssets[0];
    const dataNode: ChainNode = {
      id: 'data-0',
      type: 'data',
      label: primaryData.name,
      sublabel: `Classification: ${primaryData.classification?.toUpperCase()}`,
      severity: primaryData.classification === 'restricted' ? 'critical' : 'high',
      data: {
        contains: primaryData.contains,
        regulatoryScope: primaryData.regulatoryScope,
        estimatedRecordCount: primaryData.estimatedRecordCount,
      },
    };
    nodes.push(dataNode);
    edges.push({ from: 'asset', to: 'data-0', label: 'stores' });
  }

  // Node: Control
  if (data.controls.length > 0) {
    const primaryControl = data.controls[0];
    const controlNode: ChainNode = {
      id: 'control-0',
      type: 'control',
      label: primaryControl.name,
      sublabel: `${primaryControl.framework} · ${primaryControl.controlId}`,
      severity: primaryControl.severity || 'high',
      data: {
        requirements: primaryControl.requirements,
        framework: primaryControl.framework,
      },
    };
    nodes.push(controlNode);
    edges.push({ from: 'data-0', to: 'control-0', label: 'governed by' });
  }

  // Node: Threat
  if (data.threats.length > 0) {
    const primaryThreat = data.threats[0];
    const threatNode: ChainNode = {
      id: 'threat-0',
      type: 'threat',
      label: `${primaryThreat.techniqueId}`,
      sublabel: primaryThreat.name,
      severity: primaryThreat.severity || 'high',
      data: {
        tactics: primaryThreat.tactics,
        cloudContext: primaryThreat.cloudContext,
        externalUrl: primaryThreat.externalUrl,
      },
    };
    nodes.push(threatNode);
    edges.push({ from: 'control-0', to: 'threat-0', label: 'threatened by' });
  }

  // Node: Impact
  const impactNode: ChainNode = {
    id: 'impact',
    type: 'impact',
    label: 'Potential Data Exposure',
    sublabel: 'Unauthenticated access possible',
    severity: 'critical',
    data: {
      description:
        'An unauthenticated external party may retrieve objects from this storage location, potentially accessing sensitive customer data.',
    },
  };
  nodes.push(impactNode);
  edges.push({ from: 'threat-0', to: 'impact', label: 'enables' });

  // Node: Remediation
  const remediationNode: ChainNode = {
    id: 'remediation',
    type: 'remediation',
    label: 'Enable Block Public Access',
    sublabel: 'Proposed remediation · Human approval required',
    severity: 'info',
  };
  nodes.push(remediationNode);
  edges.push({ from: 'impact', to: 'remediation', label: 'resolved by' });

  return { nodes, edges };
}

// ─── Evidence builder ─────────────────────────────────────────────────────────

function buildEvidence(data: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  configurations: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  asset: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dataAssets: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  currentPolicies: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  threats: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controls: any[];
}): EvidenceItem[] {
  const evidence: EvidenceItem[] = [];

  // Configuration evidence
  for (const config of data.configurations) {
    evidence.push({
      type: 'configuration',
      label: `Configuration: ${config.setting}`,
      value: `Observed: ${config.observedValue} (Expected: ${config.expectedValue ?? 'N/A'})`,
      sourceId: config.source?._id,
      sourceTitle: config.source?.title,
      sourceUrl: config.source?.url,
      sourceVersion: config.source?.version,
      sourceDate: config.source?.publicationDate,
      confidence: 'high',
    });
  }

  // Asset metadata evidence
  if (data.asset) {
    evidence.push({
      type: 'asset_metadata',
      label: `Asset: ${data.asset.name}`,
      value: `Environment: ${data.asset.environment} | Service: ${data.asset.service} | Sensitivity: ${data.asset.sensitivity}`,
      sourceId: data.asset.source?._id,
      sourceTitle: data.asset.source?.title,
      confidence: 'high',
    });
  }

  // Data asset evidence
  for (const da of data.dataAssets) {
    evidence.push({
      type: 'data_classification',
      label: `Data Asset: ${da.name}`,
      value: `Classification: ${da.classification} | Contains: ${(da.contains || []).join(', ')} | Regulatory: ${(da.regulatoryScope || []).join(', ') || 'N/A'}`,
      confidence: 'high',
    });
  }

  // Policy evidence
  for (const p of data.currentPolicies.slice(0, 2)) {
    evidence.push({
      type: 'policy',
      label: `Policy: ${p.name} v${p.version}`,
      value: `${p.isCurrentVersion ? '[CURRENT] ' : '[HISTORICAL] '}${p.requirement}`,
      sourceId: p.source?._id,
      sourceTitle: p.source?.title,
      sourceUrl: p.source?.url,
      sourceVersion: p.version,
      sourceDate: p.effectiveFrom,
      confidence: 'high',
    });
  }

  // Threat intelligence evidence
  for (const t of data.threats.slice(0, 2)) {
    evidence.push({
      type: 'threat_intel',
      label: `Threat: ${t.techniqueId} — ${t.name}`,
      value: t.description?.slice(0, 200) + (t.description?.length > 200 ? '...' : ''),
      sourceId: t.source?._id,
      sourceTitle: t.source?.title,
      sourceUrl: t.externalUrl || t.source?.url,
      sourceVersion: t.source?.version,
      confidence: 'high',
    });
  }

  // Security control evidence
  for (const c of data.controls.slice(0, 2)) {
    evidence.push({
      type: 'control',
      label: `Control: ${c.controlId} — ${c.name}`,
      value: `Framework: ${c.framework} | ${c.description?.slice(0, 150)}`,
      sourceId: c.source?._id,
      sourceTitle: c.source?.title,
      sourceVersion: c.source?.version || c.version,
      confidence: 'high',
    });
  }

  return evidence;
}

// ─── Policy analysis ─────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildPolicyAnalysis(currentPolicies: any[], allPolicies: any[], configurations: any[]): PolicyAnalysis {
  const currentPolicy = currentPolicies.find((p) => p.isCurrentVersion) || currentPolicies[0];
  const historicalPolicies = allPolicies.filter((p) => !p.isCurrentVersion);

  const nonCompliantConfigs = configurations.filter((c) => c.status === 'non_compliant');

  const currentPolicyStatus: 'violated' | 'compliant' | 'unknown' =
    nonCompliantConfigs.length > 0 ? 'violated' : configurations.length > 0 ? 'compliant' : 'unknown';

  const driftDetected =
    historicalPolicies.length > 0 &&
    nonCompliantConfigs.length > 0;

  const conflictsDetected =
    historicalPolicies.some((hp) => {
      const req = hp.requirement?.toLowerCase() || '';
      return req.includes('allow') || req.includes('permit');
    }) && currentPolicyStatus === 'violated';

  return {
    currentPolicyId: currentPolicy?.policyId || 'unknown',
    currentPolicyName: currentPolicy?.name || 'Unknown Policy',
    currentPolicyVersion: currentPolicy?.version || '?',
    currentPolicyStatus,
    historicalPolicies: historicalPolicies.map((p) => ({
      policyId: p.policyId,
      name: p.name,
      version: p.version,
      status: 'compliant' as const, // historical policy was compliant with old config
      effectiveTo: p.effectiveTo,
    })),
    driftDetected,
    driftDescription: driftDetected
      ? `The current configuration matches the behavior expected under a superseded policy (${historicalPolicies[0]?.name} v${historicalPolicies[0]?.version}) but violates the current policy (${currentPolicy?.name} v${currentPolicy?.version}).`
      : undefined,
    conflictsDetected,
  };
}

// ─── Structured AI synthesis (Zod-validated) ─────────────────────────────────

const synthSchema = z.object({
  reasoningSummary: z.string().describe('A concise 2–3 sentence explanation of the finding, its significance, and why it matters from a security perspective. Do not claim live AWS access. Speak as an investigator reviewing structured evidence.'),
  nextChecks: z.array(z.string()).describe('4–6 specific, actionable investigation steps a security engineer should perform next.'),
  observations: z.array(z.string()).describe('3–5 factual observations derived from the structured evidence.'),
  limitations: z.array(z.string()).describe('1–3 limitations of this analysis (e.g., synthetic data, no live access).'),
});

async function synthesizeWithAI(data: {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  finding: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  asset: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  dataAssets: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  policies: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  threats: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  controls: any[];
  conflicts: ConflictItem[];
  policyAnalysis: PolicyAnalysis;
}) {
  const structuredContext = `
FINDING: ${data.finding.title}
ID: ${data.finding.findingId}
SEVERITY: ${data.finding.severity}
OBSERVED CONDITION: ${data.finding.observedCondition}
POTENTIAL IMPACT: ${data.finding.potentialImpact}

AFFECTED ASSET:
- Name: ${data.asset?.name}
- Service: ${data.asset?.service}
- Environment: ${data.asset?.environment}
- Sensitivity: ${data.asset?.sensitivity}
- Owner: ${data.asset?.owner}

DATA ASSETS:
${data.dataAssets.map((d) => `- ${d.name}: classification=${d.classification}, contains=[${(d.contains || []).join(', ')}], regulatory=[${(d.regulatoryScope || []).join(', ')}]`).join('\n')}

CURRENT POLICY STATUS: ${data.policyAnalysis.currentPolicyStatus.toUpperCase()}
DRIFT DETECTED: ${data.policyAnalysis.driftDetected}
${data.policyAnalysis.driftDescription ? `DRIFT: ${data.policyAnalysis.driftDescription}` : ''}

CONFLICTS DETECTED: ${data.policyAnalysis.conflictsDetected}
${data.conflicts.map((c) => `CONFLICT [${c.type}]: ${c.description}`).join('\n')}

THREAT TECHNIQUES:
${data.threats.map((t) => `- ${t.techniqueId} (${t.name}): ${t.cloudContext}`).join('\n')}

SECURITY CONTROLS APPLICABLE:
${data.controls.map((c) => `- [${c.controlId}] ${c.name} (${c.framework}): ${c.remediationGuidance}`).join('\n')}

IMPORTANT: This is analysis of synthetic demonstration data. Do not claim live AWS access or real infrastructure scanning.
`;

  const result = await generateObject({
    model: getModel(),
    schema: synthSchema,
    prompt: `You are TraceGuard, an evidence-first AI security investigator. 
    
Using ONLY the structured evidence provided below, produce a concise investigation output.

Do NOT fabricate additional security findings.
Do NOT claim to have scanned real infrastructure.
DO explain the relationships between the structured facts.
DO identify what is significant and why it matters.

STRUCTURED EVIDENCE:
${structuredContext}`,
  });

  return result.object;
}

// ─── Main Investigation Pipeline ─────────────────────────────────────────────

export async function runInvestigation(
  findingId: string,
  onStep?: StepCallback
): Promise<InvestigationResult> {
  const investigationId = `INV-${Date.now()}`;
  const totalSteps = 15;

  const emit = (step: InvestigationStep) => {
    if (onStep) onStep(step);
  };

  // Step 1: Parse finding
  const s1 = makeStep(1, 'Parsing finding');
  emit(s1);
  const finding = await getFindingById(findingId);
  if (!finding) throw new Error(`Finding ${findingId} not found in knowledge base`);
  emit(completeStep(s1, `Finding: ${finding.title}`));

  // Step 2: Identify affected asset
  const s2 = makeStep(2, 'Identifying affected asset');
  emit(s2);
  const asset = finding.affectedAsset || null;
  const assetId = asset?.assetId || '';
  emit(completeStep(s2, asset ? `Asset: ${asset.name} (${asset.service})` : 'Asset not found'));

  // Step 3: Retrieve asset configurations
  const s3 = makeStep(3, 'Retrieving asset configurations');
  emit(s3);
  const configurations = assetId ? await getConfigurationsForAsset(assetId) : [];
  emit(completeStep(s3, `${configurations.length} configuration(s) retrieved`));

  // Step 4: Retrieve data assets stored in this asset
  const s4 = makeStep(4, 'Retrieving data classification');
  emit(s4);
  const dataAssets = assetId ? await getDataAssetsForAsset(assetId) : [];
  emit(completeStep(s4, `${dataAssets.length} data asset(s) found`));

  // Step 5: Retrieve applicable policies (current)
  const s5 = makeStep(5, 'Retrieving applicable security policies');
  emit(s5);
  const currentPolicies = asset
    ? await getPoliciesForService(asset.service, asset.environment)
    : [];
  emit(completeStep(s5, `${currentPolicies.length} applicable policy/policies`));

  // Step 6: Retrieve all policy versions (for drift analysis)
  const s6 = makeStep(6, 'Retrieving historical policy versions');
  emit(s6);
  const allPolicies = await getAllPolicies();
  const historicalPolicies = allPolicies.filter(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (p: any) => !p.isCurrentVersion && currentPolicies.some((cp: any) => cp.policyId === p.policyId)
  );
  emit(completeStep(s6, `${historicalPolicies.length} historical version(s) found`));

  // Step 7: Retrieve applicable security controls
  const s7 = makeStep(7, 'Retrieving applicable security controls');
  emit(s7);
  const controls = asset ? await getControlsForService(asset.service) : [];
  emit(completeStep(s7, `${controls.length} control(s) applicable`));

  // Step 8: Retrieve relevant threat techniques
  const s8 = makeStep(8, 'Retrieving threat intelligence');
  emit(s8);
  const serviceThreats = asset ? await getThreatTechniquesForService(asset.service) : [];

  // Also search by conditions derived from configurations
  const nonCompliantConditions = configurations
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .filter((c: any) => c.status === 'non_compliant')
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .map((c: any) => c.setting);
  const conditionThreats =
    nonCompliantConditions.length > 0
      ? await getThreatTechniquesByCondition(nonCompliantConditions)
      : [];

  // Merge and deduplicate
  const allThreats = [...serviceThreats];
  for (const t of conditionThreats) {
    if (!allThreats.find((at) => at.techniqueId === t.techniqueId)) {
      allThreats.push(t);
    }
  }
  emit(completeStep(s8, `${allThreats.length} threat technique(s) identified`));

  // Step 9: Check source dates and versions
  const s9 = makeStep(9, 'Validating source currency');
  emit(s9);
  const staleSources = [
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ...controls.map((c: any) => c.source),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ...allThreats.map((t: any) => t.source),
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    ...currentPolicies.map((p: any) => p.source),
  ]
    .filter(Boolean)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .filter((s: any) => s.status === 'deprecated' || s.status === 'historical');
  emit(
    completeStep(
      s9,
      staleSources.length > 0
        ? `⚠️ ${staleSources.length} stale/deprecated source(s) detected`
        : 'All sources current'
    )
  );

  // Step 10: Detect contradictions / conflicts
  const s10 = makeStep(10, 'Detecting policy conflicts');
  emit(s10);
  const conflicts = detectPolicyConflicts(allPolicies, asset?.service, asset?.environment, configurations);
  emit(
    completeStep(
      s10,
      conflicts.length > 0
        ? `⚠️ ${conflicts.length} conflict(s) detected`
        : 'No conflicts detected'
    )
  );

  // Step 11: Build policy analysis
  const s11 = makeStep(11, 'Analyzing policy compliance and drift');
  emit(s11);
  const policyAnalysis = buildPolicyAnalysis(currentPolicies, allPolicies, configurations);
  emit(
    completeStep(
      s11,
      policyAnalysis.driftDetected
        ? '⚠️ Security drift detected'
        : `Policy status: ${policyAnalysis.currentPolicyStatus}`
    )
  );

  // Step 12: Build evidence chain
  const s12 = makeStep(12, 'Constructing evidence chain');
  emit(s12);
  const { nodes: chainNodes, edges: chainEdges } = buildEvidenceChain({
    finding,
    asset,
    dataAssets,
    controls,
    threats: allThreats,
    configurations,
  });
  const evidence = buildEvidence({
    configurations,
    asset,
    dataAssets,
    currentPolicies,
    threats: allThreats,
    controls,
  });
  emit(completeStep(s12, `${chainNodes.length} nodes, ${evidence.length} evidence items`));

  // Step 13: Retrieve pre-built remediation
  const s13 = makeStep(13, 'Retrieving remediation guidance');
  emit(s13);
  const remediationDoc = await getRemediationForFinding(findingId);
  emit(
    completeStep(
      s13,
      remediationDoc ? `Remediation: ${remediationDoc.title}` : 'No pre-built remediation found'
    )
  );

  // Step 14: AI synthesis — reasoning summary + next checks
  const s14 = makeStep(14, 'Synthesizing investigation narrative');
  emit(s14);
  const synthesis = await synthesizeWithAI({
    finding,
    asset,
    dataAssets,
    policies: currentPolicies,
    threats: allThreats,
    controls,
    conflicts,
    policyAnalysis,
  });
  emit(completeStep(s14, 'Narrative complete'));

  // Step 15: Compile and persist investigation
  const s15 = makeStep(15, 'Compiling investigation report');
  emit(s15);

  const result: InvestigationResult = {
    investigationId,
    finding,
    status: 'analysis_complete',
    observations: synthesis.observations,
    affectedAssets: asset ? [asset] : [],
    dataExposure: dataAssets,
    securityControls: controls,
    threatTechniques: allThreats,
    policyAnalysis,
    conflicts,
    evidence,
    investigationChain: chainNodes,
    chainEdges,
    nextChecks: synthesis.nextChecks,
    remediation: remediationDoc,
    operationalImpact: remediationDoc?.operationalImpact || 'No operational impact assessment available.',
    confidence: {
      overall: dataAssets.length > 0 && controls.length > 0 ? 'high' : 'medium',
      dataExposure: dataAssets.length > 0 ? 'high' : 'low',
      policyViolation: policyAnalysis.currentPolicyStatus === 'violated' ? 'high' : 'medium',
    },
    limitations: synthesis.limitations,
    reasoningSummary: synthesis.reasoningSummary,
    createdAt: new Date().toISOString(),
  };

  // Persist to Sanity (best effort — don't fail the investigation if this fails)
  try {
    await createInvestigationDocument({
      investigationId,
      finding: { _type: 'reference', _ref: finding._id },
      status: 'analysis_complete',
      reasoningSummary: result.reasoningSummary,
      evidence: result.evidence.map((e) => ({
        type: e.type,
        label: e.label,
        value: e.value,
        sourceId: e.sourceId || '',
        sourceTitle: e.sourceTitle || '',
        sourceUrl: e.sourceUrl || null,
        sourceVersion: e.sourceVersion || '',
        confidence: e.confidence,
      })),
      claims: [
        {
          statement: `This ${finding.severity} severity finding affects a ${asset?.environment} asset.`,
          supportedBy: ['Asset metadata', 'Configuration snapshot'],
          confidence: 'high',
        },
      ],
      conflicts: result.conflicts,
      nextChecks: result.nextChecks,
    });
  } catch (err) {
    console.error('[TraceGuard] Failed to persist investigation to Sanity:', err);
  }

  emit(completeStep(s15, `Investigation ${investigationId} complete`));

  return result;
}
