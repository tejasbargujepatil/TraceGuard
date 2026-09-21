// GROQ Query Library for TraceGuard
// Structured queries that power the investigation agent's knowledge retrieval.

import { sanityClient } from './client';

// ─── Findings ────────────────────────────────────────────────────────────────

export async function getAllFindings() {
  return sanityClient.fetch(`
    *[_type == "finding"] | order(_createdAt desc) {
      _id,
      findingId,
      title,
      severity,
      category,
      status,
      observedCondition,
      potentialImpact,
      discoveredAt,
      affectedAsset-> {
        _id,
        name,
        assetId,
        provider,
        service,
        environment,
        sensitivity,
        owner,
        tags
      }
    }
  `);
}

export async function getFindingById(findingId: string) {
  return sanityClient.fetch(
    `*[_type == "finding" && findingId == $findingId][0] {
      _id,
      findingId,
      title,
      severity,
      category,
      status,
      observedCondition,
      evidence,
      potentialImpact,
      discoveredAt,
      affectedAsset-> {
        _id,
        _type,
        name,
        assetId,
        provider,
        service,
        environment,
        description,
        sensitivity,
        owner,
        tags,
        region,
        accountId,
        source-> {
          _id, title, organization, url, authority, publicationDate, version, sourceType, status
        }
      },
      relatedConfigurations[]-> {
        _id,
        setting,
        observedValue,
        expectedValue,
        status,
        observedAt,
        source-> {
          _id, title, organization, url, authority, publicationDate, version, sourceType, status
        }
      },
      relatedFindings[]-> {
        _id,
        findingId,
        title,
        severity,
        category,
        status
      }
    }`,
    { findingId }
  );
}

// ─── Assets ───────────────────────────────────────────────────────────────────

export async function getAssetById(assetId: string) {
  return sanityClient.fetch(
    `*[_type == "securityAsset" && assetId == $assetId][0] {
      _id, _type, name, assetId, provider, service, environment,
      description, sensitivity, owner, tags, region, accountId,
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { assetId }
  );
}

export async function getAssetByName(name: string) {
  return sanityClient.fetch(
    `*[_type == "securityAsset" && name == $name][0] {
      _id, _type, name, assetId, provider, service, environment,
      description, sensitivity, owner, tags, region, accountId,
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { name }
  );
}

// ─── Data Assets ─────────────────────────────────────────────────────────────

export async function getDataAssetsForAsset(assetId: string) {
  return sanityClient.fetch(
    `*[_type == "dataAsset" && storedIn->assetId == $assetId] {
      _id,
      name,
      classification,
      sensitivity,
      contains,
      owner,
      description,
      regulatoryScope,
      estimatedRecordCount,
      storedIn-> { _id, name, assetId, service, environment }
    }`,
    { assetId }
  );
}

// ─── Configurations ──────────────────────────────────────────────────────────

export async function getConfigurationsForAsset(assetId: string) {
  return sanityClient.fetch(
    `*[_type == "configuration" && asset->assetId == $assetId] {
      _id,
      setting,
      observedValue,
      expectedValue,
      status,
      observedAt,
      environment,
      notes,
      configPath,
      asset-> { _id, name, assetId, service, environment },
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { assetId }
  );
}

// ─── Policies ────────────────────────────────────────────────────────────────

export async function getCurrentPolicies(tags: string[] = []) {
  void tags; // tags filtering not needed — return all current policies
  return sanityClient.fetch(
    `*[_type == "policy" && isCurrentVersion == true] {
      _id, policyId, name, version, isCurrentVersion,
      requirement, appliesTo, effectiveFrom, effectiveTo,
      exceptions, notes, approvedBy,
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`
  );
}

export async function getAllPolicies() {
  return sanityClient.fetch(
    `*[_type == "policy"] | order(effectiveFrom desc) {
      _id, policyId, name, version, isCurrentVersion,
      requirement, appliesTo, effectiveFrom, effectiveTo,
      exceptions, notes, approvedBy,
      supersededBy-> { _id, policyId, name, version },
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`
  );
}

export async function getPoliciesForService(service: string, environment: string) {
  return sanityClient.fetch(
    `*[_type == "policy" && ($service in appliesTo || $environment in appliesTo || "all" in appliesTo)] | order(isCurrentVersion desc, effectiveFrom desc) {
      _id, policyId, name, version, isCurrentVersion,
      requirement, appliesTo, effectiveFrom, effectiveTo,
      exceptions, notes,
      supersededBy-> { _id, policyId, name, version },
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { service: service.toLowerCase(), environment: environment.toLowerCase() }
  );
}

// ─── Security Controls ───────────────────────────────────────────────────────

export async function getControlsForService(service: string) {
  return sanityClient.fetch(
    `*[_type == "securityControl" && $service in applicableServices] {
      _id, controlId, name, description, framework,
      requirements, applicableServices, remediationGuidance, version, severity,
      relevantThreatTechniques[]-> {
        _id, techniqueId, name, description, severity
      },
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { service }
  );
}

// ─── Threat Techniques ───────────────────────────────────────────────────────

export async function getThreatTechniquesForService(service: string) {
  return sanityClient.fetch(
    `*[_type == "threatTechnique" && $service in affectedServices] {
      _id, techniqueId, name, description, tactics,
      affectedServices, relevantConditions, cloudContext, severity,
      mitigations, externalUrl,
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { service }
  );
}

export async function getThreatTechniquesByCondition(conditions: string[]) {
  return sanityClient.fetch(
    `*[_type == "threatTechnique" && count(relevantConditions[@ in $conditions]) > 0] {
      _id, techniqueId, name, description, tactics,
      affectedServices, relevantConditions, cloudContext, severity,
      mitigations, externalUrl,
      source-> { _id, title, organization, url, authority, publicationDate, version, sourceType, status }
    }`,
    { conditions }
  );
}

// ─── Sources ─────────────────────────────────────────────────────────────────

export async function getSourcesByAuthority(authority: string) {
  return sanityClient.fetch(
    `*[_type == "source" && authority == $authority] | order(publicationDate desc) {
      _id, title, organization, url, authority,
      publicationDate, version, sourceType, retrievedAt, status, summary
    }`,
    { authority }
  );
}

// ─── Remediation ─────────────────────────────────────────────────────────────

export async function getRemediationForFinding(findingId: string) {
  return sanityClient.fetch(
    `*[_type == "remediation" && finding->findingId == $findingId][0] {
      _id,
      title,
      proposedChange,
      rationale,
      prerequisites,
      operationalImpact,
      risk,
      verificationSteps,
      requiredApproval,
      automationAvailable,
      finding-> { _id, findingId, title },
      affectedControls[]-> { _id, controlId, name, framework }
    }`,
    { findingId }
  );
}

// ─── Investigation ───────────────────────────────────────────────────────────

export async function getInvestigationForFinding(findingId: string) {
  return sanityClient.fetch(
    `*[_type == "investigation" && finding->findingId == $findingId] | order(_createdAt desc)[0] {
      _id,
      investigationId,
      status,
      reasoningSummary,
      evidence,
      claims,
      conflicts,
      nextChecks,
      approvalStatus,
      approvedBy,
      approvedAt,
      rejectionReason,
      createdAt,
      updatedAt,
      finding-> { _id, findingId, title, severity },
      remediation-> {
        _id, title, proposedChange, risk, operationalImpact, requiredApproval
      }
    }`,
    { findingId }
  );
}

export async function updateInvestigationStatus(
  investigationId: string,
  status: string,
  approvalData?: {
    approvedBy?: string;
    approvedAt?: string;
    rejectionReason?: string;
  }
) {
  return sanityClient
    .patch(investigationId)
    .set({
      status,
      approvalStatus: status === 'approved' ? 'approved' : status === 'rejected' ? 'rejected' : 'pending',
      updatedAt: new Date().toISOString(),
      ...approvalData,
    })
    .commit();
}

export async function createInvestigationDocument(data: Record<string, unknown>) {
  return sanityClient.create({
    _type: 'investigation',
    ...data,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });
}

// ─── Security Posture (Dashboard) ────────────────────────────────────────────

export async function getSecurityPosture() {
  const [findings, investigations, policies, sources] = await Promise.all([
    sanityClient.fetch(`{
      "total": count(*[_type == "finding"]),
      "critical": count(*[_type == "finding" && severity == "critical"]),
      "high": count(*[_type == "finding" && severity == "high"]),
      "medium": count(*[_type == "finding" && severity == "medium"]),
      "low": count(*[_type == "finding" && severity == "low"]),
      "open": count(*[_type == "finding" && status == "open"]),
      "investigating": count(*[_type == "finding" && status == "investigating"])
    }`),
    sanityClient.fetch(`count(*[_type == "investigation" && status in ["investigating", "analysis_complete", "remediation_proposed", "pending_review"]])`),
    sanityClient.fetch(`count(*[_type == "policy"])`),
    sanityClient.fetch(`count(*[_type == "source"])`),
  ]);

  return {
    totalFindings: findings.total,
    criticalFindings: findings.critical,
    highFindings: findings.high,
    mediumFindings: findings.medium,
    lowFindings: findings.low,
    openFindings: findings.open,
    openInvestigations: investigations,
    totalPolicies: policies,
    evidenceSources: sources,
  };
}
