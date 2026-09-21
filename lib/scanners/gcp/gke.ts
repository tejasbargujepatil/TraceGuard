// lib/scanners/gcp/gke.ts — GKE cluster scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface GKECluster { name: string; location: string; masterAuthorizedNetworksConfig?: { enabled?: boolean; cidrBlocks?: { cidrBlock: string }[] }; workloadIdentityConfig?: { workloadPool?: string }; privateClusterConfig?: { enablePrivateEndpoint?: boolean } }
interface ClustersResponse { clusters?: GKECluster[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const data = await gcpFetch<ClustersResponse>(
      `https://container.googleapis.com/v1/projects/${project}/locations/-/clusters`, token
    );
    for (const cluster of data.clusters ?? []) {
      const id = cluster.name;
      const region = cluster.location ?? 'global';

      // Public control plane
      const authNetworks = cluster.masterAuthorizedNetworksConfig;
      const isPrivateEndpoint = cluster.privateClusterConfig?.enablePrivateEndpoint === true;
      if (!isPrivateEndpoint && (!authNetworks?.enabled || (authNetworks.cidrBlocks ?? []).some(c => c.cidrBlock === '0.0.0.0/0'))) {
        const rule = GCP_RULES['gke-public-endpoint'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region, accountId: project, provider: 'gcp', observedCondition: `GKE cluster ${id} has a publicly accessible control plane without master authorized network restrictions.`, potentialImpact: 'The Kubernetes API server is reachable from the internet. An attacker can probe for unauthenticated endpoints, exploit CVEs, or perform credential stuffing against the API.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
      }

      // Workload Identity
      if (!cluster.workloadIdentityConfig?.workloadPool) {
        const rule = GCP_RULES['gke-workload-identity-disabled'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region, accountId: project, provider: 'gcp', observedCondition: `GKE cluster ${id} does not have Workload Identity enabled.`, potentialImpact: 'Without Workload Identity, pods may be using service account JSON keys stored as Kubernetes secrets, increasing credential exposure risk.', remediation: rule.getRemediation(id), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
      }
    }
  } catch (err) { console.error('[GKE]', (err as Error).message); }
  return findings;
}
