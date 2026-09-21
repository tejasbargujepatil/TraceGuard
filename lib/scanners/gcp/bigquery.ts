// lib/scanners/gcp/bigquery.ts — BigQuery scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface Dataset { datasetReference: { datasetId: string; projectId: string }; location?: string }
interface DatasetDetail { access?: { role?: string; specialGroup?: string; iamMember?: string }[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const { datasets = [] } = await gcpFetch<{ datasets?: Dataset[] }>(
      `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets`, token
    );
    for (const ds of datasets) {
      const id = ds.datasetReference.datasetId;
      try {
        const detail = await gcpFetch<DatasetDetail>(
          `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets/${id}`, token
        );
        const publicEntities = ['allUsers', 'allAuthenticatedUsers'];
        const isPublic = (detail.access ?? []).some(a => (a.specialGroup && publicEntities.includes(a.specialGroup)) || (a.iamMember && publicEntities.some(p => a.iamMember?.includes(p))));
        if (isPublic) {
          const rule = GCP_RULES['bigquery-dataset-public'];
          if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region: ds.location ?? 'global', accountId: project, provider: 'gcp', observedCondition: `BigQuery dataset ${id} grants read access to allUsers or allAuthenticatedUsers.`, potentialImpact: 'All tables, views, and query results in this dataset are readable by anyone on the internet, potentially exposing sensitive or regulated data.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
        }
      } catch (e) { console.error(`[BigQuery:${id}]`, (e as Error).message); }
    }
  } catch (err) { console.error('[BigQuery]', (err as Error).message); }
  return findings;
}
