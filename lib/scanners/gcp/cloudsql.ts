// lib/scanners/gcp/cloudsql.ts — Cloud SQL scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface SQLInstance { name: string; region: string; settings?: { ipConfiguration?: { ipv4Enabled?: boolean; requireSsl?: boolean }; backupConfiguration?: { enabled?: boolean } } }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const { items: instances = [] } = await gcpFetch<{ items?: SQLInstance[] }>(
      `https://sqladmin.googleapis.com/sql/v1beta4/projects/${project}/instances`, token
    );
    for (const inst of instances) {
      const id = inst.name;
      const region = inst.region ?? 'global';
      const ip = inst.settings?.ipConfiguration;
      const backup = inst.settings?.backupConfiguration;

      if (ip?.ipv4Enabled === true) {
        const rule = GCP_RULES['cloudsql-public-ip'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region, accountId: project, provider: 'gcp', observedCondition: `Cloud SQL instance ${id} has a public IPv4 address enabled.`, potentialImpact: 'Public IP makes the database reachable from the internet. Even with authorized networks, it is a higher-risk configuration than private IP only.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
      }
      if (ip?.requireSsl === false || ip?.requireSsl === undefined) {
        const rule = GCP_RULES['cloudsql-ssl-not-required'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region, accountId: project, provider: 'gcp', observedCondition: `Cloud SQL instance ${id} does not require SSL for client connections.`, potentialImpact: 'Database credentials and query results may be transmitted in plaintext, vulnerable to network interception.', remediation: rule.getRemediation(id), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
      }
      if (!backup?.enabled) {
        const rule = GCP_RULES['cloudsql-backup-disabled'];
        if (rule) findings.push({ id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: id, region, accountId: project, provider: 'gcp', observedCondition: `Automated backups are disabled for Cloud SQL instance ${id}.`, potentialImpact: 'Data loss from accidental deletion, corruption, or ransomware cannot be recovered without backups.', remediation: rule.getRemediation(id), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
      }
    }
  } catch (err) { console.error('[CloudSQL]', (err as Error).message); }
  return findings;
}
