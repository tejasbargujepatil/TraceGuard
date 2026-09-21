// lib/scanners/gcp/logging.ts — Cloud Logging / Audit Logs scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface LogSink { name: string; destination: string; filter?: string; writerIdentity?: string }
interface AuditConfig { service: string; auditLogConfigs?: { logType: string }[] }
interface IAMPolicyAudit { auditConfigs?: AuditConfig[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);

    // Check audit log configuration via IAM policy
    try {
      const policy = await gcpFetch<IAMPolicyAudit>(
        `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`, token
      );
      const auditConfigs = policy.auditConfigs ?? [];
      const allServicesConfig = auditConfigs.find(ac => ac.service === 'allServices');
      const hasAdminRead = allServicesConfig?.auditLogConfigs?.some(c => c.logType === 'ADMIN_READ');
      const hasDataRead = allServicesConfig?.auditLogConfigs?.some(c => c.logType === 'DATA_READ');
      const hasDataWrite = allServicesConfig?.auditLogConfigs?.some(c => c.logType === 'DATA_WRITE');

      if (!hasAdminRead || !hasDataRead || !hasDataWrite) {
        const rule = GCP_RULES['gcp-logging-admin-activity-disabled'];
        if (rule) findings.push({
          id: `${rule.id}::${project}`,
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          category: rule.category,
          service: rule.service,
          resourceId: project,
          region: 'global',
          accountId: project,
          provider: 'gcp',
          observedCondition: `Project ${project} is missing audit log types: ${[!hasAdminRead && 'ADMIN_READ', !hasDataRead && 'DATA_READ', !hasDataWrite && 'DATA_WRITE'].filter(Boolean).join(', ')}.`,
          potentialImpact: 'Without full audit logging, API calls that create, modify, or delete resources go unrecorded. Security incidents cannot be investigated, and compliance audits will fail.',
          remediation: rule.getRemediation(project),
          compliance: rule.compliance,
          discoveredAt: new Date().toISOString(),
        });
      }
    } catch (e) { console.error('[Logging:auditConfig]', (e as Error).message); }

    // Check log sinks exist
    try {
      const { sinks = [] } = await gcpFetch<{ sinks?: LogSink[] }>(
        `https://logging.googleapis.com/v2/projects/${project}/sinks`, token
      );
      if (sinks.length === 0) {
        findings.push({
          id: `gcp-logging-no-sinks::${project}`,
          ruleId: 'gcp-logging-no-sinks',
          title: 'No Cloud Logging Sinks Configured',
          severity: 'high',
          category: 'logging',
          service: 'Cloud Logging',
          resourceId: project,
          region: 'global',
          accountId: project,
          provider: 'gcp',
          observedCondition: `Project ${project} has no log sinks configured. Logs are retained for only 30 days by default.`,
          potentialImpact: 'Without log sinks, audit and application logs are deleted after the default retention period. Long-term forensic analysis and compliance requirements (PCI: 1 year, SOC 2: varies) cannot be met.',
          remediation: {
            summary: 'Create a log sink to BigQuery, GCS, or Pub/Sub for long-term log retention.',
            steps: ['Go to Logging → Log Router → Create sink', 'Select destination: Cloud Storage bucket or BigQuery dataset', 'Set filter to include _Default logs or all logs', 'Create the sink'],
            gcpCli: `gcloud logging sinks create all-logs-sink storage.googleapis.com/YOUR_LOG_BUCKET --log-filter="" --project=${project}`,
            estimatedEffort: 'hours',
            operationalImpact: 'none',
          },
          compliance: ['CIS GCP 2.2', 'NIST DE.CM-3', 'PCI DSS 10.7', 'SOC 2 CC7.2'],
          discoveredAt: new Date().toISOString(),
        });
      }
    } catch (e) { console.error('[Logging:sinks]', (e as Error).message); }
  } catch (err) { console.error('[Logging]', (err as Error).message); }
  return findings;
}
