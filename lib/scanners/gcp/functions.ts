// lib/scanners/gcp/functions.ts — Cloud Functions scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { getGCPAccessToken, gcpFetch } from './auth';

const DEPRECATED_RUNTIMES = ['python37', 'python36', 'nodejs10', 'nodejs8', 'go111', 'go113', 'java11', 'dotnet3'];
const SECRET_PATTERN = /password|secret|api[_-]?key|token|pwd|credential/i;

interface CloudFunction { name: string; serviceConfig?: { environmentVariables?: Record<string, string>; service?: string }; buildConfig?: { runtime?: string }; environment?: string }
interface FunctionsResponse { functions?: CloudFunction[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);
    const data = await gcpFetch<FunctionsResponse>(
      `https://cloudfunctions.googleapis.com/v2/projects/${project}/locations/-/functions`, token
    );
    for (const fn of data.functions ?? []) {
      const shortName = fn.name?.split('/').pop() ?? fn.name;
      const region = fn.name?.split('/')[3] ?? 'unknown';
      const envVars = fn.serviceConfig?.environmentVariables ?? {};
      const runtime = fn.buildConfig?.runtime ?? '';

      // Secrets in env vars
      const suspectKeys = Object.keys(envVars).filter(k => SECRET_PATTERN.test(k));
      if (suspectKeys.length > 0) {
        findings.push({
          id: `gcp-function-env-secrets::${shortName}`,
          ruleId: 'gcp-function-env-secrets',
          title: 'Cloud Function Has Potential Secrets in Environment Variables',
          severity: 'critical',
          category: 'iam',
          service: 'Cloud Functions',
          resourceId: shortName,
          region,
          accountId: project,
          provider: 'gcp',
          observedCondition: `Function ${shortName} has environment variable keys that resemble secrets: ${suspectKeys.join(', ')}.`,
          potentialImpact: 'Plaintext secrets in environment variables are visible to anyone with function access and appear in logs. Leaked credentials provide persistent access to dependent services.',
          remediation: {
            summary: 'Move secrets to Secret Manager and fetch them at runtime.',
            steps: [
              'Create secrets in Secret Manager for each credential',
              'Grant the Cloud Function\'s service account secretmanager.secretAccessor role',
              `Remove the plaintext env vars from function ${shortName}`,
              'Update the function code to use the Secret Manager SDK or mount secrets as volumes',
            ],
            gcpCli: `gcloud functions deploy ${shortName} --remove-env-vars ${suspectKeys.join(',')} --region ${region}`,
            estimatedEffort: 'hours',
            operationalImpact: 'medium',
          },
          compliance: ['NIST PR.DS-2', 'PCI DSS 3.5', 'SOC 2 CC6.1'],
          mitre: ['T1552.001'],
          discoveredAt: new Date().toISOString(),
        });
      }

      // Deprecated runtime
      if (runtime && DEPRECATED_RUNTIMES.some(r => runtime.includes(r))) {
        findings.push({
          id: `gcp-function-deprecated-runtime::${shortName}`,
          ruleId: 'gcp-function-deprecated-runtime',
          title: 'Cloud Function Uses Deprecated Runtime',
          severity: 'high',
          category: 'compliance',
          service: 'Cloud Functions',
          resourceId: shortName,
          region,
          accountId: project,
          provider: 'gcp',
          observedCondition: `Function ${shortName} uses runtime ${runtime} which has reached end of life.`,
          potentialImpact: 'Deprecated runtimes no longer receive security patches. Known vulnerabilities in the runtime can be exploited to compromise the function.',
          remediation: {
            summary: 'Upgrade the Cloud Function to a supported runtime.',
            steps: [
              `Go to Cloud Functions → ${shortName} → Edit`,
              'Change Runtime to a supported version (e.g., python312, nodejs22, go122)',
              'Test the function after the upgrade',
              'Deploy the updated function',
            ],
            gcpCli: `gcloud functions deploy ${shortName} --runtime python312 --region ${region}`,
            estimatedEffort: 'hours',
            operationalImpact: 'medium',
          },
          compliance: ['AWS Well-Architected', 'NIST SI-2', 'SOC 2 CC7.1'],
          discoveredAt: new Date().toISOString(),
        });
      }
    }
  } catch (err) { console.error('[CloudFunctions]', (err as Error).message); }
  return findings;
}
