import { LambdaClient, ListFunctionsCommand } from '@aws-sdk/client-lambda';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

const DEPRECATED_RUNTIMES = ['nodejs14.x','nodejs12.x','nodejs10.x','python2.7','python3.6','python3.7','ruby2.5','java8','go1.x','dotnetcore2.1','dotnetcore3.1'];
const SECRET_REGEX = /(password|secret|key|token|api_key|apikey|pwd)/i;

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;

  for (const region of job.regions) {
    const client = new LambdaClient({
      region,
      credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
    });

    try {
      const resp = await client.send(new ListFunctionsCommand({}));
      for (const fn of resp.Functions || []) {
        const id = fn.FunctionName;
        if (!id) continue;

        if (fn.Runtime && DEPRECATED_RUNTIMES.includes(fn.Runtime)) {
          const rule = AWS_RULES['lambda-deprecated-runtime'];
          if (rule) {
            findings.push({
              id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
              resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
              observedCondition: `Lambda ${id} uses deprecated runtime ${fn.Runtime}.`,
              potentialImpact: `Deprecated runtimes do not receive security patches.`,
              remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
            });
          }
        }

        const envVars = fn.Environment?.Variables;
        if (envVars) {
          for (const key of Object.keys(envVars)) {
            if (SECRET_REGEX.test(key)) {
              const rule = AWS_RULES['lambda-env-secrets'];
              if (rule) {
                findings.push({
                  id: `${rule.id}::${id}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                  resourceId: id, region, accountId: job.cloudAccountId, provider: 'aws',
                  observedCondition: `Lambda ${id} has potential secrets in env variables (${key}).`,
                  potentialImpact: `Anyone with read access to the Lambda config can extract the secret.`,
                  remediation: rule.getRemediation(id, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
                });
              }
              break; // One finding per function is enough
            }
          }
        }
      }
    } catch (err: any) { console.error(`[AWS:Lambda:${region}]`, err.message); }
  }
  return findings;
}