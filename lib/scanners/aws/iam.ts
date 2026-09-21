import { IAMClient, GetAccountSummaryCommand, GetAccountPasswordPolicyCommand, ListUsersCommand, ListAccessKeysCommand, GetLoginProfileCommand, ListMFADevicesCommand, ListPoliciesCommand, GetPolicyVersionCommand } from '@aws-sdk/client-iam';
import type { ScanJob, ScanFinding, AWSCredentials } from '../types';
import { AWS_RULES } from '../rules/aws';

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as AWSCredentials;
  const region = 'us-east-1';
  const client = new IAMClient({
    region,
    credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, ...(creds.sessionToken && { sessionToken: creds.sessionToken }) }
  });

  try {
    const sumResponse = await client.send(new GetAccountSummaryCommand({}));
    const summaryMap = sumResponse.SummaryMap;
    if (summaryMap && (summaryMap['AccountAccessKeysPresent'] ?? 0) > 0) {
      const rule = AWS_RULES['iam-root-access-key'];
      if (rule) {
        findings.push({
          id: `${rule.id}::root`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
          resourceId: 'root', region, accountId: job.cloudAccountId, provider: 'aws',
          observedCondition: `Root user has access keys present.`,
          potentialImpact: `Compromise of root keys can lead to full account takeover.`,
          remediation: rule.getRemediation('root', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
        });
      }
    }
  } catch (err: any) { console.error(`[AWS:IAM:Summary]`, err.message); }

  try {
    const pwResponse = await client.send(new GetAccountPasswordPolicyCommand({}));
    const policy = pwResponse.PasswordPolicy;
    if (!policy || (policy.MinimumPasswordLength || 0) < 14 || !policy.RequireSymbols || !policy.RequireNumbers || !policy.RequireUppercaseCharacters || !policy.RequireLowercaseCharacters) {
      const rule = AWS_RULES['iam-password-policy-weak'];
      if (rule) {
        findings.push({
          id: `${rule.id}::account`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
          resourceId: 'account-password-policy', region, accountId: job.cloudAccountId, provider: 'aws',
          observedCondition: `Password policy is weak (length < 14 or lacks complexity).`,
          potentialImpact: `Passwords are easier to crack or guess.`,
          remediation: rule.getRemediation('account-password-policy', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
        });
      }
    }
  } catch (err: any) {
    if (err.name === 'NoSuchEntityException') {
      const rule = AWS_RULES['iam-password-policy-weak'];
      if (rule) {
        findings.push({
          id: `${rule.id}::account`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
          resourceId: 'account-password-policy', region, accountId: job.cloudAccountId, provider: 'aws',
          observedCondition: `No password policy found.`,
          potentialImpact: `Weak passwords can be used.`,
          remediation: rule.getRemediation('account-password-policy', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
        });
      }
    } else { console.error(`[AWS:IAM:PasswordPolicy]`, err.message); }
  }

  try {
    const usersResp = await client.send(new ListUsersCommand({}));
    const users = usersResp.Users || [];
    for (const user of users) {
      if (!user.UserName) continue;
      const resourceId = user.UserName;

      try {
        const keysResp = await client.send(new ListAccessKeysCommand({ UserName: resourceId }));
        for (const key of keysResp.AccessKeyMetadata || []) {
          if (key.CreateDate && (Date.now() - key.CreateDate.getTime() > 90 * 24 * 60 * 60 * 1000)) {
            const rule = AWS_RULES['iam-access-key-old'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${key.AccessKeyId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: key.AccessKeyId || '', region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `Access key ${key.AccessKeyId} for user ${resourceId} is older than 90 days.`,
                potentialImpact: `Old keys are more likely to be compromised.`,
                remediation: rule.getRemediation(key.AccessKeyId || '', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        }
      } catch (err: any) { console.error(`[AWS:IAM:AccessKeys:${resourceId}]`, err.message); }

      let hasConsole = false;
      try {
        await client.send(new GetLoginProfileCommand({ UserName: resourceId }));
        hasConsole = true;
      } catch (err: any) { if (err.name !== 'NoSuchEntityException') { console.error(`[AWS:IAM:LoginProfile:${resourceId}]`, err.message); } }

      if (hasConsole) {
        try {
          const mfaResp = await client.send(new ListMFADevicesCommand({ UserName: resourceId }));
          if (!mfaResp.MFADevices || mfaResp.MFADevices.length === 0) {
            const rule = AWS_RULES['iam-mfa-disabled'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${resourceId}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId, region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `User ${resourceId} has console access but no MFA enabled.`,
                potentialImpact: `Compromised passwords allow full console access.`,
                remediation: rule.getRemediation(resourceId, region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        } catch (err: any) { console.error(`[AWS:IAM:MFA:${resourceId}]`, err.message); }
      }
    }
  } catch (err: any) { console.error(`[AWS:IAM:ListUsers]`, err.message); }

  try {
    const polResp = await client.send(new ListPoliciesCommand({ Scope: 'Local' }));
    for (const policy of polResp.Policies || []) {
      if (!policy.Arn || !policy.DefaultVersionId) continue;
      try {
        const verResp = await client.send(new GetPolicyVersionCommand({ PolicyArn: policy.Arn, VersionId: policy.DefaultVersionId }));
        if (verResp.PolicyVersion && verResp.PolicyVersion.Document) {
          const docStr = decodeURIComponent(verResp.PolicyVersion.Document);
          const doc = JSON.parse(docStr);
          let hasWildcard = false;
          const statements = Array.isArray(doc.Statement) ? doc.Statement : [doc.Statement];
          for (const stmt of statements) {
            if (stmt.Effect === 'Allow') {
              if (stmt.Action === '*' || (Array.isArray(stmt.Action) && stmt.Action.includes('*'))) hasWildcard = true;
              if (stmt.Resource === '*' || (Array.isArray(stmt.Resource) && stmt.Resource.includes('*'))) hasWildcard = true;
            }
          }
          if (hasWildcard) {
            const rule = AWS_RULES['iam-wildcard-policy'];
            if (rule) {
              findings.push({
                id: `${rule.id}::${policy.PolicyName}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service,
                resourceId: policy.PolicyName || '', region, accountId: job.cloudAccountId, provider: 'aws',
                observedCondition: `Policy ${policy.PolicyName} uses wildcard Action or Resource.`,
                potentialImpact: `Grants excessive permissions.`,
                remediation: rule.getRemediation(policy.PolicyName || '', region, job.cloudAccountId), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString()
              });
            }
          }
        }
      } catch (err: any) { console.error(`[AWS:IAM:PolicyVersion:${policy.PolicyName}]`, err.message); }
    }
  } catch (err: any) { console.error(`[AWS:IAM:ListPolicies]`, err.message); }

  return findings;
}