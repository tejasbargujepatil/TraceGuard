// lib/scanners/gcp/compute.ts — GCE Compute Engine scanner
import type { ScanJob, ScanFinding, GCPCredentials } from '../types';
import { GCP_RULES } from '../rules/gcp';
import { getGCPAccessToken, gcpFetch } from './auth';

interface Instance { name: string; zone: string; networkInterfaces?: { accessConfigs?: { natIP?: string }[] }[]; metadata?: { items?: { key: string; value: string }[] } }
interface AggregatedInstances { items?: Record<string, { instances?: Instance[] }> }
interface Firewall { name: string; direction: string; allowed?: { IPProtocol: string; ports?: string[] }[]; sourceRanges?: string[] }

export async function scan(job: ScanJob): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];
  const creds = job.credentials as GCPCredentials;
  const project = creds.project_id;
  try {
    const token = await getGCPAccessToken(creds);

    // Instances
    const data = await gcpFetch<AggregatedInstances>(
      `https://compute.googleapis.com/compute/v1/projects/${project}/aggregated/instances`, token
    );
    for (const [, zoneData] of Object.entries(data.items ?? {})) {
      for (const instance of zoneData.instances ?? []) {
        const zone = instance.zone?.split('/').pop() ?? 'unknown';
        // External IP check
        const hasExternalIP = (instance.networkInterfaces ?? []).some(ni => (ni.accessConfigs ?? []).some(ac => !!ac.natIP));
        if (hasExternalIP) {
          const rule = GCP_RULES['gce-public-ip'];
          if (rule) findings.push({ id: `${rule.id}::${instance.name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: instance.name, region: zone, accountId: project, provider: 'gcp', observedCondition: `Instance ${instance.name} in zone ${zone} has an external (public) IP address assigned.`, potentialImpact: 'A public IP exposes the instance directly to internet-based attacks. Services on any port are reachable if firewall rules permit.', remediation: rule.getRemediation(instance.name), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
        }
        // OS Login check
        const items = instance.metadata?.items ?? [];
        const osLogin = items.find(i => i.key === 'enable-oslogin');
        if (!osLogin || osLogin.value !== 'TRUE') {
          const rule = GCP_RULES['gce-os-login-disabled'];
          if (rule) findings.push({ id: `${rule.id}::${instance.name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: instance.name, region: zone, accountId: project, provider: 'gcp', observedCondition: `Instance ${instance.name} does not have OS Login enabled via instance metadata.`, potentialImpact: 'Without OS Login, SSH access is managed via project-level SSH keys which are hard to revoke and audit.', remediation: rule.getRemediation(instance.name), compliance: rule.compliance, discoveredAt: new Date().toISOString() });
        }
      }
    }

    // Firewall rules
    const { items: firewalls = [] } = await gcpFetch<{ items?: Firewall[] }>(
      `https://compute.googleapis.com/compute/v1/projects/${project}/global/firewalls`, token
    );
    for (const fw of firewalls) {
      if (fw.direction !== 'INGRESS') continue;
      const openToAll = (fw.sourceRanges ?? []).some(r => r === '0.0.0.0/0' || r === '::/0');
      if (!openToAll) continue;
      const allowsSsh = (fw.allowed ?? []).some(a => (a.IPProtocol === 'tcp' || a.IPProtocol === 'all') && (!a.ports || a.ports.some(p => p === '22' || p.includes('-'))));
      if (allowsSsh) {
        const rule = GCP_RULES['gce-firewall-ssh-open'];
        if (rule) findings.push({ id: `${rule.id}::${fw.name}`, ruleId: rule.id, title: rule.title, severity: rule.severity, category: rule.category, service: rule.service, resourceId: fw.name, region: 'global', accountId: project, provider: 'gcp', observedCondition: `Firewall rule ${fw.name} allows SSH (port 22) from 0.0.0.0/0.`, potentialImpact: 'Any internet-connected machine can attempt SSH connections. Brute-force, credential stuffing, and zero-day SSH exploits are direct threats.', remediation: rule.getRemediation(fw.name), compliance: rule.compliance, mitre: rule.mitre, discoveredAt: new Date().toISOString() });
      }
    }
  } catch (err) { console.error('[GCE]', (err as Error).message); }
  return findings;
}
