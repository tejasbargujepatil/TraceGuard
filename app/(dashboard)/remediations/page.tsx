// app/(dashboard)/remediations/page.tsx

import { sanityClient } from '@/lib/sanity/client';
import { Wrench, AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';

async function getRemediations() {
  return sanityClient.fetch(`
    *[_type == "remediation"] | order(_createdAt desc) {
      _id, title, proposedChange, rationale, operationalImpact,
      risk, verificationSteps, requiredApproval, automationAvailable,
      finding->{ findingId, title, severity }
    }
  `);
}

const riskBadge = {
  high: 'bg-red-950/50 border-red-900/30 text-red-400',
  medium: 'bg-yellow-950/50 border-yellow-900/30 text-yellow-400',
  low: 'bg-green-950/50 border-green-900/30 text-green-400',
};

export default async function RemediationsPage() {
  let remediations: any[] = [];
  try { remediations = await getRemediations(); } catch { /* not configured */ }

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <Wrench size={16} className="text-green-400" />
          <h1 className="text-base font-semibold text-slate-100">Remediations</h1>
          <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{remediations.length}</span>
        </div>
        <p className="text-xs text-slate-500 mt-1">Human approval required — AI proposes, security team approves</p>
      </div>
      <div className="p-6 space-y-4">
        {remediations.map((r: any) => (
          <div key={r._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4 text-xs">
            <div className="flex items-start gap-3 mb-3">
              <Wrench size={14} className="text-green-400 mt-0.5 shrink-0" />
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <h3 className="font-semibold text-slate-200">{r.title}</h3>
                  {r.risk && (
                    <span className={cn('px-1.5 py-0.5 rounded border text-[10px] font-medium', (riskBadge as any)[r.risk])}>
                      {r.risk.toUpperCase()} RISK
                    </span>
                  )}
                  {r.automationAvailable && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-purple-950/40 border border-purple-900/30 text-purple-400">
                      Automatable
                    </span>
                  )}
                </div>
                {r.finding && (
                  <a href={`/findings/${r.finding.findingId}`} className="text-blue-400 hover:text-blue-300 mb-2 block">
                    ↳ {r.finding.findingId}: {r.finding.title}
                  </a>
                )}
              </div>
            </div>
            <div className="space-y-2">
              <div>
                <div className="text-[10px] font-semibold text-slate-500 uppercase mb-1">Proposed Change</div>
                <div className="text-slate-300 leading-relaxed bg-slate-900/50 p-2 rounded whitespace-pre-line">{r.proposedChange}</div>
              </div>
              {r.operationalImpact && (
                <div className="p-2 rounded bg-orange-950/20 border border-orange-900/20">
                  <div className="flex items-center gap-1 text-orange-400 font-semibold mb-1 text-[10px] uppercase">
                    <AlertTriangle size={10} /> Operational Impact
                  </div>
                  <div className="text-orange-300/80 leading-relaxed">{r.operationalImpact}</div>
                </div>
              )}
              <div className="flex items-center gap-2 text-[11px] text-slate-500">
                <span>👤 Required approver: <span className="text-slate-300">{r.requiredApproval}</span></span>
              </div>
            </div>
          </div>
        ))}
        {remediations.length === 0 && (
          <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center text-slate-600 text-sm">
            Run <code className="font-mono bg-slate-800 px-1 rounded">npm run seed</code> to load remediations
          </div>
        )}
      </div>
    </div>
  );
}
