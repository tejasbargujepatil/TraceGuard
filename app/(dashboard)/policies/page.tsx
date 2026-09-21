// app/(dashboard)/policies/page.tsx

import { sanityClient } from '@/lib/sanity/client';
import { FileText, CheckCircle2, Clock } from 'lucide-react';
import { cn } from '@/lib/utils';

async function getPolicies() {
  return sanityClient.fetch(`
    *[_type == "policy"] | order(isCurrentVersion desc, effectiveFrom desc) {
      _id, policyId, name, version, isCurrentVersion, requirement, appliesTo,
      effectiveFrom, effectiveTo, exceptions, notes, approvedBy,
      source->{ title, organization, url, status },
      supersededBy->{ name, version }
    }
  `);
}

export default async function PoliciesPage() {
  let policies: any[] = [];
  try { policies = await getPolicies(); } catch { /* Sanity not configured */ }

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <FileText size={16} className="text-yellow-400" />
          <h1 className="text-base font-semibold text-slate-100">Security Policies</h1>
          <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{policies.length} versions</span>
        </div>
        <p className="text-xs text-slate-500 mt-1">Version history enables conflict detection and security drift analysis</p>
      </div>
      <div className="p-6 space-y-3">
        {policies.map((p: any) => (
          <div
            key={p._id}
            style={{ backgroundColor: 'var(--bg-card)', borderColor: p.isCurrentVersion ? '#1e40af' : 'var(--border)' }}
            className={cn('rounded-lg border p-4 text-xs', p.isCurrentVersion && 'border-blue-800/50')}
          >
            <div className="flex items-start gap-3">
              <div className="shrink-0 mt-0.5">
                {p.isCurrentVersion
                  ? <CheckCircle2 size={15} className="text-green-400" />
                  : <Clock size={15} className="text-slate-600" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold border',
                    p.isCurrentVersion ? 'bg-green-950/50 border-green-900/30 text-green-400' : 'bg-yellow-950/40 border-yellow-900/20 text-yellow-600'
                  )}>
                    {p.isCurrentVersion ? '✅ CURRENT' : '🗄️ HISTORICAL'}
                  </span>
                  <span className="font-semibold text-slate-200">{p.name}</span>
                  <span className="text-slate-500">v{p.version}</span>
                  <span className="text-slate-600 font-mono">{p.policyId}</span>
                </div>
                <div className="text-slate-300 leading-relaxed mb-2 bg-slate-900/50 p-2 rounded">
                  {p.requirement}
                </div>
                <div className="flex gap-3 text-[11px] text-slate-500 flex-wrap">
                  <span>📅 Effective: {p.effectiveFrom}{p.effectiveTo ? ` → ${p.effectiveTo}` : ' → present'}</span>
                  {p.approvedBy && <span>👤 {p.approvedBy}</span>}
                </div>
                {p.appliesTo?.length > 0 && (
                  <div className="flex gap-1 mt-2 flex-wrap">
                    {p.appliesTo.map((tag: string) => (
                      <span key={tag} className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-400">{tag}</span>
                    ))}
                  </div>
                )}
                {p.notes && (
                  <div className="mt-2 pt-2 border-t border-slate-800 text-slate-500 italic leading-relaxed">{p.notes}</div>
                )}
                {p.exceptions?.length > 0 && (
                  <div className="mt-2">
                    <span className="text-yellow-500 font-medium">Exceptions: </span>
                    {p.exceptions.join('; ')}
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
        {policies.length === 0 && (
          <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center text-slate-600 text-sm">
            Run <code className="font-mono bg-slate-800 px-1 rounded">npm run seed</code> to load policies
          </div>
        )}
      </div>
    </div>
  );
}
