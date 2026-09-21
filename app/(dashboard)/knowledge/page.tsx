// app/(dashboard)/knowledge/page.tsx — Knowledge browser

import { sanityClient } from '@/lib/sanity/client';
import { BookOpen, ExternalLink } from 'lucide-react';

async function getKnowledge() {
  const [sources, controls, threats, policies] = await Promise.all([
    sanityClient.fetch(`*[_type == "source"] | order(authority, publicationDate desc) { _id, title, organization, url, authority, publicationDate, version, status, summary }`),
    sanityClient.fetch(`*[_type == "securityControl"] | order(framework, controlId) { _id, controlId, name, framework, applicableServices, version }`),
    sanityClient.fetch(`*[_type == "threatTechnique"] | order(techniqueId) { _id, techniqueId, name, tactics, severity, externalUrl }`),
    sanityClient.fetch(`*[_type == "policy"] | order(isCurrentVersion desc, effectiveFrom desc) { _id, policyId, name, version, isCurrentVersion, effectiveFrom, effectiveTo }`),
  ]);
  return { sources, controls, threats, policies };
}

const authorityColors: Record<string, string> = {
  aws: 'bg-orange-950/50 border-orange-900/30 text-orange-400',
  mitre: 'bg-red-950/50 border-red-900/30 text-red-400',
  cis: 'bg-blue-950/50 border-blue-900/30 text-blue-400',
  nist: 'bg-purple-950/50 border-purple-900/30 text-purple-400',
  internal: 'bg-slate-800/50 border-slate-700/30 text-slate-400',
};

export default async function KnowledgePage() {
  let data: Awaited<ReturnType<typeof getKnowledge>> | null = null;
  let error = '';
  try {
    data = await getKnowledge();
  } catch {
    error = 'Sanity not configured. Please set up .env.local and run npm run seed.';
  }

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <BookOpen size={16} className="text-purple-400" />
          <h1 className="text-base font-semibold text-slate-100">Security Knowledge Base</h1>
          <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
            Structured · Source-linked · Versioned
          </span>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {error && (
          <div className="p-4 rounded-lg bg-red-950/40 border border-red-900/40 text-sm text-red-400">{error}</div>
        )}

        {data && (
          <>
            {/* Sources */}
            <section>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <span>📚</span> Sources ({data.sources.length})
              </h2>
              <div className="grid grid-cols-1 gap-2">
                {data.sources.map((s: any) => (
                  <div key={s._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-3 text-xs">
                    <div className="flex items-start gap-2">
                      <span className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] font-medium shrink-0 ${authorityColors[s.authority] || authorityColors.internal}`}>
                        {s.authority?.toUpperCase()}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-slate-200">{s.title}</div>
                        <div className="text-slate-500 mt-0.5">{s.organization}{s.version ? ` · v${s.version}` : ''}{s.publicationDate ? ` · ${s.publicationDate}` : ''}</div>
                        {s.summary && <div className="text-slate-600 mt-1 leading-relaxed line-clamp-2">{s.summary}</div>}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] border ${s.status === 'current' ? 'bg-green-950/50 border-green-900/30 text-green-400' : 'bg-yellow-950/50 border-yellow-900/30 text-yellow-400'}`}>
                          {s.status}
                        </span>
                        {s.url && (
                          <a href={s.url} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400">
                            <ExternalLink size={11} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Threat Techniques */}
            <section>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <span>☠️</span> Threat Techniques ({data.threats.length})
              </h2>
              <div className="grid grid-cols-1 gap-2">
                {data.threats.map((t: any) => (
                  <div key={t._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-3 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-red-400">{t.techniqueId}</span>
                      <span className="text-slate-300">{t.name}</span>
                      <div className="flex gap-1 ml-auto">
                        {t.tactics?.map((tac: string) => (
                          <span key={tac} className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/40 border border-red-900/20 text-red-400">{tac}</span>
                        ))}
                        {t.externalUrl && (
                          <a href={t.externalUrl} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 ml-1">
                            <ExternalLink size={11} />
                          </a>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </section>

            {/* Security Controls */}
            <section>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <span>🛡️</span> Security Controls ({data.controls.length})
              </h2>
              <div className="grid grid-cols-1 gap-2">
                {data.controls.map((c: any) => (
                  <div key={c._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-3 text-xs">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-indigo-400 font-bold shrink-0">{c.controlId}</span>
                      <span className="text-slate-300">{c.name}</span>
                      <span className="ml-auto px-1.5 py-0.5 rounded text-[10px] bg-indigo-950/40 border border-indigo-900/30 text-indigo-400 shrink-0">{c.framework}{c.version ? ` v${c.version}` : ''}</span>
                    </div>
                    {c.applicableServices?.length > 0 && (
                      <div className="flex gap-1 mt-1.5 ml-16">
                        {c.applicableServices.map((svc: string) => (
                          <span key={svc} className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-500">{svc}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </section>

            {/* Policies */}
            <section>
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
                <span>📋</span> Policies ({data.policies.length})
              </h2>
              <div className="grid grid-cols-1 gap-2">
                {data.policies.map((p: any) => (
                  <div key={p._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-3 text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`inline-flex px-1.5 py-0.5 rounded border text-[10px] font-medium shrink-0 ${p.isCurrentVersion ? 'bg-green-950/50 border-green-900/30 text-green-400' : 'bg-yellow-950/50 border-yellow-900/30 text-yellow-500'}`}>
                        {p.isCurrentVersion ? 'CURRENT' : 'HISTORICAL'}
                      </span>
                      <span className="font-medium text-slate-200">{p.name}</span>
                      <span className="text-slate-500">v{p.version}</span>
                      <span className="text-slate-600 ml-auto">
                        {p.effectiveFrom}{p.effectiveTo ? ` → ${p.effectiveTo}` : ' → present'}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
