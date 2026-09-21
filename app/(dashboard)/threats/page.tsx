// app/(dashboard)/threats/page.tsx

import { sanityClient } from '@/lib/sanity/client';
import { Swords, ExternalLink } from 'lucide-react';
import { cn, severityBg, severityIcon } from '@/lib/utils';

async function getThreats() {
  return sanityClient.fetch(`
    *[_type == "threatTechnique"] | order(techniqueId) {
      _id, techniqueId, name, description, tactics, affectedServices,
      relevantConditions, cloudContext, severity, mitigations, externalUrl,
      source->{ title, organization }
    }
  `);
}

export default async function ThreatsPage() {
  let threats: any[] = [];
  try { threats = await getThreats(); } catch { /* not configured */ }

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <Swords size={16} className="text-red-400" />
          <h1 className="text-base font-semibold text-slate-100">Threat Techniques</h1>
          <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{threats.length}</span>
          <span className="ml-2 text-xs px-2 py-0.5 rounded bg-red-950/40 border border-red-900/30 text-red-500">MITRE ATT&amp;CK</span>
        </div>
      </div>
      <div className="p-6 space-y-4">
        {threats.map((t: any) => (
          <div key={t._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4 text-xs">
            <div className="flex items-start gap-3">
              <div className="shrink-0">
                <div className="font-mono font-bold text-red-400 text-base">{t.techniqueId}</div>
                <div className={cn('mt-1 px-1.5 py-0.5 rounded text-[10px] text-center border', severityBg(t.severity))}>
                  {severityIcon(t.severity)} {t.severity?.toUpperCase()}
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1.5">
                  <h3 className="font-semibold text-slate-100 text-sm">{t.name}</h3>
                  {t.externalUrl && (
                    <a href={t.externalUrl} target="_blank" rel="noopener noreferrer" className="text-blue-500 hover:text-blue-400 ml-auto">
                      <ExternalLink size={12} />
                    </a>
                  )}
                </div>
                <p className="text-slate-400 leading-relaxed mb-3">{t.description}</p>

                {t.cloudContext && (
                  <div className="p-2.5 rounded bg-red-950/20 border border-red-900/20 mb-3">
                    <div className="text-[10px] font-semibold text-red-400 uppercase mb-1">Cloud Context</div>
                    <div className="text-red-300/80 leading-relaxed">{t.cloudContext}</div>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  {t.tactics?.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-slate-500 uppercase mb-1">Tactics</div>
                      <div className="flex flex-wrap gap-1">
                        {t.tactics.map((tac: string) => (
                          <span key={tac} className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/40 border border-red-900/30 text-red-400">{tac}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {t.affectedServices?.length > 0 && (
                    <div>
                      <div className="text-[10px] font-semibold text-slate-500 uppercase mb-1">Affected Services</div>
                      <div className="flex flex-wrap gap-1">
                        {t.affectedServices.map((s: string) => (
                          <span key={s} className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 border border-slate-700 text-slate-400">{s}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {t.mitigations?.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[10px] font-semibold text-slate-500 uppercase mb-1">Mitigations</div>
                    <ul className="space-y-1">
                      {t.mitigations.map((m: string, i: number) => (
                        <li key={i} className="flex items-start gap-1.5 text-slate-400">
                          <span className="text-green-500 shrink-0">•</span>{m}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
        {threats.length === 0 && (
          <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center text-slate-600 text-sm">
            Run <code className="font-mono bg-slate-800 px-1 rounded">npm run seed</code> to load threat techniques
          </div>
        )}
      </div>
    </div>
  );
}
