// app/(dashboard)/assets/page.tsx

import { sanityClient } from '@/lib/sanity/client';
import { Server } from 'lucide-react';
import { cn } from '@/lib/utils';

async function getAssets() {
  return sanityClient.fetch(`
    *[_type == "securityAsset"] | order(environment, sensitivity) {
      _id, name, assetId, provider, service, environment, sensitivity, owner, tags, region
    }
  `);
}

const envBadge = {
  production: 'bg-red-950/50 border-red-900/30 text-red-400',
  staging: 'bg-yellow-950/50 border-yellow-900/30 text-yellow-400',
  development: 'bg-blue-950/50 border-blue-900/30 text-blue-400',
  unknown: 'bg-slate-800 border-slate-700 text-slate-500',
};

const sensitivityBadge = {
  restricted: 'bg-red-950/50 border-red-900/30 text-red-400',
  confidential: 'bg-orange-950/50 border-orange-900/30 text-orange-400',
  internal: 'bg-slate-800 border-slate-700 text-slate-400',
  public: 'bg-green-950/50 border-green-900/30 text-green-400',
};

export default async function AssetsPage() {
  let assets: Awaited<ReturnType<typeof getAssets>> = [];
  try { assets = await getAssets(); } catch { /* Sanity not configured */ }

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <Server size={16} className="text-blue-400" />
          <h1 className="text-base font-semibold text-slate-100">Security Assets</h1>
          <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">{assets.length}</span>
          <span className="ml-2 text-xs text-yellow-600 bg-yellow-950/50 border border-yellow-900/30 px-2 py-0.5 rounded">ACME Corp · Synthetic</span>
        </div>
      </div>
      <div className="p-6">
        <div className="space-y-2">
          {assets.map((a: any) => (
            <div key={a._id} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4 text-xs">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="font-medium text-slate-200 text-sm">{a.name}</div>
                <span className={cn('px-1.5 py-0.5 rounded border text-[10px] font-medium', (envBadge as any)[a.environment] || envBadge.unknown)}>
                  {a.environment?.toUpperCase()}
                </span>
                <span className={cn('px-1.5 py-0.5 rounded border text-[10px] font-medium', (sensitivityBadge as any)[a.sensitivity] || sensitivityBadge.internal)}>
                  {a.sensitivity}
                </span>
                <span className="text-slate-500 bg-slate-800 px-1.5 py-0.5 rounded border border-slate-700">{a.service}</span>
                {a.owner && <span className="text-slate-600 ml-auto">{a.owner}</span>}
              </div>
              <div className="font-mono text-[10px] text-slate-600 mt-1.5">{a.assetId}</div>
              {a.region && <div className="text-[10px] text-slate-700 mt-0.5">Region: {a.region}</div>}
            </div>
          ))}
          {assets.length === 0 && (
            <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center text-slate-600 text-sm">
              Run <code className="font-mono bg-slate-800 px-1 rounded">npm run seed</code> to load assets
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
