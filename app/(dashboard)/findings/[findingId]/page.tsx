// app/(dashboard)/findings/[findingId]/page.tsx
// Investigation screen for a specific finding

import { InvestigationView } from '@/components/investigation/InvestigationView';

interface Props {
  params: Promise<{ findingId: string }>;
}

async function loadFinding(findingId: string) {
  try {
    // Only import if env is configured
    if (!process.env.SANITY_PROJECT_ID && !process.env.NEXT_PUBLIC_SANITY_PROJECT_ID) {
      return null;
    }
    const { getFindingById } = await import('@/lib/sanity/queries');
    return await getFindingById(findingId);
  } catch {
    return null;
  }
}

export default async function FindingInvestigationPage({ params }: Props) {
  const { findingId } = await params;
  const finding = await loadFinding(findingId);

  if (!finding) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-xl border p-8 max-w-md text-center">
          <div className="text-3xl mb-3">🔒</div>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Finding Not Found</h2>
          <p className="text-xs text-slate-500 mb-4 leading-relaxed">
            <strong className="text-slate-400">{findingId}</strong> was not found in the knowledge base.
          </p>
          <div className="text-xs text-slate-600 bg-slate-900/50 rounded-lg p-3 text-left space-y-1">
            <div className="font-semibold text-slate-400 mb-2">Setup required:</div>
            <div>1. Copy <code className="font-mono bg-slate-800 px-1 rounded">.env.example</code> → <code className="font-mono bg-slate-800 px-1 rounded">.env.local</code></div>
            <div>2. Fill in your Sanity project ID and API token</div>
            <div>3. Run <code className="font-mono bg-slate-800 px-1 rounded">npm run seed</code></div>
            <div>4. Restart the dev server</div>
          </div>
          <a href="/" className="mt-4 inline-block text-xs text-blue-400 hover:text-blue-300">← Back to dashboard</a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
      <InvestigationView finding={finding} />
    </div>
  );
}

export async function generateMetadata({ params }: Props) {
  const { findingId } = await params;
  try {
    const finding = await loadFinding(findingId);
    return {
      title: finding ? `${finding.findingId}: ${finding.title} — TraceGuard` : `${findingId} — TraceGuard`,
    };
  } catch {
    return { title: `${findingId} — TraceGuard` };
  }
}
