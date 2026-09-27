// app/(dashboard)/findings/[findingId]/page.tsx
// Investigation screen for a specific finding

import { InvestigationView } from '@/components/investigation/InvestigationView';
import { sanityClient } from '@/lib/sanity/client';

interface Props {
  params: Promise<{ findingId: string }>;
}

async function loadFinding(rawParam: string) {
  try {
    // The URL param may be encoded (e.g. :: → %3A%3A), decode it first
    const findingId = decodeURIComponent(rawParam);

    // Try lookup by findingId field first, then by Sanity _id as fallback
    const result = await sanityClient.fetch(
      `*[_type == "finding" && (findingId == $findingId || _id == $findingId)][0] {
        _id,
        findingId,
        title,
        severity,
        category,
        status,
        observedCondition,
        evidence,
        potentialImpact,
        discoveredAt,
        cloudProvider,
        cloudAccountId,
        resourceId,
        resourceArn,
        resourceName,
        region,
        service,
        compliance,
        mitre,
        remediationSummary,
        remediationSteps,
        remediationAwsCli,
        remediationGcpCli,
        remediationTerraform,
        remediationConsoleUrl,
        remediationEffort,
        operationalImpact,
        autoDetected,
        scanTimestamp,
        affectedAsset-> {
          _id,
          _type,
          name,
          assetId,
          provider,
          service,
          environment,
          description,
          sensitivity,
          owner,
          tags,
          region
        }
      }`,
      { findingId }
    );
    return result ?? null;
  } catch (err) {
    console.error('[FindingPage] loadFinding error:', err);
    return null;
  }
}

export default async function FindingInvestigationPage({ params }: Props) {
  const { findingId: rawParam } = await params;
  const finding = await loadFinding(rawParam);

  if (!finding) {
    return (
      <div className="flex-1 flex items-center justify-center p-8">
        <div
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
          className="rounded-xl border p-8 max-w-md text-center"
        >
          <div className="text-3xl mb-3">🔍</div>
          <h2 className="text-sm font-semibold text-slate-300 mb-2">Finding Not Found</h2>
          <p className="text-xs text-slate-500 mb-4 leading-relaxed">
            No finding with ID{' '}
            <code className="font-mono bg-slate-800 px-1 rounded text-slate-300">
              {decodeURIComponent(rawParam)}
            </code>{' '}
            was found.
          </p>
          <p className="text-xs text-slate-600 mb-4">
            Run a cloud scan from{' '}
            <a href="/accounts" className="text-blue-400 hover:underline">
              Cloud Accounts
            </a>{' '}
            to generate findings, then click a finding to investigate it.
          </p>
          <a href="/findings" className="mt-2 inline-block text-xs text-blue-400 hover:text-blue-300">
            ← Back to Findings
          </a>
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
  const { findingId: rawParam } = await params;
  try {
    const finding = await loadFinding(rawParam);
    const id = decodeURIComponent(rawParam);
    return {
      title: finding
        ? `${finding.findingId ?? id}: ${finding.title} — TraceGuard`
        : `${id} — TraceGuard`,
    };
  } catch {
    return { title: `Finding — TraceGuard` };
  }
}
