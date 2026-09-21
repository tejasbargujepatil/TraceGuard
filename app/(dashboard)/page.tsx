// app/(dashboard)/page.tsx — Dashboard / Security Posture Overview

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert, AlertTriangle, GitBranch, Server, BookOpen, Search, TrendingUp
} from 'lucide-react';
import { FindingCard } from '@/components/FindingCard';
import { cn, severityBg, severityIcon } from '@/lib/utils';

interface Posture {
  totalFindings: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  lowFindings: number;
  openFindings: number;
  openInvestigations: number;
  totalPolicies: number;
  evidenceSources: number;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Finding = any;

function StatCard({ label, value, icon: Icon, color = 'text-slate-300', sub }: {
  label: string;
  value: number | string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  color?: string;
  sub?: string;
}) {
  return (
    <div
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
      className="rounded-lg border p-4"
    >
      <div className="flex items-center justify-between mb-2">
        <Icon size={16} className="text-slate-500" />
      </div>
      <div className={cn('text-2xl font-bold mb-0.5', color)}>{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
      {sub && <div className="text-xs text-slate-600 mt-1">{sub}</div>}
    </div>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [posture, setPosture] = useState<Posture | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      try {
        const [postureRes, findingsRes] = await Promise.all([
          fetch('/api/posture'),
          fetch('/api/findings'),
        ]);
        if (postureRes.ok) setPosture(await postureRes.json());
        if (findingsRes.ok) {
          const data = await findingsRes.json();
          setFindings(data.findings || []);
        }
      } catch {
        setError('Failed to load security data. Ensure Sanity is configured and seeded.');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  return (
    <div className="flex-1 overflow-y-auto">
      {/* Page header */}
      <div style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)', borderBottom: '1px solid var(--border)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-semibold text-slate-100">Security Posture</h1>
            <p className="text-xs text-slate-500 mt-0.5">
              Real-time findings from your connected cloud accounts
            </p>
          </div>
          <div className="flex items-center gap-2">
            <TrendingUp size={14} className="text-slate-600" />
            <span className="text-xs text-slate-500">Live from Sanity</span>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-6">
        {/* Error state */}
        {error && (
          <div className="p-4 rounded-lg bg-red-950/40 border border-red-900/40 text-sm text-red-400">
            <strong>Configuration Required:</strong> {error}
            <div className="mt-2 text-xs text-red-500">
              1. Copy .env.example to .env.local and fill in your Sanity credentials<br />
              2. Run: <code className="font-mono bg-red-950/80 px-1 rounded">npm run seed</code><br />
              3. Refresh this page
            </div>
          </div>
        )}

        {/* Loading */}
        {loading && (
          <div className="grid grid-cols-4 gap-4">
            {[...Array(8)].map((_, i) => (
              <div key={i} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border h-24 animate-pulse" />
            ))}
          </div>
        )}

        {/* Stats grid */}
        {posture && !loading && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <StatCard
              label="Total Findings"
              value={posture.totalFindings}
              icon={ShieldAlert}
              color="text-slate-200"
            />
            <StatCard
              label="Critical / High"
              value={`${posture.criticalFindings} / ${posture.highFindings}`}
              icon={AlertTriangle}
              color="text-red-400"
              sub={`${posture.openFindings} open`}
            />
            <StatCard
              label="Active Investigations"
              value={posture.openInvestigations}
              icon={Search}
              color="text-blue-400"
            />
            <StatCard
              label="Knowledge Sources"
              value={posture.evidenceSources}
              icon={BookOpen}
              color="text-purple-400"
              sub={`${posture.totalPolicies} policies`}
            />
          </div>
        )}

        {/* Severity breakdown */}
        {posture && !loading && (
          <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3 flex items-center gap-2">
              <AlertTriangle size={12} />
              Findings by Severity
            </h2>
            <div className="flex gap-3">
              {[
                { sev: 'critical', count: posture.criticalFindings },
                { sev: 'high', count: posture.highFindings },
                { sev: 'medium', count: posture.mediumFindings },
                { sev: 'low', count: posture.lowFindings },
              ].map(({ sev, count }) => (
                <div
                  key={sev}
                  className={cn(
                    'flex-1 text-center py-3 rounded-lg border text-xs font-semibold',
                    severityBg(sev)
                  )}
                >
                  <div className="text-xl font-bold mb-0.5">{count}</div>
                  <div className="text-[10px] uppercase opacity-80">{severityIcon(sev)} {sev}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Findings list */}
        {!loading && findings.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <ShieldAlert size={12} />
                Findings
              </h2>
              <span className="text-xs text-slate-600">Click to investigate</span>
            </div>
            <div className="space-y-2">
              {findings.map((f) => (
                <FindingCard
                  key={f._id}
                  finding={f}
                  onClick={() => router.push(`/findings/${f.findingId}`)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Empty state */}
        {!loading && !error && findings.length === 0 && (
          <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center">
            <div className="text-4xl mb-3">🔒</div>
            <div className="text-sm text-slate-400 mb-2">No findings yet</div>
            <div className="text-xs text-slate-600">
              Go to <a href="/accounts" className="text-blue-400 hover:underline">Cloud Accounts</a> to connect an AWS or GCP account and run your first scan.
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
