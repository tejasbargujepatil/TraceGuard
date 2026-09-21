// app/(dashboard)/findings/page.tsx — Findings list page

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AlertTriangle, Filter } from 'lucide-react';
import { FindingCard } from '@/components/FindingCard';
import { cn } from '@/lib/utils';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Finding = any;

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];

export default function FindingsPage() {
  const router = useRouter();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetch('/api/findings')
      .then(r => r.json())
      .then(d => setFindings(d.findings || []))
      .finally(() => setLoading(false));
  }, []);

  const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);

  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="text-orange-400" />
            <h1 className="text-base font-semibold text-slate-100">Findings</h1>
            <span className="ml-2 text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">
              {findings.length}
            </span>
          </div>
          <div className="flex items-center gap-1">
            <Filter size={12} className="text-slate-600 mr-1" />
            {SEVERITIES.map(sev => (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={cn(
                  'px-2.5 py-1 rounded text-xs capitalize transition-colors',
                  filter === sev
                    ? 'bg-blue-600/30 text-blue-300 border border-blue-700/40'
                    : 'text-slate-500 hover:text-slate-300 border border-transparent hover:border-slate-700'
                )}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="p-6">
        {loading ? (
          <div className="space-y-3">
            {[...Array(5)].map((_, i) => (
              <div key={i} style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border h-24 animate-pulse" />
            ))}
          </div>
        ) : (
          <div className="space-y-2">
            {filtered.map(f => (
              <FindingCard
                key={f._id}
                finding={f}
                onClick={() => router.push(`/findings/${f.findingId}`)}
              />
            ))}
            {filtered.length === 0 && (
              <div className="text-center py-12 text-slate-600 text-sm">
                No findings match the selected filter
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
