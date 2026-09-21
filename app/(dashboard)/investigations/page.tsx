// app/(dashboard)/investigations/page.tsx

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search } from 'lucide-react';
import { cn, statusColor, statusLabel, formatDateTime } from '@/lib/utils';

export default function InvestigationsPage() {
  // Show message directing user to click a finding
  return (
    <div className="flex-1 overflow-y-auto">
      <div style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }} className="border-b px-6 py-4 sticky top-0 z-10">
        <div className="flex items-center gap-2">
          <Search size={16} className="text-blue-400" />
          <h1 className="text-base font-semibold text-slate-100">Investigations</h1>
        </div>
      </div>
      <div className="p-6">
        <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-12 text-center">
          <div className="text-4xl mb-3">🔍</div>
          <div className="text-sm font-medium text-slate-300 mb-2">Start an Investigation</div>
          <div className="text-xs text-slate-500 max-w-sm mx-auto leading-relaxed">
            Open any finding from the <strong className="text-slate-400">Findings</strong> or{' '}
            <strong className="text-slate-400">Overview</strong> page and click{' '}
            <strong className="text-slate-400">Start Investigation</strong> to run the 15-step AI
            analysis pipeline.
          </div>
          <div className="mt-6 p-3 rounded-lg bg-blue-950/30 border border-blue-900/30 text-xs text-blue-400 max-w-sm mx-auto">
            💡 Go to{' '}
            <a href="/findings" className="underline font-medium">
              Findings
            </a>{' '}
            and click <strong>Investigate</strong> on any finding to start an AI investigation.
          </div>
        </div>
      </div>
    </div>
  );
}
