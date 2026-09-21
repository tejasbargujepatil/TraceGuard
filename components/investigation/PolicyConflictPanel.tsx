'use client';

// PolicyConflictPanel — surfaces contradictions and security drift
// This is a key differentiator: TraceGuard doesn't silently pick one source.

import { AlertTriangle, GitBranch, Clock, CheckCircle2, XCircle } from 'lucide-react';
import type { ConflictItem, PolicyAnalysis } from '@/types';
import { cn, formatDate } from '@/lib/utils';

interface PolicyConflictPanelProps {
  policyAnalysis: PolicyAnalysis | null;
  conflicts: ConflictItem[];
}

export function PolicyConflictPanel({ policyAnalysis, conflicts }: PolicyConflictPanelProps) {
  if (!policyAnalysis) {
    return (
      <div
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
        className="rounded-lg border p-4 text-xs text-slate-600 text-center"
      >
        Policy analysis will appear after investigation
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Current Policy Status */}
      <div
        style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
        className="rounded-lg border p-4"
      >
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
          Policy Analysis
        </h3>
        <div className="space-y-2">
          {/* Current policy */}
          <div className="flex items-center gap-2">
            {policyAnalysis.currentPolicyStatus === 'violated' ? (
              <XCircle size={14} className="text-red-400 shrink-0" />
            ) : policyAnalysis.currentPolicyStatus === 'compliant' ? (
              <CheckCircle2 size={14} className="text-green-400 shrink-0" />
            ) : (
              <Clock size={14} className="text-yellow-400 shrink-0" />
            )}
            <div>
              <div className="text-xs font-medium text-slate-200">
                {policyAnalysis.currentPolicyName} v{policyAnalysis.currentPolicyVersion}
              </div>
              <div className={cn(
                'text-[11px] font-semibold',
                policyAnalysis.currentPolicyStatus === 'violated' ? 'text-red-400' :
                policyAnalysis.currentPolicyStatus === 'compliant' ? 'text-green-400' : 'text-yellow-400'
              )}>
                {policyAnalysis.currentPolicyStatus === 'violated' ? '❌ VIOLATION' :
                 policyAnalysis.currentPolicyStatus === 'compliant' ? '✅ COMPLIANT' : '❓ UNKNOWN'}
              </div>
            </div>
          </div>

          {/* Historical policies */}
          {policyAnalysis.historicalPolicies.map((hp, i) => (
            <div key={i} className="flex items-center gap-2 opacity-60">
              <Clock size={14} className="text-slate-500 shrink-0" />
              <div>
                <div className="text-xs text-slate-400">
                  {hp.name} v{hp.version}
                  {hp.effectiveTo && (
                    <span className="text-slate-600 ml-1">(until {formatDate(hp.effectiveTo)})</span>
                  )}
                </div>
                <div className="text-[11px] text-slate-500">Historical · Superseded</div>
              </div>
            </div>
          ))}
        </div>

        {/* Drift indicator */}
        {policyAnalysis.driftDetected && (
          <div className="mt-3 p-2.5 rounded bg-yellow-950/40 border border-yellow-900/30">
            <div className="flex items-start gap-2">
              <GitBranch size={13} className="text-yellow-400 shrink-0 mt-0.5" />
              <div>
                <div className="text-xs font-semibold text-yellow-300 mb-1">
                  Security Drift Detected
                </div>
                <div className="text-[11px] text-yellow-600 leading-relaxed">
                  {policyAnalysis.driftDescription}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Conflicts */}
      {conflicts.length > 0 && (
        <div
          style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
          className="rounded-lg border border-l-2 border-l-purple-500 p-4"
        >
          <h3 className="text-xs font-semibold uppercase tracking-wider text-purple-400 mb-3 flex items-center gap-2">
            <AlertTriangle size={12} />
            {conflicts.length} Conflict{conflicts.length !== 1 ? 's' : ''} Detected
          </h3>
          <div className="space-y-4">
            {conflicts.map((conflict, i) => (
              <div key={i} className="text-xs space-y-2">
                <div className="font-medium text-slate-300">{conflict.description}</div>

                <div className="space-y-1.5">
                  {/* Source A */}
                  <div className="p-2 rounded bg-red-950/30 border border-red-900/20">
                    <div className="text-[10px] font-semibold text-red-400 mb-1 uppercase">Current</div>
                    <div className="text-red-300 leading-snug">{conflict.sourceA}</div>
                  </div>
                  {/* Source B */}
                  <div className="p-2 rounded bg-yellow-950/30 border border-yellow-900/20">
                    <div className="text-[10px] font-semibold text-yellow-400 mb-1 uppercase">Historical</div>
                    <div className="text-yellow-300 leading-snug">{conflict.sourceB}</div>
                  </div>
                </div>

                {/* Recommendation */}
                <div className="p-2 rounded bg-blue-950/30 border border-blue-900/20">
                  <div className="text-[10px] font-semibold text-blue-400 mb-1 uppercase">Recommended Action</div>
                  <div className="text-blue-300 leading-snug">{conflict.recommendation}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
