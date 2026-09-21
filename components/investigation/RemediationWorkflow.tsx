'use client';

// RemediationWorkflow — human-in-the-loop approval panel
// AI proposes; humans approve. No automated infrastructure changes.

import { useState } from 'react';
import { Wrench, AlertTriangle, CheckCircle, XCircle, User, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { InvestigationResult, InvestigationStatus } from '@/types';

interface RemediationWorkflowProps {
  result: InvestigationResult;
  investigationDocId?: string;
  currentStatus: InvestigationStatus;
  onStatusChange: (newStatus: InvestigationStatus) => void;
}

const workflowSteps: { key: InvestigationStatus; label: string }[] = [
  { key: 'analysis_complete', label: 'Analysis' },
  { key: 'remediation_proposed', label: 'Proposed' },
  { key: 'pending_review', label: 'Review' },
  { key: 'approved', label: 'Approved' },
  { key: 'verified', label: 'Verified' },
  { key: 'closed', label: 'Closed' },
];

const statusOrder = workflowSteps.map(s => s.key);

export function RemediationWorkflow({
  result,
  investigationDocId,
  currentStatus,
  onStatusChange,
}: RemediationWorkflowProps) {
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [reviewer, setReviewer] = useState('');
  const [rejectReason, setRejectReason] = useState('');
  const [showPrereqs, setShowPrereqs] = useState(false);
  const [showVerify, setShowVerify] = useState(false);
  const [localStatus, setLocalStatus] = useState(currentStatus);

  const rem = result.remediation;
  const currentIdx = statusOrder.indexOf(localStatus);

  const isApproved = localStatus === 'approved' || localStatus === 'verified' || localStatus === 'closed';
  const isRejected = localStatus === 'rejected';
  const isPendingReview = localStatus === 'pending_review' || localStatus === 'remediation_proposed' || localStatus === 'analysis_complete';

  async function handleApproval(action: 'approved' | 'rejected') {
    setIsSubmitting(true);
    try {
      if (investigationDocId) {
        await fetch('/api/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            investigationDocId,
            action,
            reviewer: reviewer || 'Cloud Security Owner',
            reason: rejectReason,
          }),
        });
      }
      const newStatus: InvestigationStatus = action === 'approved' ? 'approved' : 'rejected';
      setLocalStatus(newStatus);
      onStatusChange(newStatus);
    } catch (e) {
      console.error('Approval failed', e);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleVerify() {
    setIsSubmitting(true);
    try {
      if (investigationDocId) {
        await fetch('/api/approve', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            investigationDocId,
            action: 'approved',
            reviewer: reviewer || 'Cloud Security Owner',
          }),
        });
      }
      setLocalStatus('verified');
      onStatusChange('verified');
    } catch {
      // ignore
    } finally {
      setIsSubmitting(false);
    }
  }

  if (!rem) {
    return (
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4 text-xs text-slate-600">
        No remediation available for this finding.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Workflow progress bar */}
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-3">
          Remediation Workflow
        </h3>
        <div className="flex items-center gap-1">
          {workflowSteps.map((step, i) => {
            const stepIdx = statusOrder.indexOf(step.key);
            const isDone = currentIdx >= stepIdx;
            const isCurrent = currentIdx === stepIdx;
            return (
              <div key={step.key} className="flex items-center gap-1 flex-1">
                <div className={cn(
                  'flex-1 text-center py-1 px-1 rounded text-[10px] font-medium transition-colors',
                  isDone ? 'bg-blue-600/30 text-blue-300 border border-blue-700/40' :
                  isCurrent ? 'bg-blue-950/50 text-blue-400 border border-blue-800/40' :
                  'bg-slate-900/50 text-slate-600 border border-slate-800/30'
                )}>
                  {isDone && i < currentIdx ? '✓ ' : ''}{step.label}
                </div>
                {i < workflowSteps.length - 1 && (
                  <div className={cn('w-2 h-0.5 shrink-0', isDone && currentIdx > stepIdx ? 'bg-blue-600' : 'bg-slate-800')} />
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Proposed remediation */}
      <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4">
        <div className="flex items-center gap-2 mb-3">
          <Wrench size={14} className="text-green-400" />
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Proposed Remediation
          </h3>
          <span className={cn(
            'ml-auto px-2 py-0.5 rounded text-[10px] font-medium border',
            rem.risk === 'high' ? 'bg-red-950/50 border-red-900/40 text-red-300' :
            rem.risk === 'medium' ? 'bg-yellow-950/50 border-yellow-900/40 text-yellow-300' :
            'bg-green-950/50 border-green-900/40 text-green-300'
          )}>
            {rem.risk?.toUpperCase()} RISK
          </span>
        </div>

        <div className="text-sm font-medium text-slate-200 mb-2">{rem.title}</div>
        <p className="text-xs text-slate-400 leading-relaxed mb-3">{rem.proposedChange}</p>
        <p className="text-xs text-slate-500 leading-relaxed italic mb-3">{rem.rationale}</p>

        {/* Operational impact */}
        {rem.operationalImpact && (
          <div className="p-2.5 rounded bg-orange-950/30 border border-orange-900/30 mb-3">
            <div className="flex items-start gap-2">
              <AlertTriangle size={12} className="text-orange-400 shrink-0 mt-0.5" />
              <div>
                <div className="text-[10px] font-semibold text-orange-400 uppercase mb-1">Operational Impact</div>
                <div className="text-xs text-orange-300 leading-relaxed">{rem.operationalImpact}</div>
              </div>
            </div>
          </div>
        )}

        {/* Prerequisites */}
        {rem.prerequisites?.length > 0 && (
          <div className="mb-3">
            <button
              onClick={() => setShowPrereqs(!showPrereqs)}
              className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 mb-1 transition-colors"
            >
              {showPrereqs ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
              Prerequisites ({rem.prerequisites.length})
            </button>
            {showPrereqs && (
              <ul className="space-y-1 pl-3">
                {rem.prerequisites.map((p: string, i: number) => (
                  <li key={i} className="text-xs text-slate-400 leading-snug">
                    • {p}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {/* Verification steps */}
        {rem.verificationSteps?.length > 0 && (
          <div className="mb-3">
            <button
              onClick={() => setShowVerify(!showVerify)}
              className="flex items-center gap-1 text-[11px] text-slate-500 hover:text-slate-300 mb-1 transition-colors"
            >
              {showVerify ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
              Verification Steps ({rem.verificationSteps.length})
            </button>
            {showVerify && (
              <ol className="space-y-1 pl-3">
                {rem.verificationSteps.map((v: string, i: number) => (
                  <li key={i} className="text-xs text-slate-400 leading-snug">
                    {i + 1}. {v}
                  </li>
                ))}
              </ol>
            )}
          </div>
        )}

        {/* Required approver */}
        <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-4">
          <User size={11} />
          Required Approver:
          <span className="text-slate-300 font-medium">{rem.requiredApproval}</span>
        </div>

        {/* Approval UI */}
        {isPendingReview && !isApproved && !isRejected && (
          <div className="space-y-2 pt-3 border-t border-slate-800">
            <div className="text-xs text-slate-500 mb-2 flex items-center gap-1">
              <AlertTriangle size={11} className="text-yellow-500" />
              Human approval required before remediation can proceed
            </div>
            <input
              type="text"
              value={reviewer}
              onChange={e => setReviewer(e.target.value)}
              placeholder="Your name (reviewer)"
              className="w-full px-3 py-1.5 rounded text-xs bg-slate-900 border border-slate-700 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-blue-600"
            />
            <div className="flex gap-2">
              <button
                onClick={() => handleApproval('approved')}
                disabled={isSubmitting}
                className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-green-700/30 border border-green-700/50 text-green-300 hover:bg-green-700/50 transition-colors disabled:opacity-50"
              >
                <CheckCircle size={12} />
                {isSubmitting ? 'Submitting...' : 'Approve Remediation'}
              </button>
              <button
                onClick={() => handleApproval('rejected')}
                disabled={isSubmitting}
                className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-red-950/30 border border-red-900/40 text-red-400 hover:bg-red-950/50 transition-colors disabled:opacity-50"
              >
                <XCircle size={12} />
                Reject
              </button>
            </div>
            {isRejected && (
              <input
                type="text"
                value={rejectReason}
                onChange={e => setRejectReason(e.target.value)}
                placeholder="Rejection reason"
                className="w-full px-3 py-1.5 rounded text-xs bg-slate-900 border border-slate-700 text-slate-300 placeholder-slate-600 focus:outline-none focus:border-red-600"
              />
            )}
          </div>
        )}

        {/* Approved state */}
        {isApproved && localStatus !== 'verified' && (
          <div className="pt-3 border-t border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-xs text-green-400">
              <CheckCircle size={13} />
              Remediation approved. Proceed with implementation and verification.
            </div>
            <button
              onClick={handleVerify}
              disabled={isSubmitting}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium bg-blue-700/20 border border-blue-700/40 text-blue-300 hover:bg-blue-700/40 transition-colors disabled:opacity-50"
            >
              <CheckCircle size={12} />
              Mark as Verified
            </button>
          </div>
        )}

        {/* Verified state */}
        {localStatus === 'verified' && (
          <div className="pt-3 border-t border-slate-800">
            <div className="flex items-center gap-2 text-xs text-green-400">
              <CheckCircle size={13} />
              Investigation verified and closed. Compliance restored.
            </div>
          </div>
        )}

        {/* Rejected state */}
        {isRejected && (
          <div className="pt-3 border-t border-slate-800">
            <div className="flex items-center gap-2 text-xs text-red-400">
              <XCircle size={13} />
              Remediation rejected.
              {rejectReason && <span className="text-slate-500">Reason: {rejectReason}</span>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
