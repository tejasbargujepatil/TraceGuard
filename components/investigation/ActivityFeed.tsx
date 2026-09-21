'use client';

// Investigation Activity Feed
// Renders a real-time step-by-step activity panel as the agent works

import { CheckCircle, Circle, Loader, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { InvestigationStep } from '@/types';

interface ActivityFeedProps {
  steps: InvestigationStep[];
  isComplete: boolean;
  error?: string;
}

export function ActivityFeed({ steps, isComplete, error }: ActivityFeedProps) {
  const totalSteps = 15;

  return (
    <div
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
      className="rounded-lg border p-4 h-full flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Investigation Activity
        </h3>
        {!isComplete && steps.length > 0 && (
          <span className="flex items-center gap-1.5 text-xs text-blue-400">
            <Loader size={11} className="animate-spin" />
            Running
          </span>
        )}
        {isComplete && !error && (
          <span className="flex items-center gap-1.5 text-xs text-green-400">
            <CheckCircle size={11} />
            Complete
          </span>
        )}
        {error && (
          <span className="flex items-center gap-1.5 text-xs text-red-400">
            <XCircle size={11} />
            Error
          </span>
        )}
      </div>

      {/* Progress bar */}
      {steps.length > 0 && (
        <div className="mb-4">
          <div className="flex justify-between text-[10px] text-slate-600 mb-1">
            <span>Progress</span>
            <span>{steps.filter(s => s.status === 'complete').length}/{totalSteps} steps</span>
          </div>
          <div className="h-1 rounded-full bg-slate-800 overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{
                width: `${(steps.filter(s => s.status === 'complete').length / totalSteps) * 100}%`
              }}
            />
          </div>
        </div>
      )}

      {/* Steps list */}
      <div className="flex-1 overflow-y-auto space-y-1">
        {steps.length === 0 && (
          <div className="text-xs text-slate-600 text-center py-8">
            Click &quot;Start Investigation&quot; to begin
          </div>
        )}
        {steps.map((step) => (
          <div
            key={step.stepId}
            className={cn(
              'flex items-start gap-2.5 px-2 py-1.5 rounded text-xs step-enter',
              step.status === 'running' && 'bg-blue-950/30'
            )}
          >
            {/* Status icon */}
            <div className="shrink-0 mt-0.5">
              {step.status === 'complete' && (
                <CheckCircle size={13} className="text-green-500" />
              )}
              {step.status === 'running' && (
                <Loader size={13} className="text-blue-400 animate-spin" />
              )}
              {step.status === 'error' && (
                <XCircle size={13} className="text-red-500" />
              )}
              {step.status === 'pending' && (
                <Circle size={13} className="text-slate-700" />
              )}
            </div>

            <div className="flex-1 min-w-0">
              <div className={cn(
                'font-medium leading-snug',
                step.status === 'complete' ? 'text-slate-300' :
                step.status === 'running' ? 'text-blue-300' :
                step.status === 'error' ? 'text-red-400' : 'text-slate-600'
              )}>
                {step.label}
              </div>
              {step.detail && (
                <div className="text-[11px] text-slate-500 mt-0.5 leading-snug">
                  {step.detail}
                </div>
              )}
            </div>

            {/* Duration */}
            {step.durationMs !== undefined && (
              <span className="text-[10px] text-slate-700 shrink-0">
                {step.durationMs < 1000 ? `${step.durationMs}ms` : `${(step.durationMs / 1000).toFixed(1)}s`}
              </span>
            )}
          </div>
        ))}

        {error && (
          <div className="mt-2 p-3 rounded-md bg-red-950/40 border border-red-900/40 text-xs text-red-400">
            <strong>Error:</strong> {error}
          </div>
        )}
      </div>
    </div>
  );
}
