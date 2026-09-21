'use client';

// Finding card component — used on dashboard and findings list

import { cn, severityBg, severityIcon, statusColor, statusLabel, categoryLabel, formatDate } from '@/lib/utils';
import { AlertTriangle, Server, Calendar, ArrowRight } from 'lucide-react';

interface FindingCardProps {
  finding: {
    _id: string;
    findingId: string;
    title: string;
    severity: string;
    category: string;
    status: string;
    observedCondition: string;
    discoveredAt?: string;
    affectedAsset?: {
      name: string;
      service: string;
      environment: string;
    };
  };
  onClick?: () => void;
  compact?: boolean;
}

export function FindingCard({ finding, onClick, compact = false }: FindingCardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'rounded-lg border p-4 transition-all cursor-pointer group',
        'hover:border-blue-500/40 hover:bg-slate-800/30'
      )}
      style={{
        backgroundColor: 'var(--bg-card)',
        borderColor: 'var(--border)',
      }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          {/* Header row */}
          <div className="flex items-center gap-2 mb-1.5">
            <span className={cn(
              'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border',
              severityBg(finding.severity)
            )}>
              {severityIcon(finding.severity)} {finding.severity.toUpperCase()}
            </span>
            <span className="text-xs text-slate-500">{finding.findingId}</span>
            <span className="text-xs text-slate-600">·</span>
            <span className="text-xs text-slate-500">{categoryLabel(finding.category)}</span>
          </div>

          {/* Title */}
          <h3 className="font-medium text-slate-200 text-sm leading-snug mb-2 group-hover:text-white transition-colors">
            {finding.title}
          </h3>

          {/* Observed condition */}
          {!compact && (
            <p className="text-xs text-slate-500 line-clamp-2 leading-relaxed mb-3">
              {finding.observedCondition}
            </p>
          )}

          {/* Meta row */}
          <div className="flex items-center gap-3 text-xs text-slate-500 flex-wrap">
            {finding.affectedAsset && (
              <span className="flex items-center gap-1">
                <Server size={11} />
                {finding.affectedAsset.name}
                <span className={cn(
                  'ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium',
                  finding.affectedAsset.environment === 'production'
                    ? 'bg-red-950/60 text-red-400'
                    : 'bg-blue-950/60 text-blue-400'
                )}>
                  {finding.affectedAsset.environment}
                </span>
              </span>
            )}
            {finding.discoveredAt && (
              <span className="flex items-center gap-1">
                <Calendar size={11} />
                {formatDate(finding.discoveredAt)}
              </span>
            )}
            <span className={cn('flex items-center gap-1 ml-auto', statusColor(finding.status))}>
              <AlertTriangle size={11} />
              {statusLabel(finding.status)}
            </span>
          </div>
        </div>

        {/* Arrow */}
        <ArrowRight
          size={16}
          className="text-slate-600 group-hover:text-blue-400 transition-colors shrink-0 mt-1"
        />
      </div>
    </div>
  );
}
