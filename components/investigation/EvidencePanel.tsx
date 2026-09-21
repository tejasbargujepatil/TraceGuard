'use client';

// EvidencePanel — inspectable evidence cards with source attribution
// "Why did TraceGuard say this?" — each claim shows its evidence trail

import { ExternalLink, FileText, Shield, AlertTriangle, Server, Database } from 'lucide-react';
import { cn, authorityLabel, formatDate } from '@/lib/utils';
import type { EvidenceItem, ChainNode } from '@/types';

const evidenceTypeIcons: Record<string, React.ComponentType<{ size?: number; className?: string }>> = {
  configuration: Server,
  asset_metadata: Server,
  data_classification: Database,
  policy: FileText,
  threat_intel: AlertTriangle,
  control: Shield,
  source_doc: FileText,
};

const evidenceTypeBg: Record<string, string> = {
  configuration: 'bg-blue-950/40 border-blue-900/30 text-blue-300',
  asset_metadata: 'bg-slate-800/40 border-slate-700/30 text-slate-300',
  data_classification: 'bg-purple-950/40 border-purple-900/30 text-purple-300',
  policy: 'bg-yellow-950/40 border-yellow-900/30 text-yellow-300',
  threat_intel: 'bg-red-950/40 border-red-900/30 text-red-300',
  control: 'bg-indigo-950/40 border-indigo-900/30 text-indigo-300',
  source_doc: 'bg-slate-800/40 border-slate-700/30 text-slate-300',
};

interface EvidencePanelProps {
  evidence: EvidenceItem[];
  selectedNode?: ChainNode | null;
}

export function EvidencePanel({ evidence, selectedNode }: EvidencePanelProps) {
  // If a chain node is selected, show its evidence; otherwise show all
  const displayEvidence = selectedNode?.evidence?.length
    ? selectedNode.evidence
    : evidence;

  return (
    <div
      style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
      className="rounded-lg border p-4 h-full flex flex-col"
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Evidence
        </h3>
        {selectedNode && (
          <span className="text-xs text-blue-400 font-medium">
            {selectedNode.label}
          </span>
        )}
        {!selectedNode && evidence.length > 0 && (
          <span className="text-xs text-slate-500">{evidence.length} items</span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto space-y-2">
        {displayEvidence.length === 0 && (
          <div className="text-xs text-slate-600 text-center py-6">
            {selectedNode
              ? 'No evidence attached to this node'
              : 'Evidence will appear after investigation completes'}
          </div>
        )}
        {displayEvidence.map((item, i) => {
          const Icon = evidenceTypeIcons[item.type] || FileText;
          const typeCls = evidenceTypeBg[item.type] || evidenceTypeBg.source_doc;
          return (
            <div
              key={i}
              className="rounded-md border p-3 text-xs space-y-2 hover:border-blue-500/30 transition-colors"
              style={{ backgroundColor: 'var(--bg-elevated)', borderColor: 'var(--border)' }}
            >
              {/* Type badge + label */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className={cn('inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border', typeCls)}>
                  <Icon size={9} />
                  {item.type.replace('_', ' ').toUpperCase()}
                </span>
                <span className="font-medium text-slate-200 flex-1">{item.label}</span>
                {item.confidence && (
                  <span className={cn(
                    'text-[10px] px-1.5 py-0.5 rounded border',
                    item.confidence === 'high' ? 'bg-green-950/50 border-green-900/30 text-green-400' :
                    item.confidence === 'medium' ? 'bg-yellow-950/50 border-yellow-900/30 text-yellow-400' :
                    'bg-slate-800 border-slate-700 text-slate-400'
                  )}>
                    {item.confidence} confidence
                  </span>
                )}
              </div>

              {/* Value */}
              <div className="font-mono-security text-slate-400 bg-slate-900/60 rounded p-2 break-all">
                {item.value}
              </div>

              {/* Source attribution */}
              {item.sourceTitle && (
                <div className="flex items-center gap-1.5 text-[10px] text-slate-500 flex-wrap">
                  <FileText size={9} className="shrink-0" />
                  <span className="font-medium text-slate-400">{item.sourceTitle}</span>
                  {item.sourceVersion && (
                    <span className="text-slate-600">v{item.sourceVersion}</span>
                  )}
                  {item.sourceDate && (
                    <span className="text-slate-600">{formatDate(item.sourceDate)}</span>
                  )}
                  {item.sourceUrl && (
                    <a
                      href={item.sourceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center gap-0.5 text-blue-500 hover:text-blue-400 ml-auto"
                    >
                      <ExternalLink size={9} />
                      Source
                    </a>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
