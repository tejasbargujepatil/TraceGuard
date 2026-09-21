'use client';

// Investigation Screen — main investigation view
// Shows the full 15-step pipeline with streaming activity feed,
// evidence chain graph, evidence inspector, policy conflicts, and remediation workflow

import { useState, useRef, useCallback } from 'react';
import { Play, RotateCcw, Info } from 'lucide-react';
import { ActivityFeed } from '@/components/investigation/ActivityFeed';
import { EvidenceChainGraph } from '@/components/investigation/EvidenceChainGraph';
import { EvidencePanel } from '@/components/investigation/EvidencePanel';
import { PolicyConflictPanel } from '@/components/investigation/PolicyConflictPanel';
import { RemediationWorkflow } from '@/components/investigation/RemediationWorkflow';
import { cn, severityBg, severityIcon, categoryLabel, formatDate } from '@/lib/utils';
import type { InvestigationResult, InvestigationStep, ChainNode, InvestigationStatus } from '@/types';

interface InvestigationViewProps {
  finding: {
    _id: string;
    findingId: string;
    title: string;
    severity: string;
    category: string;
    status: string;
    observedCondition: string;
    potentialImpact?: string;
    discoveredAt?: string;
    affectedAsset?: {
      name: string;
      service: string;
      environment: string;
      sensitivity: string;
    };
  };
}

export function InvestigationView({ finding }: InvestigationViewProps) {
  const [steps, setSteps] = useState<InvestigationStep[]>([]);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [selectedNode, setSelectedNode] = useState<ChainNode | null>(null);
  const [activeTab, setActiveTab] = useState<'evidence' | 'policy' | 'remediation' | 'threats'>('evidence');
  const [investigationStatus, setInvestigationStatus] = useState<InvestigationStatus>('investigating');
  const [investigationDocId, setInvestigationDocId] = useState<string | undefined>();
  const abortRef = useRef<AbortController | null>(null);

  const startInvestigation = useCallback(async () => {
    setSteps([]);
    setResult(null);
    setError(null);
    setIsRunning(true);
    setIsComplete(false);
    setSelectedNode(null);
    setInvestigationStatus('investigating');

    abortRef.current = new AbortController();

    try {
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ findingId: finding.findingId }),
        signal: abortRef.current.signal,
      });

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error('No response body');

      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'step') {
              setSteps(prev => {
                const existing = prev.findIndex(s => s.stepId === data.step.stepId);
                if (existing >= 0) {
                  const next = [...prev];
                  next[existing] = data.step;
                  return next;
                }
                return [...prev, data.step];
              });
            } else if (data.type === 'complete') {
              setResult(data.result);
              setIsComplete(true);
              setInvestigationStatus('analysis_complete');
              // Store the sanity doc ID if persisted
              if (data.result?.investigationId) {
                setInvestigationDocId(data.result.investigationId);
              }
            } else if (data.type === 'error') {
              setError(data.error);
            }
          } catch {
            // ignore parse errors
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        setError(err.message || 'Investigation failed');
      }
    } finally {
      setIsRunning(false);
    }
  }, [finding.findingId]);

  const reset = () => {
    abortRef.current?.abort();
    setSteps([]);
    setResult(null);
    setError(null);
    setIsRunning(false);
    setIsComplete(false);
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Finding header */}
      <div
        style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
        className="border-b px-6 py-4 shrink-0"
      >
        <div className="flex items-start gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className={cn(
                'inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border',
                severityBg(finding.severity)
              )}>
                {severityIcon(finding.severity)} {finding.severity.toUpperCase()}
              </span>
              <span className="text-xs text-slate-500">{finding.findingId}</span>
              <span className="text-xs text-slate-600">·</span>
              <span className="text-xs text-slate-500">{categoryLabel(finding.category)}</span>
              {finding.affectedAsset && (
                <>
                  <span className="text-xs text-slate-600">·</span>
                  <span className={cn(
                    'text-xs px-1.5 py-0.5 rounded font-medium',
                    finding.affectedAsset.environment === 'production'
                      ? 'bg-red-950/50 text-red-400'
                      : 'bg-blue-950/50 text-blue-400'
                  )}>
                    {finding.affectedAsset.environment?.toUpperCase()}
                  </span>
                </>
              )}
            </div>
            <h1 className="text-lg font-semibold text-slate-100 leading-tight mb-1">
              {finding.title}
            </h1>
            {finding.affectedAsset && (
              <div className="text-sm text-slate-400">
                {finding.affectedAsset.name}
                <span className="text-slate-600 mx-1">·</span>
                <span className="text-slate-500">{finding.affectedAsset.service}</span>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 shrink-0">
            {(isRunning || isComplete) && (
              <button
                onClick={reset}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-slate-400 hover:text-slate-200 border border-slate-700 hover:border-slate-500 transition-colors"
              >
                <RotateCcw size={12} />
                Reset
              </button>
            )}
            <button
              onClick={startInvestigation}
              disabled={isRunning}
              className={cn(
                'flex items-center gap-1.5 px-4 py-1.5 rounded text-xs font-semibold transition-all',
                isRunning
                  ? 'bg-blue-700/50 text-blue-300 cursor-not-allowed'
                  : 'bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-900/30'
              )}
            >
              <Play size={12} />
              {isRunning ? 'Investigating...' : isComplete ? 'Re-Investigate' : 'Start Investigation'}
            </button>
          </div>
        </div>

        {/* Observed condition */}
        <div className="mt-3 p-3 rounded-md text-xs" style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)' }}>
          <span className="font-medium text-slate-300 mr-2">Observed:</span>
          {finding.observedCondition}
        </div>
      </div>

      {/* Main content — three-column layout */}
      <div className="flex-1 min-h-0 flex gap-4 p-4 overflow-hidden">

        {/* Left: Activity feed */}
        <div className="w-56 shrink-0 overflow-hidden flex flex-col">
          <ActivityFeed
            steps={steps}
            isComplete={isComplete}
            error={error || undefined}
          />
        </div>

        {/* Center: Evidence chain graph */}
        <div className="flex-1 min-w-0 flex flex-col gap-3">
          {/* Reasoning summary */}
          {result?.reasoningSummary && (
            <div
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
              className="rounded-lg border p-4 shrink-0"
            >
              <div className="flex items-start gap-2">
                <Info size={14} className="text-blue-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-xs font-semibold text-blue-300 mb-1 uppercase tracking-wider">Investigation Summary</div>
                  <p className="text-sm text-slate-300 leading-relaxed">{result.reasoningSummary}</p>
                </div>
              </div>
            </div>
          )}

          {/* Graph */}
          <div className="flex-1 min-h-0" style={{ minHeight: 360 }}>
            <EvidenceChainGraph
              nodes={result?.investigationChain || []}
              edges={result?.chainEdges || []}
              onNodeClick={setSelectedNode}
            />
          </div>

          {/* Observations */}
          {(result?.observations?.length ?? 0) > 0 && (
            <div
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
              className="rounded-lg border p-4 shrink-0"
            >
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Observed Conditions</div>
              <ul className="space-y-1.5">
                {result?.observations?.map((obs, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-slate-400">
                    <span className="text-blue-500 shrink-0 mt-0.5">•</span>
                    {obs}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Next checks */}
          {(result?.nextChecks?.length ?? 0) > 0 && (
            <div
              style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
              className="rounded-lg border p-4 shrink-0"
            >
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Next Investigation Checks</div>
              <ol className="space-y-1.5">
                {result?.nextChecks?.map((check, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                    <span className="text-slate-600 shrink-0 font-mono w-4">{i + 1}.</span>
                    {check}
                  </li>
                ))}
              </ol>
            </div>
          )}

        </div>

        {/* Right: Tabbed detail panel */}
        <div className="w-80 shrink-0 flex flex-col overflow-hidden">
          {/* Tabs */}
          <div
            style={{ borderColor: 'var(--border)' }}
            className="flex border-b mb-3 shrink-0"
          >
            {[
              { key: 'evidence', label: 'Evidence' },
              { key: 'policy', label: 'Policy' },
              { key: 'threats', label: 'Threats' },
              { key: 'remediation', label: 'Remediation' },
            ].map(tab => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as typeof activeTab)}
                className={cn(
                  'flex-1 px-2 py-2 text-xs font-medium transition-colors border-b-2 -mb-px',
                  activeTab === tab.key
                    ? 'border-blue-500 text-blue-300'
                    : 'border-transparent text-slate-500 hover:text-slate-300'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 min-h-0 overflow-y-auto">
            {activeTab === 'evidence' && (
              <EvidencePanel
                evidence={result?.evidence || []}
                selectedNode={selectedNode}
              />
            )}

            {activeTab === 'policy' && (
              <PolicyConflictPanel
                policyAnalysis={result?.policyAnalysis || null}
                conflicts={result?.conflicts || []}
              />
            )}

            {activeTab === 'threats' && (
              <div className="space-y-2">
                {!result?.threatTechniques?.length && (
                  <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-4 text-xs text-slate-600 text-center">
                    Threat context will appear after investigation
                  </div>
                )}
                {result?.threatTechniques?.map((t) => (
                  <div
                    key={t.techniqueId}
                    style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}
                    className="rounded-lg border p-3 text-xs"
                  >
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className="font-mono font-bold text-red-400">{t.techniqueId}</span>
                      <span className={cn(
                        'px-1.5 py-0.5 rounded text-[10px] border',
                        severityBg(t.severity)
                      )}>
                        {t.severity?.toUpperCase()}
                      </span>
                    </div>
                    <div className="font-medium text-slate-200 mb-1">{t.name}</div>
                    <div className="text-slate-500 leading-relaxed mb-2">{t.description}</div>
                    {t.tactics?.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {t.tactics.map((tac: string) => (
                          <span key={tac} className="px-1.5 py-0.5 rounded text-[10px] bg-red-950/40 border border-red-900/30 text-red-400">
                            {tac}
                          </span>
                        ))}
                      </div>
                    )}
                    {t.cloudContext && (
                      <div className="mt-2 pt-2 border-t border-slate-800 text-slate-500 leading-relaxed">
                        <span className="font-medium text-slate-400">Cloud Context: </span>
                        {t.cloudContext}
                      </div>
                    )}
                    {t.externalUrl && (
                      <a
                        href={t.externalUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="mt-2 flex items-center gap-1 text-blue-400 hover:text-blue-300 text-[11px]"
                      >
                        View on MITRE ATT&CK →
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}

            {activeTab === 'remediation' && (
              result ? (
                <RemediationWorkflow
                  result={result}
                  investigationDocId={investigationDocId}
                  currentStatus={investigationStatus}
                  onStatusChange={setInvestigationStatus}
                />
              ) : (
                <div style={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }} className="rounded-lg border p-6 text-center text-xs text-slate-600">
                  Run the investigation first to view remediation options.
                </div>
              )
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
