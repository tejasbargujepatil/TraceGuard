'use client';

import { useState, useEffect, useRef } from 'react';
import { CheckCircle, XCircle, Clock, Loader2, X, AlertTriangle, ChevronRight } from 'lucide-react';
import type { ServiceScanResult } from '@/lib/scanners/types';

const AWS_SERVICES = [
  { key: 's3', label: 'S3 Buckets' }, { key: 'iam', label: 'IAM Users & Roles' },
  { key: 'ec2', label: 'EC2 & Security Groups' }, { key: 'vpc', label: 'VPC & Networking' },
  { key: 'rds', label: 'RDS Databases' }, { key: 'lambda', label: 'Lambda Functions' },
  { key: 'eks', label: 'EKS Clusters' }, { key: 'cloudtrail', label: 'CloudTrail' },
  { key: 'kms', label: 'KMS Keys' }, { key: 'secretsmanager', label: 'Secrets Manager' },
  { key: 'acm', label: 'ACM Certificates' }, { key: 'dynamodb', label: 'DynamoDB Tables' },
  { key: 'sqs', label: 'SQS Queues' }, { key: 'sns', label: 'SNS Topics' },
  { key: 'cloudfront', label: 'CloudFront' }, { key: 'guardduty', label: 'GuardDuty' },
  { key: 'securityhub', label: 'Security Hub' }, { key: 'config', label: 'AWS Config' },
  { key: 'redshift', label: 'Redshift' }, { key: 'opensearch', label: 'OpenSearch' },
];

const GCP_SERVICES = [
  { key: 'gcs', label: 'Cloud Storage' }, { key: 'gcpiam', label: 'GCP IAM' },
  { key: 'compute', label: 'Compute Engine' }, { key: 'cloudsql', label: 'Cloud SQL' },
  { key: 'bigquery', label: 'BigQuery' }, { key: 'functions', label: 'Cloud Functions' },
  { key: 'gke', label: 'GKE Clusters' }, { key: 'kms', label: 'Cloud KMS' },
  { key: 'logging', label: 'Cloud Logging' },
];

interface Props {
  accountId: string;
  provider: 'aws' | 'gcp';
  accountName: string;
  onComplete: (totalFindings: number) => void;
  onCancel: () => void;
}

type ServiceStatus = 'pending' | 'running' | 'complete' | 'error' | 'skipped' | 'cancelled';

interface ServiceState {
  key: string;
  label: string;
  status: ServiceStatus;
  findingCount: number;
  error?: string;
  durationMs?: number;
}

function SeveritySummary({ results }: { results: ServiceScanResult[] }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of results) {
    for (const f of r.findings) {
      if (f.severity in counts) counts[f.severity as keyof typeof counts]++;
    }
  }
  if (!Object.values(counts).some(Boolean)) return <span className="text-emerald-400 text-sm">✓ No findings detected</span>;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {counts.critical > 0 && <span className="px-2 py-0.5 rounded border text-xs font-medium text-red-400 bg-red-950/60 border-red-800/50">{counts.critical} Critical</span>}
      {counts.high > 0 && <span className="px-2 py-0.5 rounded border text-xs font-medium text-orange-400 bg-orange-950/60 border-orange-800/50">{counts.high} High</span>}
      {counts.medium > 0 && <span className="px-2 py-0.5 rounded border text-xs font-medium text-yellow-400 bg-yellow-950/60 border-yellow-800/50">{counts.medium} Medium</span>}
      {counts.low > 0 && <span className="px-2 py-0.5 rounded border text-xs font-medium text-slate-400 bg-slate-800/60 border-slate-700">{counts.low} Low</span>}
    </div>
  );
}

export function ScanProgress({ accountId, provider, accountName, onComplete, onCancel }: Props) {
  const services = provider === 'aws' ? AWS_SERVICES : GCP_SERVICES;
  const [serviceStates, setServiceStates] = useState<ServiceState[]>(
    services.map(s => ({ key: s.key, label: s.label, status: 'pending', findingCount: 0 }))
  );
  const [results, setResults] = useState<ServiceScanResult[]>([]);
  const [elapsedSecs, setElapsedSecs] = useState(0);
  const [done, setDone] = useState(false);
  const cancelRef = useRef(false);
  const startTime = useRef(Date.now());

  // Elapsed timer
  useEffect(() => {
    if (done) return;
    const t = setInterval(() => setElapsedSecs(Math.floor((Date.now() - startTime.current) / 1000)), 1000);
    return () => clearInterval(t);
  }, [done]);

  // Run scan
  useEffect(() => {
    cancelRef.current = false;
    (async () => {
      const collectedResults: ServiceScanResult[] = [];
      for (let i = 0; i < services.length; i++) {
        if (cancelRef.current) {
          setServiceStates(prev => prev.map((s, idx) => idx >= i ? { ...s, status: 'cancelled' } : s));
          break;
        }
        const svc = services[i];
        setServiceStates(prev => prev.map(s => s.key === svc.key ? { ...s, status: 'running' } : s));
        try {
          const res = await fetch(`/api/accounts/${accountId}/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ service: svc.key }),
          });
          const data = await res.json() as ServiceScanResult;
          collectedResults.push(data);
          setResults([...collectedResults]);
          setServiceStates(prev => prev.map(s => s.key === svc.key ? { ...s, status: data.status === 'error' ? 'error' : 'complete', findingCount: data.findingCount, error: data.error, durationMs: data.durationMs } : s));
        } catch (e) {
          setServiceStates(prev => prev.map(s => s.key === svc.key ? { ...s, status: 'error', error: (e as Error).message } : s));
        }
      }
      if (!cancelRef.current) {
        setDone(true);
        const total = collectedResults.reduce((sum, r) => sum + r.findingCount, 0);
        onComplete(total);
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accountId]);

  function handleCancel() {
    cancelRef.current = true;
    onCancel();
  }

  const completed = serviceStates.filter(s => s.status === 'complete' || s.status === 'error').length;
  const totalFindings = serviceStates.reduce((sum, s) => sum + s.findingCount, 0);
  const progress = Math.round((completed / services.length) * 100);

  function formatDuration(ms?: number) { if (!ms) return ''; return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(1)}s`; }
  function formatElapsed(s: number) { return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`; }

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-800/40">
        <div>
          <h3 className="font-semibold text-slate-100 text-sm">Scanning {accountName}</h3>
          <p className="text-xs text-slate-400 mt-0.5">
            {done ? `Complete — ${formatElapsed(elapsedSecs)} elapsed` : `${completed}/${services.length} services · ${formatElapsed(elapsedSecs)}`}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {totalFindings > 0 && (
            <span className="text-sm font-semibold text-orange-400">{totalFindings} finding{totalFindings !== 1 ? 's' : ''}</span>
          )}
          {!done && (
            <button onClick={handleCancel} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs text-slate-400 transition-colors">
              <X className="w-3 h-3" /> Cancel
            </button>
          )}
          {done && (
            <button onClick={() => window.location.href = '/findings'} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-xs text-white transition-colors">
              View Findings <ChevronRight className="w-3 h-3" />
            </button>
          )}
        </div>
      </div>

      {/* Progress bar */}
      <div className="h-1 bg-slate-800">
        <div className="h-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all duration-500" style={{ width: `${progress}%` }} />
      </div>

      {/* Severity summary (when done) */}
      {done && (
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-800/20 flex items-center gap-3">
          <span className="text-xs text-slate-400">Summary:</span>
          <SeveritySummary results={results} />
        </div>
      )}

      {/* Service list */}
      <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/50">
        {serviceStates.map(s => (
          <div key={s.key} className="flex items-center gap-3 px-5 py-2.5">
            <div className="w-5 flex justify-center shrink-0">
              {s.status === 'pending' && <Clock className="w-4 h-4 text-slate-600" />}
              {s.status === 'running' && <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />}
              {s.status === 'complete' && <CheckCircle className="w-4 h-4 text-emerald-400" />}
              {s.status === 'error' && <XCircle className="w-4 h-4 text-red-400" />}
              {s.status === 'skipped' && <ChevronRight className="w-4 h-4 text-slate-600" />}
              {s.status === 'cancelled' && <X className="w-4 h-4 text-slate-600" />}
            </div>
            <span className={`text-sm flex-1 ${s.status === 'pending' || s.status === 'cancelled' ? 'text-slate-600' : s.status === 'running' ? 'text-slate-200' : 'text-slate-300'}`}>{s.label}</span>
            <div className="flex items-center gap-2 text-xs">
              {s.durationMs && <span className="text-slate-600">{formatDuration(s.durationMs)}</span>}
              {s.status === 'complete' && s.findingCount > 0 && (
                <span className="px-2 py-0.5 rounded bg-orange-950/50 text-orange-400 border border-orange-800/40 font-medium">{s.findingCount}</span>
              )}
              {s.status === 'complete' && s.findingCount === 0 && <span className="text-slate-600">clean</span>}
              {s.status === 'error' && <span className="text-red-500 truncate max-w-32" title={s.error}>error</span>}
            </div>
          </div>
        ))}
      </div>

      {/* Footer note */}
      {!done && (
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-800/20">
          <p className="text-xs text-slate-500 flex items-center gap-1.5"><AlertTriangle className="w-3 h-3" /> Findings are saved to Sanity in real time as each service completes.</p>
        </div>
      )}
    </div>
  );
}
