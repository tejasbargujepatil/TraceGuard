'use client';

import { useState, useEffect, useCallback } from 'react';
import { Plus, Cloud, RefreshCw, Zap } from 'lucide-react';
import { AddAccountModal } from '@/components/accounts/AddAccountModal';
import { AccountCard } from '@/components/accounts/AccountCard';
import { ScanProgress } from '@/components/scan/ScanProgress';
import type { CloudAccount } from '@/lib/scanners/types';

export default function AccountsPage() {
  const [accounts, setAccounts] = useState<CloudAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [scanningAccountId, setScanningAccountId] = useState<string | null>(null);
  const [scanningAll, setScanningAll] = useState(false);
  const [error, setError] = useState('');

  const fetchAccounts = useCallback(async () => {
    try {
      const res = await fetch('/api/accounts');
      const data = await res.json() as { accounts: CloudAccount[] };
      setAccounts(data.accounts ?? []);
    } catch {
      setError('Failed to load accounts');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void fetchAccounts(); }, [fetchAccounts]);

  async function handleDelete(accountId: string) {
    if (!confirm('Delete this cloud account? This will not delete any findings already in Sanity.')) return;
    try {
      await fetch(`/api/accounts/${accountId}`, { method: 'DELETE' });
      setAccounts(prev => prev.filter(a => a._id !== accountId));
    } catch { setError('Failed to delete account'); }
  }

  function handleScanComplete(accountId: string, totalFindings: number) {
    setScanningAccountId(null);
    setAccounts(prev => prev.map(a => a._id === accountId ? { ...a, status: 'connected', lastScannedAt: new Date().toISOString(), lastScanFindingCount: totalFindings } : a));
    void fetchAccounts(); // refresh to get accurate counts
  }

  const scanningAccount = accounts.find(a => a._id === scanningAccountId);

  return (
    <div className="flex flex-col gap-6">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100">Cloud Accounts</h1>
          <p className="text-slate-400 text-sm mt-1">Connect AWS and GCP accounts to scan all services for misconfigurations.</p>
        </div>
        <div className="flex items-center gap-2">
          {accounts.length > 1 && (
            <button onClick={() => { setScanningAll(true); setScanningAccountId(accounts[0]._id); }} disabled={!!scanningAccountId} className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-sm text-slate-300 disabled:opacity-50 transition-colors">
              <Zap className="w-4 h-4" /> Scan All
            </button>
          )}
          <button onClick={() => void fetchAccounts()} className="p-2 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors" title="Refresh"><RefreshCw className="w-4 h-4" /></button>
          <button onClick={() => setModalOpen(true)} className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors">
            <Plus className="w-4 h-4" /> Add Account
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/50 text-red-300 text-sm">{error}</div>
      )}

      {/* Active scan */}
      {scanningAccount && scanningAccountId && (
        <div className="mt-2">
          <ScanProgress
            accountId={scanningAccountId}
            provider={scanningAccount.provider}
            accountName={scanningAccount.name}
            onComplete={(total) => handleScanComplete(scanningAccountId, total)}
            onCancel={() => setScanningAccountId(null)}
          />
        </div>
      )}

      {/* Empty state */}
      {!loading && accounts.length === 0 && (
        <div className="flex flex-col items-center justify-center py-24 gap-6 text-center">
          <div className="w-20 h-20 rounded-2xl bg-slate-800/60 border border-slate-700 flex items-center justify-center">
            <Cloud className="w-10 h-10 text-slate-600" />
          </div>
          <div>
            <h2 className="text-xl font-semibold text-slate-200">No cloud accounts connected</h2>
            <p className="text-slate-400 text-sm mt-2 max-w-md">Connect your AWS or GCP account to start scanning all services for security misconfigurations, policy violations, and compliance gaps.</p>
          </div>
          <button onClick={() => setModalOpen(true)} className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white font-medium rounded-xl transition-colors">
            <Plus className="w-5 h-5" /> Connect Cloud Account
          </button>
          <div className="flex items-center gap-8 text-xs text-slate-500 mt-2">
            <span>✓ 20+ AWS services</span>
            <span>✓ 10+ GCP services</span>
            <span>✓ AES-256 encrypted credentials</span>
            <span>✓ Read-only permissions</span>
          </div>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[1, 2].map(i => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-xl p-5 animate-pulse">
              <div className="flex items-center gap-3 mb-4"><div className="w-10 h-10 bg-slate-800 rounded-lg" /><div className="space-y-2"><div className="h-4 w-32 bg-slate-800 rounded" /><div className="h-3 w-24 bg-slate-800 rounded" /></div></div>
              <div className="h-8 bg-slate-800 rounded mb-4" />
              <div className="flex justify-between"><div className="h-3 w-24 bg-slate-800 rounded" /><div className="h-6 w-20 bg-slate-800 rounded" /></div>
            </div>
          ))}
        </div>
      )}

      {/* Accounts grid */}
      {!loading && accounts.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {accounts.map(account => (
            <AccountCard
              key={account._id}
              account={account}
              onScan={(id) => setScanningAccountId(id)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {/* How it works section */}
      {!loading && accounts.length === 0 && (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { step: '1', title: 'Connect', desc: 'Add your AWS or GCP credentials. They are encrypted with AES-256-GCM before storage.' },
            { step: '2', title: 'Scan', desc: 'TraceGuard scans all services — S3, IAM, EC2, RDS, Lambda, and 15+ more services per provider.' },
            { step: '3', title: 'Investigate', desc: 'Every finding includes step-by-step remediation, CLI commands, Terraform snippets, and compliance mappings.' },
          ].map(item => (
            <div key={item.step} className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
              <div className="w-7 h-7 rounded-full bg-blue-950/60 border border-blue-800/40 flex items-center justify-center text-sm font-bold text-blue-400 mb-3">{item.step}</div>
              <h3 className="font-semibold text-slate-200 mb-1">{item.title}</h3>
              <p className="text-sm text-slate-400">{item.desc}</p>
            </div>
          ))}
        </div>
      )}

      <AddAccountModal open={modalOpen} onClose={() => setModalOpen(false)} onSuccess={() => { setModalOpen(false); void fetchAccounts(); }} />
    </div>
  );
}
