'use client';

import { useState } from 'react';
import { Cloud, Trash2, Play, Clock, AlertTriangle, CheckCircle, WifiOff, Loader2, MoreVertical } from 'lucide-react';
import type { CloudAccount } from '@/lib/scanners/types';

interface Props {
  account: CloudAccount;
  onScan: (accountId: string) => void;
  onDelete: (accountId: string) => void;
}

const SEVERITY_COLORS = { critical: 'text-red-400 bg-red-950/60 border-red-800/50', high: 'text-orange-400 bg-orange-950/60 border-orange-800/50' };

const STATUS_CONFIG = {
  connected: { icon: CheckCircle, color: 'text-emerald-400', bg: 'bg-emerald-950/40 border-emerald-800/40', label: 'Connected' },
  scanning: { icon: Loader2, color: 'text-blue-400', bg: 'bg-blue-950/40 border-blue-800/40', label: 'Scanning…' },
  error: { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-950/40 border-red-800/40', label: 'Error' },
  disconnected: { icon: WifiOff, color: 'text-slate-500', bg: 'bg-slate-800/40 border-slate-700/40', label: 'Disconnected' },
};

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function AccountCard({ account, onScan, onDelete }: Props) {
  const [menuOpen, setMenuOpen] = useState(false);
  const status = STATUS_CONFIG[account.status] ?? STATUS_CONFIG.disconnected;
  const StatusIcon = status.icon;
  const isScanning = account.status === 'scanning';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors relative">
      {/* Header row */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center text-lg ${account.provider === 'aws' ? 'bg-orange-950/60 text-orange-400' : 'bg-blue-950/60 text-blue-400'}`}>
            {account.provider === 'aws' ? '☁' : '⬡'}
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm">{account.name}</h3>
            <p className="text-xs text-slate-500 font-mono mt-0.5">{account.cloudAccountId}</p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-medium ${status.bg} ${status.color}`}>
            <StatusIcon className={`w-3 h-3 ${isScanning ? 'animate-spin' : ''}`} />
            {status.label}
          </span>
          <div className="relative">
            <button onClick={() => setMenuOpen(!menuOpen)} className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-500 hover:text-slate-300 transition-colors">
              <MoreVertical className="w-4 h-4" />
            </button>
            {menuOpen && (
              <div className="absolute right-0 top-8 z-10 w-36 bg-slate-800 border border-slate-700 rounded-lg shadow-xl py-1">
                <button onClick={() => { setMenuOpen(false); onDelete(account._id); }} className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-950/30 transition-colors">
                  <Trash2 className="w-3.5 h-3.5" /> Delete
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Finding counts */}
      {(account.lastScanFindingCount ?? 0) > 0 ? (
        <div className="flex items-center gap-2 mb-4">
          {(account.lastScanCriticalCount ?? 0) > 0 && (
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${SEVERITY_COLORS.critical}`}>
              <AlertTriangle className="w-3 h-3" /> {account.lastScanCriticalCount} Critical
            </span>
          )}
          {(account.lastScanHighCount ?? 0) > 0 && (
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${SEVERITY_COLORS.high}`}>
              {account.lastScanHighCount} High
            </span>
          )}
          <span className="text-xs text-slate-500">{account.lastScanFindingCount} total findings</span>
        </div>
      ) : account.lastScannedAt ? (
        <p className="text-xs text-emerald-500 mb-4">✓ No findings on last scan</p>
      ) : (
        <p className="text-xs text-slate-600 mb-4">Not yet scanned</p>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <Clock className="w-3 h-3" />
          {account.lastScannedAt ? `Scanned ${timeAgo(account.lastScannedAt)}` : 'Never scanned'}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-slate-500">
          <Cloud className="w-3 h-3" />
          {(account.regions ?? []).length} region{(account.regions ?? []).length !== 1 ? 's' : ''}
        </div>
        <button
          onClick={() => onScan(account._id)}
          disabled={isScanning}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg text-xs text-slate-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {isScanning ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3" />}
          {isScanning ? 'Scanning…' : 'Scan Now'}
        </button>
      </div>

      {/* Error message */}
      {account.status === 'error' && account.errorMessage && (
        <div className="mt-3 p-2 rounded bg-red-950/30 border border-red-800/40">
          <p className="text-xs text-red-400">{account.errorMessage}</p>
        </div>
      )}

      {/* Click outside to close menu */}
      {menuOpen && <div className="fixed inset-0 z-0" onClick={() => setMenuOpen(false)} />}
    </div>
  );
}
