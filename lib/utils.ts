// lib/utils.ts — shared utility functions

import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { Severity } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityColor(severity: Severity | string): string {
  switch (severity) {
    case 'critical': return '#ef4444';
    case 'high': return '#f97316';
    case 'medium': return '#eab308';
    case 'low': return '#22c55e';
    default: return '#60a5fa';
  }
}

export function severityBg(severity: Severity | string): string {
  switch (severity) {
    case 'critical': return 'bg-red-950/60 border-red-900/50 text-red-300';
    case 'high': return 'bg-orange-950/60 border-orange-900/50 text-orange-300';
    case 'medium': return 'bg-yellow-950/60 border-yellow-900/50 text-yellow-300';
    case 'low': return 'bg-green-950/60 border-green-900/50 text-green-300';
    default: return 'bg-blue-950/60 border-blue-900/50 text-blue-300';
  }
}

export function severityIcon(severity: Severity | string): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'medium': return '🟡';
    case 'low': return '🟢';
    default: return '⚪';
  }
}

export function statusColor(status: string): string {
  switch (status) {
    case 'open': return 'text-orange-400';
    case 'investigating': return 'text-blue-400';
    case 'remediated': return 'text-green-400';
    case 'closed': return 'text-slate-400';
    case 'approved': return 'text-green-400';
    case 'rejected': return 'text-red-400';
    case 'pending_review': return 'text-yellow-400';
    case 'analysis_complete': return 'text-blue-400';
    case 'remediation_proposed': return 'text-purple-400';
    default: return 'text-slate-400';
  }
}

export function statusLabel(status: string): string {
  const labels: Record<string, string> = {
    open: 'Open',
    investigating: 'Investigating',
    remediated: 'Remediated',
    closed: 'Closed',
    approved: 'Approved',
    rejected: 'Rejected',
    pending_review: 'Pending Review',
    analysis_complete: 'Analysis Complete',
    remediation_proposed: 'Remediation Proposed',
    verified: 'Verified',
    false_positive: 'False Positive',
    accepted: 'Accepted Risk',
  };
  return labels[status] || status;
}

export function formatDate(dateStr: string | undefined): string {
  if (!dateStr) return 'Unknown';
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return dateStr;
  }
}

export function formatDateTime(dateStr: string | undefined): string {
  if (!dateStr) return 'Unknown';
  try {
    return new Date(dateStr).toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return dateStr;
  }
}

export function categoryLabel(category: string): string {
  const labels: Record<string, string> = {
    data_exposure: 'Data Exposure',
    iam: 'Identity & Access',
    network: 'Network Security',
    logging: 'Logging & Monitoring',
    encryption: 'Encryption',
    drift: 'Configuration Drift',
    compliance: 'Compliance',
  };
  return labels[category] || category;
}

export function authorityLabel(authority: string): string {
  const labels: Record<string, string> = {
    aws: 'AWS',
    mitre: 'MITRE ATT&CK',
    cis: 'CIS',
    nist: 'NIST',
    internal: 'Internal',
    vendor: 'Vendor',
    other: 'Other',
  };
  return labels[authority] || authority;
}
