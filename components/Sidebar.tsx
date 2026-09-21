'use client';

// Sidebar navigation component

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldAlert, Search, AlertTriangle, Server, Database,
  BookOpen, FileText, Swords, Wrench, LogOut, ChevronRight, Cloud
} from 'lucide-react';
import { cn } from '@/lib/utils';

const navItems = [
  { href: '/', label: 'Overview', icon: ShieldAlert },
  { href: '/accounts', label: 'Cloud Accounts', icon: Cloud },
  { href: '/investigations', label: 'Investigations', icon: Search },
  { href: '/findings', label: 'Findings', icon: AlertTriangle },
  { href: '/assets', label: 'Assets', icon: Server },
  { href: '/knowledge', label: 'Knowledge', icon: BookOpen },
  { href: '/policies', label: 'Policies', icon: FileText },
  { href: '/threats', label: 'Threats', icon: Swords },
  { href: '/remediations', label: 'Remediations', icon: Wrench },
];


export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      style={{ backgroundColor: 'var(--bg-surface)', borderColor: 'var(--border)' }}
      className="w-56 min-h-screen flex flex-col border-r shrink-0"
    >
      {/* Logo */}
      <div
        style={{ borderColor: 'var(--border)' }}
        className="px-4 py-5 border-b"
      >
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-blue-600 flex items-center justify-center">
            <ShieldAlert size={15} className="text-white" />
          </div>
          <div>
            <div className="font-semibold text-sm tracking-tight text-slate-100">
              TraceGuard
            </div>
            <div className="text-[10px] text-slate-500 uppercase tracking-wider">
              Security AI
            </div>
          </div>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-2 py-3 space-y-0.5">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || (href !== '/' && pathname.startsWith(href));
          return (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-2.5 px-3 py-2 rounded-md text-sm transition-colors',
                active
                  ? 'bg-blue-600/20 text-blue-300 font-medium'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              )}
            >
              <Icon size={15} />
              {label}
              {active && <ChevronRight size={12} className="ml-auto opacity-60" />}
            </Link>
          );
        })}
      </nav>

      {/* Bottom: Studio link + env badge */}
      <div style={{ borderColor: 'var(--border)' }} className="px-3 py-3 border-t space-y-2">
        <Link
          href="/studio"
          className="flex items-center gap-2 px-3 py-2 rounded-md text-xs text-slate-500 hover:text-slate-300 hover:bg-slate-800/50 transition-colors"
        >
          <Database size={13} />
          Sanity Studio
          <LogOut size={11} className="ml-auto" />
        </Link>
        <div className="px-2 py-1.5 rounded text-[10px] text-center text-yellow-600 bg-yellow-950/40 border border-yellow-900/30 leading-tight">
          ⚠ Synthetic Environment
          <br />
          <span className="text-yellow-700">Demo Purposes Only</span>
        </div>
      </div>
    </aside>
  );
}
