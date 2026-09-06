'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  History,
  ShieldCheck,
  Eye,
  Trash2,
  Building2,
  Lock,
  Search,
  LayoutDashboard,
  Activity,
  ShoppingBag,
  FolderLock,
  Layers,
  FileCheck2,
  Disc,
  LifeBuoy,
  Network,
  Wrench,
  Gavel,
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { isFarisLocked, showNavigationLockedAlert } from '@/lib/faris-lock';

const individualNavItems = [
  { href: '/individual/dashboard', icon: LayoutDashboard, label: 'User Dashboard' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/wipe', icon: Trash2, label: 'Secure Sanitization' },
  { href: '/assessment', icon: Activity, label: 'Residual Assessment' },
  { href: '/history', icon: History, label: 'Certificates & Records' },
  { href: '/individual/marketplace', icon: ShoppingBag, label: 'Private Marketplace' },
];

const governmentNavItems = [
  { href: '/government/dashboard', icon: Building2, label: 'Fleet & LAN Command' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/wipe', icon: Trash2, label: 'Managed & Remote Wipe' },
  { href: '/government/auction', icon: Gavel, label: 'Forward Auction & Buy-Back' },
  { href: '/swarm', icon: Layers, label: 'Swarm Cluster' },
  { href: '/government/audit', icon: Activity, label: 'Tamper-Evident Audit' },
  { href: '/lifecycle', icon: ShieldCheck, label: 'Lifecycle Readiness' },
  { href: '/history', icon: History, label: 'Compliance Reports' },
];

const forensicNavItems = [
  { href: '/forensic/dashboard', icon: Search, label: 'Forensic Workbench' },
  { href: '/forensic/seek-help', icon: LifeBuoy, label: 'Seek Help (Acquire Case)' },
  { href: '/forensic/evidence-graph', icon: Network, label: 'Evidence Relationship Graph' },
  { href: '/forensic/toolkit', icon: Wrench, label: 'Forensic Toolkit' },
  { href: '/inspector', icon: Eye, label: 'Read-Only Hex Inspector' },
  { href: '/faris', icon: FolderLock, label: 'FARIS Deep Recovery' },
  { href: '/assessment', icon: Activity, label: 'Residual Evidence Check' },
  { href: '/history', icon: FileCheck2, label: 'Case Reports & Chain' },
];

const hunterNavItems = [
  { href: '/hunter/dashboard', icon: LifeBuoy, label: 'Forensic Case Investigations' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/faris', icon: FolderLock, label: 'FARIS Deep Recovery' },
  { href: '/forensic/toolkit', icon: Wrench, label: 'Forensic Toolkit' },
  { href: '/assessment', icon: Activity, label: 'Residual Evidence Check' },
  { href: '/history', icon: FileCheck2, label: 'Case Reports & Records' },
];

const legacyWorkerNavItems = [
  { href: '/individual/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/wipe', icon: Trash2, label: 'Secure Sanitization' },
  { href: '/assessment', icon: Activity, label: 'Residual Assessment' },
  { href: '/history', icon: History, label: 'History & Audit' },
];

function getRoleFromCookie(): string {
  if (typeof window === 'undefined') return 'individual';
  const roleMatch = document.cookie.match(/(?:^|; )userRole=([^;]*)/);
  if (roleMatch) return decodeURIComponent(roleMatch[1]);
  const sessionMatch = document.cookie.match(/(?:^|; )session=([^;]*)/);
  if (sessionMatch) {
    try {
      const parsed = JSON.parse(decodeURIComponent(sessionMatch[1]));
      return parsed.role || 'individual';
    } catch {
      return 'individual';
    }
  }
  return 'individual';
}

export default function AppSidebar() {
  const pathname = usePathname();
  const [role, setRole] = React.useState('individual');
  const [mounted, setMounted] = React.useState(false);
  const [isLocked, setIsLocked] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
    setRole(getRoleFromCookie());
    setIsLocked(isFarisLocked());

    const handleLockChange = (e: any) => {
      setIsLocked(Boolean(e.detail?.locked ?? isFarisLocked()));
    };

    window.addEventListener('faris-lock-change', handleLockChange);
    return () => {
      window.removeEventListener('faris-lock-change', handleLockChange);
    };
  }, [pathname]);

  const handleNavClick = (e: React.MouseEvent, targetHref: string) => {
    if (isFarisLocked()) {
      if (targetHref !== '/faris' && !targetHref.startsWith('/faris/')) {
        e.preventDefault();
        e.stopPropagation();
        showNavigationLockedAlert();
      }
    }
  };

  if (!mounted) {
    return (
      <aside className="fixed inset-y-0 left-0 z-10 hidden w-14 flex-col border-r bg-background sm:flex"></aside>
    );
  }

  let items = individualNavItems;
  let homeHref = '/individual/dashboard';

  if (role === 'government') {
    items = governmentNavItems;
    homeHref = '/government/dashboard';
  } else if (role === 'forensic') {
    items = forensicNavItems;
    homeHref = '/forensic/dashboard';
  } else if (role === 'hunter') {
    items = hunterNavItems;
    homeHref = '/hunter/dashboard';
  } else if (role === 'worker' || role === 'master') {
    items = legacyWorkerNavItems;
    homeHref = '/individual/dashboard';
  }

  return (
    <aside className="fixed inset-y-0 left-0 z-40 hidden w-64 flex-col border-r border-slate-800/80 bg-background md:flex shadow-2xl">
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-800/80">
        <Link
          href={homeHref}
          onClick={(e) => handleNavClick(e, homeHref)}
          className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 to-blue-700 text-white shadow-lg shadow-cyan-950/50 transition-transform hover:scale-105"
        >
          <ShieldCheck className="h-5 w-5" />
        </Link>
        <div className="flex flex-col">
          <span className="text-sm font-extrabold tracking-wider text-white">SECUREWIPE</span>
          <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-widest">NTRO DEFENSE PLATFORM</span>
        </div>
      </div>

      <TooltipProvider>
        {/* Nav Items */}
        <div className="flex-1 overflow-y-auto px-3 py-4 space-y-6">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 px-3 mb-2 font-semibold">
              Operational Workspace
            </div>
            <nav className="space-y-1">
              {items.map((item) => {
                const isActive = pathname === item.href || (item.href !== '/' && pathname.startsWith(`${item.href}/`));
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={(e) => handleNavClick(e, item.href)}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all group',
                      isActive
                        ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-sm font-semibold'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-900/80',
                      isLocked && item.href !== '/faris' && 'opacity-50 cursor-not-allowed'
                    )}
                  >
                    <item.icon className={cn('h-4 w-4 shrink-0 transition-transform group-hover:scale-110', isActive ? 'text-cyan-400' : 'text-slate-400')} />
                    <span className="truncate">{item.label}</span>
                    {isActive && (
                      <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/80" />
                    )}
                  </Link>
                );
              })}
            </nav>
          </div>

          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-slate-500 px-3 mb-2 font-semibold">
              Direct Persona Switch
            </div>
            <nav className="space-y-1">
              <Link
                href="/individual/dashboard"
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-all"
              >
                <LayoutDashboard className="h-3.5 w-3.5 text-cyan-400" />
                <span>Individual User</span>
              </Link>
              <Link
                href="/government/dashboard"
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-all"
              >
                <Building2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Government Fleet</span>
              </Link>
              <Link
                href="/forensic/dashboard"
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-all"
              >
                <Search className="h-3.5 w-3.5 text-amber-400" />
                <span>Forensic Workbench</span>
              </Link>
              <Link
                href="/hunter/dashboard"
                className="flex items-center gap-3 px-3 py-2 rounded-lg text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 transition-all"
              >
                <Disc className="h-3.5 w-3.5 text-purple-400" />
                <span>Hunter Console</span>
              </Link>
            </nav>
          </div>
        </div>

        {/* Bottom Operator Profile Card */}
        <div className="p-3 border-t border-slate-800/80 bg-background/80">
          <div className="flex items-center justify-between p-2 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="relative">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-800 border border-slate-700 text-xs font-bold text-cyan-400">
                  {role.slice(0, 2).toUpperCase()}
                </div>
                <span className="absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-background" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-xs font-semibold text-white truncate">
                  {role === 'government'
                    ? 'gov_officer'
                    : role === 'forensic'
                    ? 'forensic_analyst'
                    : role === 'hunter'
                    ? 'hunter_agent'
                    : 'citizen_user'}
                </div>
                <div className="text-[10px] text-cyan-400 font-mono uppercase tracking-wider truncate">
                  {role}
                </div>
              </div>
            </div>
            <Link
              href="/login"
              title="Switch Persona / Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <Lock className="h-3.5 w-3.5" />
            </Link>
          </div>
        </div>
      </TooltipProvider>
    </aside>
  );
}
