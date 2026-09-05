
'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  LayoutDashboard,
  History,
  Trash2,
  Disc3,
  Settings,
  Package,
  Eye,
  Search,
  Gamepad2,
  ChevronLeft,
  ChevronRight,
  Shield,
  Layers,
  Lock,
  Sparkles
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { isFarisLocked, showNavigationLockedAlert } from '@/lib/faris-lock';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

export const workerNavItems = [
  { href: '/worker/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/worker/wipe', icon: Trash2, label: 'Secure Wipe' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector' },
  { href: '/swarm', icon: Gamepad2, label: 'Fragment Hunter' },
  { href: '/worker/history', icon: History, label: 'Audit & Reports' },
  { href: '/iso-mode', icon: Disc3, label: 'ISO Boot Mode' },
];

export const masterNavItems = [
  { href: '/master/dashboard', icon: LayoutDashboard, label: 'Master Dashboard' },
  { href: '/wipe', icon: Trash2, label: 'Secure Wipe' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector' },
  { href: '/swarm', icon: Gamepad2, label: 'Fragment Hunter' },
  { href: '/history', icon: History, label: 'Audit & Certificates' },
  { href: '/admin', icon: ShieldCheck, label: 'Compliance Admin' },
  { href: '/master/cart', icon: Package, label: 'Hardware Shop' },
];

function getRoleFromCookie() {
  if (typeof window === 'undefined') return 'worker';
  const match = document.cookie.match(/(?:^|; )userRole=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : 'worker';
}

export default function AppSidebar() {
  const pathname = usePathname();
  const [role, setRole] = React.useState('worker');
  const [mounted, setMounted] = React.useState(false);
  const [isLocked, setIsLocked] = React.useState(false);
  const [isExpanded, setIsExpanded] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
    setRole(getRoleFromCookie());
    setIsLocked(isFarisLocked());

    // Load saved sidebar state
    const saved = localStorage.getItem('securewipe_sidebar_expanded');
    if (saved !== null) {
      setIsExpanded(saved === 'true');
    }

    const handleLockChange = (e: any) => {
      setIsLocked(Boolean(e.detail?.locked ?? isFarisLocked()));
    };

    window.addEventListener('faris-lock-change', handleLockChange);
    return () => {
      window.removeEventListener('faris-lock-change', handleLockChange);
    };
  }, [pathname]);

  const toggleExpand = () => {
    const next = !isExpanded;
    setIsExpanded(next);
    localStorage.setItem('securewipe_sidebar_expanded', String(next));
    window.dispatchEvent(new CustomEvent('sidebar-expand-change', { detail: { expanded: next } }));
  };

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
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-16 flex-col border-r bg-card/95 backdrop-blur-md md:flex"></aside>
    );
  }

  const isMaster = role === 'master';
  const base_path = isMaster ? '/master' : '/worker';
  const items = isMaster ? masterNavItems : workerNavItems;

  return (
    <aside
      className={cn(
        'fixed inset-y-0 left-0 z-30 hidden md:flex flex-col border-r bg-card/95 backdrop-blur-md transition-all duration-300 shadow-sm',
        isExpanded ? 'w-60' : 'w-16'
      )}
    >
      <TooltipProvider delayDuration={150}>
        {/* Brand / Logo Header */}
        <div className="flex h-16 items-center px-3 border-b">
          <Link
            href={`${base_path}/dashboard`}
            onClick={(e) => handleNavClick(e, `${base_path}/dashboard`)}
            className={cn(
              'flex items-center gap-3 rounded-lg overflow-hidden group focus:outline-none',
              isExpanded ? 'w-full px-2' : 'justify-center w-full'
            )}
          >
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-tr from-primary to-blue-600 text-primary-foreground shadow-md transition-transform group-hover:scale-105">
              <ShieldCheck className="h-5 w-5" />
            </div>
            {isExpanded && (
              <div className="flex flex-col min-w-0 transition-opacity duration-300">
                <span className="font-bold text-sm tracking-tight text-foreground truncate">
                  SecureWipe
                </span>
                <span className="text-[10px] text-muted-foreground font-medium uppercase tracking-wider truncate">
                  {isMaster ? 'Master Control' : 'Operator Suite'}
                </span>
              </div>
            )}
          </Link>
        </div>

        {/* Lock Banner if FARIS Active */}
        {isLocked && isExpanded && (
          <div className="m-3 p-2 rounded-md bg-amber-500/10 border border-amber-500/20 text-amber-600 dark:text-amber-400 text-xs flex items-center gap-2">
            <Lock className="h-4 w-4 shrink-0 animate-pulse" />
            <span className="text-[11px] leading-tight font-medium">
              Forensic Recovery Locked
            </span>
          </div>
        )}

        {/* Main Nav Items */}
        <nav className="flex-1 space-y-1 p-2 overflow-y-auto overflow-x-hidden">
          {items.map((item) => {
            const isActive =
              pathname === item.href ||
              (item.href !== '/dashboard' &&
                item.href !== '/master/dashboard' &&
                item.href !== '/worker/dashboard' &&
                pathname.startsWith(`${item.href}/`));

            const isItemLocked = isLocked && item.href !== '/faris';

            const linkContent = (
              <Link
                href={item.href}
                onClick={(e) => handleNavClick(e, item.href)}
                className={cn(
                  'flex items-center gap-3 rounded-lg transition-all text-sm font-medium',
                  isExpanded ? 'px-3 py-2.5 w-full' : 'h-10 w-10 justify-center mx-auto',
                  isActive
                    ? 'bg-primary text-primary-foreground shadow-sm'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  isItemLocked && 'opacity-50 cursor-not-allowed hover:bg-transparent'
                )}
              >
                <item.icon className="h-4 w-4 shrink-0" />
                {isExpanded && (
                  <span className="truncate flex-1 text-xs font-semibold">
                    {item.label}
                  </span>
                )}
                {isExpanded && isItemLocked && (
                  <Lock className="h-3 w-3 text-muted-foreground shrink-0" />
                )}
              </Link>
            );

            if (!isExpanded) {
              return (
                <Tooltip key={item.href}>
                  <TooltipTrigger asChild>{linkContent}</TooltipTrigger>
                  <TooltipContent side="right" className="text-xs font-medium">
                    {isItemLocked
                      ? `${item.label} (Locked during recovery)`
                      : item.label}
                  </TooltipContent>
                </Tooltip>
              );
            }

            return <div key={item.href}>{linkContent}</div>;
          })}
        </nav>

        {/* Footer / Toggle & Settings */}
        <div className="mt-auto border-t p-2 space-y-1">
          {/* Collapse Toggle Button */}
          <Button
            variant="ghost"
            size="sm"
            onClick={toggleExpand}
            className={cn(
              'text-muted-foreground hover:text-foreground text-xs w-full justify-center',
              isExpanded ? 'flex items-center justify-between px-3' : 'h-10 w-10 p-0 mx-auto'
            )}
            title={isExpanded ? 'Collapse Sidebar' : 'Expand Sidebar'}
          >
            {isExpanded ? (
              <>
                <span className="text-[11px] font-medium">Collapse Menu</span>
                <ChevronLeft className="h-4 w-4" />
              </>
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </Button>

          {/* Role Status Tag */}
          {isExpanded && (
            <div className="pt-2 px-3 pb-1 flex items-center justify-between border-t border-border/40 text-[11px] text-muted-foreground">
              <span className="font-medium">Active Role</span>
              <Badge variant="outline" className="text-[10px] uppercase font-bold py-0">
                {role}
              </Badge>
            </div>
          )}
        </div>
      </TooltipProvider>
    </aside>
  );
}

