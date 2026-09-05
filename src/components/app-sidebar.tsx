
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
  Undo,
  Package,
  Bomb,
  FileLock,
  Network,
  Eye,
  Search,
  Users,
  Gamepad2,
} from 'lucide-react';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { isFarisLocked, showNavigationLockedAlert } from '@/lib/faris-lock';

const workerNavItems = [
  { href: '/worker/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
  { href: '/swarm', icon: Gamepad2, label: 'Fragment Hunter (Swarm Game)' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/worker/wipe', icon: Trash2, label: 'Wipe' },
  { href: '/worker/history', icon: History, label: 'History & Audit' },
  { href: '/iso-mode', icon: Disc3, label: 'ISO Mode' },
  { href: '/worker/bomber-game', icon: Bomb, label: 'Bomber Game' },
];

const masterNavItems = [
  { href: '/master/dashboard', icon: LayoutDashboard, label: 'Master Control Panel' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
  { href: '/swarm', icon: Gamepad2, label: 'Fragment Hunter (Swarm Game)' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/dashboard', icon: ShieldCheck, label: 'Local Devices' },
  { href: '/wipe', icon: Trash2, label: 'Secure Wipe' },
  { href: '/history', icon: History, label: 'History & Audit' },
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

  const isMaster = role === 'master';
  const base_path = isMaster ? '/master' : '/worker';
  const items = isMaster ? masterNavItems : workerNavItems;

  return (
    <aside className="fixed inset-y-0 left-0 z-10 hidden w-14 flex-col border-r bg-background sm:flex">
      <TooltipProvider>
        <nav className="flex flex-col items-center gap-4 px-2 sm:py-5">
          <Link
            href={`${base_path}/dashboard`}
            onClick={(e) => handleNavClick(e, `${base_path}/dashboard`)}
            className="group flex h-9 w-9 shrink-0 items-center justify-center gap-2 rounded-full bg-primary text-lg font-semibold text-primary-foreground md:h-8 md:w-8 md:text-base"
          >
            <ShieldCheck className="h-4 w-4 transition-all group-hover:scale-110" />
            <span className="sr-only">SecureWipe</span>
          </Link>

          {items.map((item) => (
            <Tooltip key={item.href}>
              <TooltipTrigger asChild>
                <Link
                  href={item.href}
                  onClick={(e) => handleNavClick(e, item.href)}
                  className={cn(
                    'flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:text-foreground md:h-8 md:w-8',
                    (pathname === item.href || pathname.startsWith(`${item.href}/`)) && 'bg-accent text-accent-foreground',
                    isLocked && item.href !== '/faris' && 'opacity-60 cursor-not-allowed'
                  )}
                >
                  <item.icon className="h-5 w-5" />
                  <span className="sr-only">{item.label}</span>
                </Link>
              </TooltipTrigger>
              <TooltipContent side="right">
                {isLocked && item.href !== '/faris' ? `${item.label} (Locked during recovery)` : item.label}
              </TooltipContent>
            </Tooltip>
          ))}
        </nav>
        <nav className="mt-auto flex flex-col items-center gap-4 px-2 sm:py-5">
          <Tooltip>
            <TooltipTrigger asChild>
              <Link
                href="#"
                onClick={(e) => handleNavClick(e, '#')}
                className={cn(
                  "flex h-9 w-9 items-center justify-center rounded-lg text-muted-foreground transition-colors hover:text-foreground md:h-8 md:w-8",
                  isLocked && "opacity-60 cursor-not-allowed"
                )}
              >
                <Settings className="h-5 w-5" />
                <span className="sr-only">Settings</span>
              </Link>
            </TooltipTrigger>
            <TooltipContent side="right">Settings</TooltipContent>
          </Tooltip>
        </nav>
      </TooltipProvider>
    </aside>
  );
}
