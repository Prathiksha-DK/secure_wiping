'use client';

import * as React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  PanelLeft,
  ChevronRight,
  LogOut,
  User,
  Building2,
  Search,
  Eye,
  Trash2,
  LayoutDashboard,
  Layers,
  Activity,
  FolderLock,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetTrigger } from '@/components/ui/sheet';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { logout } from '@/app/actions';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';

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

export default function AppHeader() {
  const pathname = usePathname();
  const [role, setRole] = React.useState('individual');
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
    setRole(getRoleFromCookie());
  }, [pathname]);

  const pathSegments = pathname.split('/').filter(Boolean);

  const roleConfigs: Record<string, { label: string; badgeClass: string; icon: any; username: string }> = {
    individual: {
      label: 'Individual User',
      badgeClass: 'border-cyan-500/40 bg-cyan-950/40 text-cyan-300',
      icon: User,
      username: 'citizen_user',
    },
    government: {
      label: 'Government / Org',
      badgeClass: 'border-emerald-500/40 bg-emerald-950/40 text-emerald-300',
      icon: Building2,
      username: 'gov_officer',
    },
    forensic: {
      label: 'Forensic Investigator',
      badgeClass: 'border-amber-500/40 bg-amber-950/40 text-amber-300',
      icon: Search,
      username: 'forensic_analyst',
    },
    hunter: {
      label: 'Threat & Forensic Hunter',
      badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
      icon: User,
      username: 'threat_hunter',
    },
    master: {
      label: 'Master Control',
      badgeClass: 'border-purple-500/40 bg-purple-950/40 text-purple-300',
      icon: ShieldCheck,
      username: 'master_admin',
    },
    worker: {
      label: 'Operator Suite',
      badgeClass: 'border-blue-500/40 bg-blue-950/40 text-blue-300',
      icon: User,
      username: 'operator',
    },
  };

  const currentRoleConfig = roleConfigs[role] || roleConfigs.individual;
  const RoleIcon = currentRoleConfig.icon;

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-4 border-b border-slate-800/80 bg-[#090e1a]/95 px-6 backdrop-blur-md shadow-sm w-full">
      {/* Mobile Drawer */}
      <Sheet>
        <SheetTrigger asChild>
          <Button size="icon" variant="outline" className="md:hidden border-slate-800 bg-slate-900 text-slate-300">
            <PanelLeft className="h-4 w-4" />
            <span className="sr-only">Toggle Menu</span>
          </Button>
        </SheetTrigger>
        <SheetContent side="left" className="sm:max-w-xs bg-slate-950 border-slate-800 text-slate-100 p-5">
          <nav className="grid gap-4 text-sm font-medium">
            <Link
              href="/"
              className="flex items-center gap-2 text-base font-bold text-cyan-400"
            >
              <ShieldCheck className="h-5 w-5" />
              <span>SecureWipe NTRO</span>
            </Link>
            <Link href="/individual/dashboard" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <LayoutDashboard className="h-4 w-4 text-cyan-400" />
              <span>Individual Dashboard</span>
            </Link>
            <Link href="/government/dashboard" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Building2 className="h-4 w-4 text-emerald-400" />
              <span>Government Fleet</span>
            </Link>
            <Link href="/forensic/dashboard" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Search className="h-4 w-4 text-amber-400" />
              <span>Forensic Workbench</span>
            </Link>
            <div className="my-1 border-t border-slate-800/80" />
            <Link href="/inspector" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Eye className="h-4 w-4" />
              <span>Hex Inspector</span>
            </Link>
            <Link href="/wipe" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Trash2 className="h-4 w-4" />
              <span>Sanitization Engine</span>
            </Link>
            <Link href="/assessment" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Activity className="h-4 w-4" />
              <span>Residual Assessment</span>
            </Link>
            <Link href="/swarm" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <Layers className="h-4 w-4" />
              <span>Swarm Engine</span>
            </Link>
            <Link href="/faris" className="flex items-center gap-2 text-slate-300 hover:text-white">
              <FolderLock className="h-4 w-4" />
              <span>FARIS Deep Recovery</span>
            </Link>
          </nav>
        </SheetContent>
      </Sheet>

      {/* Breadcrumb Path Navigation */}
      <div className="hidden md:flex items-center gap-2 text-xs font-mono text-slate-300">
        <Link href="/" className="hover:text-cyan-300 transition-colors font-medium text-slate-400">SecureWipe</Link>
        {pathSegments.map((segment, index) => (
          <React.Fragment key={index}>
            <ChevronRight className="h-3 w-3 text-slate-500" />
            <span className={index === pathSegments.length - 1 ? 'text-white font-bold uppercase tracking-wider' : 'text-slate-300 capitalize'}>
              {segment.replace(/-/g, ' ')}
            </span>
          </React.Fragment>
        ))}
      </div>

      {/* Right-side Controls */}
      <div className="ml-auto flex items-center gap-3">
        {/* API Liveness Heartbeat */}
        <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full border border-slate-800 bg-slate-900/80 text-[11px] font-mono text-slate-300 shadow-sm">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span>Core API : 9758 Active</span>
        </div>

        {/* Role Badge */}
        <div className={`hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-mono font-medium shadow-sm ${currentRoleConfig.badgeClass}`}>
          <RoleIcon className="h-3.5 w-3.5" />
          <span>{currentRoleConfig.label}</span>
        </div>

        {/* User Dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="icon"
              className="overflow-hidden rounded-full border-slate-800 bg-slate-900 hover:border-slate-700 h-8 w-8 text-slate-200"
            >
              <Avatar className="h-8 w-8">
                <AvatarFallback className="bg-slate-800 text-xs font-bold text-cyan-400">
                  {currentRoleConfig.username.slice(0, 2).toUpperCase()}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 bg-slate-950 border-slate-800 text-slate-200 shadow-2xl">
            <DropdownMenuLabel className="font-mono text-xs">
              <div className="text-white font-semibold">{currentRoleConfig.username}</div>
              <div className="text-[10px] text-slate-400 uppercase tracking-wider">{currentRoleConfig.label}</div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem asChild className="hover:bg-slate-900 cursor-pointer">
              <Link href="/individual/dashboard" className="flex items-center gap-2 text-xs">
                <User className="h-3.5 w-3.5 text-cyan-400" />
                <span>Individual User View</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild className="hover:bg-slate-900 cursor-pointer">
              <Link href="/government/dashboard" className="flex items-center gap-2 text-xs">
                <Building2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Government Fleet View</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild className="hover:bg-slate-900 cursor-pointer">
              <Link href="/forensic/dashboard" className="flex items-center gap-2 text-xs">
                <Search className="h-3.5 w-3.5 text-amber-400" />
                <span>Forensic Workbench View</span>
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-slate-800" />
            <DropdownMenuItem
              onClick={() => logout()}
              className="text-red-400 hover:text-red-300 hover:bg-red-950/30 cursor-pointer text-xs flex items-center gap-2"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span>Sign Out Session</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
