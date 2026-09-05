
'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  PanelLeft,
  Search,
  LogOut,
  Settings,
  Lock,
  User
} from 'lucide-react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuItem,
} from '@/components/ui/dropdown-menu';
import {
  Breadcrumb,
  BreadcrumbList,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbSeparator,
  BreadcrumbPage,
} from '@/components/ui/breadcrumb';
import { ThemeToggle } from '@/components/theme-toggle';
import { logout } from '@/app/actions';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { isFarisLocked, showNavigationLockedAlert } from '@/lib/faris-lock';
import { workerNavItems, masterNavItems } from '@/components/app-sidebar';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';

function getRoleFromCookie() {
  if (typeof window === 'undefined') return 'worker';
  const match = document.cookie.match(/(?:^|; )userRole=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : 'worker';
}

export default function AppHeader() {
  const pathname = usePathname();
  const pathSegments = pathname.split('/').filter(Boolean);
  const [role, setRole] = React.useState('worker');
  const [mounted, setMounted] = React.useState(false);
  const [isLocked, setIsLocked] = React.useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = React.useState(false);

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
        return;
      }
    }
    setMobileMenuOpen(false);
  };

  if (!mounted) {
    return (
      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b bg-background/80 backdrop-blur-md px-4 sm:px-6"></header>
    );
  }

  const isMaster = role === 'master';
  const items = isMaster ? masterNavItems : workerNavItems;
  const base_path = isMaster ? '/master' : '/worker';

  return (
    <header className="sticky top-0 z-20 flex h-14 w-full items-center justify-between gap-2 border-b bg-background/90 backdrop-blur-md px-3 sm:px-6">
      {/* Left: Mobile Drawer Trigger & Breadcrumbs */}
      <div className="flex items-center gap-2 sm:gap-4 min-w-0">
        <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
          <SheetTrigger asChild>
            <Button size="icon" variant="ghost" className="md:hidden shrink-0 h-9 w-9">
              <PanelLeft className="h-5 w-5" />
              <span className="sr-only">Toggle Menu</span>
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="w-[280px] p-0 flex flex-col">
            <SheetHeader className="p-4 border-b text-left">
              <div className="flex items-center gap-2.5">
                <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-tr from-primary to-blue-600 text-primary-foreground shadow-sm">
                  <ShieldCheck className="h-4 w-4" />
                </div>
                <div>
                  <SheetTitle className="text-base font-bold">SecureWipe</SheetTitle>
                  <p className="text-[11px] text-muted-foreground uppercase font-medium">
                    {isMaster ? 'Master Control' : 'Operator Suite'}
                  </p>
                </div>
              </div>
            </SheetHeader>

            {isLocked && (
              <div className="m-3 p-2 rounded bg-amber-500/10 border border-amber-500/20 text-amber-600 text-xs flex items-center gap-2">
                <Lock className="h-3.5 w-3.5 animate-pulse shrink-0" />
                <span className="text-[11px] font-medium">Forensic Recovery in progress</span>
              </div>
            )}

            <nav className="flex-1 space-y-1 p-3 overflow-y-auto">
              {items.map((item) => {
                const isActive =
                  pathname === item.href ||
                  (item.href !== '/dashboard' &&
                    item.href !== '/master/dashboard' &&
                    item.href !== '/worker/dashboard' &&
                    pathname.startsWith(`${item.href}/`));

                const isItemLocked = isLocked && item.href !== '/faris';

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={(e) => handleNavClick(e, item.href)}
                    className={cn(
                      'flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition',
                      isActive
                        ? 'bg-primary text-primary-foreground'
                        : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                      isItemLocked && 'opacity-50 cursor-not-allowed'
                    )}
                  >
                    <div className="flex items-center gap-3">
                      <item.icon className="h-4 w-4" />
                      <span>{item.label}</span>
                    </div>
                    {isItemLocked && <Lock className="h-3 w-3 text-muted-foreground" />}
                  </Link>
                );
              })}
            </nav>

            <div className="p-3 border-t mt-auto">
              <div className="flex items-center justify-between text-xs text-muted-foreground px-2 py-1">
                <span>Account Mode:</span>
                <Badge variant="outline" className="text-[10px] uppercase font-bold">
                  {role}
                </Badge>
              </div>
            </div>
          </SheetContent>
        </Sheet>

        <Breadcrumb className="hidden sm:flex min-w-0">
          <BreadcrumbList className="text-xs">
            <BreadcrumbItem>
              <BreadcrumbLink asChild>
                <Link
                  href={`${base_path}/dashboard`}
                  onClick={(e) => handleNavClick(e, `${base_path}/dashboard`)}
                  className="font-medium"
                >
                  Dashboard
                </Link>
              </BreadcrumbLink>
            </BreadcrumbItem>
            {pathSegments.slice(1).map((segment) => (
              <React.Fragment key={segment}>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage className="capitalize truncate max-w-[120px]">
                    {segment.replace(/-/g, ' ')}
                  </BreadcrumbPage>
                </BreadcrumbItem>
              </React.Fragment>
            ))}
          </BreadcrumbList>
        </Breadcrumb>
      </div>

      {/* Right: Search & Actions */}
      <div className="flex items-center gap-2 sm:gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground pointer-events-none" />
          <Input
            type="search"
            placeholder="Search..."
            className="h-8 w-28 sm:w-44 md:w-56 pl-8 pr-2 text-xs rounded-lg bg-muted/40 focus:bg-background transition-all"
          />
        </div>

        <ThemeToggle />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="icon"
              className="h-8 w-8 rounded-full overflow-hidden shrink-0 border"
            >
              <Avatar className="h-8 w-8">
                <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">
                  {isMaster ? 'M' : 'W'}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-52">
            <DropdownMenuLabel className="font-normal">
              <div className="flex flex-col space-y-1">
                <p className="text-xs font-bold">{isMaster ? 'Master Control' : 'Operator Session'}</p>
                <p className="text-[11px] text-muted-foreground font-mono">{role}@securewipe.local</p>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href={`${base_path}/dashboard`} className="text-xs cursor-pointer">
                Console Dashboard
              </Link>
            </DropdownMenuItem>
            <DropdownMenuItem asChild>
              <Link href="/history" className="text-xs cursor-pointer">
                Audit History
              </Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <form action={logout} className="w-full">
                <button type="submit" className="w-full text-left flex items-center text-xs text-destructive">
                  <LogOut className="mr-2 h-3.5 w-3.5" />
                  Logout
                </button>
              </form>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}

