
'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  ShieldCheck,
  PanelLeft,
  Search,
  LayoutDashboard,
  History,
  Trash2,
  Settings,
  LogOut,
  Package,
  Network,
  Eye,
} from 'lucide-react';
import {
  Sheet,
  SheetContent,
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
import React from 'react';
import { logout } from '@/app/actions';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { isFarisLocked, showNavigationLockedAlert } from '@/lib/faris-lock';

const workerNavItems = [
  { href: '/worker/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
  { href: '/worker/wipe', icon: Trash2, label: 'Wipe' },
  { href: '/worker/history', icon: History, label: 'History & Audit' },
];

const masterNavItems = [
  { href: '/master/dashboard', icon: LayoutDashboard, label: 'Master Control Panel' },
  { href: '/inspector', icon: Eye, label: 'Storage Inspector (Hex)' },
  { href: '/faris', icon: Search, label: 'FARIS Recovery' },
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

export default function AppHeader() {
  const pathname = usePathname();
  const pathSegments = pathname.split('/').filter(Boolean);
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
      <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-background/80 backdrop-blur-md px-4 sm:static sm:h-auto sm:border-0 sm:bg-transparent sm:px-6"></header>
    );
  }

  const isMaster = role === 'master';
  const items = isMaster ? masterNavItems : workerNavItems;
  const base_path = isMaster ? '/master' : '/worker';

  return (
    <>
      <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b bg-background/80 backdrop-blur-md px-4 sm:static sm:h-auto sm:border-0 sm:bg-transparent sm:px-6">
        <Sheet>
          <SheetTrigger asChild>
            <Button size="icon" variant="outline" className="sm:hidden">
              <PanelLeft className="h-5 w-5" />
              <span className="sr-only">Toggle Menu</span>
            </Button>
          </SheetTrigger>
          <SheetContent side="left" className="sm:max-w-xs">
            <nav className="grid gap-6 text-lg font-medium">
              <Link
                href={`${base_path}/dashboard`}
                onClick={(e) => handleNavClick(e, `${base_path}/dashboard`)}
                className="group flex h-10 w-10 shrink-0 items-center justify-center gap-2 rounded-full bg-primary text-lg font-semibold text-primary-foreground md:text-base"
              >
                <ShieldCheck className="h-5 w-5 transition-all group-hover:scale-110" />
                <span className="sr-only">SecureWipe</span>
              </Link>
              {items.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={(e) => handleNavClick(e, item.href)}
                  className="flex items-center gap-4 px-2.5 text-muted-foreground hover:text-foreground"
                >
                  <item.icon className="h-5 w-5" />
                  {item.label}
                </Link>
              ))}
               <Link
                  href="#"
                  onClick={(e) => handleNavClick(e, '#')}
                  className="flex items-center gap-4 px-2.5 text-muted-foreground hover:text-foreground"
                >
                  <Settings className="h-5 w-5" />
                  Settings
                </Link>
            </nav>
          </SheetContent>
        </Sheet>
        <Breadcrumb className="hidden md:flex">
          <BreadcrumbList>
            <BreadcrumbItem>
              <BreadcrumbLink asChild>
                <Link href={`${base_path}/dashboard`} onClick={(e) => handleNavClick(e, `${base_path}/dashboard`)}>Dashboard</Link>
              </BreadcrumbLink>
            </BreadcrumbItem>
            {pathSegments.slice(1).map((segment, index) => (
              <React.Fragment key={segment}>
                <BreadcrumbSeparator />
                <BreadcrumbItem>
                  <BreadcrumbPage className="capitalize">
                    {segment.replace(/-/g, ' ')}
                  </BreadcrumbPage>
                </BreadcrumbItem>
              </React.Fragment>
            ))}
          </BreadcrumbList>
        </Breadcrumb>
        <div className="relative ml-auto flex-1 md:grow-0">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search..."
            className="w-full rounded-lg bg-background pl-8 md:w-[200px] lg:w-[336px]"
          />
        </div>
        <ThemeToggle />
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="outline"
              size="icon"
              className="overflow-hidden rounded-full"
            >
              <Avatar className="h-8 w-8">
                <AvatarFallback className="bg-primary/10 text-primary text-xs font-bold">
                  {isMaster ? 'M' : 'W'}
                </AvatarFallback>
              </Avatar>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>{isMaster ? 'Master Account' : 'Worker Account'}</DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem>Settings</DropdownMenuItem>
            <DropdownMenuItem>Support</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <form action={logout} className="w-full">
                <button type="submit" className="w-full text-left flex items-center">
                  <LogOut className="mr-2 h-4 w-4" />
                  Logout
                </button>
              </form>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </header>
    </>
  );
}
