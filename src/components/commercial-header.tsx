'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { ShieldCheck, ShoppingBag, RotateCcw, CheckCircle2, HelpCircle, User, LayoutDashboard, Menu, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ThemeToggle } from '@/components/theme-toggle';

export function CommercialHeader() {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = React.useState(false);

  const navLinks = [
    { label: 'Marketplace', href: '/marketplace', icon: ShoppingBag, badge: 'Verified' },
    { label: 'How It Works', href: '/how-it-works', icon: RotateCcw },
    { label: 'Why SecureWipe', href: '/why-securewipe', icon: CheckCircle2 },
    { label: 'Verify Certificate', href: '/verify', icon: ShieldCheck },
    { label: 'About', href: '/about' },
    { label: 'FAQ', href: '/faq', icon: HelpCircle },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container mx-auto flex h-16 items-center justify-between px-4 sm:px-8 max-w-7xl">
        {/* Brand Logo */}
        <Link href="/" className="flex items-center gap-2.5 font-bold text-xl tracking-tight hover:opacity-90 transition">
          <div className="h-9 w-9 rounded-xl bg-gradient-to-tr from-primary to-blue-600 flex items-center justify-center text-primary-foreground shadow-md">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <span className="bg-gradient-to-r from-foreground via-foreground to-primary bg-clip-text text-transparent">
            SecureWipe
          </span>
          <span className="text-[10px] font-semibold tracking-widest text-muted-foreground uppercase px-1.5 py-0.5 rounded bg-muted border">
            Platform
          </span>
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center gap-1 lg:gap-2">
          {navLinks.map((item) => {
            const isActive = pathname === item.href || (item.href !== '/' && pathname?.startsWith(item.href));
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                  isActive
                    ? 'bg-primary/10 text-primary font-semibold'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/60'
                }`}
              >
                {item.label}
                {item.badge && (
                  <Badge variant="secondary" className="text-[10px] py-0 px-1.5 bg-green-100 text-green-800 dark:bg-green-950/60 dark:text-green-300 border-green-200">
                    {item.badge}
                  </Badge>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Right Actions */}
        <div className="hidden md:flex items-center gap-3">
          <ThemeToggle />
          <Link href="/dashboard">
            <Button variant="outline" size="sm" className="gap-1.5">
              <LayoutDashboard className="h-4 w-4" />
              My Portal
            </Button>
          </Link>
          <Link href="/dashboard/listings/create">
            <Button size="sm" className="gap-1.5 bg-gradient-to-r from-primary to-blue-600 shadow-sm">
              <ShoppingBag className="h-4 w-4" />
              List a Device
            </Button>
          </Link>
        </div>

        {/* Mobile Hamburger Toggle */}
        <div className="flex md:hidden items-center gap-2">
          <ThemeToggle />
          <Button variant="ghost" size="icon" onClick={() => setMobileOpen(!mobileOpen)}>
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5 text-foreground" />}
          </Button>
        </div>
      </div>

      {/* Mobile Menu */}
      {mobileOpen && (
        <div className="md:hidden border-b bg-background px-4 py-4 space-y-3">
          {navLinks.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileOpen(false)}
              className="flex items-center justify-between px-3 py-2 rounded-md text-sm font-medium text-foreground hover:bg-muted"
            >
              <div className="flex items-center gap-2">
                {item.icon && <item.icon className="h-4 w-4 text-muted-foreground" />}
                {item.label}
              </div>
              {item.badge && <Badge variant="outline" className="text-[10px]">{item.badge}</Badge>}
            </Link>
          ))}
          <div className="pt-3 border-t flex flex-col gap-2">
            <Link href="/dashboard" onClick={() => setMobileOpen(false)}>
              <Button variant="outline" className="w-full justify-center gap-2">
                <LayoutDashboard className="h-4 w-4" />
                My Marketplace Dashboard
              </Button>
            </Link>
            <Link href="/dashboard/listings/create" onClick={() => setMobileOpen(false)}>
              <Button className="w-full justify-center gap-2 bg-gradient-to-r from-primary to-blue-600">
                <ShoppingBag className="h-4 w-4" />
                List a Device for Sale
              </Button>
            </Link>
          </div>
        </div>
      )}
    </header>
  );
}
