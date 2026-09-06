'use client';

import * as React from 'react';
import { usePathname } from 'next/navigation';
import AppSidebar from '@/components/app-sidebar';
import AppHeader from '@/components/app-header';
import NavigationLockModal from '@/components/navigation-lock-modal';
import EvidenceWorkspacePanel from '@/components/evidence-workspace-panel';

const SHELL_PATH_PREFIXES = [
  '/individual',
  '/government',
  '/forensic',
  '/hunter/dashboard',
  '/master',
  '/worker',
  '/inspector',
  '/wipe',
  '/faris',
  '/history',
  '/assessment',
  '/lifecycle',
  '/report',
  '/swarm',
];

export default function AppShellGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const showShell = SHELL_PATH_PREFIXES.some((p) => pathname === p || pathname.startsWith(`${p}/`));

  if (!showShell) {
    return <>{children}</>;
  }

  return (
    <div className="flex min-h-screen w-full bg-background text-foreground">
      <AppSidebar />
      <div className="flex flex-col md:pl-64 w-full min-h-screen">
        <AppHeader />
        <main className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto">{children}</main>
      </div>
      <NavigationLockModal />
      <EvidenceWorkspacePanel />
    </div>
  );
}
