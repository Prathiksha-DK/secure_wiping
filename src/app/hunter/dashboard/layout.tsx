import type { ReactNode } from 'react';
import AppSidebar from '@/components/app-sidebar';
import AppHeader from '@/components/app-header';
import NavigationLockModal from '@/components/navigation-lock-modal';

export default function HunterDashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen w-full bg-[#060A12] text-slate-100">
      <AppSidebar />
      <div className="flex flex-col md:pl-64 w-full min-h-screen">
        <AppHeader />
        <main className="flex-1 p-4 md:p-8 max-w-7xl w-full mx-auto">
          {children}
        </main>
      </div>
      <NavigationLockModal />
    </div>
  );
}
