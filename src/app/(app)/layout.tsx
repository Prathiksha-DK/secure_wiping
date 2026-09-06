import type { ReactNode } from 'react';
import AppSidebar from '@/components/app-sidebar';
import AppHeader from '@/components/app-header';
import NavigationLockModal from '@/components/navigation-lock-modal';

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen w-full bg-[#060A12] text-slate-100 overflow-x-hidden">
      <AppSidebar />
      <div className="flex flex-col flex-1 min-w-0 max-w-full md:pl-64 min-h-screen transition-all duration-300">
        <AppHeader />
        <main className="flex-1 w-full min-w-0 max-w-7xl mx-auto p-4 sm:p-6 lg:p-8 overflow-x-hidden">
          {children}
        </main>
      </div>
      <NavigationLockModal />
    </div>
  );
}
