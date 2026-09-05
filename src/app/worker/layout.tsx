import type { ReactNode } from 'react';
import AppSidebar from '@/components/app-sidebar';
import AppHeader from '@/components/app-header';

export default function WorkerLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen w-full bg-background text-foreground overflow-x-hidden">
      <AppSidebar />
      <div className="flex flex-col flex-1 min-w-0 max-w-full md:pl-16 transition-all duration-300">
        <AppHeader />
        <main className="flex-1 w-full min-w-0 max-w-full p-4 sm:p-6 lg:p-8 overflow-x-hidden">
          {children}
        </main>
      </div>
    </div>
  );
}
