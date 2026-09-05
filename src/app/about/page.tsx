import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Recycle,
  Lock,
  HeartHandshake,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  TrendingUp,
  Cpu,
  Layers,
  History
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

export default function AboutPage() {
  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-16">
        <div className="container mx-auto px-4 sm:px-8 max-w-4xl space-y-16">
          {/* Header & Mission */}
          <div className="text-center space-y-4 max-w-2xl mx-auto">
            <Badge variant="outline" className="px-3 py-1 border-primary/30 text-primary bg-primary/5 text-xs font-semibold gap-1.5">
              <Sparkles className="h-3.5 w-3.5" />
              Our Mission
            </Badge>
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight leading-tight">
              Data Security Should Not Mean Hardware Destruction.
            </h1>
            <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
              SecureWipe connects <strong>Data Security + Device Reuse + Digital Trust</strong> to build a sustainable, circular lifecycle for modern storage hardware.
            </p>
          </div>

          {/* Three Pillars */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <Card className="border p-6 space-y-3 shadow-sm hover:border-primary/40 transition">
              <div className="h-10 w-10 rounded-xl bg-primary/10 text-primary flex items-center justify-center font-bold">
                <Lock className="h-5 w-5" />
              </div>
              <h3 className="font-bold text-lg">Permanent Privacy</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Industrial-grade sanitization standards (NIST SP 800-88, DoD 5220.22-M, IEEE 2883) ensure that confidential personal and enterprise files are irreversibly eradicated.
              </p>
            </Card>

            <Card className="border p-6 space-y-3 shadow-sm hover:border-primary/40 transition">
              <div className="h-10 w-10 rounded-xl bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 flex items-center justify-center font-bold">
                <Recycle className="h-5 w-5" />
              </div>
              <h3 className="font-bold text-lg">Circular Hardware</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Extending the useful lifespan of SSDs, HDDs, and NVMe drives prevents thousands of kilograms of unnecessary electronic scrap from polluting landfills.
              </p>
            </Card>

            <Card className="border p-6 space-y-3 shadow-sm hover:border-primary/40 transition">
              <div className="h-10 w-10 rounded-xl bg-blue-100 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300 flex items-center justify-center font-bold">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <h3 className="font-bold text-lg">Digital Trust</h3>
              <p className="text-xs text-muted-foreground leading-relaxed">
                Our cryptographic Schema v1.0 certificates provide non-repudiable mathematical proof of sanitization that buyers and sellers can verify independently.
              </p>
            </Card>
          </div>

          {/* Platform Vision */}
          <div className="p-8 rounded-2xl bg-muted/40 border space-y-6">
            <h2 className="text-2xl font-bold">The Problem We Solve</h2>
            <div className="space-y-4 text-sm text-muted-foreground leading-relaxed">
              <p>
                Every year, over 50 million metric tons of electronic waste are generated globally. A staggering portion of this waste consists of fully functional storage devices destroyed out of fear: fear that old photos, financial spreadsheets, or enterprise databases might be recovered by a future buyer.
              </p>
              <p>
                Until now, individuals and IT asset managers faced a binary choice: physically shred the drive, or take an unverified gamble on basic formatting.
              </p>
              <p className="font-semibold text-foreground">
                SecureWipe creates a third path: Verified Sanitization + Trusted Transfer. We give storage hardware a confident second life.
              </p>
            </div>
          </div>

          {/* Call to Action */}
          <div className="text-center space-y-4">
            <h3 className="text-2xl font-bold">Join the SecureWipe Circular Platform</h3>
            <div className="flex justify-center gap-4 pt-2">
              <Link href="/dashboard/devices/register">
                <Button className="gap-2">
                  <ShieldCheck className="h-4 w-4" />
                  Wipe a Device
                </Button>
              </Link>
              <Link href="/marketplace">
                <Button variant="outline">
                  Explore Marketplace
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
