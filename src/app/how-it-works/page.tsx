import React from 'react';
import Link from 'next/link';
import {
  RotateCcw,
  HardDrive,
  Lock,
  Layers,
  FileCheck2,
  ShoppingBag,
  UserCheck,
  ArrowDown,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  Sparkles
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

export default function HowItWorksPage() {
  const steps = [
    {
      step: '01',
      title: 'Register & Identify Device',
      badge: 'Step 1: Onboarding',
      icon: HardDrive,
      summary: 'The SecureWipe local agent connects to your physical storage device and assigns an anonymous platform Device ID (e.g. SW-DEV-A9B8C7D6), protecting your physical serial number from public exposure.',
      details: [
        'Automatic SMART and physical capacity detection',
        'Fail-closed root & boot system disk safety protection',
        'Unique SHA-256 hardware identity fingerprinting',
      ],
    },
    {
      step: '02',
      title: 'Execute Multi-Pass Sanitization',
      badge: 'Step 2: Destruction',
      icon: Lock,
      summary: 'Select your preferred standard (NIST SP 800-88 Clear/Purge, DoD 5220.22-M 3-Pass/7-Pass, or IEEE 2883 Cryptographic Erase). The engine acquires an exclusive hardware lock and performs bit-level overwrite patterns.',
      details: [
        'Deterministic pattern sequencing (0x00, 0xFF, CSPRNG pseudorandom)',
        'Streaming chunk I/O preventing system exhaustion',
        'Real-time streaming progress, throughput, and ETA',
      ],
    },
    {
      step: '03',
      title: 'Stratified Verification & Forensic Carving',
      badge: 'Step 3: Verification',
      icon: Layers,
      summary: 'SecureWipe doesn’t assume wiping succeeded. A stratified multi-region verifier samples sectors across the disk while a streaming forensic carver scans for residual file headers, footers, and structures.',
      details: [
        'Entropy calculation detecting non-zero remnant blocks',
        '3-level deep signature carving (PDF, SQLite, Office, Images, Binaries)',
        'Adaptive classification: Sanitized, Not Verifiable, or Failed',
      ],
    },
    {
      step: '04',
      title: 'Issue Digitally Signed Certificate',
      badge: 'Step 4: Certification',
      icon: FileCheck2,
      summary: 'Upon verified completion, SecureWipe generates an immutable Schema v1.0 Sanitization Certificate. The certificate is hashed with SHA-256 and digitally signed using RSA-2048/4096 PSS asymmetric cryptography.',
      details: [
        'Tamper-evident canonical JSON digest',
        'Embedded public verification QR code',
        'Privacy-preserving masked serial number presentation',
      ],
    },
    {
      step: '05',
      title: 'List on Verified Marketplace or Transfer',
      badge: 'Step 5: Second Life',
      icon: ShoppingBag,
      summary: 'Eligible verified devices automatically qualify for the "SecureWipe Verified" badge on our marketplace. Buyers can inspect the certificate and initiate a secure ownership transfer.',
      details: [
        'Automated backend listing eligibility evaluation',
        'Verifiable Device Trust Score (0–100)',
        'Chain-of-custody ownership history update',
      ],
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-16">
        <div className="container mx-auto px-4 sm:px-8 max-w-5xl space-y-16">
          {/* Header */}
          <div className="text-center space-y-4 max-w-3xl mx-auto">
            <Badge variant="outline" className="px-3 py-1 border-primary/30 text-primary bg-primary/5 text-xs font-semibold gap-1.5">
              <RotateCcw className="h-3.5 w-3.5" />
              Circular Technology Flow
            </Badge>
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight">
              The SecureWipe Workflow
            </h1>
            <p className="text-muted-foreground text-base sm:text-lg">
              From dirty hardware to a certified, trusted asset. Explore how our end-to-end platform safeguards data privacy while enabling circular reuse.
            </p>
          </div>

          {/* Visual Lifecycle Ribbon */}
          <div className="p-6 rounded-2xl bg-muted/40 border text-center space-y-4">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-muted-foreground">The Complete Lifecycle Chain</h3>
            <div className="flex flex-wrap items-center justify-center gap-2 text-xs font-bold">
              <span className="px-3 py-1.5 rounded-lg bg-card border shadow-sm">USED DEVICE</span>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
              <span className="px-3 py-1.5 rounded-lg bg-primary/10 text-primary border border-primary/30">SECURE WIPE</span>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
              <span className="px-3 py-1.5 rounded-lg bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border border-blue-300">VERIFICATION</span>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
              <span className="px-3 py-1.5 rounded-lg bg-purple-100 text-purple-800 dark:bg-purple-950/60 dark:text-purple-300 border border-purple-300">CERTIFICATE</span>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
              <span className="px-3 py-1.5 rounded-lg bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border border-emerald-300">VERIFIED LISTING</span>
              <ArrowRight className="h-4 w-4 text-muted-foreground" />
              <span className="px-3 py-1.5 rounded-lg bg-card border shadow-sm">NEW OWNER</span>
            </div>
          </div>

          {/* Interactive Steps */}
          <div className="space-y-8">
            {steps.map((item, idx) => (
              <Card key={item.step} className="border hover:border-primary/40 transition shadow-sm overflow-hidden">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6 p-6 items-center">
                  <div className="md:col-span-1 flex md:flex-col items-center justify-center gap-2 text-center">
                    <div className="h-12 w-12 rounded-xl bg-primary/10 text-primary flex items-center justify-center font-black text-xl">
                      {item.step}
                    </div>
                  </div>

                  <div className="md:col-span-7 space-y-2">
                    <Badge variant="outline" className="text-[11px] font-semibold text-primary border-primary/20">
                      {item.badge}
                    </Badge>
                    <h3 className="text-xl font-bold">{item.title}</h3>
                    <p className="text-sm text-muted-foreground leading-relaxed">
                      {item.summary}
                    </p>
                  </div>

                  <div className="md:col-span-4 bg-muted/40 p-4 rounded-xl space-y-2 border text-xs">
                    <div className="font-semibold text-foreground flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                      Key Safeguards:
                    </div>
                    <ul className="space-y-1.5 text-muted-foreground">
                      {item.details.map((d, dIdx) => (
                        <li key={dIdx} className="flex items-start gap-1.5">
                          <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0 mt-0.5" />
                          <span>{d}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </Card>
            ))}
          </div>

          {/* CTA Banner */}
          <div className="p-8 rounded-2xl bg-gradient-to-r from-primary/10 via-blue-500/10 to-primary/10 border text-center space-y-4">
            <h2 className="text-2xl font-bold">Ready to Explore Verified Storage Hardware?</h2>
            <p className="text-sm text-muted-foreground max-w-md mx-auto">
              Find verified storage devices on the marketplace or list your certified hardware for sale.
            </p>
            <div className="pt-2 flex justify-center gap-4">
              <Link href="/marketplace">
                <Button className="gap-2 bg-gradient-to-r from-primary to-blue-600">
                  <ShoppingBag className="h-4 w-4" />
                  Explore Marketplace
                </Button>
              </Link>
              <Link href="/dashboard/listings/create">
                <Button variant="outline">
                  List a Verified Device
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
