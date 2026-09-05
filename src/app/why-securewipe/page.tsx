import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  CheckCircle2,
  Recycle,
  Layers,
  FileCheck2,
  History,
  Lock,
  AlertTriangle,
  HeartHandshake,
  TrendingUp,
  Cpu,
  ArrowRight,
  ShoppingBag
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

export default function WhySecureWipePage() {
  const values = [
    {
      title: 'Forensic Verification, Not Assumptions',
      desc: 'Most wiping utilities simply send overwrite commands and report success. SecureWipe executes multi-region stratified sampling and 3-level streaming forensic carving to verify that zero file artifacts remain.',
      icon: Layers,
    },
    {
      title: 'Cryptographic Non-Repudiation',
      desc: 'Every certificate is canonically digested using SHA-256 and digitally signed with RSA-PSS asymmetric cryptography. Buyers, auditors, and enterprises can independently verify authenticity in seconds.',
      icon: FileCheck2,
    },
    {
      title: 'Circular Tech & Reduced E-Waste',
      desc: 'Physical disk shredding produces toxic electronic waste and destroys valuable storage components. SecureWipe bridges permanent data privacy with responsible hardware reuse, extending device lifespans.',
      icon: Recycle,
    },
    {
      title: 'Transparent Device History & Trust Score',
      desc: 'Each device maintains an immutable lifecycle record from registration to transfer. Our trust score is computed exclusively from verifiable evidence like SMART health, sanitization logs, and certificate status.',
      icon: History,
    },
    {
      title: 'Privacy-First Architecture',
      desc: 'We never expose physical device serial numbers or previous owners’ personal information publicly. Physical identifiers are hashed and masked to protect privacy on public marketplace listings.',
      icon: Lock,
    },
    {
      title: 'Fail-Closed System Safety',
      desc: 'Our engine is engineered with multi-layer safeguards preventing accidental destruction of host OS boot volumes, root partitions, or application runtime files.',
      icon: ShieldCheck,
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
              <CheckCircle2 className="h-3.5 w-3.5" />
              Trust &amp; Transparency
            </Badge>
            <h1 className="text-4xl sm:text-5xl font-extrabold tracking-tight">
              Why SecureWipe?
            </h1>
            <p className="text-muted-foreground text-base sm:text-lg">
              We built SecureWipe to end the false dichotomy between strict data privacy and sustainable hardware lifecycle management.
            </p>
          </div>

          {/* Core Values Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {values.map((v, idx) => (
              <Card key={idx} className="border hover:border-primary/40 transition shadow-sm p-6 space-y-3 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="h-10 w-10 rounded-xl bg-primary/10 text-primary flex items-center justify-center">
                    <v.icon className="h-5 w-5" />
                  </div>
                  <h3 className="font-bold text-lg">{v.title}</h3>
                  <p className="text-xs text-muted-foreground leading-relaxed">{v.desc}</p>
                </div>
              </Card>
            ))}
          </div>

          {/* Technical Honesty & Flash Memory Notice */}
          <div className="space-y-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <h2 className="text-xl font-bold">Our Commitment to Technical Honesty</h2>
            </div>

            <Alert className="border-amber-300 bg-amber-50/50 dark:bg-amber-950/20 dark:border-amber-700/50">
              <AlertTitle className="text-amber-900 dark:text-amber-200 font-bold flex items-center gap-2">
                NAND Flash, SSD &amp; Wear-Leveling Transparency
              </AlertTitle>
              <AlertDescription className="text-amber-800 dark:text-amber-300 text-xs sm:text-sm mt-2 leading-relaxed space-y-2">
                <p>
                  Unlike legacy tools that make unfounded claims of &ldquo;100% physical erasure&rdquo; on flash media, SecureWipe follows NIST SP 800-88 Rev.1 guidelines.
                </p>
                <p>
                  Solid State Drives (SSDs) and NVMe media utilize internal Flash Translation Layers (FTL) that abstract physical memory blocks. While SecureWipe completely overwrites all addressable logical blocks and validates zero file remnants, unmapped or retired bad blocks cannot be physically verified by logical software alone.
                </p>
                <p className="font-semibold">
                  Therefore, SecureWipe classifies SSD logical overwrites as <code>SANITIZATION_NOT_VERIFIABLE</code> on certificates, ensuring complete honesty with auditors, sellers, and buyers.
                </p>
              </AlertDescription>
            </Alert>
          </div>

          {/* Circular Tech Impact Statement */}
          <div className="p-8 rounded-2xl bg-muted/40 border space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
              <div className="space-y-1">
                <div className="text-3xl font-black text-primary">50M+ Tons</div>
                <p className="text-xs text-muted-foreground">Global electronic waste generated annually</p>
              </div>
              <div className="space-y-1">
                <div className="text-3xl font-black text-green-600">3–5 Years</div>
                <p className="text-xs text-muted-foreground">Additional useful hardware life enabled through verified sanitization</p>
              </div>
              <div className="space-y-1">
                <div className="text-3xl font-black text-blue-600">0 Flaws</div>
                <p className="text-xs text-muted-foreground">Zero compromise on cryptographic data security</p>
              </div>
            </div>
          </div>

          {/* CTA */}
          <div className="text-center space-y-4">
            <h3 className="text-2xl font-bold">Discover Verified Hardware on the Marketplace</h3>
            <div className="flex justify-center gap-4 pt-2">
              <Link href="/marketplace">
                <Button className="gap-2 bg-gradient-to-r from-primary to-blue-600">
                  <ShoppingBag className="h-4 w-4" />
                  Browse Verified Marketplace
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
