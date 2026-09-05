import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  ShoppingBag,
  RotateCcw,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  Lock,
  FileCheck2,
  HardDrive,
  Cpu,
  Layers,
  Recycle,
  Star,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

export default function HomePage() {
  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 flex flex-col">
        {/* Hero Section */}
        <section className="relative overflow-hidden py-20 lg:py-28 bg-gradient-to-b from-primary/5 via-background to-background border-b">
          <div className="container mx-auto px-4 sm:px-8 max-w-7xl relative z-10">
            <div className="max-w-3xl mx-auto text-center space-y-6">
              <Badge variant="outline" className="px-3 py-1 border-primary/30 text-primary bg-primary/5 gap-1.5 shadow-sm text-xs font-semibold">
                <Sparkles className="h-3.5 w-3.5" />
                Next-Generation Circular Storage Platform
              </Badge>

              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight leading-[1.15]">
                Secure Your Data.{' '}
                <span className="bg-gradient-to-r from-primary via-blue-600 to-indigo-600 bg-clip-text text-transparent">
                  Verify Your Device.
                </span>{' '}
                Give It a Second Life.
              </h1>

              <p className="text-lg sm:text-xl text-muted-foreground leading-relaxed max-w-2xl mx-auto">
                SecureWipe permanently sanitizes storage devices, verifies erasure with forensic carvers,
                generates verifiable cryptographic certificates, and enables trusted resale and transfer.
              </p>

              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 pt-4">
                <Link href="/marketplace" className="w-full sm:w-auto">
                  <Button size="lg" className="w-full gap-2 text-base h-12 px-8 bg-gradient-to-r from-primary to-blue-600 shadow-md hover:shadow-lg transition">
                    <ShoppingBag className="h-5 w-5" />
                    Explore Verified Devices
                  </Button>
                </Link>
                <Link href="/dashboard/listings/create" className="w-full sm:w-auto">
                  <Button size="lg" variant="outline" className="w-full gap-2 text-base h-12 px-8 border-2">
                    <Sparkles className="h-5 w-5 text-primary" />
                    List a Verified Device
                  </Button>
                </Link>
              </div>

              {/* Trust Indicators */}
              <div className="pt-8 flex flex-wrap items-center justify-center gap-6 sm:gap-10 text-xs font-medium text-muted-foreground border-t border-border/40 max-w-2xl mx-auto">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  NIST 800-88 &amp; DoD Certified Standards
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  RSA-PSS Signed Certificates
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                  100% Circular Tech Guarantee
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Core Product Workflow: WIPE -> VERIFY -> CERTIFY -> LIST -> TRANSFER */}
        <section className="py-20 bg-muted/20 border-b">
          <div className="container mx-auto px-4 sm:px-8 max-w-7xl">
            <div className="text-center max-w-2xl mx-auto mb-16 space-y-3">
              <Badge variant="secondary" className="font-semibold uppercase tracking-wider text-[11px]">
                The Lifecycle
              </Badge>
              <h2 className="text-3xl font-bold tracking-tight">How SecureWipe Works</h2>
              <p className="text-muted-foreground">
                A seamless 5-step journey transforming used storage into verified, high-trust technology ready for reuse.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
              {[
                {
                  step: '01',
                  title: 'Register',
                  desc: 'Connect storage drive and generate an anonymous platform Device ID.',
                  icon: HardDrive,
                },
                {
                  step: '02',
                  title: 'Secure Wipe',
                  desc: 'Execute NIST SP 800-88, DoD 3-Pass, or IEEE 2883 multi-pass sanitization.',
                  icon: Lock,
                },
                {
                  step: '03',
                  title: 'Verify',
                  desc: 'Deep forensic carver confirms zero recoverable file artifacts remain.',
                  icon: Layers,
                },
                {
                  step: '04',
                  title: 'Certify',
                  desc: 'Receive an immutable, digitally signed Schema v1.0 Sanitization Certificate.',
                  icon: FileCheck2,
                },
                {
                  step: '05',
                  title: 'List & Transfer',
                  desc: 'Sell or transfer the verified device on the marketplace with full buyer trust.',
                  icon: Recycle,
                },
              ].map((item, idx) => (
                <Card key={item.step} className="border bg-card relative hover:shadow-md transition">
                  <CardHeader className="p-5 pb-2">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-2xl font-black text-primary/40">{item.step}</span>
                      <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center text-primary">
                        <item.icon className="h-5 w-5" />
                      </div>
                    </div>
                    <CardTitle className="text-base font-bold">{item.title}</CardTitle>
                  </CardHeader>
                  <CardContent className="p-5 pt-0 text-xs text-muted-foreground leading-relaxed">
                    {item.desc}
                  </CardContent>
                </Card>
              ))}
            </div>

            <div className="mt-12 text-center">
              <Link href="/how-it-works">
                <Button variant="outline" className="gap-2 text-sm font-semibold">
                  View Detailed Interactive Workflow
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>
          </div>
        </section>

        {/* Featured Verified Marketplace Preview */}
        <section className="py-20 border-b">
          <div className="container mx-auto px-4 sm:px-8 max-w-7xl">
            <div className="flex flex-col sm:flex-row items-start sm:items-end justify-between gap-4 mb-12">
              <div>
                <Badge variant="outline" className="mb-2 text-green-700 bg-green-50 dark:bg-green-950/40 dark:text-green-300 border-green-300">
                  Live Marketplace
                </Badge>
                <h2 className="text-3xl font-bold tracking-tight">Verified Storage Devices</h2>
                <p className="text-muted-foreground text-sm mt-1">
                  Every listed drive includes an authentic, independently verifiable sanitization certificate.
                </p>
              </div>
              <Link href="/marketplace">
                <Button className="gap-2">
                  Browse All Listings
                  <ArrowRight className="h-4 w-4" />
                </Button>
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {[
                {
                  id: 'SW-DEV-8F92A1B0',
                  title: 'Samsung 980 PRO 1TB NVMe Gen4 SSD',
                  type: 'NVMe SSD',
                  cap: '1 TB',
                  price: '$79.00',
                  cond: 'Like New',
                  health: '98% Healthy',
                  cert: 'CERT-SMP-001',
                },
                {
                  id: 'SW-DEV-3C41E8D2',
                  title: 'WD Ultrastar 12TB Enterprise 7200RPM HDD',
                  type: 'Enterprise HDD',
                  cap: '12 TB',
                  price: '$145.00',
                  cond: 'Refurbished',
                  health: '100% Healthy',
                  cert: 'CERT-SMP-002',
                },
                {
                  id: 'SW-DEV-9A10F4C7',
                  title: 'Crucial MX500 2TB SATA 2.5" SSD',
                  type: 'SATA SSD',
                  cap: '2 TB',
                  price: '$95.00',
                  cond: 'Excellent',
                  health: '95% Healthy',
                  cert: 'CERT-SMP-003',
                },
                {
                  id: 'SW-DEV-5E82B9A1',
                  title: 'SanDisk Extreme PRO 1TB Portable USB-C',
                  type: 'External SSD',
                  cap: '1 TB',
                  price: '$68.00',
                  cond: 'Like New',
                  health: '99% Healthy',
                  cert: 'CERT-SMP-004',
                },
              ].map((item) => (
                <Card key={item.id} className="overflow-hidden border flex flex-col justify-between hover:border-primary/50 transition duration-200">
                  <CardHeader className="p-5 pb-3">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-200 text-[10px]">
                        {item.type}
                      </Badge>
                      <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 gap-1 text-[10px]">
                        <CheckCircle2 className="h-3 w-3" />
                        Verified
                      </Badge>
                    </div>
                    <CardTitle className="text-sm font-semibold line-clamp-2">{item.title}</CardTitle>
                    <div className="text-xs text-muted-foreground pt-1 flex items-center justify-between">
                      <span>Cap: <strong>{item.cap}</strong></span>
                      <span>Condition: <strong>{item.cond}</strong></span>
                    </div>
                  </CardHeader>
                  <CardContent className="p-5 pt-0 space-y-3">
                    <div className="p-2 rounded bg-muted/50 text-[11px] space-y-1">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Certificate:</span>
                        <Link href={`/verify`} className="font-mono text-primary font-medium hover:underline">
                          {item.cert}
                        </Link>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Hardware Health:</span>
                        <span className="text-green-600 font-semibold">{item.health}</span>
                      </div>
                    </div>
                    <div className="flex items-center justify-between pt-2">
                      <span className="text-lg font-black text-foreground">{item.price}</span>
                      <Link href={`/marketplace`}>
                        <Button size="sm" variant="outline" className="text-xs gap-1">
                          View Device
                          <ChevronRight className="h-3.5 w-3.5" />
                        </Button>
                      </Link>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </section>

        {/* Why SecureWipe Value Proposition */}
        <section className="py-20 bg-muted/20 border-b">
          <div className="container mx-auto px-4 sm:px-8 max-w-7xl">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center">
              <div className="space-y-6">
                <Badge variant="secondary" className="font-semibold uppercase tracking-wider text-[11px]">
                  Why Choose SecureWipe
                </Badge>
                <h2 className="text-3xl sm:text-4xl font-bold tracking-tight leading-snug">
                  Data Security shouldn’t mean Unnecessary Electronic Waste.
                </h2>
                <p className="text-muted-foreground text-sm sm:text-base leading-relaxed">
                  Millions of perfectly operational SSDs, NVMe drives, and hard disks are physically destroyed every year because enterprises and individuals lack a verifiable method to prove erasure before selling.
                </p>
                <div className="space-y-4 pt-2">
                  <div className="flex items-start gap-3">
                    <div className="h-6 w-6 rounded-full bg-primary/10 text-primary flex items-center justify-center shrink-0 mt-0.5">
                      <CheckCircle2 className="h-4 w-4" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold">Forensic Zero-Remnant Verification</h4>
                      <p className="text-xs text-muted-foreground mt-0.5">Deep file signature carver validates that headers, footers, and structures are completely eradicated.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="h-6 w-6 rounded-full bg-primary/10 text-primary flex items-center justify-center shrink-0 mt-0.5">
                      <CheckCircle2 className="h-4 w-4" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold">Verifiable Asymmetric Certificates</h4>
                      <p className="text-xs text-muted-foreground mt-0.5">RSA-PSS cryptographic signatures ensure certificates cannot be forged, manipulated, or altered.</p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="h-6 w-6 rounded-full bg-primary/10 text-primary flex items-center justify-center shrink-0 mt-0.5">
                      <CheckCircle2 className="h-4 w-4" />
                    </div>
                    <div>
                      <h4 className="text-sm font-semibold">Circular Hardware Economy</h4>
                      <p className="text-xs text-muted-foreground mt-0.5">Monetize or donate sanitized storage hardware with 100% confidence in data privacy.</p>
                    </div>
                  </div>
                </div>
              </div>

              <Card className="border-2 border-primary/20 bg-card p-6 shadow-lg relative overflow-hidden">
                <div className="space-y-6">
                  <div className="flex items-center gap-3">
                    <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-primary to-blue-600 flex items-center justify-center text-primary-foreground font-bold">
                      ✓
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">The SecureWipe Trust Guarantee</h3>
                      <p className="text-xs text-muted-foreground">Independently Auditable Sanitization Lifecycle</p>
                    </div>
                  </div>

                  <div className="p-4 rounded-lg bg-muted/60 space-y-3 font-mono text-xs border">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Certificate Standard:</span>
                      <span className="text-foreground font-semibold">Schema v1.0 (NIST 800-88)</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Digital Signature:</span>
                      <span className="text-foreground font-semibold">RSA-PSS-SHA256</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Audit Chaining:</span>
                      <span className="text-foreground font-semibold">SHA-256 Tamper-Evident</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Privacy Protection:</span>
                      <span className="text-foreground font-semibold">Masked Physical Serials</span>
                    </div>
                  </div>

                  <Link href="/verify" className="block">
                    <Button variant="outline" className="w-full justify-center gap-2">
                      <ShieldCheck className="h-4 w-4" />
                      Test Public Certificate Verification
                    </Button>
                  </Link>
                </div>
              </Card>
            </div>
          </div>
        </section>

        {/* Call to Action */}
        <section className="py-20 bg-gradient-to-b from-background to-primary/5 text-center">
          <div className="container mx-auto px-4 sm:px-8 max-w-4xl space-y-6">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">
              Ready to Discover Verified Storage Hardware?
            </h2>
            <p className="text-muted-foreground text-sm sm:text-base max-w-xl mx-auto">
              Browse authentic verified storage devices or list your sanitized drives on the secondary marketplace with cryptographic trust.
            </p>
            <div className="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link href="/marketplace">
                <Button size="lg" className="gap-2 h-12 px-8 bg-gradient-to-r from-primary to-blue-600 shadow-md">
                  <ShoppingBag className="h-5 w-5" />
                  Explore Verified Marketplace
                </Button>
              </Link>
              <Link href="/dashboard/listings/create">
                <Button size="lg" variant="outline" className="gap-2 h-12 px-8">
                  <Sparkles className="h-4 w-4 text-primary" />
                  List a Verified Device
                </Button>
              </Link>
            </div>
          </div>
        </section>
      </main>

      <CommercialFooter />
    </div>
  );
}
