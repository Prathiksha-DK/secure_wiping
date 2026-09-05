'use client';

import React from 'react';
import Link from 'next/link';
import { ShieldCheck, ArrowRight, Heart, Sparkles, Lock, RefreshCw, CheckCircle2 } from 'lucide-react';
import { Separator } from '@/components/ui/separator';

export function CommercialFooter() {
  return (
    <footer className="w-full border-t bg-muted/30 text-muted-foreground">
      <div className="container mx-auto px-4 sm:px-8 py-12 max-w-7xl">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          {/* Brand & Mission */}
          <div className="md:col-span-1 space-y-3">
            <div className="flex items-center gap-2.5 font-bold text-lg text-foreground">
              <div className="h-7 w-7 rounded-lg bg-gradient-to-tr from-primary to-blue-600 flex items-center justify-center text-primary-foreground">
                <ShieldCheck className="h-4 w-4" />
              </div>
              <span>SecureWipe</span>
            </div>
            <p className="text-sm leading-relaxed">
              Secure Data. Verified Devices. Second Life.
            </p>
            <p className="text-xs text-muted-foreground/80">
              Connecting permanent data sanitization with trusted circular technology reuse.
            </p>
          </div>

          {/* Platform */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">Platform</h4>
            <ul className="space-y-2 text-sm">
              <li><Link href="/marketplace" className="hover:text-foreground transition">Verified Marketplace</Link></li>
              <li><Link href="/how-it-works" className="hover:text-foreground transition">How It Works</Link></li>
              <li><Link href="/why-securewipe" className="hover:text-foreground transition">Why SecureWipe</Link></li>
              <li><Link href="/verify" className="hover:text-foreground transition">Verify Certificate</Link></li>
              <li><Link href="/dashboard/listings/create" className="hover:text-foreground transition">List a Verified Device</Link></li>
            </ul>
          </div>

          {/* Technical Trust & Standards */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">Sanitization &amp; Trust</h4>
            <ul className="space-y-2 text-sm">
              <li><span className="text-foreground/90 font-medium">NIST SP 800-88 Rev.1 Clear &amp; Purge</span></li>
              <li><span className="text-foreground/90 font-medium">DoD 5220.22-M 3-Pass / 7-Pass</span></li>
              <li><span className="text-foreground/90 font-medium">IEEE 2883-2022 Cryptographic Erase</span></li>
              <li><span className="text-foreground/90 font-medium">Schema v1.0 RSA-PSS Digital Signatures</span></li>
              <li><span className="text-foreground/90 font-medium">Stratified Multi-Mode Verifier</span></li>
            </ul>
          </div>

          {/* Company & Support */}
          <div className="space-y-3">
            <h4 className="text-xs font-semibold uppercase tracking-wider text-foreground">Support &amp; Integrity</h4>
            <ul className="space-y-2 text-sm">
              <li><Link href="/about" className="hover:text-foreground transition">About SecureWipe</Link></li>
              <li><Link href="/faq" className="hover:text-foreground transition">Frequently Asked Questions</Link></li>
              <li><Link href="/dashboard" className="hover:text-foreground transition">User Portal</Link></li>
              <li><Link href="/admin" className="hover:text-foreground transition">Platform Moderation</Link></li>
            </ul>
          </div>
        </div>

        <Separator className="my-8" />

        {/* Technical Honesty Disclaimer & Copyright */}
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-xs">
          <p className="text-muted-foreground/80 text-center md:text-left max-w-2xl">
            <strong>Technical Honesty Guarantee:</strong> SecureWipe verifies logical data sanitization with deep file signature carving. 
            SSDs and Flash media are transparently labeled as non-verifiable for unmapped physical wear-leveling blocks.
          </p>
          <div className="text-center md:text-right">
            &copy; {new Date().getFullYear()} SecureWipe Platform Inc. All rights reserved.
          </div>
        </div>
      </div>
    </footer>
  );
}
