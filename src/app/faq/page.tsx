'use client';

import React from 'react';
import Link from 'next/link';
import {
  HelpCircle,
  ShieldCheck,
  ChevronDown,
  Lock,
  Layers,
  FileCheck2,
  HardDrive,
  Recycle,
  AlertTriangle
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { Card, CardContent } from '@/components/ui/card';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

export default function FAQPage() {
  const faqs = [
    {
      q: 'What does SecureWipe do?',
      a: 'SecureWipe is an end-to-end commercial platform that securely sanitizes used storage devices (HDDs, SSDs, NVMe, USB drives), forensically verifies the erasure, generates cryptographically signed certificates, and facilitates the trusted resale or transfer of verified hardware.',
    },
    {
      q: 'How is a device sanitized?',
      a: 'Sanitization is performed by the SecureWipe local engine using recognized international standards, including NIST SP 800-88 Rev.1 Clear/Purge, DoD 5220.22-M (3-Pass/7-Pass), and IEEE 2883 Cryptographic Erase. The engine overwrites addressable sectors with deterministic and cryptographically secure random bit patterns.',
    },
    {
      q: 'How is sanitization verified?',
      a: 'SecureWipe does not rely on simple command completion. It executes a stratified multi-region verifier across sectors alongside a 3-level streaming forensic carver that actively searches for residual file signatures (e.g. PDFs, SQLite databases, JPEG/PNG images, Office documents, executables).',
    },
    {
      q: 'What is a sanitization certificate?',
      a: 'A SecureWipe Sanitization Certificate is an immutable Schema v1.0 document. It includes device specifications, the sanitization method used, verification results, timestamps, and an RSA-PSS digital signature generated with the SecureWipe Certificate Authority key.',
    },
    {
      q: 'Can I sell a wiped device on the marketplace?',
      a: 'Yes. Once a device successfully passes multi-pass sanitization and forensic verification, our backend eligibility engine automatically qualifies it for listing on the SecureWipe Verified Marketplace with the "SecureWipe Verified" trust badge.',
    },
    {
      q: 'Can I verify a device before buying it?',
      a: 'Absolutely. Every marketplace listing includes a direct link to its cryptographic certificate. Buyers can independently verify the certificate ID on our public verification ledger to confirm that the drive was wiped and validated before making a purchase.',
    },
    {
      q: 'What happens if a device cannot be sufficiently verified?',
      a: 'If residual data fragments are detected or the sanitization process aborts, the device is classified as FAILED or NOT_VERIFIABLE. Our backend strictly blocks unverified or failed drives from receiving the "SecureWipe Verified" marketplace badge.',
    },
    {
      q: 'Does SecureWipe support SSD and NVMe drives?',
      a: 'Yes. SecureWipe performs logical block overwrite and cryptographic erasure on SSDs and NVMe drives. In accordance with technical honesty and NIST SP 800-88 Rev.1 guidelines, SSDs are transparently classified as SANITIZATION_NOT_VERIFIABLE regarding unmapped physical wear-leveling flash blocks.',
    },
    {
      q: 'What information is shown publicly?',
      a: 'Public marketplace listings and certificate lookups display only safe identifiers: Device Model, Manufacturer, Capacity, Interface, Sanitization Date, Verification Method, and a privacy-masked serial number (e.g. WD-****-9988). Previous owner identities and full raw serial numbers are never exposed publicly.',
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-16">
        <div className="container mx-auto px-4 sm:px-8 max-w-4xl space-y-12">
          {/* Header */}
          <div className="text-center space-y-4 max-w-2xl mx-auto">
            <Badge variant="outline" className="px-3 py-1 border-primary/30 text-primary bg-primary/5 text-xs font-semibold gap-1.5">
              <HelpCircle className="h-3.5 w-3.5" />
              Frequently Asked Questions
            </Badge>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
              Everything You Need to Know About SecureWipe
            </h1>
            <p className="text-muted-foreground text-sm sm:text-base">
              Clear answers about our sanitization technology, cryptographic verification, privacy controls, and marketplace workflows.
            </p>
          </div>

          {/* Accordion List */}
          <Card className="border p-6 shadow-sm">
            <Accordion type="single" collapsible className="w-full space-y-2">
              {faqs.map((faq, idx) => (
                <AccordionItem key={idx} value={`item-${idx}`} className="border-b last:border-b-0 py-2">
                  <AccordionTrigger className="text-base font-semibold text-left hover:no-underline hover:text-primary transition">
                    {faq.q}
                  </AccordionTrigger>
                  <AccordionContent className="text-sm text-muted-foreground leading-relaxed pt-2">
                    {faq.a}
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </Card>

          {/* Contact Banner */}
          <div className="p-8 rounded-2xl bg-muted/40 border text-center space-y-4">
            <h3 className="text-xl font-bold">Have a specific question about your device?</h3>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              Our technical guides and platform documentation cover deployment, local agent architecture, and security specifications.
            </p>
            <div className="pt-2 flex justify-center gap-4">
              <Link href="/how-it-works">
                <Button variant="outline" size="sm">
                  View How It Works
                </Button>
              </Link>
              <Link href="/dashboard/devices/register">
                <Button size="sm">
                  Register a Device
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
