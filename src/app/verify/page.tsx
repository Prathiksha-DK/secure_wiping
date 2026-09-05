'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  FileCheck2,
  Lock,
  QrCode,
  HardDrive,
  Cpu,
  Layers,
  ExternalLink,
  Loader2,
  Copy,
  Check
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

export default function PublicVerifyPage() {
  const [certId, setCertId] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<any>(null);
  const [searched, setSearched] = React.useState(false);
  const [copied, setCopied] = React.useState(false);

  async function handleVerify(idToVerify?: string) {
    const id = (idToVerify || certId).trim();
    if (!id) return;
    setLoading(true);
    setSearched(true);
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/marketplace/verify/${encodeURIComponent(id)}`);
      const data = await res.json();
      setResult(data);
    } catch (e: any) {
      setResult({
        valid: false,
        status: 'NETWORK_ERROR',
        message: 'Could not connect to the verification ledger service.'
      });
    } finally {
      setLoading(false);
    }
  }

  function handleCopy() {
    if (!result?.certificate_id) return;
    navigator.clipboard.writeText(result.certificate_id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-16">
        <div className="container mx-auto px-4 sm:px-8 max-w-4xl space-y-12">
          {/* Header */}
          <div className="text-center space-y-4 max-w-2xl mx-auto">
            <Badge variant="outline" className="px-3 py-1 border-primary/30 text-primary bg-primary/5 text-xs font-semibold gap-1.5">
              <ShieldCheck className="h-3.5 w-3.5" />
              Cryptographic Ledger Lookup
            </Badge>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
              Public Certificate Verification
            </h1>
            <p className="text-muted-foreground text-sm sm:text-base">
              Enter any SecureWipe Certificate ID or scan a certificate QR code to verify cryptographic authenticity and sanitization assurance.
            </p>
          </div>

          {/* Search Box */}
          <Card className="p-6 border shadow-md space-y-4">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleVerify();
              }}
              className="flex flex-col sm:flex-row gap-3"
            >
              <div className="relative flex-1">
                <FileCheck2 className="absolute left-3.5 top-3.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Enter Certificate ID (e.g. CERT-SMP-001 or UUID)..."
                  value={certId}
                  onChange={(e) => setCertId(e.target.value)}
                  className="pl-10 h-11 text-sm font-mono"
                />
              </div>
              <Button type="submit" disabled={loading} className="h-11 px-6 gap-2 bg-gradient-to-r from-primary to-blue-600 shrink-0">
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                Verify Certificate
              </Button>
            </form>

            <div className="flex flex-wrap items-center gap-2 pt-2 text-xs text-muted-foreground">
              <span>Quick Test Sample IDs:</span>
              {['CERT-SMP-001', 'CERT-SMP-002', 'CERT-SMP-003'].map((sampleId) => (
                <button
                  key={sampleId}
                  type="button"
                  onClick={() => {
                    setCertId(sampleId);
                    handleVerify(sampleId);
                  }}
                  className="font-mono px-2 py-0.5 rounded bg-muted hover:bg-muted/80 text-foreground font-medium border"
                >
                  {sampleId}
                </button>
              ))}
            </div>
          </Card>

          {/* Verification Results Display */}
          {searched && (
            <div className="space-y-6">
              {loading ? (
                <div className="text-center py-16 space-y-3">
                  <Loader2 className="h-8 w-8 animate-spin mx-auto text-primary" />
                  <p className="text-sm text-muted-foreground">Validating canonical digest and asymmetric signature...</p>
                </div>
              ) : result?.valid ? (
                /* Valid Certificate View */
                <Card className="border-2 border-emerald-500/40 bg-card p-6 sm:p-8 space-y-6 shadow-xl relative overflow-hidden">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b">
                    <div className="flex items-center gap-3">
                      <div className="h-12 w-12 rounded-2xl bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300 flex items-center justify-center font-bold">
                        <CheckCircle2 className="h-7 w-7" />
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <h2 className="text-xl font-extrabold text-foreground">CERTIFICATE VALID</h2>
                          <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 text-xs">
                            Active &amp; Authentic
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          Cryptographically verified against the SecureWipe Public CA.
                        </p>
                      </div>
                    </div>

                    <Button variant="outline" size="sm" onClick={handleCopy} className="gap-1.5 text-xs">
                      {copied ? <Check className="h-3.5 w-3.5 text-green-600" /> : <Copy className="h-3.5 w-3.5" />}
                      {copied ? 'Copied ID' : 'Copy ID'}
                    </Button>
                  </div>

                  {/* Sanitized Device Specs (Privacy-Safe) */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <HardDrive className="h-3.5 w-3.5" />
                      Sanitized Storage Target (Privacy Masked)
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Manufacturer</span>
                        <strong className="text-sm">{result.device?.manufacturer}</strong>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Model</span>
                        <strong className="text-sm truncate block">{result.device?.model}</strong>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Capacity</span>
                        <strong className="text-sm">{result.device?.capacity}</strong>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Masked Serial</span>
                        <strong className="text-sm font-mono">{result.device?.masked_serial}</strong>
                      </div>
                    </div>
                  </div>

                  {/* Sanitization Details */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                      <Layers className="h-3.5 w-3.5" />
                      Sanitization Operation
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Sanitization Standard</span>
                        <strong className="text-sm">{result.sanitization?.method}</strong>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Assurance Status</span>
                        <strong className="text-sm text-emerald-600">{result.sanitization?.assurance_status}</strong>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/40 border">
                        <span className="text-muted-foreground block">Completed At</span>
                        <strong className="text-sm font-mono">{result.sanitization?.completed_at ? new Date(result.sanitization.completed_at).toLocaleString() : 'Verified'}</strong>
                      </div>
                    </div>
                  </div>

                  {/* Cryptographic Integrity Block */}
                  <div className="p-4 rounded-xl bg-muted/50 border text-xs space-y-2 font-mono">
                    <div className="flex justify-between items-center text-foreground font-semibold">
                      <span>SHA-256 Canonical Digest:</span>
                      <span className="text-green-600 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> MATCHED
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-foreground font-semibold">
                      <span>RSA-PSS Digital Signature:</span>
                      <span className="text-green-600 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> VERIFIED
                      </span>
                    </div>
                    <div className="flex justify-between items-center text-muted-foreground pt-1 border-t text-[11px]">
                      <span>Issuing Authority:</span>
                      <span>{result.integrity?.signing_authority || 'SecureWipe Platform CA'}</span>
                    </div>
                  </div>

                  <p className="text-xs text-muted-foreground text-center">
                    {result.trust_statement}
                  </p>
                </Card>
              ) : (
                /* Invalid / Revoked / Not Found View */
                <Card className="border-2 border-red-400 bg-red-50/30 dark:bg-red-950/20 p-6 sm:p-8 space-y-4">
                  <div className="flex items-center gap-3">
                    <XCircle className="h-8 w-8 text-red-600 shrink-0" />
                    <div>
                      <h3 className="text-lg font-bold text-red-900 dark:text-red-200">
                        {result?.status === 'REVOKED' ? 'CERTIFICATE REVOKED' : 'CERTIFICATE INVALID OR NOT FOUND'}
                      </h3>
                      <p className="text-xs text-red-800 dark:text-red-300 mt-1">
                        {result?.message || 'The specified Certificate ID could not be validated against the public ledger.'}
                      </p>
                    </div>
                  </div>
                </Card>
              )}
            </div>
          )}

          {/* Privacy Guarantee Note */}
          <Alert className="border-blue-200 bg-blue-50/50 dark:bg-blue-950/20 text-xs">
            <Lock className="h-4 w-4 text-blue-600" />
            <AlertTitle className="text-blue-900 dark:text-blue-200 font-bold">Privacy Protection Policy</AlertTitle>
            <AlertDescription className="text-blue-800 dark:text-blue-300 mt-1">
              Public certificate lookups never reveal the previous owner’s identity, physical address, or complete unmasked hardware serial numbers.
            </AlertDescription>
          </Alert>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
