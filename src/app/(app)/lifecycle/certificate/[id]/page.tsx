'use client';

import React from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  ArrowLeft,
  Copy,
  Download,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Info,
  Loader2,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';

const API_BASE = 'http://localhost:9758/api';

type CertificateDetail = {
  id: string;
  version: string;
  generated_at: string;
  assurance_status: string;
  assurance_reason?: string;
  assurance_limitations?: string[];
  device_technology_note?: string;

  device: {
    id: string;
    type?: string;
    model?: string;
    serial?: string;
    technology?: string;
    capacity_bytes?: number;
  };

  sanitization: {
    method?: string;
    passes?: number;
    started_at?: string;
    completed_at?: string;
    duration_seconds?: number;
    bytes_written?: number;
  };

  verification: {
    method?: string;
    coverage_percent?: number;
    result?: string;
  };

  lifecycle_decision: {
    recommended_action?: string;
    policy_profile?: string;
    decided_at?: string;
  };

  forensic_assessment?: {
    evidence_level?: string;
    confidence_score?: number;
    validated_artifacts?: string[];
  };

  integrity: {
    sha256_digest?: string;
    signature_status?: string;
    verification_mechanism?: string;
  };

  operator?: {
    name?: string;
    id?: string;
  };

  application?: {
    name?: string;
    version?: string;
  };
};

function getAssuranceBadge(status: string) {
  switch (status) {
    case 'SANITIZED_REUSABLE':
      return (
        <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border-green-300 text-sm px-3 py-1">
          <CheckCircle2 className="h-4 w-4 mr-1.5" /> Sanitized &amp; Reusable
        </Badge>
      );
    case 'SANITIZATION_NOT_VERIFIABLE':
      return (
        <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-300 text-sm px-3 py-1">
          <AlertTriangle className="h-4 w-4 mr-1.5" /> Not Verifiable
        </Badge>
      );
    case 'SANITIZATION_FAILED':
      return (
        <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-300 text-sm px-3 py-1">
          <XCircle className="h-4 w-4 mr-1.5" /> Sanitization Failed
        </Badge>
      );
    case 'DISPOSAL_REQUIRED':
      return (
        <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200 border-orange-300 text-sm px-3 py-1">
          <ShieldX className="h-4 w-4 mr-1.5" /> Disposal Required
        </Badge>
      );
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function getVerificationResultBadge(result?: string) {
  switch (result) {
    case 'PASS':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">PASS</Badge>;
    case 'WARN':
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">WARN</Badge>;
    case 'FAIL':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">FAIL</Badge>;
    default:
      return <Badge variant="outline">{result ?? '—'}</Badge>;
  }
}

function getDecisionBadge(action?: string) {
  switch (action) {
    case 'REUSE':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 text-sm px-3 py-1">✅ Reuse</Badge>;
    case 'REVIEW':
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 text-sm px-3 py-1">🔍 Review</Badge>;
    case 'DISPOSAL_REQUIRED':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 text-sm px-3 py-1">🗑️ Disposal Required</Badge>;
    default:
      return <Badge variant="outline">{action ?? '—'}</Badge>;
  }
}

function getSignatureBadge(status?: string) {
  switch (status) {
    case 'VALID':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">VALID</Badge>;
    case 'INVALID':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">INVALID</Badge>;
    case 'MODIFIED':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">MODIFIED</Badge>;
    case 'UNKNOWN':
    default:
      return <Badge className="bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300">{status ?? 'UNKNOWN'}</Badge>;
  }
}

function formatBytes(bytes?: number): string {
  if (!bytes) return '—';
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} MB`;
  return `${bytes} bytes`;
}

function maskSerial(serial?: string): string {
  if (!serial) return '—';
  if (serial.length <= 4) return '****';
  return serial.slice(0, 2) + '****' + serial.slice(-4);
}

export default function CertificateDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [cert, setCert] = React.useState<CertificateDetail | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [verifying, setVerifying] = React.useState(false);
  const [verifyResult, setVerifyResult] = React.useState<{ status: string; message?: string } | null>(null);
  const [copied, setCopied] = React.useState(false);

  React.useEffect(() => {
    async function fetchCert() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`${API_BASE}/compliance/certificates/${id}`);
        if (!res.ok) throw new Error(`Certificate not found (${res.status})`);
        const data = await res.json();
        setCert(data);
      } catch (err: any) {
        setError(err.message ?? 'Failed to load certificate.');
      } finally {
        setLoading(false);
      }
    }
    if (id) fetchCert();
  }, [id]);

  async function handleVerify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await fetch(`${API_BASE}/compliance/certificates/${id}/verify`, { method: 'POST' });
      const data = await res.json();
      setVerifyResult(data);
    } catch {
      setVerifyResult({ status: 'UNKNOWN', message: 'Verification request failed.' });
    } finally {
      setVerifying(false);
    }
  }

  async function handleExport() {
    try {
      const res = await fetch(`${API_BASE}/compliance/certificates/${id}/export`);
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `certificate-${id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      alert('Export failed. Please try again.');
    }
  }

  function copyDigest() {
    if (cert?.integrity?.sha256_digest) {
      navigator.clipboard.writeText(cert.integrity.sha256_digest);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <span className="ml-3 text-muted-foreground">Loading certificate…</span>
      </div>
    );
  }

  if (error || !cert) {
    return (
      <div className="flex flex-col gap-4">
        <Button variant="ghost" size="sm" asChild className="w-fit">
          <Link href="/lifecycle/certificates">
            <ArrowLeft className="h-4 w-4 mr-1.5" /> Back to Certificates
          </Link>
        </Button>
        <Alert variant="destructive">
          <AlertTitle>Certificate Not Found</AlertTitle>
          <AlertDescription>{error ?? 'The requested certificate could not be loaded.'}</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 max-w-5xl">
      {/* Nav */}
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/lifecycle/certificates">
            <ArrowLeft className="h-4 w-4 mr-1.5" /> Back to Certificates
          </Link>
        </Button>
        <Button variant="outline" size="sm" onClick={handleExport}>
          <Download className="h-4 w-4 mr-1.5" /> Export JSON
        </Button>
      </div>

      {/* Certificate Header */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center gap-3 flex-wrap">
          <ShieldCheck className="h-7 w-7 text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">Sanitization Certificate</h1>
          {getAssuranceBadge(cert.assurance_status)}
        </div>
        <p className="font-mono text-sm text-muted-foreground break-all">{cert.id}</p>
        <p className="text-xs text-muted-foreground">
          Generated: {cert.generated_at ? new Date(cert.generated_at).toLocaleString() : '—'}
          {cert.version && ` · v${cert.version}`}
        </p>
      </div>

      {/* Device + Sanitization info */}
      <div className="grid md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Device Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Type" value={cert.device.type} />
            <Row label="Model" value={cert.device.model} />
            <Row label="Serial" value={maskSerial(cert.device.serial)} mono />
            <Row label="Technology" value={cert.device.technology} />
            <Row label="Capacity" value={formatBytes(cert.device.capacity_bytes)} />
            <Row label="Device ID" value={cert.device.id?.substring(0, 24) + '…'} mono />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Sanitization Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Method" value={cert.sanitization.method} />
            <Row label="Passes" value={cert.sanitization.passes?.toString()} />
            <Row label="Started" value={cert.sanitization.started_at ? new Date(cert.sanitization.started_at).toLocaleString() : undefined} />
            <Row label="Completed" value={cert.sanitization.completed_at ? new Date(cert.sanitization.completed_at).toLocaleString() : undefined} />
            <Row label="Duration" value={cert.sanitization.duration_seconds ? `${cert.sanitization.duration_seconds}s` : undefined} />
            <Row label="Bytes Written" value={formatBytes(cert.sanitization.bytes_written)} />
          </CardContent>
        </Card>
      </div>

      {/* Verification */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Verification</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-6 text-sm">
            <div>
              <span className="text-muted-foreground">Method: </span>
              <span>{cert.verification.method ?? '—'}</span>
            </div>
            <div>
              <span className="text-muted-foreground">Coverage: </span>
              <span>{cert.verification.coverage_percent != null ? `${cert.verification.coverage_percent}%` : '—'}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Result: </span>
              {getVerificationResultBadge(cert.verification.result)}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Assurance Status */}
      <Card className="border-2">
        <CardHeader>
          <CardTitle className="text-base">Assurance Status</CardTitle>
          <CardDescription>The overall sanitization assurance determination for this device.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div>{getAssuranceBadge(cert.assurance_status)}</div>
          {cert.assurance_reason && (
            <p className="text-sm">{cert.assurance_reason}</p>
          )}
          {cert.device_technology_note && (
            <Alert>
              <Info className="h-4 w-4" />
              <AlertDescription className="text-sm">{cert.device_technology_note}</AlertDescription>
            </Alert>
          )}
          {cert.assurance_limitations && cert.assurance_limitations.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">Limitations</p>
              <ul className="list-disc list-inside text-sm space-y-1">
                {cert.assurance_limitations.map((lim, i) => (
                  <li key={i} className="text-muted-foreground">{lim}</li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Lifecycle Decision */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Lifecycle Decision</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <div className="flex items-center gap-3">
            <span className="text-muted-foreground">Recommended Action:</span>
            {getDecisionBadge(cert.lifecycle_decision.recommended_action)}
          </div>
          <Row label="Policy Profile" value={cert.lifecycle_decision.policy_profile} />
          <Row label="Decided At" value={cert.lifecycle_decision.decided_at ? new Date(cert.lifecycle_decision.decided_at).toLocaleString() : undefined} />
        </CardContent>
      </Card>

      {/* Forensic Assessment */}
      {cert.forensic_assessment && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Forensic Assessment</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row label="Evidence Level" value={cert.forensic_assessment.evidence_level} />
            <Row label="Confidence Score" value={cert.forensic_assessment.confidence_score != null ? `${cert.forensic_assessment.confidence_score}%` : undefined} />
            {cert.forensic_assessment.validated_artifacts && cert.forensic_assessment.validated_artifacts.length > 0 && (
              <div>
                <span className="text-muted-foreground">Validated Artifacts: </span>
                <span>{cert.forensic_assessment.validated_artifacts.join(', ')}</span>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Integrity & Verification */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Certificate Integrity</CardTitle>
          <CardDescription>Cryptographic integrity of this certificate record.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2 text-sm">
            <div className="flex items-start gap-2">
              <span className="text-muted-foreground shrink-0">SHA-256:</span>
              <span className="font-mono text-xs break-all">
                {cert.integrity.sha256_digest ? cert.integrity.sha256_digest.substring(0, 40) + '…' : '—'}
              </span>
              {cert.integrity.sha256_digest && (
                <Button variant="ghost" size="icon" className="h-5 w-5 shrink-0" onClick={copyDigest}>
                  <Copy className="h-3.5 w-3.5" />
                </Button>
              )}
              {copied && <span className="text-xs text-green-600">Copied!</span>}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-muted-foreground">Signature:</span>
              {getSignatureBadge(cert.integrity.signature_status)}
            </div>
            {cert.integrity.verification_mechanism && (
              <div>
                <span className="text-muted-foreground">Mechanism: </span>
                <span>{cert.integrity.verification_mechanism}</span>
              </div>
            )}
          </div>

          <Separator />

          <div className="flex flex-col gap-3">
            <Button onClick={handleVerify} disabled={verifying} className="w-fit">
              {verifying ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Verifying…
                </>
              ) : (
                <>
                  <ShieldCheck className="h-4 w-4 mr-2" />
                  Verify Certificate
                </>
              )}
            </Button>

            {verifyResult && (
              <Alert
                className={
                  verifyResult.status === 'VALID'
                    ? 'border-green-300 bg-green-50 dark:bg-green-950/30'
                    : verifyResult.status === 'INVALID' || verifyResult.status === 'MODIFIED'
                    ? 'border-red-300 bg-red-50 dark:bg-red-950/30'
                    : ''
                }
              >
                {verifyResult.status === 'VALID' ? (
                  <CheckCircle2 className="h-4 w-4 text-green-600" />
                ) : verifyResult.status === 'INVALID' || verifyResult.status === 'MODIFIED' ? (
                  <ShieldX className="h-4 w-4 text-red-600" />
                ) : (
                  <AlertTriangle className="h-4 w-4" />
                )}
                <AlertTitle>{verifyResult.status}</AlertTitle>
                {verifyResult.message && (
                  <AlertDescription>{verifyResult.message}</AlertDescription>
                )}
              </Alert>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Operator & Application */}
      {(cert.operator || cert.application) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Operator &amp; Application</CardTitle>
          </CardHeader>
          <CardContent className="grid sm:grid-cols-2 gap-4 text-sm">
            {cert.operator && (
              <div className="space-y-1">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Operator</p>
                <Row label="Name" value={cert.operator.name} />
                <Row label="ID" value={cert.operator.id} mono />
              </div>
            )}
            {cert.application && (
              <div className="space-y-1">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Application</p>
                <Row label="Name" value={cert.application.name} />
                <Row label="Version" value={cert.application.version} />
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="flex gap-2">
      <span className="text-muted-foreground shrink-0 w-28">{label}:</span>
      <span className={`${mono ? 'font-mono text-xs' : ''} break-all`}>{value ?? '—'}</span>
    </div>
  );
}
