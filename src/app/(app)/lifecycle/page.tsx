'use client';

import React from 'react';
import Link from 'next/link';
import {
  ClipboardCheck,
  Cpu,
  Search,
  ShieldCheck,
  FileText,
  GitBranch,
  Recycle,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Info,
  ArrowRight,
  ExternalLink,
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const API_BASE = 'http://localhost:9758/api';

type DashboardStats = {
  total_certificates: number;
  sanitized_reusable: number;
  not_verifiable: number;
  failed: number;
  disposal_required: number;
};

type Certificate = {
  id: string;
  device_id: string;
  device_model?: string;
  assurance_status: string;
  lifecycle_decision: string;
  generated_at: string;
};

type Integration = {
  name: string;
  display_name: string;
  status: string;
  description?: string;
};

const defaultStats: DashboardStats = {
  total_certificates: 0,
  sanitized_reusable: 0,
  not_verifiable: 0,
  failed: 0,
  disposal_required: 0,
};

const LIFECYCLE_STEPS = [
  { label: 'Device Detection', icon: Cpu },
  { label: 'Inspection', icon: Search },
  { label: 'Sanitization', icon: ShieldCheck },
  { label: 'Verification', icon: CheckCircle2 },
  { label: 'Certificate', icon: FileText },
  { label: 'Decision', icon: GitBranch },
  { label: 'Reuse / Disposal', icon: Recycle },
];

function getAssuranceBadge(status: string) {
  switch (status) {
    case 'SANITIZED_REUSABLE':
      return (
        <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border-green-300">
          ✅ Sanitized & Reusable
        </Badge>
      );
    case 'SANITIZATION_NOT_VERIFIABLE':
      return (
        <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-300">
          ⚠️ Not Verifiable
        </Badge>
      );
    case 'SANITIZATION_FAILED':
      return (
        <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-300">
          ❌ Sanitization Failed
        </Badge>
      );
    case 'DISPOSAL_REQUIRED':
      return (
        <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200 border-orange-300">
          🗑️ Disposal Required
        </Badge>
      );
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function getDecisionBadge(decision: string) {
  switch (decision) {
    case 'REUSE':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Reuse</Badge>;
    case 'REVIEW':
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">Review</Badge>;
    case 'DISPOSAL_REQUIRED':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">Disposal</Badge>;
    default:
      return <Badge variant="outline">{decision}</Badge>;
  }
}

function getIntegrationBadge(status: string) {
  const map: Record<string, string> = {
    NOT_CONFIGURED: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
    READY_FOR_CONFIGURATION: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    CONFIGURED: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
    CONNECTED: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    ACTIVE: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    AUTHENTICATION_FAILED: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    SUBMISSION_FAILED: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  };
  return (
    <Badge className={map[status] ?? 'bg-gray-100 text-gray-700'}>
      {status.replace(/_/g, ' ')}
    </Badge>
  );
}

export default function LifecycleDashboardPage() {
  const [stats, setStats] = React.useState<DashboardStats>(defaultStats);
  const [certificates, setCertificates] = React.useState<Certificate[]>([]);
  const [integrations, setIntegrations] = React.useState<Integration[]>([]);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchAll() {
      setLoading(true);
      try {
        const [statsRes, certsRes, intRes] = await Promise.allSettled([
          fetch(`${API_BASE}/compliance/dashboard-stats`),
          fetch(`${API_BASE}/compliance/certificates`),
          fetch(`${API_BASE}/compliance/integration-status`),
        ]);

        if (statsRes.status === 'fulfilled' && statsRes.value.ok) {
          setStats(await statsRes.value.json());
        }
        if (certsRes.status === 'fulfilled' && certsRes.value.ok) {
          const data = await certsRes.value.json();
          setCertificates(Array.isArray(data) ? data.slice(0, 10) : (data.certificates?.slice(0, 10) ?? []));
        }
        if (intRes.status === 'fulfilled' && intRes.value.ok) {
          const data = await intRes.value.json();
          setIntegrations(Array.isArray(data) ? data : (data.integrations ?? []));
        }
      } catch {
        // Graceful degradation — show zeros, don't crash
      } finally {
        setLoading(false);
      }
    }
    fetchAll();
  }, []);

  const statCards = [
    {
      label: 'Total Devices Processed',
      value: stats.total_certificates,
      badgeClass: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      icon: ClipboardCheck,
    },
    {
      label: 'Sanitized & Reusable',
      value: stats.sanitized_reusable,
      badgeClass: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
      icon: CheckCircle2,
    },
    {
      label: 'Not Verifiable',
      value: stats.not_verifiable,
      badgeClass: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
      icon: AlertTriangle,
    },
    {
      label: 'Sanitization Failed',
      value: stats.failed,
      badgeClass: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
      icon: XCircle,
    },
    {
      label: 'Disposal Required',
      value: stats.disposal_required,
      badgeClass: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
      icon: Recycle,
    },
    {
      label: 'Certificates Generated',
      value: stats.total_certificates,
      badgeClass: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
      icon: FileText,
    },
  ];

  return (
    <div className="flex flex-col gap-6">
      {/* Page header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Device Lifecycle Dashboard</h1>
        <p className="text-muted-foreground mt-1">
          End-to-end device sanitization, certification, and lifecycle decision tracking.
        </p>
      </div>

      {/* Stats row */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
        {statCards.map((card) => {
          const Icon = card.icon;
          return (
            <Card key={card.label}>
              <CardHeader className="pb-2">
                <CardDescription className="flex items-center gap-1.5 text-xs">
                  <Icon className="h-3.5 w-3.5" />
                  {card.label}
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{loading ? '—' : card.value}</div>
                <Badge className={`mt-1 text-[10px] ${card.badgeClass}`}>{card.label}</Badge>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Lifecycle Flow Diagram */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Lifecycle Flow</CardTitle>
          <CardDescription>Sequential stages every device passes through in SecureWipe.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-1">
            {LIFECYCLE_STEPS.map((step, idx) => {
              const Icon = step.icon;
              return (
                <React.Fragment key={step.label}>
                  <div className="flex flex-col items-center gap-1 px-3 py-2 rounded-lg border bg-muted/50 min-w-[90px] text-center">
                    <Icon className="h-5 w-5 text-primary" />
                    <span className="text-xs font-medium leading-tight">{step.label}</span>
                  </div>
                  {idx < LIFECYCLE_STEPS.length - 1 && (
                    <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0" />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Recent Certificates */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Recent Certificates</CardTitle>
              <CardDescription>Last 10 sanitization certificates generated by the platform.</CardDescription>
            </div>
            <Button variant="outline" size="sm" asChild>
              <Link href="/lifecycle/certificates">
                View All <ExternalLink className="ml-1.5 h-3.5 w-3.5" />
              </Link>
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Certificate ID</TableHead>
                <TableHead>Device</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Generated At</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    Loading certificates…
                  </TableCell>
                </TableRow>
              ) : certificates.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No certificates yet. Run a sanitization workflow to generate the first certificate.
                  </TableCell>
                </TableRow>
              ) : (
                certificates.map((cert) => (
                  <TableRow key={cert.id}>
                    <TableCell className="font-mono text-xs">{cert.id.substring(0, 16)}…</TableCell>
                    <TableCell className="text-sm">
                      <div>{cert.device_model ?? cert.device_id}</div>
                      <div className="text-[11px] text-muted-foreground font-mono">{cert.device_id.substring(0, 16)}</div>
                    </TableCell>
                    <TableCell>{getAssuranceBadge(cert.assurance_status)}</TableCell>
                    <TableCell>{getDecisionBadge(cert.lifecycle_decision)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {cert.generated_at ? new Date(cert.generated_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="outline" size="sm" asChild>
                        <Link href={`/lifecycle/certificate/${cert.id}`}>View</Link>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Integration Status */}
      <Card>
        <CardHeader>
          <CardTitle>Integration Status</CardTitle>
          <CardDescription>
            External integrations require configuration with real authorized providers.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {integrations.length === 0 ? (
            <div className="space-y-3">
              {['E-Waste / CPCB Recycler', 'GRC Platform', 'Government Procurement (GeM)'].map((name) => (
                <div key={name} className="flex items-center justify-between py-2 border-b last:border-b-0">
                  <span className="text-sm font-medium">{name}</span>
                  {getIntegrationBadge('NOT_CONFIGURED')}
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {integrations.map((int) => (
                <div key={int.name} className="flex items-center justify-between py-2 border-b last:border-b-0">
                  <div>
                    <div className="text-sm font-medium">{int.display_name ?? int.name}</div>
                    {int.description && (
                      <div className="text-xs text-muted-foreground">{int.description}</div>
                    )}
                  </div>
                  {getIntegrationBadge(int.status)}
                </div>
              ))}
            </div>
          )}
          <p className="text-xs text-muted-foreground mt-4 border-t pt-3">
            ⚠️ External integrations require configuration with real authorized providers.
          </p>
        </CardContent>
      </Card>

      {/* Disclaimer */}
      <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-950/30 dark:border-blue-800">
        <Info className="h-4 w-4 text-blue-600 dark:text-blue-400" />
        <AlertTitle className="text-blue-800 dark:text-blue-300">Platform Status &amp; Claims</AlertTitle>
        <AlertDescription className="text-blue-700 dark:text-blue-400 space-y-1 mt-2">
          <p>✅ <strong>IMPLEMENTED:</strong> Core sanitization, verification, certificate generation, lifecycle decisions, audit trail.</p>
          <p>🔷 <strong>ARCHITECTURE READY:</strong> E-Waste adapter interface, GRC adapter interface, Government procurement readiness.</p>
          <p>⚠️ <strong>EXTERNAL DEPENDENCY:</strong> CPCB recycler integration, GeM listing, STQC certification, GRC vendor connection.</p>
          <p>❌ <strong>NOT VERIFIED:</strong> Official government API specifications for any external integrations.</p>
        </AlertDescription>
      </Alert>
    </div>
  );
}
