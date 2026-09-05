'use client';

import React from 'react';
import { Network, ArrowRight, CheckCircle2, AlertTriangle, XCircle, Info } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';

const API_BASE = 'http://localhost:9758/api';

type IntegrationStatus = {
  name: string;
  display_name: string;
  status: string;
  description?: string;
  capabilities?: string[];
  error?: string;
};

const STATUS_BADGE: Record<string, { cls: string; icon: React.ReactNode }> = {
  NOT_CONFIGURED: {
    cls: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300',
    icon: <Info className="h-3.5 w-3.5 mr-1" />,
  },
  READY_FOR_CONFIGURATION: {
    cls: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
    icon: <Info className="h-3.5 w-3.5 mr-1" />,
  },
  CONFIGURED: {
    cls: 'bg-teal-100 text-teal-800 dark:bg-teal-900 dark:text-teal-200',
    icon: <CheckCircle2 className="h-3.5 w-3.5 mr-1" />,
  },
  CONNECTED: {
    cls: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    icon: <CheckCircle2 className="h-3.5 w-3.5 mr-1" />,
  },
  ACTIVE: {
    cls: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
    icon: <CheckCircle2 className="h-3.5 w-3.5 mr-1" />,
  },
  AUTHENTICATION_FAILED: {
    cls: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
    icon: <XCircle className="h-3.5 w-3.5 mr-1" />,
  },
  SUBMISSION_FAILED: {
    cls: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
    icon: <AlertTriangle className="h-3.5 w-3.5 mr-1" />,
  },
};

function getStatusBadge(status: string) {
  const s = STATUS_BADGE[status];
  return (
    <Badge className={`flex items-center ${s?.cls ?? 'bg-gray-100 text-gray-700'}`}>
      {s?.icon}
      {status.replace(/_/g, ' ')}
    </Badge>
  );
}

const DEFAULT_INTEGRATIONS: IntegrationStatus[] = [
  {
    name: 'ewaste',
    display_name: 'E-Waste Integration (CPCB / Authorized Recyclers)',
    status: 'NOT_CONFIGURED',
    description: 'Enables device certificate submission to authorized e-waste recyclers. Requires verified API credentials from a registered authorized recycler.',
    capabilities: [
      'Submit device record to recycler',
      'Submit sanitization certificate',
      'Get submission status',
      'Retrieve disposal evidence',
    ],
  },
  {
    name: 'grc',
    display_name: 'GRC Integration (Enterprise Compliance Platforms)',
    status: 'NOT_CONFIGURED',
    description: 'Enables compliance evidence submission to enterprise GRC systems (ISO 27001, SOC 2, etc.). Requires vendor-specific API credentials.',
    capabilities: [
      'Create compliance evidence record',
      'Upload sanitization certificate',
      'Associate with asset register',
      'Sync audit metadata',
    ],
  },
  {
    name: 'gem',
    display_name: 'Government Procurement (GeM Channel)',
    status: 'NOT_CONFIGURED',
    description: "Government e-Marketplace integration for procurement channels. SecureWipe is not currently listed on GeM.",
    capabilities: [],
  },
];

const INTEGRATION_FOOTERS: Record<string, string> = {
  ewaste: '⚠️ EXTERNAL DEPENDENCY: Real recycler API specifications not yet verified.',
  grc: '⚠️ EXTERNAL DEPENDENCY: No specific GRC vendor implemented. Interface is architecture-ready.',
  gem: '⚠️ NOT VERIFIED: GeM listing requirements and API specifications not yet confirmed.',
};

const ARCH_STEPS = [
  'SecureWipe Core',
  'Compliance Service',
  'Certificate Service',
  'Integration Adapter Layer',
  'E-Waste | GRC | Government',
];

export default function IntegrationsPage() {
  const [integrations, setIntegrations] = React.useState<IntegrationStatus[]>(DEFAULT_INTEGRATIONS);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchIntegrations() {
      try {
        const res = await fetch(`${API_BASE}/compliance/integration-status`);
        if (res.ok) {
          const data = await res.json();
          const list: IntegrationStatus[] = Array.isArray(data) ? data : (data.integrations ?? []);
          if (list.length > 0) {
            // Merge API data with defaults for display purposes
            setIntegrations(DEFAULT_INTEGRATIONS.map((def) => {
              const live = list.find((l) => l.name === def.name);
              return live ? { ...def, ...live } : def;
            }));
          }
        }
      } catch { /* Use defaults */ } finally {
        setLoading(false);
      }
    }
    fetchIntegrations();
  }, []);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Network className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">External Integrations</h1>
          <p className="text-muted-foreground">
            Status of all external integration adapters.
          </p>
        </div>
      </div>

      <Alert className="border-blue-200 bg-blue-50 dark:bg-blue-950/30 dark:border-blue-800">
        <Info className="h-4 w-4 text-blue-600 dark:text-blue-400" />
        <AlertTitle className="text-blue-800 dark:text-blue-300">Integration Requirements</AlertTitle>
        <AlertDescription className="text-blue-700 dark:text-blue-400">
          External integrations require real API credentials and authorization from the respective organizations.
          No external system connection is active. The adapter layer is architecture-ready for future integration.
        </AlertDescription>
      </Alert>

      {/* Integration Cards */}
      <div className="grid gap-4 lg:grid-cols-3">
        {integrations.map((integration) => (
          <Card key={integration.name} className="flex flex-col">
            <CardHeader>
              <div className="flex items-start justify-between gap-2">
                <CardTitle className="text-base leading-snug">{integration.display_name}</CardTitle>
              </div>
              <div className="mt-1">{getStatusBadge(integration.status)}</div>
            </CardHeader>
            <CardContent className="flex-grow space-y-3">
              {integration.description && (
                <p className="text-sm text-muted-foreground">{integration.description}</p>
              )}
              {integration.capabilities && integration.capabilities.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">Capabilities</p>
                  <ul className="space-y-1">
                    {integration.capabilities.map((cap) => (
                      <li key={cap} className="flex items-center gap-2 text-sm">
                        <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                        {cap}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {integration.error && (
                <Alert variant="destructive">
                  <AlertDescription className="text-xs">{integration.error}</AlertDescription>
                </Alert>
              )}
            </CardContent>
            <CardFooter className="pt-3 border-t">
              <p className="text-xs text-muted-foreground">
                {INTEGRATION_FOOTERS[integration.name] ?? '⚠️ External integration not configured.'}
              </p>
            </CardFooter>
          </Card>
        ))}
      </div>

      <Separator />

      {/* Architecture Diagram */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Architecture Overview</CardTitle>
          <CardDescription>
            How SecureWipe connects to external systems through the adapter layer.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-1">
            {ARCH_STEPS.map((step, idx) => (
              <React.Fragment key={step}>
                <div
                  className={`px-3 py-1.5 rounded-md border text-xs font-medium ${
                    idx === ARCH_STEPS.length - 1
                      ? 'border-dashed border-muted-foreground text-muted-foreground bg-transparent'
                      : 'bg-muted/50'
                  }`}
                >
                  {step}
                </div>
                {idx < ARCH_STEPS.length - 1 && (
                  <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
          <p className="text-xs text-muted-foreground mt-4 border-t pt-3">
            The Integration Adapter Layer provides a standardized interface for external systems. Each adapter is independently configurable and can be enabled when real API credentials are available.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
