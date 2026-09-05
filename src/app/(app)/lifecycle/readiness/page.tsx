'use client';

import React from 'react';
import { CheckSquare, Info, AlertTriangle } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
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

type ChecklistItem = {
  category: string;
  item: string;
  status: string;
  notes?: string;
};

function getStatusBadge(status: string) {
  switch (status) {
    case 'AVAILABLE':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">✅ Available</Badge>;
    case 'PARTIAL':
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">⚠️ Partial</Badge>;
    case 'MISSING':
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">❌ Missing</Badge>;
    case 'EXTERNAL_REQUIRED':
      return <Badge className="bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-300">🔗 External Required</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

function ChecklistTable({ items, loading, error }: { items: ChecklistItem[]; loading: boolean; error: string | null }) {
  if (loading) {
    return <div className="text-center py-10 text-muted-foreground">Loading checklist…</div>;
  }
  if (error) {
    return <div className="text-center py-10 text-red-500">{error}</div>;
  }
  if (items.length === 0) {
    return <div className="text-center py-10 text-muted-foreground">No checklist items available.</div>;
  }

  // Group by category
  const categories = Array.from(new Set(items.map((i) => i.category)));

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Category</TableHead>
          <TableHead>Item</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Notes</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {categories.flatMap((cat) => {
          const catItems = items.filter((i) => i.category === cat);
          return catItems.map((item, idx) => (
            <TableRow key={`${cat}-${idx}`}>
              {idx === 0 ? (
                <TableCell
                  rowSpan={catItems.length}
                  className="align-top font-medium text-sm border-r"
                >
                  {cat}
                </TableCell>
              ) : null}
              <TableCell className="text-sm">{item.item}</TableCell>
              <TableCell>{getStatusBadge(item.status)}</TableCell>
              <TableCell className="text-xs text-muted-foreground">{item.notes ?? '—'}</TableCell>
            </TableRow>
          ));
        })}
      </TableBody>
    </Table>
  );
}

export default function ReadinessPage() {
  const [assessmentItems, setAssessmentItems] = React.useState<ChecklistItem[]>([]);
  const [procurementItems, setProcurementItems] = React.useState<ChecklistItem[]>([]);
  const [loadingAssessment, setLoadingAssessment] = React.useState(true);
  const [loadingProcurement, setLoadingProcurement] = React.useState(true);
  const [assessmentError, setAssessmentError] = React.useState<string | null>(null);
  const [procurementError, setProcurementError] = React.useState<string | null>(null);

  React.useEffect(() => {
    async function fetchChecklists() {
      // Assessment checklist
      try {
        const res = await fetch(`${API_BASE}/compliance/assessment-checklist`);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const data = await res.json();
        setAssessmentItems(Array.isArray(data) ? data : (data.items ?? []));
      } catch (err: any) {
        setAssessmentError(err.message ?? 'Failed to load assessment checklist.');
      } finally {
        setLoadingAssessment(false);
      }

      // Procurement checklist
      try {
        const res = await fetch(`${API_BASE}/compliance/procurement-checklist`);
        if (!res.ok) throw new Error(`Server returned ${res.status}`);
        const data = await res.json();
        setProcurementItems(Array.isArray(data) ? data : (data.items ?? []));
      } catch (err: any) {
        setProcurementError(err.message ?? 'Failed to load procurement checklist.');
      } finally {
        setLoadingProcurement(false);
      }
    }
    fetchChecklists();
  }, []);

  const assessmentAvailable = assessmentItems.filter((i) => i.status === 'AVAILABLE').length;
  const procurementAvailable = procurementItems.filter((i) => i.status === 'AVAILABLE').length;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-3">
        <CheckSquare className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Assessment &amp; Procurement Readiness</h1>
          <p className="text-muted-foreground">
            Evidence availability and documentation status for compliance assessments.
          </p>
        </div>
      </div>

      <Tabs defaultValue="assessment" className="w-full">
        <TabsList>
          <TabsTrigger value="assessment">Assessment Readiness</TabsTrigger>
          <TabsTrigger value="procurement">Government Procurement</TabsTrigger>
        </TabsList>

        {/* Tab 1: Assessment Readiness */}
        <TabsContent value="assessment" className="mt-4 flex flex-col gap-4">
          <div>
            <h2 className="text-xl font-semibold">Security Assessment Readiness</h2>
            <p className="text-muted-foreground text-sm mt-0.5">
              This is NOT an STQC certification. It organizes evidence for a future external assessment.
            </p>
          </div>

          <Alert className="border-orange-300 bg-orange-50 dark:bg-orange-950/30 dark:border-orange-700">
            <AlertTriangle className="h-4 w-4 text-orange-600 dark:text-orange-400" />
            <AlertTitle className="text-orange-800 dark:text-orange-300">Not an Official Certification</AlertTitle>
            <AlertDescription className="text-orange-700 dark:text-orange-400">
              SecureWipe is not STQC certified. This checklist identifies evidence available for a future assessment process.
              STQC certification requires an official submission and evaluation by the certifying authority.
            </AlertDescription>
          </Alert>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Assessment Evidence Checklist</CardTitle>
                  <CardDescription>
                    {!loadingAssessment && `${assessmentAvailable} of ${assessmentItems.length} items available`}
                  </CardDescription>
                </div>
                {!loadingAssessment && assessmentItems.length > 0 && (
                  <div className="text-right text-sm">
                    <div className="font-bold text-2xl text-green-600">
                      {Math.round((assessmentAvailable / assessmentItems.length) * 100)}%
                    </div>
                    <div className="text-muted-foreground text-xs">available</div>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <ChecklistTable items={assessmentItems} loading={loadingAssessment} error={assessmentError} />
            </CardContent>
          </Card>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {(['AVAILABLE', 'PARTIAL', 'MISSING', 'EXTERNAL_REQUIRED'] as const).map((status) => {
              const count = assessmentItems.filter((i) => i.status === status).length;
              return (
                <Card key={status} className="text-center p-4">
                  <div className="text-2xl font-bold">{count}</div>
                  <div className="mt-1">{getStatusBadge(status)}</div>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        {/* Tab 2: Government Procurement */}
        <TabsContent value="procurement" className="mt-4 flex flex-col gap-4">
          <div>
            <h2 className="text-xl font-semibold">Government Procurement Readiness</h2>
            <p className="text-muted-foreground text-sm mt-0.5">
              Checklist for GeM / government procurement documentation requirements.
            </p>
          </div>

          <Alert className="border-orange-300 bg-orange-50 dark:bg-orange-950/30 dark:border-orange-700">
            <AlertTriangle className="h-4 w-4 text-orange-600 dark:text-orange-400" />
            <AlertTitle className="text-orange-800 dark:text-orange-300">Not Listed on GeM</AlertTitle>
            <AlertDescription className="text-orange-700 dark:text-orange-400">
              SecureWipe is not listed on GeM. This checklist identifies documentation requirements for future
              procurement consideration. GeM listing requires a formal application and approval process.
            </AlertDescription>
          </Alert>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Procurement Documentation Checklist</CardTitle>
                  <CardDescription>
                    {!loadingProcurement && `${procurementAvailable} of ${procurementItems.length} items available`}
                  </CardDescription>
                </div>
                {!loadingProcurement && procurementItems.length > 0 && (
                  <div className="text-right text-sm">
                    <div className="font-bold text-2xl text-green-600">
                      {Math.round((procurementAvailable / procurementItems.length) * 100)}%
                    </div>
                    <div className="text-muted-foreground text-xs">available</div>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <ChecklistTable items={procurementItems} loading={loadingProcurement} error={procurementError} />
            </CardContent>
          </Card>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {(['AVAILABLE', 'PARTIAL', 'MISSING', 'EXTERNAL_REQUIRED'] as const).map((status) => {
              const count = procurementItems.filter((i) => i.status === status).length;
              return (
                <Card key={status} className="text-center p-4">
                  <div className="text-2xl font-bold">{count}</div>
                  <div className="mt-1">{getStatusBadge(status)}</div>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
