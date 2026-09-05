'use client';

import React from 'react';
import { Recycle, ArrowRight, AlertTriangle, Plus, Loader2 } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';

const API_BASE = 'http://localhost:9758/api';

type Recycler = {
  id: string;
  organization_name: string;
  authorization_reference?: string;
  contact_info?: string;
};

type Handover = {
  id: string;
  certificate_id: string;
  recycler_id: string;
  recycler_name?: string;
  status: string;
  created_at: string;
  disposal_reason?: string;
};

const DISPOSAL_STEPS = [
  'Sanitization',
  'Disposal Decision',
  'Recycler Selection',
  'Handover Record',
  'Disposal Evidence',
  'Compliance Record',
];

function getHandoverStatusBadge(status: string) {
  switch (status) {
    case 'PENDING':
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">Pending</Badge>;
    case 'HANDED_OVER':
      return <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200">Handed Over</Badge>;
    case 'DISPOSAL_CONFIRMED':
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">Disposal Confirmed</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

export default function DisposalPage() {
  const [recyclers, setRecyclers] = React.useState<Recycler[]>([]);
  const [handovers, setHandovers] = React.useState<Handover[]>([]);
  const [loadingData, setLoadingData] = React.useState(true);

  // Handover form state
  const [certId, setCertId] = React.useState('');
  const [selectedRecycler, setSelectedRecycler] = React.useState('');
  const [disposalReason, setDisposalReason] = React.useState('');
  const [notes, setNotes] = React.useState('');
  const [submittingHandover, setSubmittingHandover] = React.useState(false);
  const [handoverMsg, setHandoverMsg] = React.useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Add recycler form state
  const [orgName, setOrgName] = React.useState('');
  const [authRef, setAuthRef] = React.useState('');
  const [contactInfo, setContactInfo] = React.useState('');
  const [submittingRecycler, setSubmittingRecycler] = React.useState(false);
  const [recyclerMsg, setRecyclerMsg] = React.useState<{ type: 'success' | 'error'; text: string } | null>(null);

  async function fetchData() {
    setLoadingData(true);
    try {
      const [rRes, hRes] = await Promise.allSettled([
        fetch(`${API_BASE}/compliance/recyclers`),
        fetch(`${API_BASE}/compliance/disposal-handovers`),
      ]);
      if (rRes.status === 'fulfilled' && rRes.value.ok) {
        const d = await rRes.value.json();
        setRecyclers(Array.isArray(d) ? d : (d.recyclers ?? []));
      }
      if (hRes.status === 'fulfilled' && hRes.value.ok) {
        const d = await hRes.value.json();
        setHandovers(Array.isArray(d) ? d : (d.handovers ?? []));
      }
    } catch { /* Graceful */ } finally {
      setLoadingData(false);
    }
  }

  React.useEffect(() => { fetchData(); }, []);

  async function handleHandoverSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!certId || !selectedRecycler) {
      setHandoverMsg({ type: 'error', text: 'Certificate ID and Recycler are required.' });
      return;
    }
    setSubmittingHandover(true);
    setHandoverMsg(null);
    try {
      const res = await fetch(`${API_BASE}/compliance/disposal-handovers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate_id: certId, recycler_id: selectedRecycler, disposal_reason: disposalReason, notes }),
      });
      if (!res.ok) throw new Error(await res.text());
      setHandoverMsg({ type: 'success', text: 'Disposal handover record created successfully.' });
      setCertId(''); setSelectedRecycler(''); setDisposalReason(''); setNotes('');
      fetchData();
    } catch (err: any) {
      setHandoverMsg({ type: 'error', text: err.message ?? 'Failed to create handover.' });
    } finally {
      setSubmittingHandover(false);
    }
  }

  async function handleConfirmDisposal(handoverId: string) {
    try {
      const res = await fetch(`${API_BASE}/compliance/disposal-handovers/${handoverId}/confirm`, { method: 'POST' });
      if (!res.ok) throw new Error('Confirmation failed');
      fetchData();
    } catch (err: any) {
      alert(err.message ?? 'Failed to confirm disposal.');
    }
  }

  async function handleRecyclerSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!orgName) {
      setRecyclerMsg({ type: 'error', text: 'Organization name is required.' });
      return;
    }
    setSubmittingRecycler(true);
    setRecyclerMsg(null);
    try {
      const res = await fetch(`${API_BASE}/compliance/recyclers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ organization_name: orgName, authorization_reference: authRef, contact_info: contactInfo }),
      });
      if (!res.ok) throw new Error(await res.text());
      setRecyclerMsg({ type: 'success', text: 'Recycler registered successfully.' });
      setOrgName(''); setAuthRef(''); setContactInfo('');
      fetchData();
    } catch (err: any) {
      setRecyclerMsg({ type: 'error', text: err.message ?? 'Failed to register recycler.' });
    } finally {
      setSubmittingRecycler(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Recycle className="h-7 w-7 text-primary" />
        <div>
          <h1 className="text-3xl font-bold tracking-tight">E-Waste &amp; Secure Disposal</h1>
          <p className="text-muted-foreground">Manage secure device disposal and recycler handovers.</p>
        </div>
      </div>

      {/* IMPORTANT Disclaimer */}
      <Alert className="border-orange-300 bg-orange-50 dark:bg-orange-950/30 dark:border-orange-700">
        <AlertTriangle className="h-4 w-4 text-orange-600 dark:text-orange-400" />
        <AlertTitle className="text-orange-800 dark:text-orange-300">IMPORTANT</AlertTitle>
        <AlertDescription className="text-orange-700 dark:text-orange-400">
          E-waste integration with external recyclers requires real API credentials from an authorized recycler.
          No external integration is currently active. This system records handover intent only.
        </AlertDescription>
      </Alert>

      {/* Disposal Lifecycle Flow */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Disposal Lifecycle Flow</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-1">
            {DISPOSAL_STEPS.map((step, idx) => (
              <React.Fragment key={step}>
                <div className="px-3 py-1.5 rounded-md border bg-muted/50 text-xs font-medium">{step}</div>
                {idx < DISPOSAL_STEPS.length - 1 && (
                  <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Create Handover + Handover Records */}
      <div className="grid lg:grid-cols-2 gap-6">
        {/* Left: Create Disposal Handover */}
        <Card>
          <CardHeader>
            <CardTitle>Create Disposal Handover</CardTitle>
            <CardDescription>Record a device disposal handover to an authorized recycler.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleHandoverSubmit} className="space-y-4">
              <div className="space-y-1">
                <Label htmlFor="certId">Certificate ID</Label>
                <Input
                  id="certId"
                  placeholder="Enter sanitization certificate ID"
                  value={certId}
                  onChange={(e) => setCertId(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="recycler">Recycler</Label>
                <Select value={selectedRecycler} onValueChange={setSelectedRecycler}>
                  <SelectTrigger id="recycler">
                    <SelectValue placeholder={loadingData ? 'Loading…' : recyclers.length === 0 ? 'No recyclers registered' : 'Select recycler'} />
                  </SelectTrigger>
                  <SelectContent>
                    {recyclers.map((r) => (
                      <SelectItem key={r.id} value={r.id}>{r.organization_name}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1">
                <Label htmlFor="reason">Disposal Reason</Label>
                <Textarea
                  id="reason"
                  placeholder="Explain why this device requires disposal…"
                  rows={2}
                  value={disposalReason}
                  onChange={(e) => setDisposalReason(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="notes">Notes (optional)</Label>
                <Textarea
                  id="notes"
                  placeholder="Additional notes…"
                  rows={2}
                  value={notes}
                  onChange={(e) => setNotes(e.target.value)}
                />
              </div>
              {handoverMsg && (
                <Alert className={handoverMsg.type === 'success' ? 'border-green-300 bg-green-50 dark:bg-green-950/30' : 'border-red-300 bg-red-50 dark:bg-red-950/30'}>
                  <AlertDescription className={handoverMsg.type === 'success' ? 'text-green-700' : 'text-red-700'}>
                    {handoverMsg.text}
                  </AlertDescription>
                </Alert>
              )}
              <Button type="submit" disabled={submittingHandover}>
                {submittingHandover ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Creating…</> : 'Create Handover Record'}
              </Button>
            </form>
          </CardContent>
        </Card>

        {/* Right: Handover Records */}
        <Card>
          <CardHeader>
            <CardTitle>Handover Records</CardTitle>
            <CardDescription>All device disposal handover records.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Handover ID</TableHead>
                  <TableHead>Certificate</TableHead>
                  <TableHead>Recycler</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Timestamp</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loadingData ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-6 text-muted-foreground">Loading…</TableCell>
                  </TableRow>
                ) : handovers.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-6 text-muted-foreground">No handover records yet.</TableCell>
                  </TableRow>
                ) : (
                  handovers.map((h) => (
                    <TableRow key={h.id}>
                      <TableCell className="font-mono text-xs">{h.id.substring(0, 12)}…</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{h.certificate_id.substring(0, 12)}…</TableCell>
                      <TableCell className="text-xs">{h.recycler_name ?? h.recycler_id}</TableCell>
                      <TableCell>{getHandoverStatusBadge(h.status)}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{new Date(h.created_at).toLocaleString()}</TableCell>
                      <TableCell className="text-right">
                        {h.status === 'HANDED_OVER' && (
                          <Button variant="outline" size="sm" onClick={() => handleConfirmDisposal(h.id)}>
                            Confirm Disposal
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      <Separator />

      {/* Recycler Management */}
      <div>
        <h2 className="text-xl font-semibold mb-4">Recycler Management</h2>
        <div className="grid lg:grid-cols-2 gap-6">
          {/* Registered Recyclers */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Registered Recyclers</CardTitle>
              <CardDescription>Authorized e-waste recyclers configured in the system.</CardDescription>
            </CardHeader>
            <CardContent>
              {loadingData ? (
                <p className="text-sm text-muted-foreground">Loading…</p>
              ) : recyclers.length === 0 ? (
                <p className="text-sm text-muted-foreground">No recyclers registered yet.</p>
              ) : (
                <div className="space-y-3">
                  {recyclers.map((r) => (
                    <div key={r.id} className="border rounded-lg p-3 space-y-1">
                      <div className="font-medium text-sm">{r.organization_name}</div>
                      {r.authorization_reference && (
                        <div className="text-xs text-muted-foreground">Auth Ref: {r.authorization_reference}</div>
                      )}
                      {r.contact_info && (
                        <div className="text-xs text-muted-foreground">Contact: {r.contact_info}</div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              <Alert className="mt-4 border-yellow-200 bg-yellow-50 dark:bg-yellow-950/30">
                <AlertDescription className="text-yellow-700 dark:text-yellow-400 text-xs">
                  Recycler must be an authorized e-waste recycler. SecureWipe does not validate recycler authorization status.
                </AlertDescription>
              </Alert>
            </CardContent>
          </Card>

          {/* Add Recycler Form */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Add Recycler</CardTitle>
              <CardDescription>Register a new authorized e-waste recycler.</CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleRecyclerSubmit} className="space-y-4">
                <div className="space-y-1">
                  <Label htmlFor="orgName">Organization Name <span className="text-red-500">*</span></Label>
                  <Input id="orgName" placeholder="e.g., GreenTech Recyclers Pvt. Ltd." value={orgName} onChange={(e) => setOrgName(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="authRef">Authorization Reference</Label>
                  <Input id="authRef" placeholder="CPCB registration / authorization number" value={authRef} onChange={(e) => setAuthRef(e.target.value)} />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="contactInfo">Contact Info</Label>
                  <Input id="contactInfo" placeholder="Email or phone" value={contactInfo} onChange={(e) => setContactInfo(e.target.value)} />
                </div>
                {recyclerMsg && (
                  <Alert className={recyclerMsg.type === 'success' ? 'border-green-300 bg-green-50 dark:bg-green-950/30' : 'border-red-300 bg-red-50 dark:bg-red-950/30'}>
                    <AlertDescription className={recyclerMsg.type === 'success' ? 'text-green-700' : 'text-red-700'}>
                      {recyclerMsg.text}
                    </AlertDescription>
                  </Alert>
                )}
                <Button type="submit" disabled={submittingRecycler} variant="outline">
                  {submittingRecycler ? <><Loader2 className="h-4 w-4 mr-2 animate-spin" />Adding…</> : <><Plus className="h-4 w-4 mr-2" />Add Recycler</>}
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
