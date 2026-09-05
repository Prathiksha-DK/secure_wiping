'use client';

import React, { Suspense } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShoppingBag,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ChevronLeft,
  ArrowRight,
  HardDrive,
  FileCheck2,
  Loader2,
  Tag,
  Truck,
  Sparkles
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

function CreateListingContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialDeviceId = searchParams?.get('device_id') || '';

  const [myDevices, setMyDevices] = React.useState<any[]>([]);
  const [selectedDeviceId, setSelectedDeviceId] = React.useState(initialDeviceId);
  const [loadingDevices, setLoadingDevices] = React.useState(true);

  // Listing Form State
  const [title, setTitle] = React.useState('');
  const [description, setDescription] = React.useState('');
  const [price, setPrice] = React.useState('');
  const [condition, setCondition] = React.useState('Used - Excellent');
  const [shipping, setShipping] = React.useState('Standard Domestic ($4.99) / Local Pickup');
  const [location, setLocation] = React.useState('San Jose, CA');
  const [warranty, setWarranty] = React.useState('30-Day Functionality Guarantee');

  // Eligibility state
  const [eligibility, setEligibility] = React.useState<{ eligible?: boolean; reason?: string } | null>(null);
  const [checkingEligibility, setCheckingEligibility] = React.useState(false);

  const [submitting, setSubmitting] = React.useState(false);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  // Fetch eligible devices
  React.useEffect(() => {
    async function loadDevices() {
      try {
        const res = await fetch(`${API_BASE}/marketplace/devices/my-devices`);
        if (res.ok) {
          const data = await res.json();
          const devList = data.devices || [];
          setMyDevices(devList);

          if (!selectedDeviceId && devList.length > 0) {
            // Pick first verified device
            const verifiedOne = devList.find((d: any) => d.status === 'VERIFIED') || devList[0];
            setSelectedDeviceId(verifiedOne.device_id);
          }
        }
      } catch (e) {
        console.error('Failed to load user devices:', e);
      } finally {
        setLoadingDevices(false);
      }
    }
    loadDevices();
  }, []);

  // Check eligibility whenever selected device changes
  React.useEffect(() => {
    async function checkDeviceEligibility() {
      if (!selectedDeviceId) return;
      setCheckingEligibility(true);
      setErrorMsg(null);
      try {
        const res = await fetch(`${API_BASE}/marketplace/devices/${selectedDeviceId}/eligibility`);
        const data = await res.json();
        setEligibility(data);

        // Auto-populate title if empty
        const currentDev = myDevices.find((d) => d.device_id === selectedDeviceId);
        if (currentDev && !title) {
          setTitle(`${currentDev.manufacturer} ${currentDev.model} ${currentDev.capacity_human} — Verified`);
        }
      } catch (e) {
        setEligibility({ eligible: true });
      } finally {
        setCheckingEligibility(false);
      }
    }
    checkDeviceEligibility();
  }, [selectedDeviceId, myDevices]);

  const selectedDevice = myDevices.find((d) => d.device_id === selectedDeviceId);

  async function handleSubmitListing(e: React.FormEvent) {
    e.preventDefault();
    if (!title || !price) {
      setErrorMsg('Title and Price are required.');
      return;
    }
    if (eligibility && !eligibility.eligible) {
      setErrorMsg(`Device cannot be listed: ${eligibility.reason}`);
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);

    try {
      const res = await fetch(`${API_BASE}/marketplace/listings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          device_id: selectedDeviceId,
          title,
          description,
          price_usd: parseFloat(price),
          condition,
          shipping_options: shipping,
          location,
          warranty_terms: warranty
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Listing creation failed.');

      router.push(`/marketplace/${data.listing?.listing_id}`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to publish listing.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-12">
        <div className="container mx-auto px-4 sm:px-8 max-w-3xl space-y-8">
          {/* Breadcrumb Back */}
          <Link href="/dashboard" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" />
            Back to Dashboard
          </Link>

          {/* Header */}
          <div className="space-y-2">
            <h1 className="text-3xl font-extrabold tracking-tight">List Verified Device for Sale</h1>
            <p className="text-sm text-muted-foreground">
              Offer your sanitized storage hardware on the marketplace with an attached, cryptographically verified certificate.
            </p>
          </div>

          <Card className="border p-6 sm:p-8 shadow-sm space-y-6">
            <form onSubmit={handleSubmitListing} className="space-y-6">
              {/* Select Registered Device */}
              <div className="space-y-2">
                <Label htmlFor="device" className="text-xs font-semibold">Select Device to List</Label>
                {loadingDevices ? (
                  <div className="text-xs text-muted-foreground">Loading your devices...</div>
                ) : myDevices.length === 0 ? (
                  <Alert className="text-xs">
                    <AlertTitle>No Devices in Inventory</AlertTitle>
                    <AlertDescription>
                      You currently have no devices in your inventory to list.
                    </AlertDescription>
                  </Alert>
                ) : (
                  <Select value={selectedDeviceId} onValueChange={setSelectedDeviceId}>
                    <SelectTrigger id="device" className="text-xs">
                      <SelectValue placeholder="Choose a registered device..." />
                    </SelectTrigger>
                    <SelectContent>
                      {myDevices.map((d) => (
                        <SelectItem key={d.device_id} value={d.device_id}>
                          {d.model} ({d.capacity_human} • {d.device_type}) — Status: {d.status}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}
              </div>

              {/* Eligibility Status Alert */}
              {checkingEligibility ? (
                <div className="text-xs text-muted-foreground flex items-center gap-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
                  Checking backend listing eligibility...
                </div>
              ) : eligibility && !eligibility.eligible ? (
                <Alert variant="destructive" className="text-xs">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertTitle className="font-bold">Ineligible for Marketplace</AlertTitle>
                  <AlertDescription>{eligibility.reason}</AlertDescription>
                </Alert>
              ) : selectedDevice ? (
                <div className="p-4 rounded-xl border border-emerald-300 bg-emerald-50/50 dark:bg-emerald-950/20 text-xs space-y-2">
                  <div className="flex items-center gap-2 text-emerald-800 dark:text-emerald-300 font-bold">
                    <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                    Verified &amp; Listing Eligible
                  </div>
                  <div className="text-muted-foreground flex justify-between">
                    <span>Attached Certificate:</span>
                    <span className="font-mono font-semibold text-foreground">{selectedDevice.certificate_id || 'Available'}</span>
                  </div>
                </div>
              ) : null}

              <Separator />

              {/* Listing Details */}
              <div className="space-y-4">
                <div className="space-y-1.5">
                  <Label htmlFor="title" className="text-xs">Listing Title</Label>
                  <Input
                    id="title"
                    placeholder="e.g. Samsung 980 PRO 1TB NVMe M.2 SSD — SecureWipe Verified"
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    required
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="price" className="text-xs">Price (USD)</Label>
                    <div className="relative">
                      <span className="absolute left-3 top-2.5 text-muted-foreground text-sm font-bold">$</span>
                      <Input
                        id="price"
                        type="number"
                        step="0.01"
                        min="1"
                        placeholder="79.00"
                        value={price}
                        onChange={(e) => setPrice(e.target.value)}
                        className="pl-7"
                        required
                      />
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="condition" className="text-xs">Condition</Label>
                    <Select value={condition} onValueChange={setCondition}>
                      <SelectTrigger id="condition" className="text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Used - Like New">Used - Like New</SelectItem>
                        <SelectItem value="Used - Excellent">Used - Excellent</SelectItem>
                        <SelectItem value="Used - Good">Used - Good</SelectItem>
                        <SelectItem value="Refurbished">Refurbished</SelectItem>
                        <SelectItem value="Brand New">Brand New (Unused)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="desc" className="text-xs">Description &amp; Notes</Label>
                  <Textarea
                    id="desc"
                    placeholder="Describe usage history, condition, accessories included..."
                    rows={3}
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="shipping" className="text-xs">Shipping Options</Label>
                    <Input
                      id="shipping"
                      placeholder="Free Shipping, Local Pickup"
                      value={shipping}
                      onChange={(e) => setShipping(e.target.value)}
                    />
                  </div>

                  <div className="space-y-1.5">
                    <Label htmlFor="location" className="text-xs">Location (City, State)</Label>
                    <Input
                      id="location"
                      placeholder="e.g. San Jose, CA"
                      value={location}
                      onChange={(e) => setLocation(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              {errorMsg && (
                <Alert variant="destructive" className="text-xs">
                  <AlertDescription>{errorMsg}</AlertDescription>
                </Alert>
              )}

              <Button
                type="submit"
                disabled={Boolean(submitting || (eligibility && !eligibility.eligible))}
                className="w-full h-11 gap-2 bg-gradient-to-r from-primary to-blue-600 shadow-md"
              >
                {submitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Publishing Verified Listing...
                  </>
                ) : (
                  <>
                    <ShoppingBag className="h-4 w-4" />
                    Publish to Verified Marketplace
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Button>
            </form>
          </Card>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}

export default function CreateListingPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-sm text-muted-foreground">Loading listing editor...</div>}>
      <CreateListingContent />
    </Suspense>
  );
}

