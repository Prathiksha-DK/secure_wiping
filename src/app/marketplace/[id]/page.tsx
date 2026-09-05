'use client';

import React from 'react';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import {
  ShieldCheck,
  CheckCircle2,
  HardDrive,
  Cpu,
  Layers,
  FileCheck2,
  ShoppingBag,
  ExternalLink,
  ChevronLeft,
  Lock,
  ArrowRight,
  Sparkles,
  Info,
  Check,
  Loader2,
  User,
  Truck
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Separator } from '@/components/ui/separator';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

export default function ListingDetailPage() {
  const params = useParams();
  const router = useRouter();
  const listingId = params?.id as string;

  const [listing, setListing] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(true);
  const [purchasing, setPurchasing] = React.useState(false);
  const [purchaseMsg, setPurchaseMsg] = React.useState<{ type: 'success' | 'error'; text: string } | null>(null);

  React.useEffect(() => {
    async function fetchListing() {
      if (!listingId) return;
      try {
        const res = await fetch(`${API_BASE}/marketplace/listings/${listingId}`);
        if (res.ok) {
          const data = await res.json();
          setListing(data.listing);
        }
      } catch (e) {
        console.error('Failed to load listing:', e);
      } finally {
        setLoading(false);
      }
    }
    fetchListing();
  }, [listingId]);

  async function handleBuy() {
    setPurchasing(true);
    setPurchaseMsg(null);
    try {
      const res = await fetch(`${API_BASE}/marketplace/listings/${listingId}/buy`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transfer_notes: 'Standard purchase via SecureWipe Marketplace' })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Purchase initiation failed.');
      setPurchaseMsg({
        type: 'success',
        text: `Order placed successfully! Transfer ID: ${data.order?.transfer_id}. Device ownership is now pending handover.`
      });
      // Refresh listing state
      setListing((prev: any) => ({ ...prev, listing_status: 'PENDING_TRANSFER' }));
    } catch (err: any) {
      setPurchaseMsg({ type: 'error', text: err.message || 'Failed to place purchase order.' });
    } finally {
      setPurchasing(false);
    }
  }

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col bg-background">
        <CommercialHeader />
        <div className="flex-1 flex items-center justify-center py-24">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
        </div>
        <CommercialFooter />
      </div>
    );
  }

  if (!listing) {
    return (
      <div className="min-h-screen flex flex-col bg-background">
        <CommercialHeader />
        <div className="flex-1 container mx-auto px-4 py-24 text-center space-y-4 max-w-lg">
          <h2 className="text-2xl font-bold">Listing Not Found</h2>
          <p className="text-sm text-muted-foreground">The device listing you requested does not exist or has been removed.</p>
          <Link href="/marketplace">
            <Button variant="outline">Return to Marketplace</Button>
          </Link>
        </div>
        <CommercialFooter />
      </div>
    );
  }

  const smart = listing.smart_data || {};

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-10">
        <div className="container mx-auto px-4 sm:px-8 max-w-6xl space-y-8">
          {/* Breadcrumb Back */}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Link href="/marketplace" className="hover:text-foreground flex items-center gap-1">
              <ChevronLeft className="h-3.5 w-3.5" />
              Marketplace
            </Link>
            <span>/</span>
            <span>{listing.device_type}</span>
            <span>/</span>
            <span className="text-foreground font-medium truncate max-w-xs">{listing.title}</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
            {/* Left Column: Device Info, Certificate & Health */}
            <div className="lg:col-span-8 space-y-6">
              {/* Main Card */}
              <Card className="border p-6 space-y-6">
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-200">
                      {listing.device_type}
                    </Badge>
                    <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 gap-1">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      SecureWipe Verified
                    </Badge>
                    <Badge variant="outline">{listing.condition}</Badge>
                  </div>

                  <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
                    {listing.title}
                  </h1>

                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {listing.description}
                  </p>
                </div>

                <Separator />

                {/* Technical Specifications */}
                <div>
                  <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                    <HardDrive className="h-4 w-4 text-primary" />
                    Storage Specifications
                  </h3>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Manufacturer</span>
                      <strong className="text-sm">{listing.manufacturer}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Model</span>
                      <strong className="text-sm truncate block">{listing.model}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Capacity</span>
                      <strong className="text-sm">{listing.capacity_human}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Interface</span>
                      <strong className="text-sm">{listing.interface}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Platform Device ID</span>
                      <strong className="text-sm font-mono">{listing.device_id}</strong>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/40 border">
                      <span className="text-muted-foreground block">Masked Serial</span>
                      <strong className="text-sm font-mono">{listing.masked_serial}</strong>
                    </div>
                  </div>
                </div>

                {/* Hardware Health & SMART Data (Non-fabricated) */}
                {Object.keys(smart).length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                      <Cpu className="h-4 w-4 text-primary" />
                      Hardware Health &amp; SMART Telemetry
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                      {smart.power_on_hours !== undefined && (
                        <div className="p-3 rounded-lg bg-muted/40 border">
                          <span className="text-muted-foreground block">Power-On Hours</span>
                          <strong className="text-sm">{smart.power_on_hours} hrs</strong>
                        </div>
                      )}
                      {smart.wear_level !== undefined && (
                        <div className="p-3 rounded-lg bg-muted/40 border">
                          <span className="text-muted-foreground block">Remaining Life</span>
                          <strong className="text-sm text-green-600">{smart.wear_level}% Healthy</strong>
                        </div>
                      )}
                      {smart.temperature_c !== undefined && (
                        <div className="p-3 rounded-lg bg-muted/40 border">
                          <span className="text-muted-foreground block">Operating Temp</span>
                          <strong className="text-sm">{smart.temperature_c} °C</strong>
                        </div>
                      )}
                      {smart.reallocated_sectors !== undefined && (
                        <div className="p-3 rounded-lg bg-muted/40 border">
                          <span className="text-muted-foreground block">Bad Sectors</span>
                          <strong className="text-sm">{smart.reallocated_sectors}</strong>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Sanitization Certificate Guarantee Card */}
                <div className="p-5 rounded-xl border-2 border-primary/20 bg-primary/5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <FileCheck2 className="h-5 w-5 text-primary" />
                      <div>
                        <h4 className="font-bold text-sm">Attached Sanitization Certificate</h4>
                        <p className="text-xs text-muted-foreground">Digitally Signed Schema v1.0 Certificate</p>
                      </div>
                    </div>
                    <Badge variant="outline" className="text-xs font-mono">
                      {listing.certificate_id}
                    </Badge>
                  </div>

                  <p className="text-xs text-muted-foreground leading-relaxed">
                    This drive completed multi-pass sanitization with deep file signature verification. The certificate is cryptographically signed using RSA-PSS and can be verified independently before purchase.
                  </p>

                  <Link href={`/verify`} className="inline-block">
                    <Button variant="outline" size="sm" className="gap-1.5 text-xs bg-background">
                      <ShieldCheck className="h-3.5 w-3.5 text-primary" />
                      Inspect Cryptographic Certificate
                      <ExternalLink className="h-3 w-3" />
                    </Button>
                  </Link>
                </div>
              </Card>
            </div>

            {/* Right Column: Price, Trust Score & Purchase Action */}
            <div className="lg:col-span-4 space-y-6">
              <Card className="border p-6 space-y-6 shadow-md">
                <div className="space-y-1">
                  <span className="text-xs text-muted-foreground font-medium">Price</span>
                  <div className="text-3xl font-black text-foreground">
                    ${listing.price_usd.toFixed(2)}
                  </div>
                  <span className="text-xs text-green-600 font-semibold block pt-1">
                    ✓ Verified In Stock &amp; Sanitized
                  </span>
                </div>

                <Separator />

                {/* Trust Score Card */}
                <div className="space-y-2">
                  <div className="flex justify-between items-center text-xs">
                    <span className="font-semibold text-muted-foreground">Device Trust Score:</span>
                    <strong className="text-sm text-foreground">{listing.trust_score}/100</strong>
                  </div>
                  <div className="h-2 w-full bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-emerald-500 to-primary rounded-full transition-all duration-500"
                      style={{ width: `${listing.trust_score}%` }}
                    />
                  </div>
                  <p className="text-[11px] text-muted-foreground pt-1">
                    Calculated from verifiable sanitization passes, active certificate, and hardware SMART health telemetry.
                  </p>
                </div>

                <Separator />

                {/* Seller Info & Shipping */}
                <div className="space-y-3 text-xs">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground flex items-center gap-1">
                      <User className="h-3.5 w-3.5" /> Seller:
                    </span>
                    <strong className="text-foreground">{listing.seller_username}</strong>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground flex items-center gap-1">
                      <Truck className="h-3.5 w-3.5" /> Shipping:
                    </span>
                    <span className="text-foreground font-medium">{listing.shipping_options}</span>
                  </div>
                  {listing.location && (
                    <div className="flex justify-between items-center">
                      <span className="text-muted-foreground">Location:</span>
                      <span className="text-foreground">{listing.location}</span>
                    </div>
                  )}
                </div>

                {purchaseMsg && (
                  <Alert className={purchaseMsg.type === 'success' ? 'border-green-300 bg-green-50 dark:bg-green-950/40 text-green-800' : 'border-red-300 bg-red-50 text-red-800'}>
                    <AlertDescription className="text-xs font-medium">
                      {purchaseMsg.text}
                    </AlertDescription>
                  </Alert>
                )}

                {/* Purchase Button */}
                <Button
                  onClick={handleBuy}
                  disabled={purchasing || listing.listing_status !== 'ACTIVE'}
                  className="w-full gap-2 h-11 bg-gradient-to-r from-primary to-blue-600 shadow-md"
                >
                  {purchasing ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Placing Order...
                    </>
                  ) : listing.listing_status === 'ACTIVE' ? (
                    <>
                      <ShoppingBag className="h-4 w-4" />
                      Purchase &amp; Transfer Ownership
                    </>
                  ) : (
                    `Status: ${listing.listing_status}`
                  )}
                </Button>

                <p className="text-[11px] text-muted-foreground text-center leading-tight">
                  Upon purchase confirmation, ownership records in the SecureWipe ledger will be officially transferred to your account.
                </p>
              </Card>
            </div>
          </div>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
