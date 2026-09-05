'use client';

import React from 'react';
import Link from 'next/link';
import {
  LayoutDashboard,
  HardDrive,
  ShoppingBag,
  RotateCcw,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Plus,
  ArrowRight,
  ExternalLink,
  Lock,
  Layers,
  FileCheck2,
  Loader2,
  Trash2,
  User,
  Clock,
  Sparkles,
  ChevronRight
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

function getDeviceStatusBadge(status: string) {
  switch (status) {
    case 'REGISTERED':
      return <Badge variant="outline" className="bg-yellow-50 text-yellow-800 border-yellow-300 dark:bg-yellow-950/40 dark:text-yellow-300">Wipe Pending</Badge>;
    case 'WIPING':
      return <Badge className="bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-950 dark:text-blue-300 animate-pulse">Wiping in Progress</Badge>;
    case 'VERIFIED':
    case 'SANITIZED':
      return <Badge className="bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300 gap-1">✓ Verified</Badge>;
    case 'LISTED':
      return <Badge className="bg-purple-100 text-purple-800 border-purple-300 dark:bg-purple-950 dark:text-purple-300">Active on Marketplace</Badge>;
    case 'TRANSFERRED':
    case 'SOLD':
      return <Badge className="bg-slate-100 text-slate-800 border-slate-300 dark:bg-slate-800 dark:text-slate-300">Transferred / Sold</Badge>;
    case 'NOT_VERIFIABLE':
      return <Badge variant="outline" className="bg-amber-50 text-amber-800 border-amber-300">Not Verifiable</Badge>;
    case 'FAILED':
      return <Badge variant="destructive">Sanitization Failed</Badge>;
    default:
      return <Badge variant="outline">{status}</Badge>;
  }
}

export default function UserDashboardPage() {
  const [devices, setDevices] = React.useState<any[]>([]);
  const [listings, setListings] = React.useState<any[]>([]);
  const [loading, setLoading] = React.useState(true);

  async function fetchDashboardData() {
    setLoading(true);
    try {
      const [devRes, listRes] = await Promise.allSettled([
        fetch(`${API_BASE}/marketplace/devices/my-devices`),
        fetch(`${API_BASE}/marketplace/listings?verified_only=false`)
      ]);

      if (devRes.status === 'fulfilled' && devRes.value.ok) {
        const d = await devRes.value.json();
        setDevices(d.devices || []);
      }
      if (listRes.status === 'fulfilled' && listRes.value.ok) {
        const l = await listRes.value.json();
        setListings(l.listings || []);
      }
    } catch (e) {
      console.error('Failed to load dashboard:', e);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    fetchDashboardData();
  }, []);

  const verifiedDevices = devices.filter((d) => d.status === 'VERIFIED' || d.status === 'LISTED');
  const pendingWipes = devices.filter((d) => d.status === 'REGISTERED' || d.status === 'WIPING');

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-10">
        <div className="container mx-auto px-4 sm:px-8 max-w-7xl space-y-8">
          {/* Header & Quick Action */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Badge variant="outline" className="text-primary border-primary/30 bg-primary/5 text-xs font-semibold gap-1">
                  <LayoutDashboard className="h-3.5 w-3.5" />
                  My SecureWipe Portal
                </Badge>
              </div>
              <h1 className="text-3xl font-extrabold tracking-tight">User Dashboard</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                Manage your registered storage devices, sanitization workflows, certificates, and marketplace listings.
              </p>
            </div>

            <div className="flex items-center gap-3">
              <Link href="/dashboard/devices/register">
                <Button className="gap-2 bg-gradient-to-r from-primary to-blue-600 shadow-sm">
                  <Plus className="h-4 w-4" />
                  Register New Device
                </Button>
              </Link>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <Card className="p-4 border shadow-sm space-y-1">
              <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
                <HardDrive className="h-3.5 w-3.5 text-primary" /> Total Devices
              </span>
              <div className="text-2xl font-black">{devices.length}</div>
            </Card>
            <Card className="p-4 border shadow-sm space-y-1">
              <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" /> Verified &amp; Certified
              </span>
              <div className="text-2xl font-black text-emerald-600">{verifiedDevices.length}</div>
            </Card>
            <Card className="p-4 border shadow-sm space-y-1">
              <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
                <ShoppingBag className="h-3.5 w-3.5 text-purple-600" /> Active Listings
              </span>
              <div className="text-2xl font-black text-purple-600">
                {listings.filter((l) => l.listing_status === 'ACTIVE').length}
              </div>
            </Card>
            <Card className="p-4 border shadow-sm space-y-1">
              <span className="text-xs text-muted-foreground font-medium flex items-center gap-1.5">
                <Clock className="h-3.5 w-3.5 text-amber-600" /> Pending Wipe
              </span>
              <div className="text-2xl font-black text-amber-600">{pendingWipes.length}</div>
            </Card>
          </div>

          {/* Dashboard Tabs: My Devices | My Listings | Ownership & Transfers */}
          <Tabs defaultValue="devices" className="w-full space-y-6">
            <TabsList className="grid w-full sm:w-[450px] grid-cols-3">
              <TabsTrigger value="devices">My Devices</TabsTrigger>
              <TabsTrigger value="listings">My Listings</TabsTrigger>
              <TabsTrigger value="transfers">Transfers</TabsTrigger>
            </TabsList>

            {/* Tab 1: My Devices */}
            <TabsContent value="devices" className="space-y-4">
              <Card className="border">
                <CardHeader className="p-6 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-lg">Registered Storage Devices</CardTitle>
                    <CardDescription className="text-xs">
                      Devices attached to your account with their current sanitization lifecycle status.
                    </CardDescription>
                  </div>
                  <Link href="/dashboard/devices/register">
                    <Button size="sm" variant="outline" className="gap-1 text-xs">
                      <Plus className="h-3.5 w-3.5" /> Add Device
                    </Button>
                  </Link>
                </CardHeader>
                <CardContent className="p-0">
                  {loading ? (
                    <div className="py-12 text-center text-sm text-muted-foreground">
                      <Loader2 className="h-6 w-6 animate-spin mx-auto mb-2 text-primary" />
                      Loading your devices...
                    </div>
                  ) : devices.length === 0 ? (
                    <div className="py-12 text-center space-y-3 px-4">
                      <HardDrive className="h-8 w-8 mx-auto text-muted-foreground" />
                      <p className="text-sm font-medium">No storage devices registered yet.</p>
                      <Link href="/dashboard/devices/register">
                        <Button size="sm" className="gap-1.5">
                          <Plus className="h-4 w-4" /> Register Your First Device
                        </Button>
                      </Link>
                    </div>
                  ) : (
                    <div className="w-full overflow-x-auto">
                      <Table className="min-w-[680px]">
                        <TableHeader>
                          <TableRow>
                            <TableHead>Device ID</TableHead>
                            <TableHead>Manufacturer / Model</TableHead>
                            <TableHead>Capacity</TableHead>
                            <TableHead>Type</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead>Certificate</TableHead>
                            <TableHead className="text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {devices.map((dev) => (
                            <TableRow key={dev.device_id}>
                              <TableCell className="font-mono text-xs font-semibold">{dev.device_id}</TableCell>
                              <TableCell>
                                <div className="font-medium text-xs">{dev.model}</div>
                                <div className="text-[11px] text-muted-foreground">{dev.manufacturer} • {dev.masked_serial}</div>
                              </TableCell>
                              <TableCell className="text-xs">{dev.capacity_human}</TableCell>
                              <TableCell><Badge variant="outline" className="text-[10px]">{dev.device_type}</Badge></TableCell>
                              <TableCell>{getDeviceStatusBadge(dev.status)}</TableCell>
                              <TableCell>
                                {dev.certificate_id ? (
                                  <Link href="/verify" className="font-mono text-xs text-primary hover:underline flex items-center gap-1">
                                    {dev.certificate_id.substring(0, 10)}...
                                    <ExternalLink className="h-3 w-3" />
                                  </Link>
                                ) : (
                                  <span className="text-xs text-muted-foreground">—</span>
                                )}
                              </TableCell>
                              <TableCell className="text-right">
                                {dev.status === 'REGISTERED' && (
                                  <Link href={`/dashboard/listings/create?device_id=${dev.device_id}`}>
                                    <Button size="sm" variant="outline" className="text-xs h-8 gap-1 text-primary border-primary/30">
                                      <ShoppingBag className="h-3.5 w-3.5" /> List Device
                                    </Button>
                                  </Link>
                                )}
                                {dev.status === 'VERIFIED' && (
                                  <Link href={`/dashboard/listings/create?device_id=${dev.device_id}`}>
                                    <Button size="sm" variant="outline" className="text-xs h-8 gap-1 text-primary border-primary/30">
                                      <ShoppingBag className="h-3.5 w-3.5" /> List for Sale
                                    </Button>
                                  </Link>
                                )}
                                {dev.status === 'LISTED' && (
                                  <Link href="/marketplace">
                                    <Button size="sm" variant="ghost" className="text-xs h-8">
                                      View in Marketplace
                                    </Button>
                                  </Link>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Tab 2: My Listings */}
            <TabsContent value="listings" className="space-y-4">
              <Card className="border">
                <CardHeader className="p-6 pb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-lg">My Marketplace Listings</CardTitle>
                    <CardDescription className="text-xs">
                      Verified storage devices you are currently offering on the marketplace.
                    </CardDescription>
                  </div>
                  <Link href="/dashboard/listings/create">
                    <Button size="sm" variant="outline" className="gap-1 text-xs">
                      <Plus className="h-3.5 w-3.5" /> Create New Listing
                    </Button>
                  </Link>
                </CardHeader>
                <CardContent className="p-0">
                  {listings.length === 0 ? (
                    <div className="py-12 text-center text-sm text-muted-foreground space-y-2">
                      <ShoppingBag className="h-8 w-8 mx-auto text-muted-foreground" />
                      <p>You have no active marketplace listings.</p>
                    </div>
                  ) : (
                    <div className="w-full overflow-x-auto">
                      <Table className="min-w-[680px]">
                        <TableHeader>
                          <TableRow>
                            <TableHead>Listing ID</TableHead>
                            <TableHead>Title</TableHead>
                            <TableHead>Price</TableHead>
                            <TableHead>Condition</TableHead>
                            <TableHead>Verified Badge</TableHead>
                            <TableHead>Status</TableHead>
                            <TableHead className="text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {listings.map((l) => (
                            <TableRow key={l.listing_id}>
                              <TableCell className="font-mono text-xs">{l.listing_id}</TableCell>
                              <TableCell className="font-medium text-xs max-w-xs truncate">{l.title}</TableCell>
                              <TableCell className="text-xs font-bold">${Number(l.price_usd).toFixed(2)}</TableCell>
                              <TableCell className="text-xs">{l.condition}</TableCell>
                              <TableCell>
                                {l.is_verified === 1 ? (
                                  <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 text-[10px]">
                                    ✓ Verified
                                  </Badge>
                                ) : (
                                  <Badge variant="outline" className="text-[10px]">Unverified</Badge>
                                )}
                              </TableCell>
                              <TableCell><Badge variant="outline" className="text-xs">{l.listing_status}</Badge></TableCell>
                              <TableCell className="text-right">
                                <Link href={`/marketplace/${l.listing_id}`}>
                                  <Button size="sm" variant="ghost" className="text-xs h-8 gap-1">
                                    View <ChevronRight className="h-3 w-3" />
                                  </Button>
                                </Link>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>
                  )}
                </CardContent>
              </Card>
            </TabsContent>

            {/* Tab 3: Transfers & Orders */}
            <TabsContent value="transfers" className="space-y-4">
              <Card className="border p-6 space-y-4">
                <CardTitle className="text-lg">Ownership Transfers &amp; Orders</CardTitle>
                <CardDescription className="text-xs">
                  Track physical device handovers and cryptographic ownership transfers.
                </CardDescription>

                <Alert className="border-blue-200 bg-blue-50/50 dark:bg-blue-950/20 text-xs">
                  <ShieldCheck className="h-4 w-4 text-blue-600" />
                  <AlertTitle className="text-blue-900 dark:text-blue-200 font-bold">Ownership Transfer Protocol</AlertTitle>
                  <AlertDescription className="text-blue-800 dark:text-blue-300 mt-1">
                    When a buyer orders a device, the listing enters <code>PENDING_TRANSFER</code>. Once delivery is confirmed, ownership is updated in the SecureWipe ledger.
                  </AlertDescription>
                </Alert>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
