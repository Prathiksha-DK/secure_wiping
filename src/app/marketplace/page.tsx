'use client';

import React from 'react';
import Link from 'next/link';
import {
  ShoppingBag,
  Search,
  Filter,
  CheckCircle2,
  ShieldCheck,
  ChevronRight,
  HardDrive,
  Cpu,
  Layers,
  Sparkles,
  SlidersHorizontal,
  ExternalLink,
  Check,
  Loader2
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

type MarketplaceListing = {
  listing_id: string;
  device_id: string;
  seller_username: string;
  title: string;
  description: string;
  price_usd: number;
  condition: string;
  shipping_options: string;
  location: string;
  manufacturer: string;
  model: string;
  capacity_human: string;
  interface: string;
  device_type: string;
  masked_serial: string;
  certificate_id: string;
  health_status: string;
  is_verified: number;
  trust_score: number;
  created_at: string;
};

export default function MarketplacePage() {
  const [listings, setListings] = React.useState<MarketplaceListing[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [searchQuery, setSearchQuery] = React.useState('');
  const [category, setCategory] = React.useState('all');
  const [condition, setCondition] = React.useState('all');
  const [verifiedOnly, setVerifiedOnly] = React.useState(true);

  async function fetchListings() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (category !== 'all') params.append('category', category);
      if (condition !== 'all') params.append('condition', condition);
      if (searchQuery) params.append('query', searchQuery);
      params.append('verified_only', verifiedOnly ? 'true' : 'false');

      const res = await fetch(`${API_BASE}/marketplace/listings?${params.toString()}`);
      if (res.ok) {
        const data = await res.json();
        setListings(data.listings || []);
      }
    } catch (e) {
      console.error('Failed to fetch marketplace listings:', e);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    fetchListings();
  }, [category, condition, verifiedOnly]);

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    fetchListings();
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-12">
        <div className="container mx-auto px-4 sm:px-8 max-w-7xl space-y-8">
          {/* Header */}
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Badge variant="outline" className="text-primary border-primary/30 bg-primary/5 text-xs font-semibold gap-1">
                  <ShoppingBag className="h-3.5 w-3.5" />
                  Verified Secondary Marketplace
                </Badge>
              </div>
              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
                Verified Storage Marketplace
              </h1>
              <p className="text-sm text-muted-foreground mt-1">
                Every listed device has been permanently sanitized and certified using the SecureWipe platform.
              </p>
            </div>

            <Link href="/dashboard/listings/create">
              <Button className="gap-2 bg-gradient-to-r from-primary to-blue-600 shadow-sm">
                <ShoppingBag className="h-4 w-4" />
                List a Verified Device
              </Button>
            </Link>
          </div>

          {/* Search & Filter Toolbar */}
          <div className="p-4 rounded-xl bg-card border shadow-sm space-y-4">
            <form onSubmit={handleSearchSubmit} className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search manufacturer, model (e.g. Samsung 980, WD Ultrastar)..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Button type="submit" className="gap-2 shrink-0">
                Search
              </Button>
            </form>

            <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t text-xs">
              <div className="flex flex-wrap items-center gap-3">
                <span className="text-muted-foreground font-medium flex items-center gap-1">
                  <SlidersHorizontal className="h-3.5 w-3.5" />
                  Category:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {['all', 'NVMe', 'SSD', 'HDD', 'USB'].map((cat) => (
                    <Button
                      key={cat}
                      size="sm"
                      variant={category === cat ? 'default' : 'outline'}
                      onClick={() => setCategory(cat)}
                      className="h-7 text-xs px-2.5 rounded-lg capitalize"
                    >
                      {cat}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-3">
                <span className="text-muted-foreground font-medium">Condition:</span>
                <Select value={condition} onValueChange={setCondition}>
                  <SelectTrigger className="h-8 text-xs w-[160px]">
                    <SelectValue placeholder="All Conditions" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Conditions</SelectItem>
                    <SelectItem value="Used - Like New">Used - Like New</SelectItem>
                    <SelectItem value="Used - Excellent">Used - Excellent</SelectItem>
                    <SelectItem value="Used - Good">Used - Good</SelectItem>
                    <SelectItem value="Refurbished">Refurbished</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Listings Grid */}
          {loading ? (
            <div className="text-center py-24 space-y-3">
              <Loader2 className="h-8 w-8 animate-spin mx-auto text-primary" />
              <p className="text-sm text-muted-foreground">Loading verified storage devices...</p>
            </div>
          ) : listings.length === 0 ? (
            <div className="text-center py-24 border rounded-2xl bg-muted/20 space-y-4">
              <div className="h-12 w-12 rounded-full bg-muted flex items-center justify-center mx-auto text-muted-foreground">
                <HardDrive className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-bold">No Verified Listings Found</h3>
              <p className="text-xs text-muted-foreground max-w-sm mx-auto">
                No storage devices match your selected filters. Try broadening your search or list your own verified device.
              </p>
              <Link href="/dashboard/listings/create">
                <Button size="sm" variant="outline">
                  List a Verified Device
                </Button>
              </Link>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {listings.map((item) => (
                <Card key={item.listing_id} className="overflow-hidden border flex flex-col justify-between hover:border-primary/50 hover:shadow-md transition duration-200">
                  <CardHeader className="p-5 pb-3">
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <Badge className="bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-200 text-[10px]">
                        {item.device_type}
                      </Badge>

                      {/* Verified Badge */}
                      {item.is_verified === 1 ? (
                        <Link href={`/verify`} className="hover:opacity-80">
                          <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 gap-1 text-[10px] cursor-pointer">
                            <CheckCircle2 className="h-3 w-3" />
                            SecureWipe Verified
                          </Badge>
                        </Link>
                      ) : (
                        <Badge variant="outline" className="text-[10px]">Unverified</Badge>
                      )}
                    </div>

                    <CardTitle className="text-sm font-semibold line-clamp-2 leading-snug">
                      {item.title}
                    </CardTitle>

                    <div className="text-xs text-muted-foreground pt-1.5 flex items-center justify-between">
                      <span>Cap: <strong>{item.capacity_human}</strong></span>
                      <span>Interface: <strong>{item.interface}</strong></span>
                    </div>
                  </CardHeader>

                  <CardContent className="p-5 pt-0 space-y-3">
                    <div className="p-2.5 rounded-lg bg-muted/50 text-[11px] space-y-1.5 border">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Condition:</span>
                        <span className="font-medium text-foreground">{item.condition}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Certificate ID:</span>
                        <Link href={`/verify`} className="font-mono text-primary font-medium hover:underline flex items-center gap-1">
                          {item.certificate_id ? item.certificate_id.substring(0, 12) + '...' : 'Available'}
                          <ExternalLink className="h-2.5 w-2.5" />
                        </Link>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Hardware Health:</span>
                        <span className="text-green-600 font-semibold">{item.health_status}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Trust Score:</span>
                        <span className="font-bold text-foreground">{item.trust_score}/100</span>
                      </div>
                    </div>

                    <div className="flex items-center justify-between pt-2">
                      <div>
                        <span className="text-xs text-muted-foreground block">Price</span>
                        <span className="text-xl font-black text-foreground">${item.price_usd.toFixed(2)}</span>
                      </div>
                      <Link href={`/marketplace/${item.listing_id}`}>
                        <Button size="sm" className="text-xs gap-1">
                          Inspect &amp; Buy
                          <ChevronRight className="h-3.5 w-3.5" />
                        </Button>
                      </Link>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
