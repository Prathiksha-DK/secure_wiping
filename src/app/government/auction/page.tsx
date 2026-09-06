"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Gavel,
  ShieldCheck,
  Building2,
  RefreshCw,
  Plus,
  ArrowRight,
  Clock,
  DollarSign,
  TrendingUp,
  FileCheck2,
  CheckCircle2,
  AlertCircle,
  HardDrive,
  BadgeCheck,
  Tag,
  Receipt,
  ArrowUpRight,
  Sparkles,
  Layers,
  Search,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";

interface AuctionLot {
  id: string;
  lot_number: string;
  title: string;
  device_name: string;
  media_type: string;
  capacity_gb: number;
  certificate_id: string;
  agency_name: string;
  reserve_price_inr: number;
  current_bid_inr: number;
  highest_bidder: string;
  total_bids: number;
  status: string;
  end_time: number;
  created_at: number;
}

interface BuybackClaim {
  id: string;
  voucher_code: string;
  device_name: string;
  serial_number: string;
  media_type: string;
  capacity_gb: number;
  certificate_id: string;
  agency_name: string;
  vendor_name: string;
  credit_value_inr: number;
  status: string;
  created_at: number;
}

function GovernmentAuctionContent() {
  const searchParams = useSearchParams();
  const prefillCert = searchParams.get("certId") || "";
  const prefillDevice = searchParams.get("device") || "";
  const prefillCapacity = searchParams.get("capacity") || "500";
  const prefillMedia = searchParams.get("media") || "SSD";
  const defaultTab = searchParams.get("tab") || "auctions";

  const [auctions, setAuctions] = useState<AuctionLot[]>([]);
  const [buybacks, setBuybacks] = useState<BuybackClaim[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState(defaultTab);

  // New Auction Form State
  const [openNewLotModal, setOpenNewLotModal] = useState(!!prefillCert && defaultTab === "auctions");
  const [newLotTitle, setNewLotTitle] = useState(prefillDevice ? `Lot: ${prefillDevice} Certified Sanitized Fleet` : "");
  const [newDeviceName, setNewDeviceName] = useState(prefillDevice || "");
  const [newMediaType, setNewMediaType] = useState(prefillMedia);
  const [newCapacityGb, setNewCapacityGb] = useState(prefillCapacity);
  const [newCertId, setNewCertId] = useState(prefillCert);
  const [newReservePrice, setNewReservePrice] = useState("25000");
  const [newDurationDays, setNewDurationDays] = useState("7");

  // New Buyback Form State
  const [openBuybackModal, setOpenBuybackModal] = useState(!!prefillCert && defaultTab === "buyback");
  const [bbDeviceName, setBbDeviceName] = useState(prefillDevice || "");
  const [bbSerial, setBbSerial] = useState("SN-GOV-REF");
  const [bbMediaType, setBbMediaType] = useState(prefillMedia);
  const [bbCapacityGb, setBbCapacityGb] = useState(prefillCapacity);
  const [bbCertId, setBbCertId] = useState(prefillCert);
  const [bbVendor, setBbVendor] = useState("OEM Certified Asset Trade-In (Dell/HP/Lenovo)");
  const [bbCreditValue, setBbCreditValue] = useState("3500");

  // Bidding State
  const [selectedAuction, setSelectedAuction] = useState<AuctionLot | null>(null);
  const [bidAmount, setBidAmount] = useState("");
  const [bidderName, setBidderName] = useState("Authorized IT Recycler");
  const [notification, setNotification] = useState<{ type: "success" | "error"; message: string } | null>(null);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [aucRes, bbRes] = await Promise.all([
        fetch("http://localhost:9758/api/lifecycle/government/auction/items"),
        fetch("http://localhost:9758/api/lifecycle/government/buyback/claims"),
      ]);
      if (aucRes.ok) {
        const data = await aucRes.json();
        setAuctions(data);
      }
      if (bbRes.ok) {
        const data = await bbRes.json();
        setBuybacks(data);
      }
    } catch (err) {
      console.error("Failed to load auction data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateLot = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotification(null);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/government/auction/list", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: newLotTitle,
          device_name: newDeviceName,
          media_type: newMediaType,
          capacity_gb: parseFloat(newCapacityGb),
          certificate_id: newCertId,
          reserve_price_inr: parseInt(newReservePrice),
          duration_days: parseInt(newDurationDays),
        }),
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        setNotification({ type: "success", message: `Forward Auction Lot ${data.lot.lot_number} created successfully!` });
        setOpenNewLotModal(false);
        fetchData();
      } else {
        setNotification({ type: "error", message: data.message || "Failed to create auction lot." });
      }
    } catch (err: any) {
      setNotification({ type: "error", message: err.message || "Network error contacting auction engine." });
    }
  };

  const handleCreateBuyback = async (e: React.FormEvent) => {
    e.preventDefault();
    setNotification(null);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/government/buyback/claim", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          device_name: bbDeviceName,
          serial_number: bbSerial,
          media_type: bbMediaType,
          capacity_gb: parseFloat(bbCapacityGb),
          certificate_id: bbCertId,
          vendor_name: bbVendor,
          credit_value_inr: parseInt(bbCreditValue),
        }),
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        setNotification({
          type: "success",
          message: `Buy-back voucher ${data.claim.voucher_code} issued! Credit value: ₹${data.claim.credit_value_inr.toLocaleString()}`,
        });
        setOpenBuybackModal(false);
        fetchData();
      } else {
        setNotification({ type: "error", message: data.message || "Failed to submit buy-back claim." });
      }
    } catch (err: any) {
      setNotification({ type: "error", message: err.message || "Network error processing buy-back claim." });
    }
  };

  const handlePlaceBid = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedAuction) return;
    setNotification(null);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/government/auction/bid", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          auction_id: selectedAuction.id,
          bidder_name: bidderName,
          bid_amount_inr: parseInt(bidAmount),
        }),
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        setNotification({
          type: "success",
          message: `Bid of ₹${parseInt(bidAmount).toLocaleString()} accepted for ${data.bid.lot_number}!`,
        });
        setSelectedAuction(null);
        setBidAmount("");
        fetchData();
      } else {
        setNotification({ type: "error", message: data.message || "Bid submission failed." });
      }
    } catch (err: any) {
      setNotification({ type: "error", message: err.message || "Network error placing bid." });
    }
  };

  const totalAuctionValue = auctions.reduce((acc, a) => acc + a.current_bid_inr, 0);
  const totalBuybackCredit = buybacks.reduce((acc, b) => acc + b.credit_value_inr, 0);

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <Building2 className="h-3 w-3" />
              Government Post-Wipe Asset Disposition Command
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-xs text-slate-400 font-mono">GeM Compliant Forward Auction & OEM Buy-Back</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white flex items-center gap-3">
            <Gavel className="h-7 w-7 text-emerald-400" />
            Government Forward Auction & Buy-Back Portal
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl font-normal leading-relaxed">
            Following certified media sanitization, government and enterprise fleets must execute formal disposal. 
            Select between <strong>Forward Public Auction</strong> (competitive e-auction bidding) or <strong>OEM Buy-Back</strong> (vendor exchange credit against future hardware procurement).
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchData}
            disabled={loading}
            className="border-slate-700/80 bg-[#0E1628] hover:bg-[#152038] text-slate-200 text-xs flex items-center gap-2 h-9 px-3.5 shadow-sm transition-all"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </Button>

          <Button
            size="sm"
            onClick={() => setOpenNewLotModal(true)}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-emerald-950/40 transition-all"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>New Auction Lot</span>
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => setOpenBuybackModal(true)}
            className="border-emerald-500/40 bg-emerald-950/20 hover:bg-emerald-900/40 text-emerald-300 font-semibold text-xs flex items-center gap-2 h-9 px-4"
          >
            <Receipt className="h-3.5 w-3.5" />
            <span>Claim Buy-Back</span>
          </Button>
        </div>
      </div>

      {/* Notifications */}
      {notification && (
        <div
          className={`p-4 rounded-xl border text-xs font-medium flex items-center justify-between shadow-md ${
            notification.type === "success"
              ? "border-emerald-500/40 bg-emerald-950/40 text-emerald-200"
              : "border-rose-500/40 bg-rose-950/40 text-rose-200"
          }`}
        >
          <div className="flex items-center gap-3">
            {notification.type === "success" ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
            )}
            <span>{notification.message}</span>
          </div>
          <Button
            size="sm"
            variant="ghost"
            className="h-6 text-[10px] text-slate-400 hover:text-white"
            onClick={() => setNotification(null)}
          >
            Dismiss
          </Button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Active Forward Lots</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Gavel className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">{auctions.length} Lots</div>
          <p className="text-xs text-slate-400 mt-1">Ready for public/refurbisher bidding</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Current Bid Volume</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <TrendingUp className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-cyan-300 font-mono">
            ₹{totalAuctionValue.toLocaleString()}
          </div>
          <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1">
            <CheckCircle2 className="h-3 w-3" /> Total Realization Pipeline
          </p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">OEM Buy-Back Vouchers</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Receipt className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono">{buybacks.length} Claims</div>
          <p className="text-xs text-slate-400 mt-1">Institutional trade-in credits</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Cumulative Buy-Back Credit</span>
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <DollarSign className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-purple-300 font-mono">
            ₹{totalBuybackCredit.toLocaleString()}
          </div>
          <p className="text-xs text-slate-400 mt-1">Offset against new procurement</p>
        </div>
      </div>

      {/* Main Tabs Navigation */}
      <Tabs defaultValue={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <TabsList className="bg-[#060A12] border border-slate-800 p-1 rounded-xl">
            <TabsTrigger
              value="auctions"
              className="data-[state=active]:bg-emerald-600 data-[state=active]:text-white text-xs font-semibold px-4 py-2 rounded-lg"
            >
              <Gavel className="h-3.5 w-3.5 mr-2" />
              Forward Auction Lots ({auctions.length})
            </TabsTrigger>
            <TabsTrigger
              value="buyback"
              className="data-[state=active]:bg-emerald-600 data-[state=active]:text-white text-xs font-semibold px-4 py-2 rounded-lg"
            >
              <Receipt className="h-3.5 w-3.5 mr-2" />
              OEM Buy-Back Ledger ({buybacks.length})
            </TabsTrigger>
            <TabsTrigger
              value="compliance"
              className="data-[state=active]:bg-emerald-600 data-[state=active]:text-white text-xs font-semibold px-4 py-2 rounded-lg"
            >
              <ShieldCheck className="h-3.5 w-3.5 mr-2" />
              Legal & GFR Framework
            </TabsTrigger>
          </TabsList>

          <span className="text-xs text-slate-400 font-mono hidden sm:inline-block">
            Standard: GFR 2017 Rule 217 (Disposal of Obsolete IT Stores)
          </span>
        </div>

        {/* TAB 1: Forward Auction Lots */}
        <TabsContent value="auctions" className="space-y-4 m-0">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {auctions.map((lot) => {
              const timeLeftHours = Math.max(0, Math.round((lot.end_time - Date.now() / 1000) / 3600));
              const daysLeft = Math.floor(timeLeftHours / 24);
              const remHours = timeLeftHours % 24;

              return (
                <div
                  key={lot.id}
                  className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-xl hover:border-emerald-500/60 transition-all flex flex-col justify-between group"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/30 text-emerald-300">
                        {lot.lot_number}
                      </span>
                      <span className="inline-flex items-center gap-1 text-[11px] font-mono text-amber-300 bg-amber-950/30 border border-amber-500/20 px-2 py-0.5 rounded">
                        <Clock className="h-3 w-3" />
                        {daysLeft > 0 ? `${daysLeft}d ${remHours}h left` : `${remHours}h left`}
                      </span>
                    </div>

                    <div>
                      <h3 className="font-bold text-base text-white group-hover:text-emerald-300 transition-colors line-clamp-2">
                        {lot.title}
                      </h3>
                      <p className="text-xs text-slate-400 mt-1 font-mono">
                        {lot.device_name} • {lot.capacity_gb >= 1000 ? `${(lot.capacity_gb / 1000).toFixed(1)} TB` : `${lot.capacity_gb} GB`} {lot.media_type}
                      </p>
                    </div>

                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">Reserve Price:</span>
                        <span className="font-mono text-slate-300">₹{lot.reserve_price_inr.toLocaleString()}</span>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400 font-semibold">Current Highest Bid:</span>
                        <span className="font-mono font-bold text-emerald-400 text-sm">
                          ₹{lot.current_bid_inr.toLocaleString()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1 border-t border-slate-800">
                        <span>Total Bids: <strong className="text-white">{lot.total_bids}</strong></span>
                        <span className="truncate max-w-[140px]" title={lot.highest_bidder || "No bids yet"}>
                          {lot.highest_bidder ? lot.highest_bidder : "Awaiting first bid"}
                        </span>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-400 flex items-center justify-between">
                      <span className="truncate text-slate-400">Origin: <strong>{lot.agency_name}</strong></span>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800/80 space-y-2">
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-slate-400">Sanitization Proof:</span>
                      <Link
                        href={`/report?id=${lot.certificate_id}`}
                        className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                      >
                        {lot.certificate_id} <ArrowUpRight className="h-3 w-3" />
                      </Link>
                    </div>

                    <Button
                      className="w-full bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold h-9 rounded-xl shadow-md shadow-emerald-950/40"
                      onClick={() => {
                        setSelectedAuction(lot);
                        const min = lot.total_bids > 0 ? lot.current_bid_inr + 1000 : lot.reserve_price_inr;
                        setBidAmount(min.toString());
                      }}
                    >
                      <Gavel className="h-3.5 w-3.5 mr-1.5" />
                      Place Competitive Bid
                    </Button>
                  </div>
                </div>
              );
            })}

            {auctions.length === 0 && !loading && (
              <div className="col-span-full p-12 text-center border border-dashed border-slate-800 rounded-2xl bg-[#0D1527] space-y-3">
                <Gavel className="h-8 w-8 text-slate-600 mx-auto" />
                <div className="text-sm font-semibold text-white">No active forward auction lots</div>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  When government storage endpoints are wiped, select &quot;Forward Auction&quot; in the post-wipe matrix to list them here.
                </p>
                <Button
                  size="sm"
                  onClick={() => setOpenNewLotModal(true)}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs"
                >
                  Create First Auction Lot
                </Button>
              </div>
            )}
          </div>
        </TabsContent>

        {/* TAB 2: OEM Buy-Back Ledger */}
        <TabsContent value="buyback" className="space-y-4 m-0">
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Receipt className="h-4 w-4 text-emerald-400" />
                  Government OEM Buy-Back Ledger & Trade-In Vouchers
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Official exchange vouchers logged against contracted IT refresh vendors. Each voucher carries cryptographic proof of sanitization.
                </p>
              </div>
              <Button
                size="sm"
                onClick={() => setOpenBuybackModal(true)}
                className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs h-8 px-3"
              >
                <Plus className="h-3.5 w-3.5 mr-1" />
                New Buy-Back Claim
              </Button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#060A12] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800/80">
                  <tr>
                    <th className="py-3.5 px-4">Voucher Reference</th>
                    <th className="py-3.5 px-4">Target Hardware Spec</th>
                    <th className="py-3.5 px-4">Vendor Partner</th>
                    <th className="py-3.5 px-4">Sanitization Certificate</th>
                    <th className="py-3.5 px-4">Trade-In Credit</th>
                    <th className="py-3.5 px-4">Status</th>
                    <th className="py-3.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-slate-300">
                  {buybacks.map((bb) => (
                    <tr key={bb.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-4 px-4 whitespace-nowrap">
                        <div className="font-mono font-bold text-emerald-400">{bb.voucher_code}</div>
                        <div className="text-[10px] text-slate-400 font-mono mt-0.5">{bb.agency_name}</div>
                      </td>
                      <td className="py-4 px-4 whitespace-nowrap">
                        <div className="font-semibold text-white">{bb.device_name}</div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          {bb.capacity_gb} GB {bb.media_type} • SN: {bb.serial_number}
                        </div>
                      </td>
                      <td className="py-4 px-4 font-mono text-slate-300 whitespace-nowrap">
                        <span className="bg-[#060A12] px-2.5 py-1 rounded border border-slate-800 text-cyan-300">
                          {bb.vendor_name}
                        </span>
                      </td>
                      <td className="py-4 px-4 font-mono text-slate-300 whitespace-nowrap">
                        <Link href={`/report?id=${bb.certificate_id}`} className="text-cyan-400 hover:underline flex items-center gap-1">
                          <FileCheck2 className="h-3 w-3" /> {bb.certificate_id}
                        </Link>
                      </td>
                      <td className="py-4 px-4 font-mono whitespace-nowrap">
                        <span className="text-base font-extrabold text-emerald-400">
                          ₹{bb.credit_value_inr.toLocaleString()}
                        </span>
                      </td>
                      <td className="py-4 px-4 whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono px-2.5 py-0.5 rounded-full border border-emerald-500/40 bg-emerald-500/15 text-emerald-300 font-semibold">
                          <CheckCircle2 className="h-3 w-3" />
                          {bb.status}
                        </span>
                      </td>
                      <td className="py-4 px-4 text-right whitespace-nowrap">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 text-xs text-slate-300 hover:text-white"
                          onClick={() => {
                            alert(`Voucher ${bb.voucher_code} is active for credit of ₹${bb.credit_value_inr.toLocaleString()} with ${bb.vendor_name}.`);
                          }}
                        >
                          Print Voucher
                        </Button>
                      </td>
                    </tr>
                  ))}

                  {buybacks.length === 0 && !loading && (
                    <tr>
                      <td colSpan={7} className="py-10 px-4 text-center text-slate-400 font-sans text-xs">
                        No OEM buy-back claims logged yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </TabsContent>

        {/* TAB 3: Legal & GFR Framework */}
        <TabsContent value="compliance" className="space-y-4 m-0">
          <div className="grid gap-6 md:grid-cols-2">
            <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 border-b border-slate-800 pb-3">
                <div className="h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
                  <Gavel className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-base">Pathway 1: Forward Public Auction</h3>
                  <p className="text-xs text-slate-400 font-mono">GFR 2017 Rule 217 & GeM Forward Auction Directives</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                When government departments decommission IT hardware with residual operational life, competitive forward auction maximizes exchequer revenue.
              </p>
              <ul className="space-y-2 text-xs text-slate-300 font-sans">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Mandatory Sanitization Proof:</strong> No government device can be put up for bidding without an attached tamper-evident sanitization certificate.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Certified Recyclers & Buyers:</strong> Forward auctions accept bids only from vetted refurbishment firms and e-waste authorized entities.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Highest Bid Realization:</strong> Automated reserve price matching ensures optimal asset recovery value.</span>
                </li>
              </ul>
            </div>

            <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-3 border-b border-slate-800 pb-3">
                <div className="h-10 w-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                  <Receipt className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-bold text-white text-base">Pathway 2: OEM Buy-Back Scheme</h3>
                  <p className="text-xs text-slate-400 font-mono">Institutional Trade-in Against Replacement Tenders</p>
                </div>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Under institutional hardware procurement agreements, retiring IT gear is traded back to the original equipment manufacturer (OEM) for immediate credit.
              </p>
              <ul className="space-y-2 text-xs text-slate-300 font-sans">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
                  <span><strong>Pre-Negotiated Trade-In Rates:</strong> Credit values are computed transparently based on S.M.A.R.T. wear level, media capacity, and generation.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
                  <span><strong>Direct Invoice Deduction:</strong> Buy-back vouchers are redeemed directly on GeM replacement tenders.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="h-4 w-4 text-blue-400 shrink-0 mt-0.5" />
                  <span><strong>Cryptographic Compliance Audit:</strong> The signed wipe certificate serves as the legal release of liability for the government agency.</span>
                </li>
              </ul>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* MODAL 1: Create New Forward Auction Lot */}
      <Dialog open={openNewLotModal} onOpenChange={setOpenNewLotModal}>
        <DialogContent className="bg-[#090F1D] border border-slate-800 text-slate-100 sm:max-w-[540px]">
          <DialogHeader>
            <DialogTitle className="text-lg font-bold text-white flex items-center gap-2">
              <Gavel className="h-5 w-5 text-emerald-400" />
              List Sanitized Device in Forward Auction
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              Publish a decommissioned, certified-clean IT storage asset for competitive forward bidding.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateLot} className="space-y-4 py-2">
            <div className="space-y-1.5">
              <Label className="text-xs font-semibold text-slate-300">Auction Lot Title</Label>
              <Input
                value={newLotTitle}
                onChange={(e) => setNewLotTitle(e.target.value)}
                placeholder="e.g. 10x Dell Latitude NVMe SSDs (Certified Wiped)"
                required
                className="bg-[#060A12] border-slate-800 text-xs text-white"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Device Description</Label>
                <Input
                  value={newDeviceName}
                  onChange={(e) => setNewDeviceName(e.target.value)}
                  placeholder="e.g. Samsung PM9A1 1TB"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Media Type</Label>
                <Input
                  value={newMediaType}
                  onChange={(e) => setNewMediaType(e.target.value)}
                  placeholder="SSD, NVME, HDD"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Total Capacity (GB)</Label>
                <Input
                  type="number"
                  value={newCapacityGb}
                  onChange={(e) => setNewCapacityGb(e.target.value)}
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Sanitization Certificate ID</Label>
                <Input
                  value={newCertId}
                  onChange={(e) => setNewCertId(e.target.value)}
                  placeholder="CERT-GOV-2026-XXXX"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Reserve Starting Price (₹ INR)</Label>
                <Input
                  type="number"
                  value={newReservePrice}
                  onChange={(e) => setNewReservePrice(e.target.value)}
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Bidding Duration (Days)</Label>
                <Input
                  type="number"
                  value={newDurationDays}
                  onChange={(e) => setNewDurationDays(e.target.value)}
                  min="1"
                  max="30"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>
            </div>

            <DialogFooter className="pt-3 border-t border-slate-800">
              <Button type="button" variant="outline" size="sm" onClick={() => setOpenNewLotModal(false)} className="border-slate-800 text-xs">
                Cancel
              </Button>
              <Button type="submit" size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs">
                Publish Forward Auction Lot
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* MODAL 2: Create OEM Buy-Back Claim */}
      <Dialog open={openBuybackModal} onOpenChange={setOpenBuybackModal}>
        <DialogContent className="bg-[#090F1D] border border-slate-800 text-slate-100 sm:max-w-[540px]">
          <DialogHeader>
            <DialogTitle className="text-lg font-bold text-white flex items-center gap-2">
              <Receipt className="h-5 w-5 text-emerald-400" />
              Claim Government OEM Buy-Back Credit
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              Initiate official trade-in credit with certified OEM or contracted hardware vendor.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={handleCreateBuyback} className="space-y-4 py-2">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Device Description</Label>
                <Input
                  value={bbDeviceName}
                  onChange={(e) => setBbDeviceName(e.target.value)}
                  placeholder="e.g. HP ZBook NVMe 512GB"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Serial Number</Label>
                <Input
                  value={bbSerial}
                  onChange={(e) => setBbSerial(e.target.value)}
                  placeholder="e.g. SN-8849-012"
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Capacity (GB)</Label>
                <Input
                  type="number"
                  value={bbCapacityGb}
                  onChange={(e) => setBbCapacityGb(e.target.value)}
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Sanitization Certificate ID</Label>
                <Input
                  value={bbCertId}
                  onChange={(e) => setBbCertId(e.target.value)}
                  placeholder="CERT-GOV-XXXX"
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white font-mono"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-semibold text-slate-300">Contracted Vendor / OEM</Label>
              <Input
                value={bbVendor}
                onChange={(e) => setBbVendor(e.target.value)}
                placeholder="e.g. Dell Technologies / HP Enterprise / Lenovo Global"
                required
                className="bg-[#060A12] border-slate-800 text-xs text-white"
              />
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs font-semibold text-slate-300">Calculated Exchange Credit Value (₹ INR)</Label>
              <Input
                type="number"
                value={bbCreditValue}
                onChange={(e) => setBbCreditValue(e.target.value)}
                required
                className="bg-[#060A12] border-slate-800 text-xs text-white font-mono font-bold text-emerald-400"
              />
              <p className="text-[10px] text-slate-400 italic">
                Credit will be applied against your department&apos;s upcoming hardware procurement order.
              </p>
            </div>

            <DialogFooter className="pt-3 border-t border-slate-800">
              <Button type="button" variant="outline" size="sm" onClick={() => setOpenBuybackModal(false)} className="border-slate-800 text-xs">
                Cancel
              </Button>
              <Button type="submit" size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs">
                Approve & Generate Voucher
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* MODAL 3: Place Bid */}
      <Dialog open={!!selectedAuction} onOpenChange={(open) => !open && setSelectedAuction(null)}>
        <DialogContent className="bg-[#090F1D] border border-slate-800 text-slate-100 sm:max-w-[480px]">
          <DialogHeader>
            <DialogTitle className="text-base font-bold text-white flex items-center gap-2">
              <Gavel className="h-5 w-5 text-emerald-400" />
              Place Bid: {selectedAuction?.lot_number}
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              Enter competitive forward bid for: {selectedAuction?.title}
            </DialogDescription>
          </DialogHeader>

          {selectedAuction && (
            <form onSubmit={handlePlaceBid} className="space-y-4 py-2">
              <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-400">Current Highest Bid:</span>
                  <span className="font-mono font-bold text-emerald-400">₹{selectedAuction.current_bid_inr.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Minimum Next Bid:</span>
                  <span className="font-mono font-semibold text-cyan-300">
                    ₹{(selectedAuction.total_bids > 0 ? selectedAuction.current_bid_inr + 1000 : selectedAuction.reserve_price_inr).toLocaleString()}
                  </span>
                </div>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Your Bidder Organization Name</Label>
                <Input
                  value={bidderName}
                  onChange={(e) => setBidderName(e.target.value)}
                  required
                  className="bg-[#060A12] border-slate-800 text-xs text-white"
                />
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs font-semibold text-slate-300">Bid Amount (₹ INR)</Label>
                <Input
                  type="number"
                  value={bidAmount}
                  onChange={(e) => setBidAmount(e.target.value)}
                  required
                  className="bg-[#060A12] border-slate-800 text-sm font-mono font-bold text-emerald-400"
                />
              </div>

              <DialogFooter className="pt-3 border-t border-slate-800">
                <Button type="button" variant="outline" size="sm" onClick={() => setSelectedAuction(null)} className="border-slate-800 text-xs">
                  Cancel
                </Button>
                <Button type="submit" size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs">
                  Submit Binding Bid
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default function GovernmentAuctionPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-slate-400 font-mono text-xs">Loading Government Auction Command...</div>}>
      <GovernmentAuctionContent />
    </Suspense>
  );
}
