"use client";

import React, { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ShoppingBag,
  ShieldCheck,
  CheckCircle2,
  FileCheck2,
  ArrowLeft,
  Plus,
  Building2,
  DollarSign,
  AlertCircle,
  Tag,
  FileText,
  BadgeCheck,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";

function PrivateMarketplaceContent() {
  const searchParams = useSearchParams();
  const prefillCert = searchParams.get("certId") || "";
  const prefillDevice = searchParams.get("device") || "";

  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [openModal, setOpenModal] = useState(!!prefillCert);

  // Form states for new listing
  const [certId, setCertId] = useState(prefillCert);
  const [deviceTitle, setDeviceTitle] = useState(prefillDevice ? `${prefillDevice} (Certified Sanitized)` : "");
  const [mediaType, setMediaType] = useState("SSD");
  const [capacityGb, setCapacityGb] = useState("512");
  const [healthScore, setHealthScore] = useState("95");
  const [valueInr, setValueInr] = useState("3200");
  const [statusMsg, setStatusMsg] = useState<{ type: string; text: string } | null>(null);

  const fetchItems = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/marketplace/items");
      if (res.ok) {
        const data = await res.json();
        setItems(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchItems();
  }, []);

  const handleCreateListing = async (e: React.FormEvent) => {
    e.preventDefault();
    setStatusMsg(null);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/marketplace/list", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          certificate_id: certId,
          device_title: deviceTitle,
          media_type: mediaType,
          capacity_gb: parseFloat(capacityGb),
          health_score: parseInt(healthScore),
          estimated_value_inr: parseInt(valueInr),
        }),
      });

      const data = await res.json();
      if (res.ok && data.status === "success") {
        setStatusMsg({ type: "success", text: "Hardware listed successfully with legal asset agreement!" });
        setOpenModal(false);
        fetchItems();
      } else {
        setStatusMsg({ type: "error", text: data.message || "Listing failed. Ensure health is >= 70% and cert is valid." });
      }
    } catch (err: any) {
      setStatusMsg({ type: "error", text: err.message || "Failed to contact marketplace service." });
    }
  };

  return (
    <div className="flex-1 space-y-6 p-6 md:p-8 pt-6 max-w-7xl mx-auto text-slate-100">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Link href="/individual/dashboard" className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1">
              <ArrowLeft className="h-3 w-3" /> Back to Dashboard
            </Link>
            <span className="text-slate-600">•</span>
            <Badge variant="outline" className="border-amber-500/40 text-amber-400 bg-amber-950/20 text-[10px] font-mono">
              Certified Asset Lifecycle
            </Badge>
          </div>
          <h2 className="text-2xl md:text-3xl font-bold tracking-tight text-white">
            Private Hardware Marketplace & Asset Transfer
          </h2>
          <p className="text-sm text-slate-400">
            Institutional marketplace for reusable devices certified 100% sanitized with zero residual forensic artifacts.
          </p>
        </div>

        <Dialog open={openModal} onOpenChange={setOpenModal}>
          <DialogTrigger asChild>
            <Button className="bg-amber-600 hover:bg-amber-500 text-white font-medium text-xs flex items-center gap-1.5 shadow-lg shadow-amber-950/40">
              <Plus className="h-3.5 w-3.5" />
              List Sanitized Device
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-slate-900 border-slate-800 text-slate-100 max-w-md">
            <DialogHeader>
              <DialogTitle className="text-white flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-400" />
                List Certified Reusable Media
              </DialogTitle>
              <DialogDescription className="text-xs text-slate-400">
                Only devices that have passed NIST 800-88 / DoD verification with an issued certificate can be listed.
              </DialogDescription>
            </DialogHeader>

            <form onSubmit={handleCreateListing} className="space-y-3.5 pt-2">
              <div className="space-y-1">
                <Label className="text-xs text-slate-300">Sanitization Certificate ID</Label>
                <Input
                  required
                  placeholder="e.g., CERT-NTRO-94821A"
                  value={certId}
                  onChange={(e) => setCertId(e.target.value)}
                  className="bg-slate-950 border-slate-700 text-xs font-mono"
                />
              </div>

              <div className="space-y-1">
                <Label className="text-xs text-slate-300">Device Model & Title</Label>
                <Input
                  required
                  placeholder="e.g., Samsung EVO 970 NVMe 512GB"
                  value={deviceTitle}
                  onChange={(e) => setDeviceTitle(e.target.value)}
                  className="bg-slate-950 border-slate-700 text-xs"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <Label className="text-xs text-slate-300">Capacity (GB)</Label>
                  <Input
                    type="number"
                    value={capacityGb}
                    onChange={(e) => setCapacityGb(e.target.value)}
                    className="bg-slate-950 border-slate-700 text-xs"
                  />
                </div>
                <div className="space-y-1">
                  <Label className="text-xs text-slate-300">Health Score (%)</Label>
                  <Input
                    type="number"
                    min="70"
                    max="100"
                    value={healthScore}
                    onChange={(e) => setHealthScore(e.target.value)}
                    className="bg-slate-950 border-slate-700 text-xs"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <Label className="text-xs text-slate-300">Indicative Valuation (INR ₹)</Label>
                <Input
                  type="number"
                  value={valueInr}
                  onChange={(e) => setValueInr(e.target.value)}
                  className="bg-slate-950 border-slate-700 text-xs font-mono text-cyan-300"
                />
              </div>

              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 leading-relaxed font-mono">
                Asset Transfer Agreement will be cryptographically bound to the audit trail upon listing.
              </div>

              <DialogFooter className="pt-2">
                <Button type="button" variant="outline" size="sm" onClick={() => setOpenModal(false)} className="border-slate-700 text-xs">
                  Cancel
                </Button>
                <Button type="submit" size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-xs text-white">
                  Publish to Marketplace
                </Button>
              </DialogFooter>
            </form>
          </DialogContent>
        </Dialog>
      </div>

      {statusMsg && (
        <div
          className={`p-3 rounded-lg text-xs font-medium border ${
            statusMsg.type === "success"
              ? "border-emerald-500/40 bg-emerald-950/20 text-emerald-300"
              : "border-red-500/40 bg-red-950/20 text-red-300"
          }`}
        >
          {statusMsg.text}
        </div>
      )}

      {/* Grid of Marketplace Items */}
      <div className="grid gap-4 md:grid-cols-3">
        {items.map((item, idx) => (
          <Card key={idx} className="bg-slate-900/80 border-slate-800 flex flex-col justify-between shadow-lg">
            <CardHeader className="pb-3 border-b border-slate-800/80">
              <div className="flex items-center justify-between">
                <Badge variant="outline" className="border-emerald-500/40 text-emerald-400 bg-emerald-950/20 text-[10px] font-mono">
                  Certified Reusable
                </Badge>
                <span className="text-[11px] font-mono text-slate-400">{item.id}</span>
              </div>
              <CardTitle className="text-base text-white font-semibold mt-2">{item.device_title}</CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Seller / Dept: {item.seller_name}
              </CardDescription>
            </CardHeader>

            <CardContent className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2 rounded bg-slate-950/70 border border-slate-800">
                  <div className="text-slate-500 text-[10px]">CAPACITY</div>
                  <div className="text-white font-bold">{item.capacity_gb} GB</div>
                </div>
                <div className="p-2 rounded bg-slate-950/70 border border-slate-800">
                  <div className="text-slate-500 text-[10px]">HEALTH SCORE</div>
                  <div className="text-emerald-400 font-bold">{item.health_score}%</div>
                </div>
              </div>

              <div className="p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-500/30 flex items-center justify-between">
                <span className="text-xs text-slate-300">Indicative Value:</span>
                <span className="text-base font-bold font-mono text-cyan-300">
                  ₹{Number(item.estimated_value_inr).toLocaleString()}
                </span>
              </div>

              <div className="text-[11px] text-slate-400 flex items-center gap-1.5 font-mono">
                <BadgeCheck className="h-4 w-4 text-emerald-400 shrink-0" />
                <span className="truncate">Cert: {item.certificate_id}</span>
              </div>
            </CardContent>

            <CardFooter className="pt-0 p-4 border-t border-slate-800/60 flex items-center justify-between">
              <span className="text-[11px] text-emerald-400 font-mono">Status: ACTIVE LISTING</span>
              <Button size="sm" variant="outline" className="text-xs border-slate-700 hover:bg-slate-800">
                View Agreement
              </Button>
            </CardFooter>
          </Card>
        ))}

        {items.length === 0 && !loading && (
          <div className="md:col-span-3 p-12 text-center border border-dashed border-slate-800 rounded-2xl bg-slate-900/30 text-slate-400 space-y-3">
            <ShoppingBag className="h-10 w-10 text-slate-600 mx-auto" />
            <div className="font-semibold text-white">No Marketplace Listings Yet</div>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Devices that have successfully completed adaptive sanitization and verified S.M.A.R.T. health (&gt;= 70%) can be listed here for institutional reuse.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

export default function PrivateMarketplacePage() {
  return (
    <Suspense fallback={<div className="p-8 text-center text-slate-400 font-mono text-xs">Loading Private Marketplace...</div>}>
      <PrivateMarketplaceContent />
    </Suspense>
  );
}
