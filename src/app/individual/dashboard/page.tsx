"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  HardDrive,
  ShieldCheck,
  Trash2,
  Eye,
  FileCheck2,
  ShoppingBag,
  Activity,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  Cpu,
  Lock,
  PlusCircle,
  FileText,
  Clock,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

interface Device {
  name: string;
  serial: string;
  bus: string;
  type: string;
  size: string;
  sizeBytes: number;
  health: number;
  healthStatus: string;
}

export default function IndividualDashboardPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [healthValuation, setHealthValuation] = useState<any | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [devRes, histRes] = await Promise.all([
        fetch("http://localhost:9758/api/devices"),
        fetch("http://localhost:9758/api/history"),
      ]);

      if (devRes.ok) {
        const devData = await devRes.json();
        const devArr = Array.isArray(devData) ? devData : devData.value || [];
        setDevices(devArr);
        if (devArr.length > 0 && !selectedDevice) {
          setSelectedDevice(devArr[0]);
        }
      }

      if (histRes.ok) {
        const histData = await histRes.json();
        setHistory(Array.isArray(histData) ? histData : []);
      }
    } catch (err) {
      console.error("Failed to load individual dashboard data", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleEvaluateHealth = async (device: Device) => {
    setSelectedDevice(device);
    setEvaluating(true);
    try {
      const res = await fetch("http://localhost:9758/api/lifecycle/evaluate-health", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(device),
      });
      if (res.ok) {
        const data = await res.json();
        setHealthValuation(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setEvaluating(false);
    }
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-cyan-500/30 bg-cyan-500/10 text-cyan-400">
              Individual Persona
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-xs text-slate-400 font-mono">Authenticated: citizen_user</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Personal Data Sanitization & Hardware Health
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Securely erase personal files or entire storage drives, generate verifiable certificates, and assess device resale valuation.
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

          <Link href="/wipe">
            <Button size="sm" className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-cyan-950/40 transition-all hover:scale-[1.02]">
              <Trash2 className="h-3.5 w-3.5" />
              <span>New Sanitization Job</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Quick Metrics */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Detected Media</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <HardDrive className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">{devices.length} Drives</div>
          <p className="text-xs text-slate-400 mt-1.5">Ready for inspection or sanitization</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Verified Certificates</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">
            {history.filter((h) => h.status === "Completed" || h.finalState === "SANITIZED_AND_REUSABLE").length}
          </div>
          <p className="text-xs text-slate-400 mt-1.5">Tamper-evident certificates available</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Average Drive Health</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Activity className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">
            {devices.length > 0 ? Math.round(devices.reduce((a, b) => a + (b.health || 100), 0) / devices.length) : 100}%
          </div>
          <p className="text-xs text-emerald-400 mt-1.5 flex items-center gap-1.5 font-medium">
            <CheckCircle2 className="h-3.5 w-3.5" /> S.M.A.R.T. Operational
          </p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Marketplace Eligibility</span>
            <div className="h-8 w-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
              <ShoppingBag className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-amber-300 font-mono tracking-tight">Certified Reusable</div>
          <p className="text-xs text-slate-400 mt-1.5">Indicative buyback value available</p>
        </div>
      </div>

      {/* Main Section: Devices and Action Panel */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Device Cards List */}
        <div className="lg:col-span-2 space-y-6">
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-cyan-400" />
                Connected Storage Media
              </h2>
              <span className="text-xs text-slate-400 font-mono">Select drive to assess</span>
            </div>

            <div className="grid gap-3">
              {devices.map((device, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer bg-[#0D1527] flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
                    selectedDevice?.serial === device.serial
                      ? "border-cyan-500/70 shadow-lg shadow-cyan-950/40 bg-[#0E172A]"
                      : "border-slate-800/80 hover:border-slate-700"
                  }`}
                  onClick={() => handleEvaluateHealth(device)}
                >
                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 text-cyan-400 shrink-0">
                      <HardDrive className="h-6 w-6" />
                    </div>
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-bold text-sm text-white">{device.name}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
                          {device.type} ({device.bus})
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3 mt-1 font-mono">
                        <span>Capacity: <strong className="text-slate-200">{device.size}</strong></span>
                        <span>•</span>
                        <span>Serial: <strong className="text-slate-300">{device.serial}</strong></span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between sm:justify-end gap-4 shrink-0">
                    <div className="text-left sm:text-right">
                      <div className="text-xs font-semibold text-emerald-400">{device.healthStatus}</div>
                      <div className="text-xs text-slate-400 font-mono mt-0.5">Health: {device.health}%</div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="border-slate-700/80 bg-[#060A12] text-xs text-slate-200 hover:bg-cyan-950/50 hover:text-cyan-300 rounded-lg h-8 px-3"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleEvaluateHealth(device);
                      }}
                    >
                      Assess
                    </Button>
                  </div>
                </div>
              ))}

              {devices.length === 0 && !loading && (
                <div className="p-10 text-center border border-dashed border-slate-800 rounded-2xl text-slate-400 text-xs">
                  No storage drives detected. Connect an external drive or USB stick to begin.
                </div>
              )}
            </div>
          </div>

          {/* Recent Operations & Certificates Table */}
          <div className="space-y-3 pt-2">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <FileCheck2 className="h-4 w-4 text-emerald-400" />
              Recent Certificates & Sanitization History
            </h2>
            <div className="border border-slate-800/80 rounded-2xl overflow-hidden bg-[#0D1527] shadow-xl">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#060A12] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800/80">
                  <tr>
                    <th className="py-3.5 px-4">Reference ID</th>
                    <th className="py-3.5 px-4">Target Device</th>
                    <th className="py-3.5 px-4">Wipe Standard</th>
                    <th className="py-3.5 px-4">Final State</th>
                    <th className="py-3.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-slate-300">
                  {history.slice(0, 4).map((h, i) => (
                    <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-cyan-400 whitespace-nowrap">{h.id || `WIPE-${i + 101}`}</td>
                      <td className="py-3.5 px-4 font-medium text-white whitespace-nowrap">{h.device}</td>
                      <td className="py-3.5 px-4 whitespace-nowrap">{h.standard || h.method}</td>
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${
                            h.finalState === "SANITIZED_AND_REUSABLE" || h.status === "Completed"
                              ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                              : "border-amber-500/40 bg-amber-500/15 text-amber-300"
                          }`}
                        >
                          {h.finalState || h.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <Link href={`/report?id=${h.id}`}>
                          <Button size="sm" variant="ghost" className="h-7 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-slate-800">
                            View Cert <ArrowRight className="ml-1 h-3 w-3" />
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {history.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-8 px-4 text-center text-slate-500 font-sans text-xs">
                        No previous sanitization records found.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Right Sidebar: Health Assessment & Private Marketplace Card */}
        <div className="space-y-5">
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex items-center justify-between">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity className="h-4 w-4 text-cyan-400" />
                Hardware Valuation Engine
              </h2>
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono border border-blue-500/30 bg-blue-500/10 text-blue-400">
                Indicative
              </span>
            </div>

            <div className="p-5 space-y-4">
              {selectedDevice ? (
                <div className="space-y-4">
                  <div className="p-3.5 rounded-xl bg-[#060A12] border border-slate-800">
                    <div className="text-[10px] text-slate-400 font-mono uppercase font-semibold">Assessing Target</div>
                    <div className="font-bold text-sm text-white mt-1">{selectedDevice.name}</div>
                    <div className="text-xs text-slate-400 font-mono mt-1">
                      {selectedDevice.type} • {selectedDevice.size} • S.M.A.R.T.: {selectedDevice.health}%
                    </div>
                  </div>

                  {healthValuation ? (
                    <div className="space-y-3 pt-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-400">Composite Health Score</span>
                        <span className="font-mono font-bold text-emerald-400">
                          {healthValuation.composite_health_score}/100
                        </span>
                      </div>
                      <Progress value={healthValuation.composite_health_score} className="h-2 bg-slate-800" />

                      <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-emerald-300">Reusability Verdict:</span>
                          <span className="text-xs font-mono font-bold text-white">
                            {healthValuation.disposition_decision}
                          </span>
                        </div>
                        <div className="text-xs text-slate-300 pt-1">
                          Estimated Valuation:{" "}
                          <span className="text-base font-extrabold text-cyan-300 font-mono ml-1">
                            ₹{healthValuation.indicative_valuation_inr.toLocaleString()}
                          </span>
                        </div>
                      </div>

                      <p className="text-[10px] text-slate-400 italic">
                        *{healthValuation.valuation_disclaimer}
                      </p>

                      <Link href="/individual/marketplace" className="block pt-1">
                        <Button className="w-full bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs h-10 rounded-xl flex items-center justify-center gap-2 shadow-lg shadow-emerald-950/40">
                          <ShoppingBag className="h-4 w-4" />
                          List in Private Marketplace
                        </Button>
                      </Link>
                    </div>
                  ) : (
                    <Button
                      onClick={() => handleEvaluateHealth(selectedDevice)}
                      disabled={evaluating}
                      className="w-full bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold h-10 rounded-xl mt-2"
                    >
                      {evaluating ? "Evaluating S.M.A.R.T..." : "Run Health Valuation Assessment"}
                    </Button>
                  )}
                </div>
              ) : (
                <div className="text-center p-8 text-xs text-slate-500 font-mono">
                  Select a connected storage drive to run health and marketplace valuation.
                </div>
              )}
            </div>
          </div>

          {/* Quick Tools */}
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg space-y-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold block">
              Security Shortcuts
            </span>
            <div className="space-y-2">
              <Link href="/inspector" className="block">
                <div className="p-3 rounded-xl border border-slate-800 bg-[#060A12] hover:border-slate-700 text-xs flex items-center justify-between transition-colors">
                  <div className="flex items-center gap-2.5 text-slate-200">
                    <Eye className="h-4 w-4 text-cyan-400" />
                    <span>Raw Storage Inspector (Hex)</span>
                  </div>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                </div>
              </Link>
              <Link href="/restore" className="block">
                <div className="p-3 rounded-xl border border-slate-800 bg-[#060A12] hover:border-slate-700 text-xs flex items-center justify-between transition-colors">
                  <div className="flex items-center gap-2.5 text-slate-200">
                    <Lock className="h-4 w-4 text-blue-400" />
                    <span>Decrypt & Restore Backup</span>
                  </div>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                </div>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
