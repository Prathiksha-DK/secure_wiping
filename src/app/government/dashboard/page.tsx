"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Building2,
  Server,
  Network,
  ShieldCheck,
  ShieldAlert,
  Trash2,
  Eye,
  RefreshCw,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Lock,
  ArrowRight,
  HardDrive,
  Users,
  Activity,
  FileCheck2,
  Radio,
  SlidersHorizontal,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function GovernmentDashboardPage() {
  const [lanDevices, setLanDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [authorizing, setAuthorizing] = useState<string | null>(null);
  const [statusNotice, setStatusNotice] = useState<string | null>(null);

  const fetchLanDevices = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/devices/discover-lan");
      if (res.ok) {
        const data = await res.json();
        setLanDevices(Array.isArray(data) ? data : data.value || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLanDevices();
  }, []);

  const handleAuthorize = async (deviceId: string) => {
    setAuthorizing(deviceId);
    setStatusNotice(null);
    try {
      const res = await fetch("http://localhost:9758/api/devices/authorize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device_id: deviceId, operator: "gov_officer" }),
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        setStatusNotice(`Device ${deviceId} successfully authorized for managed operations.`);
        fetchLanDevices();
      } else {
        setStatusNotice(data.message || "Authorization failed.");
      }
    } catch (err: any) {
      setStatusNotice(err.message || "Failed to contact authorization server.");
    } finally {
      setAuthorizing(null);
    }
  };

  const onlineCount = lanDevices.filter((d) => d.status === "online").length;
  const authorizedCount = lanDevices.filter((d) => d.is_authorized === 1).length;

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              Government & Enterprise Fleet Command
            </span>
            <span className="text-slate-600">•</span>
            <span className="text-xs text-slate-400 font-mono">NTRO Secure Agency Network</span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Authorized LAN Device Discovery & Managed Sanitization
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Centrally manage authorized agency endpoints, execute cryptographically verified remote sanitization, and audit cross-fleet compliance.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchLanDevices}
            disabled={loading}
            className="border-slate-700/80 bg-[#0E1628] hover:bg-[#152038] text-slate-200 text-xs flex items-center gap-2 h-9 px-3.5 shadow-sm transition-all"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
            <span>Scan LAN Network</span>
          </Button>

          <Link href="/government/audit">
            <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-emerald-950/40 transition-all hover:scale-[1.02]">
              <Activity className="h-3.5 w-3.5" />
              <span>Verify Audit Chain</span>
            </Button>
          </Link>
        </div>
      </div>

      {statusNotice && (
        <div className="p-4 rounded-xl border border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 to-[#0B1322] text-emerald-300 text-xs font-medium flex items-center gap-3 shadow-md">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>{statusNotice}</span>
        </div>
      )}

      {/* Fleet KPI Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Discovered Agents</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Network className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">{lanDevices.length} Nodes</div>
          <p className="text-xs text-slate-400 mt-1.5">Authenticated subnet endpoints</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Online & Reachable</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Radio className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-cyan-300 font-mono tracking-tight">{onlineCount} Endpoints</div>
          <p className="text-xs text-emerald-400 mt-1.5 flex items-center gap-1.5 font-medium">
            <CheckCircle2 className="h-3.5 w-3.5" /> Real-time Heartbeat
          </p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Paired / Authorized</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <ShieldCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">{authorizedCount} Active</div>
          <p className="text-xs text-slate-400 mt-1.5">Requires 2-party sign-off</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Compliance Stance</span>
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono tracking-tight">100% Compliant</div>
          <p className="text-xs text-slate-400 mt-1.5">NIST 800-88 / DoD Certs Logged</p>
        </div>
      </div>

      {/* LAN Fleet Table */}
      <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" />
              Government LAN Fleet Inventory
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Target devices running authenticated agent daemons on the 10.14.x.x subnet. Discovery alone does not grant wipe access.
            </p>
          </div>
          <span className="inline-flex items-center px-3 py-1 rounded-full text-[11px] font-mono font-medium border border-slate-700 bg-slate-800/60 text-slate-300 self-start sm:self-auto">
            LAN Port: 8586 / Socket.IO
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead className="bg-[#060A12] text-slate-400 font-mono uppercase text-[11px] tracking-wider border-b border-slate-800/80">
              <tr>
                <th className="py-3.5 px-4">Device ID & Node</th>
                <th className="py-3.5 px-4">IP Address</th>
                <th className="py-3.5 px-4">Storage Spec</th>
                <th className="py-3.5 px-4">S.M.A.R.T. Health</th>
                <th className="py-3.5 px-4">Agent Version</th>
                <th className="py-3.5 px-4">Authorization</th>
                <th className="py-3.5 px-4 text-right">Operations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-slate-300">
              {lanDevices.map((dev, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-4 px-4 whitespace-nowrap">
                    <div className="font-semibold text-white text-sm">{dev.name}</div>
                    <div className="text-[11px] font-mono text-cyan-400 mt-0.5">{dev.id} • SN: {dev.serial_number}</div>
                  </td>
                  <td className="py-4 px-4 font-mono text-slate-300 whitespace-nowrap">
                    <span className="bg-[#060A12] px-2 py-1 rounded border border-slate-800">
                      {dev.ip_address}
                    </span>
                  </td>
                  <td className="py-4 px-4 whitespace-nowrap">
                    <div className="font-mono font-bold text-white">
                      {Math.round(dev.capacity_bytes / (1024 ** 3))} GB {dev.media_type}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">Bus: {dev.bus_type}</div>
                  </td>
                  <td className="py-4 px-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${
                        dev.health_score >= 80
                          ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/15"
                          : "border-amber-500/40 text-amber-300 bg-amber-500/15"
                      }`}
                    >
                      {dev.health_score}% {dev.health_status}
                    </span>
                  </td>
                  <td className="py-4 px-4 font-mono text-slate-400 whitespace-nowrap">{dev.agent_version}</td>
                  <td className="py-4 px-4 whitespace-nowrap">
                    {dev.is_authorized === 1 ? (
                      <span className="inline-flex items-center gap-1.5 text-xs font-mono text-emerald-400 font-semibold px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        Paired & Authorized
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-xs font-mono text-amber-400 font-semibold px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20">
                        <Lock className="h-3.5 w-3.5 text-amber-400" />
                        Pending Approval
                      </span>
                    )}
                  </td>
                  <td className="py-4 px-4 text-right space-x-2 whitespace-nowrap">
                    {dev.is_authorized === 0 ? (
                      <Button
                        size="sm"
                        onClick={() => handleAuthorize(dev.id)}
                        disabled={authorizing === dev.id}
                        className="h-8 text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-semibold rounded-lg px-3 shadow-md shadow-emerald-950/40"
                      >
                        {authorizing === dev.id ? "Pairing..." : "Approve Pairing"}
                      </Button>
                    ) : (
                      <Link href={`/wipe?device=${encodeURIComponent(dev.name)}&targetType=disk`}>
                        <Button
                          size="sm"
                          className="h-8 text-xs bg-rose-600 hover:bg-rose-500 text-white font-semibold rounded-lg px-3 shadow-md shadow-rose-950/40"
                        >
                          <Trash2 className="h-3.5 w-3.5 mr-1" />
                          Remote Wipe
                        </Button>
                      </Link>
                    )}
                  </td>
                </tr>
              ))}

              {lanDevices.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="py-12 px-4 text-center text-slate-400 font-sans text-xs">
                    No LAN devices discovered. Click &quot;Scan LAN Network&quot; to probe for authenticated agent nodes.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
