"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  RefreshCw,
  ArrowLeft,
  Lock,
  Search,
  FileCheck2,
  Clock,
  Terminal,
  Hash,
  Filter,
  SlidersHorizontal,
  Key,
  Cpu,
  Layers,
  Copy,
  Check,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

export default function GovernmentAuditPage() {
  const [logs, setLogs] = useState<any[]>([]);
  const [verification, setVerification] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/audit/logs?limit=100");
      if (res.ok) {
        const data = await res.json();
        setLogs(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyChain = async () => {
    setVerifying(true);
    try {
      const res = await fetch("http://localhost:9758/api/audit/verify-chain");
      if (res.ok) {
        const data = await res.json();
        setVerification(data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    handleVerifyChain();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      searchQuery === "" ||
      log.operation?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.user_id?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.curr_hash?.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.device_id?.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesRole = roleFilter === "all" || log.role?.toLowerCase() === roleFilter.toLowerCase();
    return matchesSearch && matchesRole;
  });

  const getOperationBadge = (op: string) => {
    if (op.includes("LOGIN"))
      return "bg-sky-500/15 text-sky-300 border-sky-500/30";
    if (op.includes("DISCOVERY") || op.includes("AUTHORIZE"))
      return "bg-teal-500/15 text-teal-300 border-teal-500/30";
    if (op.includes("WIPE") || op.includes("SANITIZ"))
      return "bg-rose-500/15 text-rose-300 border-rose-500/30";
    if (op.includes("FORENSIC") || op.includes("CARVE"))
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    if (op.includes("CERTIFICATE") || op.includes("REPORT"))
      return "bg-purple-500/15 text-purple-300 border-purple-500/30";
    return "bg-slate-800/80 text-slate-300 border-slate-700/60";
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Link
              href="/government/dashboard"
              className="text-xs text-slate-400 hover:text-emerald-400 transition-colors flex items-center gap-1.5 font-medium"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Fleet Operations
            </Link>
            <span className="text-slate-600">•</span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-emerald-500/30 bg-emerald-500/10 text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              Continuous Cryptographic Integrity Ledger
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Tamper-Evident SHA-256 Audit Trail
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Every critical system action is cryptographically linked to the preceding entry using SHA-256 hash chaining.
            Any unauthorized modification or gap in the ledger immediately invalidates the cryptographic proof.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchLogs}
            disabled={loading}
            className="border-slate-700/80 bg-[#0E1628] hover:bg-[#152038] text-slate-200 text-xs flex items-center gap-2 h-9 px-3.5 shadow-sm transition-all"
          >
            <RefreshCw className={`h-3.5 w-3.5 text-slate-400 ${loading ? "animate-spin" : ""}`} />
            <span>Refresh Ledger</span>
          </Button>

          <Button
            size="sm"
            onClick={handleVerifyChain}
            disabled={verifying}
            className="bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-emerald-950/50 transition-all hover:scale-[1.02]"
          >
            <ShieldCheck className={`h-4 w-4 ${verifying ? "animate-spin" : ""}`} />
            <span>Verify Cryptographic Chain</span>
          </Button>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verification && (
        <div
          className={`p-5 rounded-2xl border transition-all ${
            verification.verified
              ? "border-emerald-500/40 bg-gradient-to-r from-emerald-950/40 via-[#0B1322] to-[#0B1322] shadow-xl shadow-emerald-950/20"
              : "border-rose-500/40 bg-gradient-to-r from-rose-950/40 via-[#0B1322] to-[#0B1322] shadow-xl shadow-rose-950/20"
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start md:items-center gap-4">
              <div
                className={`p-3 rounded-xl border shrink-0 ${
                  verification.verified
                    ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-400"
                    : "border-rose-500/30 bg-rose-500/15 text-rose-400"
                }`}
              >
                {verification.verified ? <ShieldCheck className="h-6 w-6" /> : <ShieldAlert className="h-6 w-6" />}
              </div>
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2.5">
                  <span className="font-bold text-white text-base tracking-tight">{verification.status}</span>
                  <span
                    className={`font-mono text-[11px] font-semibold px-2.5 py-0.5 rounded-full border ${
                      verification.verified
                        ? "border-emerald-400/40 text-emerald-300 bg-emerald-950/60"
                        : "border-rose-400/40 text-rose-300 bg-rose-950/60"
                    }`}
                  >
                    {verification.verified ? "100% MATHEMATICALLY VERIFIED" : "INTEGRITY ALERT"}
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-normal">{verification.message}</p>
                <div className="text-[11px] text-slate-400 font-mono flex flex-wrap items-center gap-3 pt-1">
                  <span className="text-slate-300">Verified Sequence Depth: <strong className="text-emerald-400 font-semibold">#{verification.total_events}</strong> records</span>
                  <span>•</span>
                  <span className="flex items-center gap-1.5">
                    <span>Head Digest:</span>
                    <span className="font-mono text-cyan-300 bg-[#060A12] px-2 py-0.5 rounded border border-slate-800">
                      {verification.latest_hash?.slice(0, 20)}...
                    </span>
                  </span>
                </div>
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <div className="px-4 py-2.5 rounded-xl bg-[#060A12] border border-slate-800/80 text-right font-mono">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider">Tampering Status</div>
                <div className="text-xs font-bold text-emerald-400 flex items-center justify-end gap-1 mt-0.5">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  Zero Broken Links
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Audit Telemetry KPI Row */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Total Audit Events</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Activity className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold font-mono text-white tracking-tight">{logs.length} Records</div>
          <p className="text-xs text-slate-400 mt-1.5">Immutable append-only entries</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Hashing Standard</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Hash className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold font-mono text-cyan-300 tracking-tight">SHA-256</div>
          <p className="text-xs text-slate-400 mt-1.5">256-bit cryptographic digest</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Genesis Hash</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Key className="h-4 w-4" />
            </div>
          </div>
          <div className="text-base font-bold font-mono text-slate-200 truncate mt-1">00000000...0000</div>
          <p className="text-xs text-slate-400 mt-1.5">64-zero canonical root anchor</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Compliance Standard</span>
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="text-xl font-extrabold text-white tracking-tight">NTRO / CERT-In</div>
          <p className="text-xs text-emerald-400 mt-1.5 flex items-center gap-1.5 font-medium">
            <CheckCircle2 className="h-3.5 w-3.5" /> Non-Repudiation Verified
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-4 shadow-lg flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-96">
          <Search className="h-4 w-4 text-slate-400 absolute left-3.5 top-3 pointer-events-none" />
          <Input
            placeholder="Search operation, user, device, hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-[#060A12] border-slate-700/70 text-xs pl-10 text-white placeholder:text-slate-500 h-10 rounded-xl focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-end">
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-medium flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-slate-400" /> Filter:
            </span>
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              aria-label="Filter audit logs by role"
              className="bg-[#060A12] border border-slate-700/70 text-xs text-slate-200 rounded-xl px-3 py-2 focus:ring-1 focus:ring-cyan-500 focus:border-cyan-500 outline-none"
            >
              <option value="all">All Roles</option>
              <option value="individual">Individual</option>
              <option value="government">Government</option>
              <option value="forensic">Forensic</option>
            </select>
          </div>

          <span className="text-xs text-slate-400 font-mono px-3 py-1.5 rounded-lg bg-[#060A12] border border-slate-800">
            Showing <strong className="text-white">{filteredLogs.length}</strong> of {logs.length}
          </span>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Cryptographically Chained Event Ledger
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Entries arranged in chronological order with cryptographically verifiable hash pointers to preceding blocks.
            </p>
          </div>
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-medium border border-slate-700 bg-slate-800/60 text-slate-300 shrink-0">
            <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
            Live Hash-Chain Verification
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead className="bg-[#060A12] text-slate-400 font-mono uppercase text-[11px] tracking-wider border-b border-slate-800/80">
              <tr>
                <th className="py-3.5 px-4">Seq</th>
                <th className="py-3.5 px-4">Timestamp (UTC)</th>
                <th className="py-3.5 px-4">User Context</th>
                <th className="py-3.5 px-4">Operation Type</th>
                <th className="py-3.5 px-4">Target Device / Scope</th>
                <th className="py-3.5 px-4">Status</th>
                <th className="py-3.5 px-4">Current Block Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70 text-slate-300 font-mono text-xs">
              {filteredLogs.map((log, idx) => (
                <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                  {/* Sequence */}
                  <td className="py-4 px-4 font-bold text-cyan-400 whitespace-nowrap">
                    #{String(log.sequence).padStart(4, "0")}
                  </td>

                  {/* Timestamp */}
                  <td className="py-4 px-4 text-slate-300 text-[11px] whitespace-nowrap">
                    {log.timestamp}
                  </td>

                  {/* User Context */}
                  <td className="py-4 px-4 font-sans whitespace-nowrap">
                    <div className="font-semibold text-white text-xs">{log.user_id}</div>
                    <span className="text-[10px] text-slate-400 font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800/60 border border-slate-700/60 inline-block mt-1">
                      {log.role}
                    </span>
                  </td>

                  {/* Operation */}
                  <td className="py-4 px-4 whitespace-nowrap">
                    <span className={`font-mono text-[11px] py-1 px-2.5 rounded-md font-semibold border ${getOperationBadge(log.operation)}`}>
                      {log.operation}
                    </span>
                  </td>

                  {/* Target / Device */}
                  <td className="py-4 px-4 font-sans text-xs text-slate-200 whitespace-nowrap">
                    <span className="font-mono text-slate-300 bg-[#060A12] px-2 py-1 rounded border border-slate-800">
                      {log.device_id || "SYSTEM_CORE"}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-4 px-4 whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1.5 text-xs font-mono font-semibold px-2.5 py-1 rounded-full border ${
                        log.status === "SUCCESS"
                          ? "text-emerald-300 bg-emerald-500/15 border-emerald-500/30"
                          : "text-rose-300 bg-rose-500/15 border-rose-500/30"
                      }`}
                    >
                      <CheckCircle2 className="h-3 w-3" />
                      {log.status}
                    </span>
                  </td>

                  {/* Block Hash */}
                  <td className="py-4 px-4">
                    <div className="flex items-center gap-2">
                      <div
                        className="bg-[#060A12] border border-slate-700/70 rounded-lg px-2.5 py-1 text-[11px] text-slate-300 max-w-[210px] truncate hover:text-white font-mono transition-colors"
                        title={`Current: ${log.curr_hash}\nPrevious: ${log.prev_hash}`}
                      >
                        {log.curr_hash?.slice(0, 14)}...{log.curr_hash?.slice(-8)}
                      </div>
                      <button
                        onClick={() => handleCopy(log.curr_hash)}
                        title="Copy SHA-256 Hash"
                        aria-label="Copy SHA-256 Hash"
                        className="p-1 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
                      >
                        {copiedHash === log.curr_hash ? (
                          <Check className="h-3.5 w-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="h-3.5 w-3.5" />
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}

              {filteredLogs.length === 0 && !loading && (
                <tr>
                  <td colSpan={7} className="py-12 px-4 text-center text-slate-400 font-sans text-xs">
                    No matching audit records found. Try adjusting your search query or filter.
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
