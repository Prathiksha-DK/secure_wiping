"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  Search,
  ShieldCheck,
  Lock,
  FileCheck2,
  HardDrive,
  FolderTree,
  Terminal,
  RefreshCw,
  Play,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  Eye,
  ArrowRight,
  ShieldAlert,
  Sliders,
  Layers,
  Sparkles,
  KeyRound,
  FileCode,
  Binary,
  Check,
  Copy,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export default function ForensicDashboardPage() {
  const [targetPath, setTargetPath] = useState("");
  const [targetType, setTargetType] = useState<"file" | "folder" | "disk">("file");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<any | null>(null);
  const [cases, setCases] = useState<any[]>([]);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [createdReport, setCreatedReport] = useState<any | null>(null);
  const [caseTitle, setCaseTitle] = useState("Evidence Media Forensics — Acquisition #0849");
  const [copiedDigest, setCopiedDigest] = useState(false);

  const fetchCases = async () => {
    try {
      const res = await fetch("http://localhost:9758/api/forensics/cases");
      if (res.ok) {
        const data = await res.json();
        setCases(Array.isArray(data) ? data : []);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchCases();
  }, []);

  const handleStartCarve = async () => {
    if (!targetPath) return;
    setScanning(true);
    setScanResult(null);
    setCreatedReport(null);

    try {
      const res = await fetch("http://localhost:9758/api/forensics/carve-stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: targetPath, target_type: targetType }),
      });

      if (res.ok) {
        const data = await res.json();
        setScanResult(data);
      }
    } catch (err) {
      console.error("Carving failed", err);
    } finally {
      setScanning(false);
    }
  };

  const handleGenerateReport = async () => {
    if (!scanResult) return;
    setGeneratingReport(true);
    try {
      const res = await fetch("http://localhost:9758/api/forensics/create-case", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: caseTitle,
          target_source: targetPath,
          carve_results: scanResult,
          notes: "Forensic acquisition acquired under strict non-destructive read-only protocol.",
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setCreatedReport(data.report);
        fetchCases();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setGeneratingReport(false);
    }
  };

  const evidenceLevelStyles: Record<string, { badge: string; border: string; glow: string }> = {
    NO_EVIDENCE: {
      badge: "border-emerald-500/40 text-emerald-300 bg-emerald-500/15",
      border: "border-emerald-500/40",
      glow: "shadow-emerald-950/20",
    },
    LOW_CONFIDENCE_TRACE: {
      badge: "border-sky-500/40 text-sky-300 bg-sky-500/15",
      border: "border-sky-500/40",
      glow: "shadow-sky-950/20",
    },
    PROBABLE_RECOVERABLE_ARTIFACT: {
      badge: "border-amber-500/40 text-amber-300 bg-amber-500/15",
      border: "border-amber-500/40",
      glow: "shadow-amber-950/20",
    },
    VALIDATED_RECOVERABLE_ARTIFACT: {
      badge: "border-rose-500/40 text-rose-300 bg-rose-500/15",
      border: "border-rose-500/40",
      glow: "shadow-rose-950/20",
    },
  };

  const currentLevelStyle = scanResult
    ? evidenceLevelStyles[scanResult.evidence_level] || evidenceLevelStyles.NO_EVIDENCE
    : evidenceLevelStyles.NO_EVIDENCE;

  const handleCopyDigest = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDigest(true);
    setTimeout(() => setCopiedDigest(false), 2000);
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium border border-amber-500/30 bg-amber-500/10 text-amber-400">
              Forensic Investigator Command
            </span>
            <span className="text-slate-600">•</span>
            <div className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[11px] text-emerald-400 font-mono shadow-sm">
              <Lock className="h-3 w-3 text-emerald-400" />
              <span>Strict Read-Only Guarantee (No Writes Permitted)</span>
            </div>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Forensic Carving & Recovery Verification
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Non-destructive streaming file carving, structural format verification, and multi-tier evidence classification.
            Destructive wiping actions are hardware-prohibited under this role.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link href="/faris">
            <Button
              size="sm"
              variant="outline"
              className="border-slate-700/80 bg-[#0E1628] hover:bg-[#152038] text-slate-200 text-xs flex items-center gap-2 h-9 px-3.5 shadow-sm transition-all"
            >
              <Layers className="h-3.5 w-3.5 text-cyan-400" />
              <span>FARIS 10-Branch Engine</span>
            </Button>
          </Link>
          <Link href="/inspector">
            <Button
              size="sm"
              className="bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-amber-950/40 transition-all hover:scale-[1.02]"
            >
              <Eye className="h-3.5 w-3.5" />
              <span>Hex Sector Inspector</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Quick Metrics */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Hardware Safety</span>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <Lock className="h-4 w-4" />
            </div>
          </div>
          <div className="text-xl font-extrabold text-emerald-400 font-mono tracking-tight">STRICT READ-ONLY</div>
          <p className="text-xs text-slate-400 mt-1.5">Zero disk modification commands</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Signature Engine</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <Cpu className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">11 Format Parsers</div>
          <p className="text-xs text-slate-400 mt-1.5">PDF, Office, PNG, JPEG, ELF, PE, 7z</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Validation Depth</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Sliders className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-blue-300 font-mono tracking-tight">3-Tier Depth</div>
          <p className="text-xs text-slate-400 mt-1.5">Signature → Structure → Decompression</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Evidence Registry</span>
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-purple-300 font-mono tracking-tight">{cases.length} Recorded</div>
          <p className="text-xs text-slate-400 mt-1.5">Cryptographically signed case files</p>
        </div>
      </div>

      {/* Main Forensic Workspace */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column: Interactive Carver Console */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Search className="h-4 w-4 text-amber-400" />
                  Read-Only Forensic Carver Console
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Streaming buffer evaluation across chunk boundaries with 64 KiB structural overlap.
                </p>
              </div>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold border border-slate-700 bg-slate-800/60 text-slate-300 self-start sm:self-auto">
                C-Accelerated bytes.find
              </span>
            </div>

            <div className="p-6 space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="sm:col-span-2 space-y-1.5">
                  <Label className="text-xs font-semibold text-slate-200">Target Evidence Path</Label>
                  <Input
                    placeholder="e.g., D:\wiping\backend\cart.db or raw disk image"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    className="bg-[#060A12] border-slate-700/80 text-xs font-mono text-white placeholder:text-slate-500 h-10 rounded-xl focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs font-semibold text-slate-200">Target Type</Label>
                  <select
                    value={targetType}
                    onChange={(e: any) => setTargetType(e.target.value)}
                    aria-label="Target evidence type"
                    className="w-full bg-[#060A12] border border-slate-700/80 rounded-xl px-3 py-2 text-xs text-white h-10 focus:border-amber-500 focus:ring-1 focus:ring-amber-500 outline-none"
                  >
                    <option value="file">File / Container</option>
                    <option value="folder">Directory Tree</option>
                    <option value="disk">Raw Block Device</option>
                  </select>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3">
                <Button
                  onClick={handleStartCarve}
                  disabled={scanning || !targetPath}
                  className="bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold flex items-center gap-2 h-10 px-5 rounded-xl shadow-lg shadow-amber-950/40 transition-all hover:scale-[1.02]"
                >
                  <Play className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
                  <span>{scanning ? "Streaming Carving Scan..." : "Execute Forensic Carve"}</span>
                </Button>

                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setTargetPath("D:\\jaisree\\sih26\\secure_wiping\\backend\\cart.db");
                    setTargetType("file");
                  }}
                  className="border-slate-700/80 bg-[#0E1628] text-xs text-slate-300 hover:text-white hover:bg-slate-800 h-10 px-4 rounded-xl"
                >
                  Load cart.db Test Sample
                </Button>
              </div>

              {/* Scan Results Panel */}
              {scanResult && (
                <div className={`p-5 rounded-2xl border bg-[#060A12] space-y-4 shadow-xl ${currentLevelStyle.border} ${currentLevelStyle.glow}`}>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
                    <div>
                      <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider font-semibold">Classification Verdict</div>
                      <span className={`inline-block mt-1 font-mono text-xs font-bold px-3 py-1 rounded-full border ${currentLevelStyle.badge}`}>
                        {scanResult.evidence_level}
                      </span>
                    </div>

                    <div className="sm:text-right">
                      <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider font-semibold">Forensic Confidence Score</div>
                      <div className="text-3xl font-extrabold font-mono text-amber-400 mt-0.5">
                        {scanResult.confidence_score?.toFixed(1)}%
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 leading-relaxed font-sans">
                    {scanResult.summary_reason}
                  </p>

                  {/* 3-Tier Counters */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
                    <div className="p-4 rounded-xl bg-[#0B111E] border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400 uppercase font-semibold">Tier 1: Signature Hits</div>
                      <div className="text-2xl font-extrabold text-white mt-1">
                        {scanResult.counts?.level_1_signature_hits || 0}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">Raw Magic Byte Matches</div>
                    </div>
                    <div className="p-4 rounded-xl bg-[#0B111E] border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400 uppercase font-semibold">Tier 2: Valid Candidates</div>
                      <div className="text-2xl font-extrabold text-amber-300 mt-1">
                        {scanResult.counts?.level_2_valid_candidates || 0}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">Headers & Length Confirmed</div>
                    </div>
                    <div className="p-4 rounded-xl bg-[#0B111E] border border-slate-800 text-center">
                      <div className="text-[10px] text-slate-400 uppercase font-semibold">Tier 3: Validated Artifacts</div>
                      <div className="text-2xl font-extrabold text-rose-400 mt-1">
                        {scanResult.counts?.level_3_validated_artifacts || 0}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1">Decompressed / Full Trailer</div>
                    </div>
                  </div>

                  {/* Extracted Artifacts Table */}
                  {scanResult.validated_artifacts?.length > 0 && (
                    <div className="space-y-2 pt-2">
                      <div className="text-xs font-semibold text-white flex items-center gap-1.5">
                        <FileCode className="h-4 w-4 text-cyan-400" />
                        <span>Recoverable Files Carved:</span>
                      </div>
                      <div className="max-h-48 overflow-y-auto space-y-2 pr-1 text-xs font-mono">
                        {scanResult.validated_artifacts.map((a: any, i: number) => (
                          <div key={i} className="p-3 rounded-xl bg-[#0B111E] border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-slate-700 transition-colors">
                            <span className="font-bold text-cyan-300 bg-cyan-500/10 px-2.5 py-0.5 rounded-md border border-cyan-500/30 self-start">
                              {a.format}
                            </span>
                            <span className="text-slate-200 truncate max-w-sm font-sans">{a.details}</span>
                            <span className="text-slate-400 font-mono text-[11px]">Offset: +0x{a.header_offset?.toString(16).toUpperCase()}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <span className="text-xs text-slate-400 font-mono">
                      Throughput: <strong className="text-slate-200">{scanResult.throughput_mbps?.toFixed(1)} MB/s</strong> • Scanned: <strong className="text-slate-200">{scanResult.bytes_scanned?.toLocaleString()} bytes</strong>
                    </span>
                    <Button
                      size="sm"
                      onClick={handleGenerateReport}
                      disabled={generatingReport}
                      className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold h-9 px-4 rounded-xl shadow-md shadow-cyan-950/40"
                    >
                      {generatingReport ? "Hashing Report..." : "Generate Signed Forensic Report"}
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Generated Forensic Case Report */}
          {createdReport && (
            <div className="bg-[#0D1527] border border-cyan-500/40 rounded-2xl shadow-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCheck2 className="h-4 w-4 text-emerald-400" />
                  <span className="text-sm font-bold text-white">Official Forensic Case Report: {createdReport.case_id}</span>
                </div>
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold border border-cyan-500/30 bg-cyan-500/10 text-cyan-300">
                  Signed & Sealed
                </span>
              </div>
              <div className="p-6 space-y-3 text-xs font-mono text-slate-300">
                <div>Case Title: <strong className="text-white font-sans text-sm ml-1">{createdReport.title}</strong></div>
                <div>Investigator: <span className="text-white ml-1">{createdReport.investigator}</span></div>
                <div>Evidence Source: <span className="text-cyan-300 ml-1">{createdReport.target_source}</span></div>
                <div>Chain of Custody: <span className="text-slate-300 font-sans ml-1">{createdReport.chain_of_custody}</span></div>
                <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 mt-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-400 uppercase tracking-wider font-semibold text-[10px]">Evidence Integrity Digest (SHA-256):</span>
                    <button
                      onClick={() => handleCopyDigest(createdReport.evidence_integrity_sha256)}
                      className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-sans"
                    >
                      {copiedDigest ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                      <span>{copiedDigest ? "Copied" : "Copy"}</span>
                    </button>
                  </div>
                  <div className="text-emerald-400 font-bold font-mono mt-1 break-all text-xs">{createdReport.evidence_integrity_sha256}</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Casebook Registry */}
        <div className="space-y-4">
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D]">
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <FileText className="h-4 w-4 text-amber-400" />
                Casebook & Evidence Registry
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Recorded investigation cases anchored with immutable SHA-256 digests.
              </p>
            </div>

            <div className="p-4 space-y-3 max-h-[600px] overflow-y-auto">
              {cases.map((c, i) => (
                <div key={i} className="p-4 rounded-xl bg-[#060A12] border border-slate-800/90 space-y-2 hover:border-slate-700 transition-colors">
                  <div className="flex items-center justify-between text-xs font-mono">
                    <span className="text-cyan-400 font-bold">{c.case_number}</span>
                    <span className="text-slate-400 text-[11px]">{new Date(c.created_at * 1000).toLocaleDateString()}</span>
                  </div>
                  <div className="font-semibold text-xs text-white leading-snug">{c.title}</div>
                  <div className="text-xs text-slate-400 font-mono">Investigator: <span className="text-slate-300">{c.investigator}</span></div>
                  <div className="pt-1.5 flex items-center justify-between">
                    <span className={`text-[11px] font-mono font-semibold px-2.5 py-0.5 rounded-full border ${evidenceLevelStyles[c.evidence_level]?.badge || "border-slate-700 text-slate-300 bg-slate-800"}`}>
                      {c.evidence_level} ({c.confidence_score}%)
                    </span>
                  </div>
                </div>
              ))}

              {cases.length === 0 && (
                <div className="py-12 px-4 text-center text-xs text-slate-500 font-mono">
                  No forensic cases logged yet. Execute a carving scan to create an official case entry.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
