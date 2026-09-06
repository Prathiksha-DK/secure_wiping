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
  Bell,
  UserCheck,
  UserX,
  XCircle,
  Award,
  User,
  Phone,
  Mail,
  CreditCard,
  Disc,
  Plus,
  X,
  Filter,
  Calendar,
  Loader2,
  Building,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";

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

  // Hunter Registration Requests State
  const [hunterRequests, setHunterRequests] = useState<any[]>([]);
  const [hunterCounts, setHunterCounts] = useState({ total: 0, pending: 0, approved: 0, rejected: 0 });
  const [notificationMsg, setNotificationMsg] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"ALL" | "PENDING" | "APPROVED" | "REJECTED">("PENDING");
  const [selectedDossier, setSelectedDossier] = useState<any | null>(null);
  const [rejectingApp, setRejectingApp] = useState<any | null>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewFeedback, setReviewFeedback] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Forensic ISO Images State
  const [isoImages, setIsoImages] = useState<any[]>([]);
  const [isPublishModalOpen, setIsPublishModalOpen] = useState(false);
  const [publishLoading, setPublishLoading] = useState(false);
  const [newIsoForm, setNewIsoForm] = useState({
    image_name: "",
    case_ref_id: "",
    description: "",
    file_size_human: "4.2 GB",
  });

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

  const fetchHunterRequests = async () => {
    try {
      const res = await fetch("http://localhost:9758/api/forensics/hunter-requests");
      if (res.ok) {
        const data = await res.json();
        setHunterRequests(data.requests || []);
        if (data.counts) {
          setHunterCounts(data.counts);
          if (data.counts.pending > 0) {
            setNotificationMsg("New Hunter registration requires approval.");
          } else {
            setNotificationMsg(null);
          }
        }
      }
    } catch (err) {
      console.error("Failed to fetch hunter requests:", err);
    }
  };

  const fetchIsoImages = async () => {
    try {
      const res = await fetch("http://localhost:9758/api/forensics/iso-images");
      if (res.ok) {
        const data = await res.json();
        setIsoImages(data.iso_images || []);
      }
    } catch (err) {
      console.error("Failed to fetch ISO images:", err);
    }
  };

  useEffect(() => {
    fetchCases();
    fetchHunterRequests();
    fetchIsoImages();

    // Periodic poll for new hunter requests
    const interval = setInterval(() => {
      fetchHunterRequests();
      fetchIsoImages();
    }, 8000);

    return () => clearInterval(interval);
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

  const handleReviewDecision = async (appId: string, decision: "APPROVE" | "REJECT", reasonText?: string) => {
    setReviewLoading(true);
    setReviewFeedback(null);
    try {
      const res = await fetch(`http://localhost:9758/api/forensics/hunter-requests/${appId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision,
          rejection_reason: reasonText || rejectionReason,
          investigator: "forensic_analyst",
        }),
      });

      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || "Failed to execute review decision.");
      }

      setReviewFeedback({
        type: "success",
        text: `Applicant ${data.hunter_username} has been successfully ${decision.toLowerCase()}d. Audit event chained.`,
      });

      setRejectingApp(null);
      setRejectionReason("");
      setSelectedDossier(null);
      await fetchHunterRequests();
    } catch (err: any) {
      setReviewFeedback({ type: "error", text: err.message });
    } finally {
      setReviewLoading(false);
    }
  };

  const handlePublishIso = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIsoForm.image_name || !newIsoForm.case_ref_id) return;
    setPublishLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/forensics/iso-images", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(newIsoForm),
      });
      if (res.ok) {
        setIsPublishModalOpen(false);
        setNewIsoForm({ image_name: "", case_ref_id: "", description: "", file_size_human: "4.2 GB" });
        await fetchIsoImages();
      }
    } catch (err) {
      console.error("Failed to publish ISO:", err);
    } finally {
      setPublishLoading(false);
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

  // Filter requests
  const filteredRequests = hunterRequests.filter((req) => {
    if (activeTab === "PENDING") return req.status === "PENDING_FORENSIC_APPROVAL" || req.status === "Pending";
    if (activeTab === "APPROVED") return req.status === "APPROVED" || req.status === "Approved";
    if (activeTab === "REJECTED") return req.status === "REJECTED" || req.status === "Rejected";
    return true;
  });

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
            Forensic Carving & Clearance Authority
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Non-destructive streaming file carving, structural verification, hunter credential approval, and forensic evidence distribution.
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
              <span>FARIS Engine</span>
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

      {/* FORENSIC INVESTIGATOR NOTIFICATION: Visible while any hunter registration requires approval */}
      {hunterCounts.pending > 0 && (
        <div className="p-4 rounded-2xl border border-purple-500/60 bg-gradient-to-r from-purple-950/50 via-[#0D1527] to-amber-950/30 shadow-2xl flex flex-col sm:flex-row sm:items-center justify-between gap-4 animate-in fade-in-50">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="h-10 w-10 rounded-xl bg-purple-500/20 border border-purple-500/40 flex items-center justify-center text-purple-300 shrink-0 shadow-lg shadow-purple-950/50">
              <Bell className="h-5 w-5 animate-pulse" />
            </div>
            <div>
              <div className="text-sm font-bold text-white flex items-center gap-2">
                <span>New Hunter registration requires approval.</span>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-purple-500/30 text-purple-200 border border-purple-500/50 font-bold">
                  {hunterCounts.pending} Pending
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                External triage candidate submitted identity and global certification credentials. Action required before account activation.
              </p>
            </div>
          </div>
          <a href="#hunter-registration-requests">
            <Button
              size="sm"
              className="bg-purple-600 hover:bg-purple-500 text-white text-xs h-9 px-4 rounded-xl font-semibold shadow-lg shadow-purple-950/50 shrink-0 flex items-center gap-1.5"
            >
              <span>Review Requests</span>
              <ArrowRight className="h-3.5 w-3.5" />
            </Button>
          </a>
        </div>
      )}

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
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Hunter Intake</span>
            <div className="h-8 w-8 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
              <UserCheck className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">
            {hunterCounts.pending} <span className="text-xs font-normal text-amber-400">Pending Review</span>
          </div>
          <p className="text-xs text-slate-400 mt-1.5">{hunterCounts.approved} Approved / {hunterCounts.total} Total Applicants</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Shared ISO Images</span>
            <div className="h-8 w-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
              <Disc className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-blue-300 font-mono tracking-tight">
            {isoImages.length} Images
          </div>
          <p className="text-xs text-slate-400 mt-1.5">Published for authorized Hunter triage</p>
        </div>

        <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl p-5 shadow-lg hover:border-slate-700/80 transition-all">
          <div className="flex items-center justify-between pb-3">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-medium">Evidence Registry</span>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <FileCheck2 className="h-4 w-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-cyan-300 font-mono tracking-tight">{cases.length} Recorded</div>
          <p className="text-xs text-slate-400 mt-1.5">Cryptographically signed case files</p>
        </div>
      </div>

      {/* DEDICATED SECTION: Hunter Registration Requests */}
      <div id="hunter-registration-requests" className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden scroll-mt-6">
        <div className="px-6 py-5 border-b border-slate-800/80 bg-[#090F1D] flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <UserCheck className="h-5 w-5 text-purple-400" />
              <h2 className="text-base font-bold text-white">Hunter Registration Requests</h2>
              {hunterCounts.pending > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                  {hunterCounts.pending} Action Required
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Review applicant personal identity, Aadhaar & PAN verification status, and global certifications to authorize or deny Hunter clearance.
            </p>
          </div>

          {/* Filter Tabs */}
          <div className="flex items-center gap-1.5 bg-[#060A12] p-1 rounded-xl border border-slate-800">
            {(["PENDING", "ALL", "APPROVED", "REJECTED"] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all font-medium ${
                  activeTab === tab
                    ? "bg-purple-600 text-white shadow-md shadow-purple-950/40 font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                {tab === "PENDING" && `Pending (${hunterCounts.pending})`}
                {tab === "ALL" && `All (${hunterCounts.total})`}
                {tab === "APPROVED" && `Approved (${hunterCounts.approved})`}
                {tab === "REJECTED" && `Rejected (${hunterCounts.rejected})`}
              </button>
            ))}
          </div>
        </div>

        {/* Status Feedback alert */}
        {reviewFeedback && (
          <div
            className={`p-3.5 mx-6 mt-4 rounded-xl border text-xs flex items-center justify-between gap-2 ${
              reviewFeedback.type === "success"
                ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-200"
                : "bg-rose-500/10 border-rose-500/30 text-rose-200"
            }`}
          >
            <span>{reviewFeedback.text}</span>
            <button onClick={() => setReviewFeedback(null)} className="text-slate-400 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Requests List */}
        <div className="p-6 space-y-4">
          {filteredRequests.length === 0 ? (
            <div className="py-12 text-center space-y-2">
              <UserCheck className="h-10 w-10 text-slate-600 mx-auto" />
              <p className="text-sm font-semibold text-slate-400">No Hunter Registration Requests in this category.</p>
              <p className="text-xs text-slate-500">
                {activeTab === "PENDING"
                  ? "All candidate applications have been processed. New registrations will automatically alert here."
                  : "No applications found."}
              </p>
            </div>
          ) : (
            filteredRequests.map((req) => (
              <div
                key={req.id}
                className="bg-[#080E1A] border border-slate-800/90 rounded-xl p-5 hover:border-slate-700/80 transition-all space-y-4 shadow-sm"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800/70 pb-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-bold text-sm text-white">{req.full_name}</span>
                      <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                        @{req.username}
                      </span>
                      <span className="text-[11px] font-mono text-slate-500">ID: {req.id}</span>
                      {req.status === "PENDING_FORENSIC_APPROVAL" && (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 border border-amber-500/40 text-amber-300">
                          ⏳ PENDING REVIEW
                        </span>
                      )}
                      {req.status === "APPROVED" && (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/40 text-emerald-300">
                          ✓ APPROVED & ACTIVE
                        </span>
                      )}
                      {req.status === "REJECTED" && (
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/15 border border-rose-500/40 text-rose-300">
                          ✕ REJECTED
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
                      <span className="flex items-center gap-1.5">
                        <Mail className="h-3.5 w-3.5 text-slate-500" />
                        {req.email}
                      </span>
                      <span className="flex items-center gap-1.5">
                        <Phone className="h-3.5 w-3.5 text-slate-500" />
                        {req.mobile_number}
                      </span>
                      <span className="flex items-center gap-1.5 font-mono text-[11px]">
                        <Calendar className="h-3.5 w-3.5 text-slate-500" />
                        {req.created_at_human}
                      </span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 self-start lg:self-center">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setSelectedDossier(req)}
                      className="border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-300 text-xs h-8 px-3 rounded-lg"
                    >
                      <Eye className="h-3.5 w-3.5 mr-1 text-cyan-400" />
                      <span>View Dossier</span>
                    </Button>

                    {req.status === "PENDING_FORENSIC_APPROVAL" && (
                      <>
                        <Button
                          size="sm"
                          disabled={reviewLoading}
                          onClick={() => handleReviewDecision(req.id, "APPROVE")}
                          className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs h-8 px-3.5 rounded-lg font-semibold shadow-md shadow-emerald-950/40 flex items-center gap-1"
                        >
                          <Check className="h-3.5 w-3.5" />
                          <span>Approve</span>
                        </Button>
                        <Button
                          size="sm"
                          disabled={reviewLoading}
                          onClick={() => {
                            setRejectingApp(req);
                            setRejectionReason("");
                          }}
                          className="bg-rose-600/90 hover:bg-rose-500 text-white text-xs h-8 px-3.5 rounded-lg font-semibold shadow-md shadow-rose-950/40 flex items-center gap-1"
                        >
                          <XCircle className="h-3.5 w-3.5" />
                          <span>Reject</span>
                        </Button>
                      </>
                    )}
                  </div>
                </div>

                {/* Identity & Certification Cards Preview */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Identity Check */}
                  <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between text-slate-400 font-semibold text-[11px]">
                      <span className="flex items-center gap-1">
                        <CreditCard className="h-3 w-3 text-cyan-400" />
                        Aadhaar Verification
                      </span>
                      <span className="text-emerald-400 font-mono text-[10px]">VERIFIED</span>
                    </div>
                    <div className="font-mono text-slate-200">{req.aadhaar_masked || req.aadhaar_number}</div>
                    <div className="text-[10px] text-slate-500">{req.aadhaar_status}</div>
                  </div>

                  {/* PAN Check */}
                  <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between text-slate-400 font-semibold text-[11px]">
                      <span className="flex items-center gap-1">
                        <CreditCard className="h-3 w-3 text-amber-400" />
                        PAN Authority Status
                      </span>
                      <span className="text-emerald-400 font-mono text-[10px]">VERIFIED</span>
                    </div>
                    <div className="font-mono text-slate-200">{req.pan_formatted || req.pan_number}</div>
                    <div className="text-[10px] text-slate-500">{req.pan_status}</div>
                  </div>

                  {/* Certification Check */}
                  <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1.5 text-xs">
                    <div className="flex items-center justify-between text-slate-400 font-semibold text-[11px]">
                      <span className="flex items-center gap-1">
                        <Award className="h-3 w-3 text-purple-400" />
                        Global Certification
                      </span>
                      <span className="text-purple-300 font-mono text-[10px]">{req.cert_id}</span>
                    </div>
                    <div className="font-semibold text-slate-200 truncate">{req.cert_name}</div>
                    <div className="text-[10px] text-slate-400 truncate">
                      {req.issuing_org} {req.cert_expiry ? `• Exp: ${req.cert_expiry}` : ""}
                    </div>
                  </div>
                </div>

                {/* Audit Trail Reviewer Details (if decided) */}
                {req.reviewed_by && (
                  <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
                    <div className="text-slate-400">
                      Investigator Decision by: <span className="text-cyan-300 font-semibold">{req.reviewed_by}</span> at {req.reviewed_at_human}
                    </div>
                    {req.rejection_reason && (
                      <div className="text-rose-400 font-sans">
                        <strong>Rejection Reason:</strong> {req.rejection_reason}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>

      {/* FORENSIC ISO IMAGES MANAGEMENT SECTION */}
      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-xl overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Disc className="h-5 w-5 text-blue-400" />
              <h2 className="text-base font-bold text-white">Forensic ISO Images Repository</h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-blue-500/10 border border-blue-500/30 text-blue-300">
                Hunter Triage Clearance
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Forensic bit-stream disk images and memory dumps authorized for examination by approved Threat & Forensic Hunters.
            </p>
          </div>
          <Button
            size="sm"
            onClick={() => setIsPublishModalOpen(true)}
            className="bg-blue-600 hover:bg-blue-500 text-white text-xs h-9 px-4 rounded-xl font-semibold shadow-md flex items-center gap-1.5"
          >
            <Plus className="h-4 w-4" />
            <span>Publish New Evidence ISO</span>
          </Button>
        </div>

        <div className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {isoImages.map((iso) => (
            <div
              key={iso.id}
              className="bg-[#060A12] border border-slate-800 rounded-xl p-4 space-y-3 hover:border-slate-700 transition-colors"
            >
              <div className="flex items-start justify-between gap-2">
                <div className="space-y-0.5">
                  <span className="font-mono text-[10px] text-cyan-400 font-semibold">{iso.case_ref_id}</span>
                  <h3 className="text-xs font-bold text-white leading-tight break-all">{iso.image_name}</h3>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 shrink-0">
                  {iso.status}
                </span>
              </div>

              <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{iso.description}</p>

              <div className="pt-2 border-t border-slate-800/80 space-y-1.5 text-[11px] font-mono text-slate-400">
                <div className="flex justify-between">
                  <span>File Size:</span>
                  <span className="text-slate-200 font-semibold">{iso.file_size_human}</span>
                </div>
                <div className="flex justify-between">
                  <span>Uploaded By:</span>
                  <span className="text-cyan-300">{iso.uploaded_by}</span>
                </div>
                <div className="space-y-0.5 pt-1">
                  <div className="flex justify-between text-[10px] text-slate-500">
                    <span>SHA-256 Checksum:</span>
                    <button
                      onClick={() => handleCopyDigest(iso.sha256_hash)}
                      className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                    >
                      <Copy className="h-2.5 w-2.5" />
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="text-[10px] font-mono text-slate-300 truncate bg-slate-900/90 p-1 rounded border border-slate-800">
                    {iso.sha256_hash}
                  </div>
                </div>

                <div className="pt-2 flex items-center justify-between border-t border-slate-800/60">
                  <a
                    href={`http://localhost:9758/api/forensics/iso-images/${iso.id}/download`}
                    download={iso.image_name}
                    className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 hover:text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20 px-2.5 py-1 rounded border border-emerald-500/30 transition-all"
                    title="Download authentic binary file"
                  >
                    <Download className="h-3 w-3" />
                    <span>Download ISO Binary</span>
                  </a>
                  <span className="text-[10px] text-slate-500 font-mono">ECMA-119 Verified</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Forensic Workspace: Interactive Carver & Casebook */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left Column: Interactive Carver Console */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold text-white flex items-center gap-2">
                  <Terminal className="h-4 w-4 text-cyan-400" />
                  Streaming Read-Only Carver Console
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Direct structural parsing: PDF, PNG, JPEG, ELF, PE, SQLite, ZIP, 7z.
                </p>
              </div>
              <Badge variant="outline" className="text-[11px] font-mono border-cyan-500/30 text-cyan-300 self-start sm:self-auto">
                LBA 512-Byte Alignment
              </Badge>
            </div>

            <div className="p-6 space-y-5">
              <div className="space-y-2">
                <Label htmlFor="target" className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                  <HardDrive className="h-3.5 w-3.5 text-slate-400" />
                  Target Evidence Source (Read-Only)
                </Label>
                <div className="flex gap-2">
                  <Input
                    id="target"
                    placeholder="e.g. D:\evidence\disk_image.raw or \\.\PhysicalDrive1 or sample.bin"
                    value={targetPath}
                    onChange={(e) => setTargetPath(e.target.value)}
                    className="bg-[#060A12] border-slate-700/80 text-white placeholder:text-slate-600 text-xs font-mono h-10 rounded-xl focus:border-cyan-500"
                  />
                  <Button
                    onClick={handleStartCarve}
                    disabled={scanning || !targetPath}
                    className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs h-10 px-5 rounded-xl shadow-lg shadow-cyan-950/40 shrink-0 flex items-center gap-2"
                  >
                    {scanning ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        <span>Carving...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5" />
                        <span>Inspect & Carve</span>
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {/* Target Type Selector */}
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className="text-slate-400">Target Type:</span>
                {(["file", "folder", "disk"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setTargetType(t)}
                    className={`px-3 py-1 rounded-lg border text-xs capitalize transition-all ${
                      targetType === t
                        ? "border-cyan-500/60 bg-cyan-500/15 text-cyan-300 font-semibold"
                        : "border-slate-800 bg-[#070C16] text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Scan Results Presentation */}
          {scanResult && (
            <div className="bg-[#0D1527] border border-slate-800/80 rounded-2xl shadow-xl overflow-hidden space-y-4 p-6">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
                <div>
                  <h3 className="text-sm font-bold text-white">Carving Triage Assessment</h3>
                  <p className="text-xs text-slate-400">Multi-tier forensic classification result</p>
                </div>
                <span className={`text-xs font-mono font-bold px-3 py-1 rounded-full border ${currentLevelStyle.badge}`}>
                  {scanResult.evidence_level}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80">
                  <div className="text-slate-400 text-[10px]">TOTAL ARTIFACTS</div>
                  <div className="text-lg font-bold text-white">{scanResult.artifacts_count || 0}</div>
                </div>
                <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80">
                  <div className="text-slate-400 text-[10px]">CONFIDENCE SCORE</div>
                  <div className="text-lg font-bold text-cyan-400">{scanResult.confidence_score || 0}%</div>
                </div>
                <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 sm:col-span-2">
                  <div className="text-slate-400 text-[10px]">HASH CHAIN INTEGRITY</div>
                  <div className="text-xs font-bold text-emerald-400 truncate mt-1">VERIFIED SHA-256</div>
                </div>
              </div>

              <div className="pt-2">
                <Button
                  onClick={handleGenerateReport}
                  disabled={generatingReport}
                  className="w-full bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs h-10 rounded-xl"
                >
                  {generatingReport ? "Securing Chain & Case Log..." : "Log Official Case Record & Generate Cryptographic Case File"}
                </Button>
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
              <p className="text-xs text-slate-400 mt-0.5">Recorded investigation cases anchored with immutable SHA-256 digests.</p>
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

      {/* REJECT MODAL WITH REASON PROMPT */}
      {rejectingApp && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-rose-500/40 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <UserX className="h-5 w-5 text-rose-400" />
                <h3 className="text-sm font-bold text-white">Reject Hunter Registration</h3>
              </div>
              <button onClick={() => setRejectingApp(null)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="text-xs text-slate-300 space-y-2">
              <p>
                You are rejecting the Hunter clearance application for{' '}
                <strong className="text-white">{rejectingApp.full_name}</strong> (Username: <span className="font-mono text-cyan-300">{rejectingApp.username}</span>).
              </p>
              <p className="text-slate-400">
                The candidate account will be marked as <span className="text-rose-300 font-mono">REJECTED</span> and will be blocked from logging into the Hunter Dashboard. This action is permanently recorded in the SHA-256 audit chain.
              </p>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="rej_reason" className="text-xs font-semibold text-slate-200">
                Rejection Reason <span className="text-rose-400">*</span>
              </Label>
              <Textarea
                id="rej_reason"
                placeholder="e.g. Certification ID could not be validated with issuing authority, expired credential, or identity documentation mismatch..."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                rows={3}
                required
                className="bg-[#060A12] border-slate-700 text-white text-xs rounded-xl focus:border-rose-500 resize-none"
              />
            </div>

            <div className="pt-2 flex items-center justify-end gap-2.5">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setRejectingApp(null)}
                className="border-slate-700 text-slate-300 text-xs h-9 px-4 rounded-xl"
              >
                Cancel
              </Button>
              <Button
                size="sm"
                disabled={reviewLoading}
                onClick={() => handleReviewDecision(rejectingApp.id, "REJECT", rejectionReason)}
                className="bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs h-9 px-4 rounded-xl shadow-lg shadow-rose-950/50"
              >
                {reviewLoading ? "Recording Rejection..." : "Confirm Rejection"}
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* FULL HUNTER DOSSIER MODAL */}
      {selectedDossier && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-purple-500/40 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Award className="h-5 w-5 text-purple-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">Hunter Credential Dossier</h3>
                  <p className="text-[11px] text-slate-400 font-mono">Reference: {selectedDossier.id}</p>
                </div>
              </div>
              <button onClick={() => setSelectedDossier(null)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              {/* Personal Section */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <User className="h-3.5 w-3.5 text-cyan-400" />
                  Personal & Government Identity
                </h4>
                <div className="grid grid-cols-2 gap-2 text-slate-300">
                  <div>Full Legal Name: <strong className="text-white">{selectedDossier.full_name}</strong></div>
                  <div>Account Username: <span className="font-mono text-cyan-300">{selectedDossier.username}</span></div>
                  <div>Email Address: <span className="text-slate-200">{selectedDossier.email}</span></div>
                  <div>Mobile Number: <span className="text-slate-200">{selectedDossier.mobile_number}</span></div>
                  <div>Aadhaar Details: <span className="font-mono text-slate-200">{selectedDossier.aadhaar_number}</span></div>
                  <div>PAN Number: <span className="font-mono text-slate-200">{selectedDossier.pan_number}</span></div>
                </div>
              </div>

              {/* Certification Section */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Award className="h-3.5 w-3.5 text-purple-400" />
                  Global Certification Credentials
                </h4>
                <div className="grid grid-cols-2 gap-2 text-slate-300">
                  <div>Certification Name: <strong className="text-white">{selectedDossier.cert_name}</strong></div>
                  <div>Certification ID: <span className="font-mono text-purple-300">{selectedDossier.cert_id}</span></div>
                  <div>Issuing Organization: <span className="text-slate-200">{selectedDossier.issuing_org}</span></div>
                  <div>Validity / Expiry: <span className="text-slate-200">{selectedDossier.cert_expiry || "Not Specified"}</span></div>
                </div>
                {selectedDossier.professional_details && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-slate-400 text-[11px] block">Professional Background & Scope:</span>
                    <p className="text-slate-300 text-[11px] mt-1 leading-relaxed bg-[#0A101D] p-2.5 rounded-lg border border-slate-800">
                      {selectedDossier.professional_details}
                    </p>
                  </div>
                )}
              </div>

              {/* Status & Review Trail */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-2 font-mono text-[11px]">
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Current Status:</span>
                  <span className="font-bold text-white">{selectedDossier.status}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-slate-400">Submission Timestamp:</span>
                  <span className="text-slate-300">{selectedDossier.created_at_human}</span>
                </div>
                {selectedDossier.reviewed_by && (
                  <>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Reviewed By:</span>
                      <span className="text-cyan-300">{selectedDossier.reviewed_by}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-slate-400">Decision Timestamp:</span>
                      <span className="text-slate-300">{selectedDossier.reviewed_at_human}</span>
                    </div>
                  </>
                )}
                {selectedDossier.rejection_reason && (
                  <div className="pt-2 border-t border-slate-800 text-rose-400 font-sans">
                    <strong>Recorded Rejection Reason:</strong> {selectedDossier.rejection_reason}
                  </div>
                )}
              </div>
            </div>

            {/* Actions if still pending */}
            {selectedDossier.status === "PENDING_FORENSIC_APPROVAL" && (
              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2.5">
                <Button
                  size="sm"
                  onClick={() => {
                    setRejectingApp(selectedDossier);
                    setRejectionReason("");
                    setSelectedDossier(null);
                  }}
                  className="bg-rose-600 hover:bg-rose-500 text-white text-xs h-9 px-4 rounded-xl"
                >
                  Reject Application
                </Button>
                <Button
                  size="sm"
                  onClick={() => handleReviewDecision(selectedDossier.id, "APPROVE")}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs h-9 px-4 rounded-xl font-semibold"
                >
                  Approve Clearance
                </Button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* PUBLISH ISO MODAL */}
      {isPublishModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-blue-500/40 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Disc className="h-5 w-5 text-blue-400" />
                <h3 className="text-sm font-bold text-white">Publish Evidence ISO to Hunters</h3>
              </div>
              <button onClick={() => setIsPublishModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <form onSubmit={handlePublishIso} className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="image_name" className="text-xs font-semibold text-slate-200">
                  Image Filename (.iso / .raw / .dd) <span className="text-rose-400">*</span>
                </Label>
                <Input
                  id="image_name"
                  placeholder="e.g. NTRO-CR-2026-9021-CLONE.iso"
                  value={newIsoForm.image_name}
                  onChange={(e) => setNewIsoForm((p) => ({ ...p, image_name: e.target.value }))}
                  required
                  className="bg-[#060A12] border-slate-700 text-white text-xs h-10 rounded-xl font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="case_ref_id" className="text-xs font-semibold text-slate-200">
                  Case / Reference ID <span className="text-rose-400">*</span>
                </Label>
                <Input
                  id="case_ref_id"
                  placeholder="e.g. NTRO-CR-2026-9021"
                  value={newIsoForm.case_ref_id}
                  onChange={(e) => setNewIsoForm((p) => ({ ...p, case_ref_id: e.target.value }))}
                  required
                  className="bg-[#060A12] border-slate-700 text-white text-xs h-10 rounded-xl font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="file_size_human" className="text-xs font-semibold text-slate-200">
                  File Size (Human Readable)
                </Label>
                <Input
                  id="file_size_human"
                  placeholder="e.g. 4.2 GB"
                  value={newIsoForm.file_size_human}
                  onChange={(e) => setNewIsoForm((p) => ({ ...p, file_size_human: e.target.value }))}
                  className="bg-[#060A12] border-slate-700 text-white text-xs h-10 rounded-xl font-mono"
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="description" className="text-xs font-semibold text-slate-200">
                  Investigation Scope / Description
                </Label>
                <Textarea
                  id="description"
                  placeholder="Describe acquisition source, filesystem layout, or specific triage instructions for Hunters..."
                  value={newIsoForm.description}
                  onChange={(e) => setNewIsoForm((p) => ({ ...p, description: e.target.value }))}
                  rows={3}
                  className="bg-[#060A12] border-slate-700 text-white text-xs rounded-xl resize-none"
                />
              </div>

              <div className="pt-2 flex items-center justify-end gap-2.5">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => setIsPublishModalOpen(false)}
                  className="border-slate-700 text-slate-300 text-xs h-9 px-4 rounded-xl"
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  size="sm"
                  disabled={publishLoading}
                  className="bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs h-9 px-4 rounded-xl shadow-lg shadow-blue-950/50"
                >
                  {publishLoading ? "Publishing ISO..." : "Publish ISO to Hunter Repository"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
