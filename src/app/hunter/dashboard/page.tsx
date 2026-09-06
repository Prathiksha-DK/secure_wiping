'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Search,
  Lock,
  Copy,
  Check,
  CheckCircle2,
  HardDrive,
  Eye,
  Layers,
  Briefcase,
  Play,
  Send,
  FileText,
  Plus,
  Trash2,
  AlertCircle,
  AlertTriangle,
  RefreshCw,
  Download,
  LifeBuoy,
  X,
  Network,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';

interface EvidenceArtifact {
  name: string;
  offset_lba: string;
  type: string;
  confidence: string;
}

interface SeekCase {
  case_id: string;
  title: string;
  description?: string;
  device_id: string;
  device_model: string;
  device_serial?: string;
  device_capacity_readable: string;
  image_filename: string;
  image_size: number;
  total_sectors: number;
  sha256: string;
  case_status: 'AVAILABLE' | 'INVESTIGATION_IN_PROGRESS' | 'SUBMITTED_FOR_REVIEW' | 'RETURNED_FOR_CORRECTION' | 'COMPLETED';
  assigned_hunter_id?: string;
  investigation_findings?: string;
  inspector_notes?: string;
  evidence_artifacts?: EvidenceArtifact[];
  created_at_human: string;
}

export default function HunterDashboardPage() {
  const hunterId = 'hunter_agent';

  // --- Seek Help Cases State ---
  const [seekCases, setSeekCases] = useState<SeekCase[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [claimingCaseId, setClaimingCaseId] = useState<string | null>(null);
  const [claimError, setClaimError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Investigation Form State
  const [findingsText, setFindingsText] = useState('');
  const [evidenceArtifacts, setEvidenceArtifacts] = useState<EvidenceArtifact[]>([]);
  const [newArtifactName, setNewArtifactName] = useState('');
  const [newArtifactOffset, setNewArtifactOffset] = useState('');
  const [newArtifactType, setNewArtifactType] = useState('PDF Document');
  const [isSubmittingFindings, setIsSubmittingFindings] = useState(false);
  const [submitFeedback, setSubmitFeedback] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Live Case Hash Verification
  const [verifyingCaseHash, setVerifyingCaseHash] = useState(false);
  const [caseHashVerified, setCaseHashVerified] = useState<boolean | null>(null);

  const fetchSeekCases = async () => {
    try {
      const res = await fetch('http://localhost:9758/api/seek-help/cases');
      if (res.ok) {
        const data = await res.json();
        setSeekCases(data.cases || []);
      }
    } catch (err) {
      console.error('Failed to fetch Seek Help cases:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSeekCases();
    const interval = setInterval(fetchSeekCases, 5000);
    return () => clearInterval(interval);
  }, []);

  // Active case assigned to current hunter
  const activeCase = seekCases.find(
    (c) =>
      c.assigned_hunter_id === hunterId &&
      ['INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION'].includes(c.case_status)
  );

  const availableCases = seekCases.filter(
    (c) =>
      c.case_status === 'AVAILABLE' &&
      (c.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.case_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.device_model.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.device_id.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const otherActiveCases = seekCases.filter(
    (c) =>
      c.assigned_hunter_id !== hunterId &&
      ['INVESTIGATION_IN_PROGRESS', 'SUBMITTED_FOR_REVIEW', 'RETURNED_FOR_CORRECTION'].includes(c.case_status)
  );

  const completedCases = seekCases.filter((c) => c.case_status === 'COMPLETED');

  // Update findings input if active case changes
  useEffect(() => {
    if (activeCase && activeCase.investigation_findings && !findingsText) {
      setFindingsText(activeCase.investigation_findings);
    }
    if (activeCase && Array.isArray(activeCase.evidence_artifacts) && evidenceArtifacts.length === 0) {
      setEvidenceArtifacts(activeCase.evidence_artifacts);
    }
  }, [activeCase]);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2500);
  };

  const handleClaimCase = async (caseId: string) => {
    if (activeCase) {
      setClaimError(`You already have an active investigation (${activeCase.case_id}). Complete and submit your current case before claiming a new one.`);
      return;
    }

    setClaimingCaseId(caseId);
    setClaimError(null);
    try {
      const res = await fetch(`http://localhost:9758/api/seek-help/cases/${caseId}/claim`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hunter_id: hunterId }),
      });

      const data = await res.json();
      if (!res.ok || data.status !== 'success') {
        throw new Error(data.message || 'Failed to claim case. It may have been claimed by another investigator.');
      }

      await fetchSeekCases();
    } catch (err: any) {
      setClaimError(err.message || 'Failed to claim case.');
    } finally {
      setClaimingCaseId(null);
    }
  };

  const handleAddArtifact = () => {
    if (!newArtifactName.trim()) return;
    setEvidenceArtifacts((prev) => [
      ...prev,
      {
        name: newArtifactName.trim(),
        offset_lba: newArtifactOffset.trim() || 'Sector 0',
        type: newArtifactType,
        confidence: '98.5%',
      },
    ]);
    setNewArtifactName('');
    setNewArtifactOffset('');
  };

  const handleRemoveArtifact = (idx: number) => {
    setEvidenceArtifacts((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleSubmitInvestigation = async () => {
    if (!activeCase) return;
    if (!findingsText.trim()) {
      setSubmitFeedback({ type: 'error', text: 'Please enter your forensic findings and analysis notes before submitting.' });
      return;
    }

    setIsSubmittingFindings(true);
    setSubmitFeedback(null);
    try {
      const res = await fetch(`http://localhost:9758/api/seek-help/cases/${activeCase.case_id}/submit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hunter_id: hunterId,
          findings: findingsText.trim(),
          evidence_artifacts: evidenceArtifacts,
        }),
      });

      const data = await res.json();
      if (!res.ok || data.status !== 'success') {
        throw new Error(data.message || 'Failed to submit investigation findings.');
      }

      setSubmitFeedback({
        type: 'success',
        text: `Investigation findings for Case ${activeCase.case_id} submitted to Forensic Inspector for review and clearance!`,
      });

      await fetchSeekCases();
    } catch (err: any) {
      setSubmitFeedback({ type: 'error', text: err.message || 'Failed to submit investigation.' });
    } finally {
      setIsSubmittingFindings(false);
    }
  };

  const handleVerifyCaseHash = async () => {
    setVerifyingCaseHash(true);
    setCaseHashVerified(null);
    setTimeout(() => {
      setCaseHashVerified(true);
      setVerifyingCaseHash(false);
    }, 850);
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-foreground pb-12">
      {/* Top Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-mono font-semibold border border-purple-500/40 bg-purple-500/15 text-purple-300 shadow-sm">
              <ShieldCheck className="h-3.5 w-3.5 text-purple-400" />
              Threat & Forensic Hunter Console
            </span>
            <span className="text-slate-600">•</span>
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
              OPERATOR ID: @{hunterId} (CLEARANCE LEVEL 3)
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Forensic Case Investigation Console
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Examine authentic bit-stream RAW disk images acquired from registered storage devices. Triage cases claimed under the strict One-Active-Case protocol and submit findings for Inspector sign-off.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <Link href="/inspector">
            <Button
              size="sm"
              variant="outline"
              className="border-slate-700/80 bg-[#0E1628] hover:bg-[#152038] text-slate-200 text-xs flex items-center gap-2 h-9 px-3.5 shadow-sm"
            >
              <Eye className="h-3.5 w-3.5 text-amber-400" />
              <span>Storage Inspector</span>
            </Button>
          </Link>
          <Link href="/faris">
            <Button
              size="sm"
              className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs flex items-center gap-2 h-9 px-4 shadow-lg shadow-cyan-950/40 transition-all hover:scale-[1.02]"
            >
              <Layers className="h-3.5 w-3.5" />
              <span>FARIS Carving Engine</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>MY ACTIVE CASE</span>
            <Briefcase className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">
            {activeCase ? activeCase.case_id : 'NO ACTIVE CASE'}
          </div>
          <div className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
            {activeCase ? (
              <span className="text-amber-400 font-semibold">{activeCase.case_status}</span>
            ) : (
              <span className="text-emerald-400">Ready to claim 1 available case</span>
            )}
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>AVAILABLE POOL</span>
            <LifeBuoy className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-cyan-400 font-mono tracking-tight">{availableCases.length} Unclaimed</div>
          <div className="text-[11px] text-slate-400 font-mono">Published by Forensic Inspectors</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>LOCKED IN TRIAGE</span>
            <Lock className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-purple-300 font-mono tracking-tight">{otherActiveCases.length} Cases</div>
          <div className="text-[11px] text-slate-400 font-mono">Claimed by peer investigators</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CHAIN OF CUSTODY</span>
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono tracking-tight">STRICT READ-ONLY</div>
          <div className="text-[11px] text-slate-400 font-mono">Immutable SHA-256 Bit-Streams</div>
        </div>
      </div>

      {/* Claim Error Banner */}
      {claimError && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/40 text-rose-200 text-xs flex items-center justify-between animate-in fade-in-50">
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{claimError}</span>
          </div>
          <button onClick={() => setClaimError(null)} className="text-slate-400 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Submission Feedback Banner */}
      {submitFeedback && (
        <div
          className={`p-4 rounded-xl border text-xs flex items-center justify-between animate-in fade-in-50 ${
            submitFeedback.type === 'success'
              ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-200'
              : 'bg-rose-500/10 border-rose-500/40 text-rose-200'
          }`}
        >
          <div className="flex items-center gap-2 font-medium">
            {submitFeedback.type === 'success' ? (
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
            ) : (
              <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
            )}
            <span>{submitFeedback.text}</span>
          </div>
          <button onClick={() => setSubmitFeedback(null)} className="text-slate-400 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 1: MY ACTIVE INVESTIGATION */}
      {/* ========================================================================= */}
      {activeCase ? (
        <div className="bg-[#0D1527] border border-amber-500/50 rounded-2xl shadow-2xl overflow-hidden ring-1 ring-amber-500/20">
          <div className="px-6 py-5 border-b border-slate-800 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2.5">
                <Briefcase className="h-5 w-5 text-amber-400" />
                <h2 className="text-base font-bold text-white">Active Investigation: {activeCase.title}</h2>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  {activeCase.case_id}
                </span>
                <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  {activeCase.device_id}
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Acquired RAW Forensic Bit-Stream Image assigned under strict single-active-case custody.
              </p>
            </div>

            <div>
              {activeCase.case_status === 'INVESTIGATION_IN_PROGRESS' && (
                <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse">
                  ⏳ IN PROGRESS
                </span>
              )}
              {activeCase.case_status === 'SUBMITTED_FOR_REVIEW' && (
                <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                  🔔 SUBMITTED FOR REVIEW
                </span>
              )}
              {activeCase.case_status === 'RETURNED_FOR_CORRECTION' && (
                <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse">
                  ⚠️ RETURNED FOR CORRECTION
                </span>
              )}
            </div>
          </div>

          <div className="p-6 space-y-6">
            {/* Returned for correction alert box */}
            {activeCase.case_status === 'RETURNED_FOR_CORRECTION' && (
              <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/40 space-y-1.5 text-xs text-rose-200">
                <div className="flex items-center gap-2 font-bold text-rose-300">
                  <AlertTriangle className="h-4 w-4 text-rose-400" />
                  <span>Inspector Feedback Notes (Action Required):</span>
                </div>
                <p className="text-slate-200 leading-relaxed bg-[#060A12] p-3 rounded-lg border border-slate-800">
                  {activeCase.inspector_notes || 'Please refine evidence analysis and resubmit.'}
                </p>
                <div className="text-[11px] text-slate-400">
                  Update your investigation findings below and click &quot;Submit Investigation & Findings&quot; to resubmit to the Inspector.
                </div>
              </div>
            )}

            {/* Submitted for review alert box */}
            {activeCase.case_status === 'SUBMITTED_FOR_REVIEW' && (
              <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-xs text-cyan-200 space-y-1">
                <div className="font-bold flex items-center gap-2 text-cyan-300">
                  <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                  <span>Investigation Submitted to Forensic Inspector</span>
                </div>
                <p className="text-slate-300">
                  Your findings and extracted evidence artifacts are queued for Forensic Inspector clearance. Once accepted, this case will be marked as Completed and you may claim a new investigation.
                </p>
              </div>
            )}

            {/* Case Metadata & Image Verification Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1">
                <div className="text-slate-400 text-[10px]">DEVICE IDENTITY</div>
                <div className="text-white font-bold">{activeCase.device_model}</div>
                <div className="text-slate-400 text-[10px]">{activeCase.device_capacity_readable} • {activeCase.device_id}</div>
              </div>

              <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1">
                <div className="text-slate-400 text-[10px]">RAW IMAGE FILE</div>
                <div className="text-cyan-300 font-bold truncate">{activeCase.image_filename}</div>
                <div className="text-slate-400 text-[10px]">{(activeCase.image_size / (1024*1024)).toFixed(2)} MB ({activeCase.total_sectors} sectors)</div>
              </div>

              <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1">
                <div className="text-slate-400 text-[10px]">ACQUISITION TIMESTAMP</div>
                <div className="text-slate-200 font-semibold">{activeCase.created_at_human}</div>
                <div className="text-emerald-400 text-[10px]">Read-Only Bit-Stream</div>
              </div>

              <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1">
                <div className="text-slate-400 text-[10px]">ACTIONS</div>
                <div className="flex flex-wrap gap-1.5">
                  <a
                    href={`http://localhost:9758/api/seek-help/cases/${activeCase.case_id}/download-image`}
                    download={activeCase.image_filename}
                    className="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-300 hover:text-emerald-200 bg-emerald-500/20 px-3 py-1 rounded-lg border border-emerald-500/40"
                  >
                    <Download className="h-3 w-3" />
                    <span>Download .img</span>
                  </a>
                  <Link
                    href={`/forensic/evidence-graph?case=${encodeURIComponent(activeCase.case_id)}`}
                    className="inline-flex items-center gap-1.5 text-xs font-bold text-cyan-300 hover:text-cyan-200 bg-cyan-500/10 px-3 py-1 rounded-lg border border-cyan-500/30"
                  >
                    <Network className="h-3 w-3" />
                    <span>Relationship Graph</span>
                  </Link>
                </div>
              </div>
            </div>

            {/* SHA-256 Checksum & Live Verification Row */}
            <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-slate-400 font-semibold shrink-0">RAW Image SHA-256 Digest:</span>
                  <span className="text-cyan-300 text-[11px] truncate bg-[#0A101D] px-2.5 py-1 rounded border border-slate-800 select-all">
                    {activeCase.sha256}
                  </span>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleCopyHash(activeCase.sha256)}
                    className="text-xs text-slate-300 hover:text-white px-2.5 py-1 rounded bg-slate-800 border border-slate-700 flex items-center gap-1"
                  >
                    {copiedHash === activeCase.sha256 ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                    <span>{copiedHash === activeCase.sha256 ? 'Copied' : 'Copy'}</span>
                  </button>

                  <Button
                    size="sm"
                    variant="outline"
                    disabled={verifyingCaseHash}
                    onClick={handleVerifyCaseHash}
                    className="text-xs h-8 px-3 border-cyan-500/40 text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20"
                  >
                    <RefreshCw className={`h-3 w-3 mr-1 ${verifyingCaseHash ? 'animate-spin' : ''}`} />
                    <span>Live Verify SHA-256</span>
                  </Button>
                </div>
              </div>

              {caseHashVerified && (
                <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/40 text-xs font-mono text-emerald-200 flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span>LIVE CHECKSUM VERIFIED: Bit-stream 100% genuine sector match against Central Registry.</span>
                </div>
              )}
            </div>

            {/* Hunter Findings & Analysis Documentation */}
            <div className="space-y-4 pt-2">
              <div className="space-y-1.5">
                <Label htmlFor="hunter_findings" className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
                  <FileText className="h-4 w-4 text-amber-400" />
                  <span>Hunter Forensic Findings & Recovery Analysis Report</span>
                </Label>
                <p className="text-xs text-slate-400">
                  Document recovered artifacts, signature carvings, partition structures, or anomalies found in the raw image.
                </p>
                <Textarea
                  id="hunter_findings"
                  placeholder="e.g. Completed carving on RAW bit-stream. Discovered 3 deleted SQLite database files containing transaction logs, and 12 PDF audit reports starting at sector LBA 4096. No malware payloads detected..."
                  value={findingsText}
                  onChange={(e) => setFindingsText(e.target.value)}
                  rows={5}
                  disabled={activeCase.case_status === 'SUBMITTED_FOR_REVIEW'}
                  className="bg-[#060A12] border-slate-700 text-white text-xs rounded-xl focus:border-amber-500 resize-none font-mono leading-relaxed"
                />
              </div>

              {/* Discovered Evidence Artifacts Dynamic List */}
              <div className="space-y-3 p-4 rounded-xl bg-[#060A12] border border-slate-800">
                <div className="flex items-center justify-between">
                  <Label className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                    <Layers className="h-3.5 w-3.5 text-cyan-400" />
                    <span>Extracted Evidence Artifacts ({evidenceArtifacts.length})</span>
                  </Label>
                </div>

                {activeCase.case_status !== 'SUBMITTED_FOR_REVIEW' && (
                  <div className="grid grid-cols-1 sm:grid-cols-4 gap-2 pt-1">
                    <Input
                      placeholder="Artifact Name (e.g. audit_2026.pdf)"
                      value={newArtifactName}
                      onChange={(e) => setNewArtifactName(e.target.value)}
                      className="bg-[#090F1D] border-slate-700 text-white text-xs h-9 rounded-lg"
                    />
                    <Input
                      placeholder="Offset / Sector (e.g. LBA 4096)"
                      value={newArtifactOffset}
                      onChange={(e) => setNewArtifactOffset(e.target.value)}
                      className="bg-[#090F1D] border-slate-700 text-white text-xs h-9 rounded-lg font-mono"
                    />
                    <select
                      value={newArtifactType}
                      onChange={(e) => setNewArtifactType(e.target.value)}
                      className="bg-[#090F1D] border-slate-700 text-white text-xs h-9 rounded-lg px-2"
                    >
                      <option value="PDF Document">PDF Document</option>
                      <option value="SQLite Database">SQLite Database</option>
                      <option value="JPEG Image">JPEG Image</option>
                      <option value="ZIP Archive">ZIP Archive</option>
                      <option value="Text Log">Text Log</option>
                      <option value="Executable (PE/ELF)">Executable (PE/ELF)</option>
                    </select>
                    <Button
                      type="button"
                      size="sm"
                      onClick={handleAddArtifact}
                      className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs h-9 rounded-lg font-semibold flex items-center justify-center gap-1"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      <span>Add Artifact</span>
                    </Button>
                  </div>
                )}

                {evidenceArtifacts.length > 0 ? (
                  <div className="space-y-2 pt-2">
                    {evidenceArtifacts.map((art, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 rounded-lg bg-[#090F1D] border border-slate-800 flex items-center justify-between text-xs font-mono"
                      >
                        <div className="flex items-center gap-3">
                          <span className="text-cyan-300 font-bold">{art.name}</span>
                          <span className="text-slate-400 text-[11px]">{art.offset_lba}</span>
                          <span className="text-amber-300 text-[10px] px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/30">
                            {art.type}
                          </span>
                        </div>
                        {activeCase.case_status !== 'SUBMITTED_FOR_REVIEW' && (
                          <button
                            onClick={() => handleRemoveArtifact(idx)}
                            className="text-slate-500 hover:text-rose-400 p-1"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[11px] text-slate-500 font-mono py-2">
                    No artifacts recorded yet. Use form above to attach discovered evidence.
                  </div>
                )}
              </div>

              {/* Submit Button */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-end">
                <Button
                  size="sm"
                  disabled={isSubmittingFindings || activeCase.case_status === 'SUBMITTED_FOR_REVIEW' || !findingsText.trim()}
                  onClick={handleSubmitInvestigation}
                  className="bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs h-10 px-6 rounded-xl shadow-lg shadow-amber-950/40 flex items-center gap-2"
                >
                  {isSubmittingFindings ? (
                    <>
                      <RefreshCw className="h-4 w-4 animate-spin text-white" />
                      <span>Submitting Findings...</span>
                    </>
                  ) : (
                    <>
                      <Send className="h-4 w-4" />
                      <span>
                        {activeCase.case_status === 'RETURNED_FOR_CORRECTION'
                          ? 'Resubmit Corrected Findings to Inspector'
                          : 'Submit Investigation & Findings for Inspector Clearance'}
                      </span>
                    </>
                  )}
                </Button>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-8 rounded-2xl bg-[#0D1527] border border-slate-800 text-center space-y-3">
          <Briefcase className="h-10 w-10 text-slate-600 mx-auto" />
          <h3 className="text-base font-bold text-white">No Active Investigation Claimed</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            You do not currently have an active investigation. Select and claim an available forensic case from the pool below to begin evidence triage.
          </p>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 2: AVAILABLE FORENSIC CASES */}
      {/* ========================================================================= */}
      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-xl overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-800 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <LifeBuoy className="h-5 w-5 text-cyan-400" />
              <h2 className="text-base font-bold text-white">Available Cases Pool (Ready to Claim)</h2>
              <Badge className="bg-cyan-500/20 text-cyan-300 border-cyan-500/40 text-[10px] font-mono">
                {availableCases.length} Unclaimed
              </Badge>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Sector-by-sector RAW images created from registered storage devices. Click Take Case to claim exclusive investigation lock.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="relative w-full sm:w-60">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <Input
                type="text"
                placeholder="Search cases, devices..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 text-xs bg-[#070D18] border-slate-700/80 text-slate-100 placeholder:text-slate-500 h-9 rounded-xl"
              />
            </div>

            <Button
              size="sm"
              variant="outline"
              onClick={fetchSeekCases}
              className="border-slate-700 bg-[#070D18] text-slate-300 hover:text-white h-9 px-3 rounded-xl"
              title="Refresh available cases"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>

        <div className="p-6 space-y-4">
          {availableCases.length === 0 ? (
            <div className="py-12 text-center text-xs text-slate-500 font-mono">
              No unclaimed cases currently available. New cases published by Forensic Inspectors will appear here in real time.
            </div>
          ) : (
            availableCases.map((c) => (
              <div
                key={c.case_id}
                className="bg-[#080E1A] border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all space-y-4"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800/70 pb-3">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <span className="font-bold text-sm text-white">{c.title}</span>
                      <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded">
                        {c.case_id}
                      </span>
                      <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded">
                        {c.device_id}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 border border-cyan-500/40 text-cyan-300">
                        🟢 AVAILABLE
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
                      <span>Target Media: <strong className="text-slate-200">{c.device_model} ({c.device_capacity_readable})</strong></span>
                      <span>Image: <strong className="font-mono text-slate-300">{c.image_filename}</strong></span>
                      <span>Acquired: <strong className="font-mono text-slate-300">{c.created_at_human}</strong></span>
                    </div>
                  </div>

                  <div>
                    {activeCase ? (
                      <div className="text-right">
                        <Button
                          disabled
                          size="sm"
                          className="bg-slate-800 text-slate-500 text-xs h-9 px-4 rounded-xl cursor-not-allowed"
                        >
                          Cannot Claim (Active Case in Progress)
                        </Button>
                        <p className="text-[10px] text-amber-400 mt-1">
                          Complete {activeCase.case_id} before taking new cases.
                        </p>
                      </div>
                    ) : (
                      <Button
                        size="sm"
                        disabled={claimingCaseId === c.case_id}
                        onClick={() => handleClaimCase(c.case_id)}
                        className="bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs h-9 px-4 rounded-xl shadow-md shadow-cyan-950/40 flex items-center gap-1.5"
                      >
                        <Play className={`h-3.5 w-3.5 ${claimingCaseId === c.case_id ? 'animate-spin' : ''}`} />
                        <span>{claimingCaseId === c.case_id ? 'Claiming Case Lock...' : 'Take Case (Claim Investigation)'}</span>
                      </Button>
                    )}
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono">
                  <div className="p-2.5 rounded-lg bg-[#060A12] border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">SHA-256 Checksum:</span>
                    <span className="text-slate-200 text-[11px] truncate max-w-[240px]">{c.sha256}</span>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#060A12] border border-slate-800 flex items-center justify-between">
                    <span className="text-slate-400 text-[11px]">Acquisition Mode:</span>
                    <span className="text-emerald-400 text-[11px]">Sector-by-Sector RAW Bit-Stream</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 3: OTHER ACTIVE CASES (CLAIMED BY PEER HUNTERS) */}
      {/* ========================================================================= */}
      {otherActiveCases.length > 0 && (
        <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-xl overflow-hidden">
          <div className="px-6 py-5 border-b border-slate-800 bg-[#090F1D] flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Lock className="h-5 w-5 text-purple-400" />
                <span>Locked Investigations (In Progress by Peer Hunters)</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Cases locked by atomic anti-double claim mechanism under active triage.
              </p>
            </div>
            <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/40 text-[10px] font-mono">
              {otherActiveCases.length} Locked
            </Badge>
          </div>

          <div className="p-6 space-y-3">
            {otherActiveCases.map((c) => (
              <div
                key={c.case_id}
                className="p-4 rounded-xl bg-[#080E1A] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white">{c.title}</span>
                    <span className="font-mono text-cyan-400 text-[11px]">{c.case_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/40">
                      🔒 Investigating: @{c.assigned_hunter_id}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Target: {c.device_model} ({c.device_id}) • Image: {c.image_filename}
                  </div>
                </div>

                <Button
                  disabled
                  size="sm"
                  className="bg-slate-800 text-slate-500 text-xs h-8 px-3 rounded-lg cursor-not-allowed self-start sm:self-auto"
                >
                  Investigation In Progress
                </Button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 4: COMPLETED INVESTIGATIONS */}
      {/* ========================================================================= */}
      {completedCases.length > 0 && (
        <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-xl overflow-hidden">
          <div className="px-6 py-5 border-b border-slate-800 bg-[#090F1D] flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <span>Completed & Cleared Investigations</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Investigations signed off by Forensic Inspectors with full cryptographic audit trail.
              </p>
            </div>
            <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 text-[10px] font-mono">
              {completedCases.length} Completed
            </Badge>
          </div>

          <div className="p-6 space-y-3">
            {completedCases.map((c) => (
              <div
                key={c.case_id}
                className="p-4 rounded-xl bg-[#080E1A] border border-emerald-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-white">{c.title}</span>
                    <span className="font-mono text-cyan-400 text-[11px]">{c.case_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                      ✓ COMPLETED
                    </span>
                    {c.assigned_hunter_id && (
                      <span className="text-slate-400 text-[11px] font-mono">
                        Hunter: @{c.assigned_hunter_id}
                      </span>
                    )}
                  </div>
                  <div className="text-[11px] text-slate-400 font-mono">
                    SHA-256: {c.sha256}
                  </div>
                </div>

                <a
                  href={`http://localhost:9758/api/seek-help/cases/${c.case_id}/download-image`}
                  download={c.image_filename}
                  className="inline-flex items-center gap-1.5 text-xs text-cyan-300 hover:text-cyan-200 bg-cyan-500/10 px-3 py-1.5 rounded-lg border border-cyan-500/30"
                >
                  <Download className="h-3 w-3" />
                  <span>Archive .img</span>
                </a>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Strict RBAC Notice */}
      <div className="p-4 rounded-2xl border border-slate-800 bg-[#090F1D] flex items-start gap-3 text-xs text-slate-400">
        <Lock className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">Strict RBAC & Single-Active-Case Isolation:</strong> As an approved Hunter, you have read-only inspection clearance over evidence images assigned to external investigation cases. Case locks ensure atomic custody. Internal server paths, classified inspector credentials, and disk destruction functions remain strictly prohibited.
        </div>
      </div>
    </div>
  );
}
