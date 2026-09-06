"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  LifeBuoy,
  Briefcase,
  HardDrive,
  Lock,
  RefreshCw,
  Play,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Download,
  Eye,
  ArrowLeft,
  Copy,
  Check,
  X,
  Layers,
  Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import CentralDeviceRegistryCard from "@/components/central-device-registry-card";
import RegisteredDevicesModal from "@/components/registered-devices-modal";

export default function ForensicSeekHelpPage() {
  const [registeredModalOpen, setRegisteredModalOpen] = useState(false);
  const [seekConnectedDevices, setSeekConnectedDevices] = useState<any[]>([]);
  const [selectedSeekDevice, setSelectedSeekDevice] = useState<any | null>(null);
  const [seekCaseTitle, setSeekCaseTitle] = useState("");
  const [seekAcquiring, setSeekAcquiring] = useState(false);
  const [seekAcqResult, setSeekAcqResult] = useState<any | null>(null);
  const [seekAcqError, setSeekAcqError] = useState<string | null>(null);
  const [seekHelpCases, setSeekHelpCases] = useState<any[]>([]);
  const [seekHelpFilter, setSeekHelpFilter] = useState<"ALL" | "SUBMITTED_FOR_REVIEW" | "INVESTIGATION_IN_PROGRESS" | "AVAILABLE" | "COMPLETED">("ALL");
  const [reviewingCase, setReviewingCase] = useState<any | null>(null);
  const [reviewNotes, setReviewNotes] = useState("");
  const [reviewDecisionLoading, setReviewDecisionLoading] = useState(false);
  const [reviewFeedbackMsg, setReviewFeedbackMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [copiedDigest, setCopiedDigest] = useState(false);

  const fetchSeekHelpData = async () => {
    try {
      const devRes = await fetch("http://localhost:9758/api/devices/current");
      if (devRes.ok) {
        const devData = await devRes.json();
        const devs: any[] = devData.connected_devices || [];
        setSeekConnectedDevices(devs);
        
        setSelectedSeekDevice((prev: any) => {
          if (prev) {
            // Retain user's active selection if device is still connected
            const matched = devs.find((d: any) =>
              (d.device_id && prev.device_id && d.device_id === prev.device_id) ||
              (d.device_fingerprint && prev.device_fingerprint && d.device_fingerprint === prev.device_fingerprint) ||
              (d.os_device_path && prev.os_device_path && d.os_device_path === prev.os_device_path)
            );
            if (matched) return matched;
            // The previously selected device didn't appear in this enumeration snapshot
            // (e.g. the OS transiently fails to enumerate it while it's busy servicing a
            // raw sector-by-sector read during acquisition). Keep the existing selection
            // instead of silently falling back to whatever else is in the list, which can
            // land on the host system drive.
            return prev;
          }
          // Default selection priority: Registered external/USB drive -> Unregistered external drive.
          // Never default to a system/boot drive just because it happens to be the only
          // (or first) entry returned in a given snapshot.
          return (
            devs.find((d: any) => d.is_registered && !d.raw_device?.isSystem && d.os_device_path !== "\\\\.\\PhysicalDrive0") ||
            devs.find((d: any) => !d.raw_device?.isSystem && d.os_device_path !== "\\\\.\\PhysicalDrive0") ||
            null
          );
        });
      }

      const casesRes = await fetch("http://localhost:9758/api/seek-help/cases");
      if (casesRes.ok) {
        const casesData = await casesRes.json();
        setSeekHelpCases(casesData.cases || []);
      }
    } catch (err) {
      console.error("Failed to fetch Seek Help data:", err);
    }
  };

  useEffect(() => {
    fetchSeekHelpData();
    const interval = setInterval(fetchSeekHelpData, 6000);
    return () => clearInterval(interval);
  }, []);

  const handleCopyDigest = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedDigest(true);
    setTimeout(() => setCopiedDigest(false), 2000);
  };

  const handleCreateSeekHelpCase = async () => {
    if (!selectedSeekDevice) return;

    const isSys = selectedSeekDevice.raw_device?.isSystem || selectedSeekDevice.os_device_path === "\\\\.\\PhysicalDrive0";
    if (isSys) {
      setSeekAcqError("Host system drive (PhysicalDrive0) cannot be acquired for investigation. Please select a registered external USB, pendrive, or forensic evidence storage device.");
      return;
    }

    if (!selectedSeekDevice.is_registered) {
      setSeekAcqError("This device must be registered in the Central Device Registry before forensic acquisition.");
      return;
    }

    setSeekAcquiring(true);
    setSeekAcqError(null);
    setSeekAcqResult(null);

    try {
      const payload = {
        device_id: selectedSeekDevice.device_id,
        device_path: selectedSeekDevice.os_device_path || selectedSeekDevice.raw_device?.devicePath || "",
        title: seekCaseTitle.trim() || undefined,
      };

      const res = await fetch("http://localhost:9758/api/seek-help/acquire-and-create-case", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || "Forensic image acquisition failed.");
      }

      setSeekAcqResult(data);
      setSeekCaseTitle("");
      await fetchSeekHelpData();
    } catch (err: any) {
      setSeekAcqError(err.message || "Failed to acquire forensic image.");
    } finally {
      setSeekAcquiring(false);
    }
  };

  const handleInspectorReviewCase = async (caseId: string, decision: "ACCEPT" | "RETURN_FOR_CORRECTION", notesText?: string) => {
    setReviewDecisionLoading(true);
    setReviewFeedbackMsg(null);

    try {
      const res = await fetch(`http://localhost:9758/api/seek-help/cases/${caseId}/review`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision,
          notes: notesText || reviewNotes,
          inspector: "forensic_analyst",
        }),
      });

      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || "Failed to submit inspector review decision.");
      }

      setReviewFeedbackMsg({
        type: "success",
        text: decision === "ACCEPT"
          ? `Case ${caseId} marked as COMPLETED. Assigned hunter released.`
          : `Case ${caseId} returned to hunter for correction with feedback notes.`,
      });

      setReviewingCase(null);
      setReviewNotes("");
      await fetchSeekHelpData();
    } catch (err: any) {
      setReviewFeedbackMsg({ type: "error", text: err.message });
    } finally {
      setReviewDecisionLoading(false);
    }
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
      {/* Top Navigation & Breadcrumb */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800/80 pb-6">
        <div>
          <div className="flex flex-wrap items-center gap-2 mb-2">
            <Link
              href="/forensic/dashboard"
              className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-mono font-semibold border border-slate-700 bg-slate-900/90 text-slate-300 hover:text-white hover:border-slate-600 transition-all"
            >
              <ArrowLeft className="h-3 w-3" />
              <span>Forensic Investigator Dashboard</span>
            </Link>
            <span className="text-slate-600">•</span>
            <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-mono font-semibold border border-amber-500/40 bg-amber-500/15 text-amber-300">
              <LifeBuoy className="h-3.5 w-3.5 text-amber-400" />
              Seek Help Authority
            </span>
            <span className="text-slate-600">•</span>
            <div className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-[11px] text-emerald-400 font-mono shadow-sm">
              <Lock className="h-3 w-3 text-emerald-400" />
              <span>Strict Read-Only Guarantee</span>
            </div>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Seek Help — RAW Forensic Image Acquisition & Investigation Cases
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Select a registered storage media from the Central Device Registry, acquire an authentic sector-by-sector RAW bit-stream (.img), and publish an investigation case for Threat & Forensic Hunters.
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

      {/* Central Device Registry Overview Card */}
      <CentralDeviceRegistryCard currentPersona="forensic" />

      {/* Device Selection & RAW Acquisition Card */}
      <div className="bg-[#0D1527] border border-amber-500/30 rounded-2xl shadow-2xl overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-800/80 bg-[#090F1D] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <LifeBuoy className="h-5 w-5 text-amber-400" />
              <h2 className="text-base font-bold text-white">1. Select Target Media (Central Device Registry Gated)</h2>
              <Badge className="bg-emerald-500/15 text-emerald-300 border-emerald-500/30 text-[10px] font-mono">
                Strict Read-Only Bit-Stream
              </Badge>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Only devices verified in the Central Device Registry can proceed to forensic acquisition. Unregistered devices cannot be imaged.
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            {seekConnectedDevices.filter((d) => d.is_registered).length} of {seekConnectedDevices.length} Connected Media Registered
          </span>
        </div>

        <div className="p-6 space-y-6">
          {/* Connected Devices Grid */}
          {seekConnectedDevices.length === 0 ? (
            <div className="p-6 rounded-xl bg-[#060A12] border border-slate-800 text-center text-xs text-slate-400 font-mono">
              No physical storage devices currently detected on host system.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {seekConnectedDevices.map((dev, idx) => {
                const isSelected = selectedSeekDevice?.device_fingerprint === dev.device_fingerprint ||
                  (selectedSeekDevice?.device_id && selectedSeekDevice.device_id === dev.device_id);
                const isReg = dev.is_registered;
                const isSysDrive = dev.raw_device?.isSystem || dev.os_device_path === "\\\\.\\PhysicalDrive0";

                return (
                  <div
                    key={idx}
                    onClick={() => setSelectedSeekDevice(dev)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? "bg-[#111C33] border-amber-500/70 shadow-lg shadow-amber-950/30 ring-1 ring-amber-500/50"
                        : isSysDrive
                        ? "bg-[#060A12]/60 border-slate-800/80 opacity-75 hover:border-slate-700"
                        : "bg-[#060A12] border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-0.5">
                        <div className="font-bold text-xs text-white truncate max-w-[200px]">
                          {dev.record?.model || dev.detected_metadata?.model || dev.raw_device?.name || "Storage Device"}
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          {dev.record?.capacity_readable || dev.detected_metadata?.capacity_readable || dev.raw_device?.size} • {dev.record?.interface || dev.detected_metadata?.interface || "USB"}
                        </div>
                      </div>
                      {isSysDrive ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
                          SYSTEM DISK
                        </span>
                      ) : isReg ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          ✓ REGISTERED
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                          NOT REGISTERED
                        </span>
                      )}
                    </div>

                    <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                      <span className="text-slate-400">
                        {dev.drive_letters && dev.drive_letters.length > 0 ? `Drive ${dev.drive_letters.join(", ")}` : "Physical"}
                      </span>
                      <span className={isSysDrive ? "text-slate-500" : isReg ? "text-cyan-400 font-bold" : "text-amber-400"}>
                        {isSysDrive ? "System Host" : isReg ? dev.device_id : "Registration Req."}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* Selected Device Details & Acquisition Trigger */}
          {selectedSeekDevice && (
            <div className="p-5 rounded-xl bg-[#060A12] border border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                <div>
                  <div className="text-xs font-bold text-white flex items-center gap-2">
                    <span>Selected Media:</span>
                    <span className="text-amber-300">
                      {selectedSeekDevice.record?.model || selectedSeekDevice.detected_metadata?.model || selectedSeekDevice.raw_device?.name}
                    </span>
                    {(selectedSeekDevice.raw_device?.isSystem || selectedSeekDevice.os_device_path === "\\\\.\\PhysicalDrive0") ? (
                      <Badge className="bg-slate-800 text-slate-300 border-slate-700 text-[10px] font-mono">
                        HOST OS DISK
                      </Badge>
                    ) : selectedSeekDevice.is_registered ? (
                      <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 text-[10px] font-mono">
                        {selectedSeekDevice.device_id}
                      </Badge>
                    ) : (
                      <Badge className="bg-rose-500/20 text-rose-300 border-rose-500/40 text-[10px] font-mono">
                        NOT REGISTERED
                      </Badge>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Hardware Fingerprint: <span className="font-mono text-slate-300">{selectedSeekDevice.device_fingerprint?.substring(0, 32)}...</span>
                  </p>
                </div>

                <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/30">
                  <Lock className="h-3.5 w-3.5" />
                  <span>Non-Destructive Read-Only Acquisition</span>
                </div>
              </div>

              {(selectedSeekDevice.raw_device?.isSystem || selectedSeekDevice.os_device_path === "\\\\.\\PhysicalDrive0") ? (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-amber-300">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    <span>Host System Drive (PhysicalDrive0) — Bit-Stream Prohibited</span>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    The host operating system drive is protected and cannot be acquired in Seek Help. Please select a registered external USB, pendrive, or forensic evidence storage device.
                  </p>
                </div>
              ) : selectedSeekDevice.is_registered ? (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <Label htmlFor="seek_title" className="text-xs font-semibold text-slate-200">
                      Investigation Case Title (Optional)
                    </Label>
                    <Input
                      id="seek_title"
                      placeholder={`e.g. Investigation — ${selectedSeekDevice.record?.model || "Flash Drive"} (${selectedSeekDevice.device_id})`}
                      value={seekCaseTitle}
                      onChange={(e) => setSeekCaseTitle(e.target.value)}
                      className="bg-[#090F1D] border-slate-700 text-white text-xs h-10 rounded-xl"
                    />
                  </div>

                  <Button
                    onClick={handleCreateSeekHelpCase}
                    disabled={seekAcquiring}
                    className="w-full bg-amber-600 hover:bg-amber-500 text-white font-semibold text-xs h-11 rounded-xl shadow-lg shadow-amber-950/40 flex items-center justify-center gap-2"
                  >
                    {seekAcquiring ? (
                      <>
                        <RefreshCw className="h-4 w-4 animate-spin text-white" />
                        <span>Acquiring Sector-by-Sector RAW Forensic Image & Computing SHA-256...</span>
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4" />
                        <span>Create RAW Forensic Image (.img) & Launch Investigation Case</span>
                      </>
                    )}
                  </Button>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 space-y-2">
                  <div className="flex items-center gap-2 text-xs font-bold text-amber-300">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    <span>Registration: NOT REGISTERED</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    Forensic acquisition is unavailable. Please register this device using the existing Central Device Registry workflow.
                  </p>
                  <div className="pt-2 flex items-center justify-between">
                    <span className="text-[11px] text-slate-400">Register device via Central Device Registry or Wiping/FARIS workflow.</span>
                    <Button
                      disabled
                      size="sm"
                      className="bg-slate-800 text-slate-500 text-xs h-8 px-4 rounded-lg cursor-not-allowed"
                    >
                      Cannot Create Image
                    </Button>
                  </div>
                </div>
              )}

              {/* Acquisition Success Feedback */}
              {seekAcqResult && (
                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs space-y-2 animate-in fade-in-50">
                  <div className="flex items-center justify-between text-emerald-300 font-bold">
                    <span className="flex items-center gap-1.5">
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                      <span>Forensic RAW Image Successfully Acquired & Case Published!</span>
                    </span>
                    <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-emerald-500/20 border border-emerald-500/40">
                      {seekAcqResult.case_id}
                    </span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300 font-mono text-[11px] pt-1">
                    <div>Image Filename: <span className="text-white">{seekAcqResult.image_filename}</span></div>
                    <div>Total Size: <span className="text-white">{(seekAcqResult.image_size / (1024*1024)).toFixed(2)} MB ({seekAcqResult.total_sectors} sectors)</span></div>
                    <div className="sm:col-span-2 flex items-center justify-between gap-2 bg-[#090F1D] p-2 rounded border border-slate-800">
                      <span className="text-slate-400">SHA-256 Digest:</span>
                      <span className="text-cyan-300 truncate">{seekAcqResult.sha256}</span>
                      <button
                        onClick={() => handleCopyDigest(seekAcqResult.sha256)}
                        className="text-cyan-400 hover:text-cyan-300 px-2 py-0.5 rounded border border-cyan-500/30 text-[10px]"
                      >
                        {copiedDigest ? "Copied" : "Copy"}
                      </button>
                    </div>
                  </div>
                  <p className="text-[11px] text-emerald-200">
                    Case is now <strong className="font-mono">AVAILABLE</strong> in the Hunter workspace. Authorized Hunters can claim and triage evidence.
                  </p>
                </div>
              )}

              {/* Acquisition Error Alert */}
              {seekAcqError && (
                <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200 flex items-center justify-between">
                  <span>{seekAcqError}</span>
                  <button onClick={() => setSeekAcqError(null)} className="text-slate-400 hover:text-white">
                    <X className="h-4 w-4" />
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Casebook & Inspector Review Queue */}
      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-2xl overflow-hidden">
        <div className="px-6 py-5 border-b border-slate-800/80 bg-[#090F1D] flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Briefcase className="h-5 w-5 text-amber-400" />
              <h2 className="text-base font-bold text-white">Seek Help Investigation Casebook & Review Queue</h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/10 border border-amber-500/30 text-amber-300">
                {seekHelpCases.length} Total Cases
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect active investigation cases, verify assigned Threat Hunters, and review returned forensic findings for clearance.
            </p>
          </div>

          {/* Status Filter Tabs */}
          <div className="flex flex-wrap items-center gap-1.5 bg-[#060A12] p-1 rounded-xl border border-slate-800">
            {(['ALL', 'SUBMITTED_FOR_REVIEW', 'INVESTIGATION_IN_PROGRESS', 'AVAILABLE', 'COMPLETED'] as const).map((tab) => {
              const tabCount = tab === 'ALL'
                ? seekHelpCases.length
                : seekHelpCases.filter((c) => c.case_status === tab).length;

              return (
                <button
                  key={tab}
                  onClick={() => setSeekHelpFilter(tab)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all font-medium ${
                    seekHelpFilter === tab
                      ? 'bg-amber-600 text-white shadow-md shadow-amber-950/40 font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab === 'SUBMITTED_FOR_REVIEW' && `Review Queue (${tabCount})`}
                  {tab === 'INVESTIGATION_IN_PROGRESS' && `In Progress (${tabCount})`}
                  {tab === 'AVAILABLE' && `Available (${tabCount})`}
                  {tab === 'COMPLETED' && `Completed (${tabCount})`}
                  {tab === 'ALL' && `All (${tabCount})`}
                </button>
              );
            })}
          </div>
        </div>

        {/* Review Feedback Alert */}
        {reviewFeedbackMsg && (
          <div
            className={`p-3.5 mx-6 mt-4 rounded-xl border text-xs flex items-center justify-between gap-2 ${
              reviewFeedbackMsg.type === 'success'
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                : 'bg-rose-500/10 border-rose-500/30 text-rose-200'
            }`}
          >
            <span>{reviewFeedbackMsg.text}</span>
            <button onClick={() => setReviewFeedbackMsg(null)} className="text-slate-400 hover:text-white">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Cases List */}
        <div className="p-6 space-y-4">
          {seekHelpCases.filter((c) => seekHelpFilter === 'ALL' || c.case_status === seekHelpFilter).length === 0 ? (
            <div className="py-12 text-center space-y-2">
              <Briefcase className="h-10 w-10 text-slate-600 mx-auto" />
              <p className="text-sm font-semibold text-slate-400">No investigation cases in this category.</p>
              <p className="text-xs text-slate-500">
                {seekHelpFilter === 'SUBMITTED_FOR_REVIEW'
                  ? 'No cases currently waiting for Forensic Inspector review decision.'
                  : 'Create a new case by selecting a registered device above.'}
              </p>
            </div>
          ) : (
            seekHelpCases
              .filter((c) => seekHelpFilter === 'ALL' || c.case_status === seekHelpFilter)
              .map((c) => (
                <div
                  key={c.case_id}
                  className="bg-[#080E1A] border border-slate-800/90 rounded-xl p-5 hover:border-slate-700/80 transition-all space-y-4 shadow-sm"
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

                        {/* Status Badges */}
                        {c.case_status === 'AVAILABLE' && (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-500/15 border border-cyan-500/40 text-cyan-300">
                            🟢 AVAILABLE TO HUNTERS
                          </span>
                        )}
                        {c.case_status === 'INVESTIGATION_IN_PROGRESS' && (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-500/15 border border-amber-500/40 text-amber-300">
                            ⏳ IN PROGRESS (@{c.assigned_hunter_id})
                          </span>
                        )}
                        {c.case_status === 'SUBMITTED_FOR_REVIEW' && (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-500/20 border border-rose-500/50 text-rose-300 animate-pulse">
                            🔔 SUBMITTED FOR REVIEW
                          </span>
                        )}
                        {c.case_status === 'RETURNED_FOR_CORRECTION' && (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-purple-500/15 border border-purple-500/40 text-purple-300">
                            ↩ RETURNED FOR CORRECTION
                          </span>
                        )}
                        {c.case_status === 'COMPLETED' && (
                          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-500/15 border border-emerald-500/40 text-emerald-300">
                            ✓ COMPLETED
                          </span>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-4 text-xs text-slate-400">
                        <span>Device: <strong className="text-slate-200">{c.device_model} ({c.device_capacity_readable})</strong></span>
                        <span>Image: <strong className="font-mono text-slate-300">{c.image_filename}</strong></span>
                        <span>Created: <strong className="font-mono text-slate-300">{c.created_at_human}</strong></span>
                        {c.assigned_hunter_id && (
                          <span>Assigned Hunter: <strong className="text-purple-300 font-mono">@{c.assigned_hunter_id}</strong></span>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 self-start lg:self-center">
                      {c.case_status === 'SUBMITTED_FOR_REVIEW' && (
                        <Button
                          size="sm"
                          onClick={() => {
                            setReviewingCase(c);
                            setReviewNotes("");
                          }}
                          className="bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs h-8 px-4 rounded-lg shadow-md flex items-center gap-1.5"
                        >
                          <Eye className="h-3.5 w-3.5" />
                          <span>Review Case Findings</span>
                        </Button>
                      )}

                      <Link
                        href={`/forensic/evidence-graph?case=${encodeURIComponent(c.case_id)}`}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-slate-300 hover:text-white bg-slate-800/60 hover:bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 transition-all"
                        title="View Evidence Relationship Graph"
                      >
                        <Network className="h-3.5 w-3.5" />
                        <span>Relationship Graph</span>
                      </Link>

                      <a
                        href={`http://localhost:9758/api/seek-help/cases/${c.case_id}/download-image`}
                        download={c.image_filename}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 hover:bg-cyan-500/20 px-3 py-1.5 rounded-lg border border-cyan-500/30 transition-all"
                        title="Download Immutable RAW Image"
                      >
                        <Download className="h-3.5 w-3.5" />
                        <span>Download .img</span>
                      </a>
                    </div>
                  </div>

                  {/* Integrity & Hash Row */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-[#060A12] border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">RAW SHA-256 Checksum:</span>
                      <span className="text-slate-200 text-[11px] truncate max-w-[240px]">{c.sha256}</span>
                      <button
                        onClick={() => handleCopyDigest(c.sha256)}
                        className="text-cyan-400 hover:text-cyan-300 text-[10px] ml-1"
                      >
                        Copy
                      </button>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#060A12] border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-400 text-[11px]">Acquisition Mode:</span>
                      <span className="text-emerald-400 text-[11px]">Sector-by-Sector RAW Bit-Stream</span>
                    </div>
                  </div>

                  {/* Submitted Findings Preview */}
                  {c.investigation_findings && (
                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800 space-y-1 text-xs">
                      <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Hunter Submitted Findings:</span>
                      <p className="text-slate-300 text-xs leading-relaxed">{c.investigation_findings}</p>
                      {c.inspector_notes && (
                        <div className="pt-2 border-t border-slate-800 text-[11px]">
                          <strong className="text-amber-400">Inspector Feedback:</strong> <span className="text-slate-300">{c.inspector_notes}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))
          )}
        </div>
      </div>

      {/* INSPECTOR REVIEW CASE MODAL */}
      {reviewingCase && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0D1527] border border-amber-500/40 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl max-h-[90vh] overflow-y-auto animate-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Briefcase className="h-5 w-5 text-amber-400" />
                <div>
                  <h3 className="text-sm font-bold text-white">Forensic Inspector Case Review</h3>
                  <p className="text-[11px] text-slate-400 font-mono">Case ID: {reviewingCase.case_id}</p>
                </div>
              </div>
              <button onClick={() => setReviewingCase(null)} className="text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              {/* Case Metadata */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <HardDrive className="h-3.5 w-3.5 text-cyan-400" />
                  Case Information & Target Storage Device
                </h4>
                <div className="grid grid-cols-2 gap-2 text-slate-300">
                  <div>Case Title: <strong className="text-white">{reviewingCase.title}</strong></div>
                  <div>Status: <span className="font-mono text-rose-300 font-bold">{reviewingCase.case_status}</span></div>
                  <div>Device ID: <span className="font-mono text-cyan-300">{reviewingCase.device_id}</span></div>
                  <div>Device Model: <span className="text-slate-200">{reviewingCase.device_model} ({reviewingCase.device_capacity_readable})</span></div>
                  <div>Assigned Hunter: <span className="font-mono text-purple-300">@{reviewingCase.assigned_hunter_id}</span></div>
                  <div>Acquisition SHA-256: <span className="font-mono text-emerald-400 truncate text-[10px]">{reviewingCase.sha256}</span></div>
                </div>
              </div>

              {/* Hunter's Submitted Findings */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-slate-800 space-y-2">
                <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5 text-purple-400" />
                  Hunter&apos;s Investigation Findings & Evidence Report
                </h4>
                <p className="text-slate-300 text-xs leading-relaxed bg-[#0A101D] p-3 rounded-lg border border-slate-800 whitespace-pre-wrap">
                  {reviewingCase.investigation_findings || "No findings recorded by hunter."}
                </p>

                {reviewingCase.evidence_artifacts && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-slate-400 text-[11px] block font-semibold">Extracted Evidence Artifacts:</span>
                    <div className="text-slate-300 text-xs mt-1 bg-[#0A101D] p-2.5 rounded-lg border border-slate-800 font-mono">
                      {typeof reviewingCase.evidence_artifacts === "string"
                        ? reviewingCase.evidence_artifacts
                        : JSON.stringify(reviewingCase.evidence_artifacts, null, 2)}
                    </div>
                  </div>
                )}
              </div>

              {/* Inspector Review Notes / Feedback */}
              <div className="space-y-1.5">
                <Label htmlFor="review_notes" className="text-xs font-semibold text-slate-200">
                  Inspector Review Notes & Feedback (Optional for approval, recommended for return)
                </Label>
                <Textarea
                  id="review_notes"
                  placeholder="e.g. Findings validated. Cryptographic chain verified / or Please inspect sector range 2048-4096 for additional database fragments..."
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  rows={3}
                  className="bg-[#060A12] border-slate-700 text-white text-xs rounded-xl resize-none"
                />
              </div>
            </div>

            {/* Action Buttons */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setReviewingCase(null)}
                className="border-slate-700 text-slate-300 text-xs h-9 px-4 rounded-xl"
              >
                Cancel
              </Button>

              <div className="flex items-center gap-2.5">
                <Button
                  size="sm"
                  disabled={reviewDecisionLoading}
                  onClick={() => handleInspectorReviewCase(reviewingCase.case_id, "RETURN_FOR_CORRECTION", reviewNotes)}
                  className="bg-amber-600 hover:bg-amber-500 text-white text-xs h-9 px-4 rounded-xl font-semibold shadow-md flex items-center gap-1.5"
                >
                  <RefreshCw className={`h-3.5 w-3.5 ${reviewDecisionLoading ? "animate-spin" : ""}`} />
                  <span>Return for Correction</span>
                </Button>

                <Button
                  size="sm"
                  disabled={reviewDecisionLoading}
                  onClick={() => handleInspectorReviewCase(reviewingCase.case_id, "ACCEPT", reviewNotes)}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs h-9 px-4 rounded-xl font-semibold shadow-md shadow-emerald-950/50 flex items-center gap-1.5"
                >
                  <Check className="h-3.5 w-3.5" />
                  <span>Accept & Mark Completed</span>
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Central Device Registry Popup Modal */}
      <RegisteredDevicesModal
        open={registeredModalOpen}
        onOpenChange={setRegisteredModalOpen}
        currentPersona="forensic"
      />
    </div>
  );
}
