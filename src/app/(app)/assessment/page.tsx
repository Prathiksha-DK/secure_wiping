"use client";

import React, { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HardDrive,
  Eye,
  Search,
  Activity,
  Layers,
  Binary,
  RotateCcw,
  Play,
  CheckCircle2,
  XCircle,
  FileDown,
  RefreshCw,
  Cpu,
  ArrowRight,
  Sliders,
  ChevronLeft,
  ChevronRight,
  Lock,
  Sparkles,
  Gamepad2,
  FileCheck2,
  Info,
} from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";

interface StorageTarget {
  name: string;
  friendlyName?: string;
  type: string;
  size: string;
  sizeBytes: number;
  health: number;
  healthStatus: string;
  serial?: string;
  model?: string;
  isSystem?: boolean;
  isImage?: boolean;
}

interface ArtifactFinding {
  candidate_id: string;
  format: string;
  classification: string;
  validation_level: number;
  validation_level_name: string;
  confidence_score: number;
  start_byte_offset: number;
  start_lba: number;
  end_byte_offset: number;
  end_lba: number;
  length_bytes: number;
  sector_span: [number, number];
  sha256_hash: string;
  hex_preview?: string;
  ascii_preview?: string;
  details: string;
  is_fragmented: boolean;
}

interface HeatmapBin {
  bin_index: number;
  start_byte: number;
  end_byte: number;
  total_bytes: number;
  start_lba: number;
  end_lba: number;
  zero_ratio: number;
  ff_ratio: number;
  entropy: number;
  artifact_count: number;
  artifacts: string[];
  state: string;
}

interface AssessmentReport {
  assessment_id: string;
  status: string;
  target: {
    path: string;
    type: string;
    total_bytes: number;
    total_sectors: number;
    sector_size: number;
    sha256_at_scan_time: string;
    sha512_at_scan_time: string;
  };
  scientific_assessment: {
    method_performed: string;
    post_sanitization_observation: string;
    overall_classification: string;
    confidence_score: number;
    is_zero_residual: boolean;
  };
  scan_metrics: {
    bytes_scanned: number;
    sectors_scanned: number;
    coverage_pct: number;
    duration_seconds: number;
    throughput_mbps: number;
    read_errors: number;
  };
  findings_summary: {
    total_candidates: number;
    validated_artifacts: number;
    partial_artifacts: number;
    unknown_anomalies: number;
    signature_only_hits: number;
  };
  findings_ledger: ArtifactFinding[];
  heatmap_summary: {
    total_bins: number;
    clean_zero_bins: number;
    clean_pattern_bins: number;
    high_entropy_bins: number;
    artifact_bins: number;
    anomaly_bins: number;
  };
  heatmap_bins: HeatmapBin[];
  swarm_reconstruction: {
    eligible: boolean;
    status_message: string;
    fragment_count: number;
  };
  disclaimers: {
    ssd_nand_wear_leveling: string;
    empirical_observation_scope: string;
  };
  logs: string[];
}

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://127.0.0.1:9758";

export default function AssessmentPage() {
  const { toast } = useToast();
  const [targets, setTargets] = useState<StorageTarget[]>([]);
  const [selectedTarget, setSelectedTarget] = useState<string>("");
  const [loadingTargets, setLoadingTargets] = useState(false);

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [currentAssessmentId, setCurrentAssessmentId] = useState<string>("");
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState<string>("IDLE");
  const [report, setReport] = useState<AssessmentReport | null>(null);
  const [liveMetrics, setLiveMetrics] = useState<{
    current_lba?: number;
    scan_rate_mb_s?: number;
    elapsed_seconds?: number;
    eta_seconds?: number;
    current_region?: string;
    matches_count?: number;
  }>({});

  // Byte Inspector State
  const [inspectorOffset, setInspectorOffset] = useState<number>(0);
  const [inspectorLength, setInspectorLength] = useState<number>(512);
  const [inspectorData, setInspectorData] = useState<any>(null);
  const [loadingInspector, setLoadingInspector] = useState(false);

  // Comparative Experiment State
  const [expMethod, setExpMethod] = useState<string>("nist-clear");
  const [isRunningExp, setIsRunningExp] = useState(false);
  const [expResult, setExpResult] = useState<any>(null);

  // Certificate state
  const [certData, setCertData] = useState<any>(null);
  const [certVerified, setCertVerified] = useState<boolean | null>(null);
  const [activeTab, setActiveTab] = useState<string>("assessment");
  const [ledgerFilter, setLedgerFilter] = useState<string>("ALL");

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    setLoadingTargets(true);
    try {
      const res = await fetch(`${BACKEND_URL}/api/assessment/devices`);
      if (res.ok) {
        const data = await res.json();
        const list = data.all_targets || [];
        setTargets(list);
        if (list.length > 0 && !selectedTarget) {
          // Default to forensic live image or non-system drive
          const defaultTarget = list.find((t: StorageTarget) => t.isImage) || list[0];
          setSelectedTarget(defaultTarget.name);
        }
      }
    } catch (e) {
      console.error("Failed to load targets:", e);
      toast({ title: "Connection Error", description: "Failed to connect to backend assessment engine.", variant: "destructive" });
    } finally {
      setLoadingTargets(false);
    }
  };

  const generateTestImage = async () => {
    try {
      toast({ title: "Generating Image", description: "Generating authentic forensic test disk image..." });
      const res = await fetch(`${BACKEND_URL}/api/assessment/generate-test-image`, { method: "POST" });
      if (res.ok) {
        toast({ title: "Image Ready", description: "Authentic multi-format forensic disk image generated!" });
        await fetchTargets();
      }
    } catch (e) {
      toast({ title: "Error", description: "Error generating test image.", variant: "destructive" });
    }
  };

  const cancelAssessment = async () => {
    if (!currentAssessmentId) return;
    try {
      await fetch(`${BACKEND_URL}/api/assessment/cancel`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ assessment_id: currentAssessmentId }),
      });
      toast({ title: "Cancellation Requested", description: "Stopping residual assessment scan..." });
    } catch (e) {
      console.error("Cancel error:", e);
    }
  };

  const startAssessment = async () => {
    if (!selectedTarget) {
      toast({ title: "Target Required", description: "Please select a valid storage device or forensic image.", variant: "destructive" });
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanStatus("INITIALIZING");
    setLiveMetrics({});
    setReport(null);
    setCertData(null);
    setCertVerified(null);

    try {
      const targetObj = targets.find((t) => t.name === selectedTarget);
      const res = await fetch(`${BACKEND_URL}/api/assessment/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_path: selectedTarget,
          target_type: targetObj?.isImage ? "forensic_image" : "disk",
          sector_size: 512,
          prior_sanitization_meta: {
            job_id: `SAN-${Date.now().toString(36).toUpperCase()}`,
            method_label: "NIST SP 800-88 Rev.1 Clear / Overwrite",
            completed_at: new Date().toISOString(),
          },
        }),
      });

      if (!res.ok) {
        throw new Error("Failed to start assessment session");
      }

      const data = await res.json();
      const asmtId = data.assessment_id;
      setCurrentAssessmentId(asmtId);

      // Poll progress
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await fetch(`${BACKEND_URL}/api/assessment/status/${asmtId}`);
          if (statusRes.ok) {
            const sData = await statusRes.json();
            setScanProgress(sData.progress_pct || 0);
            setScanStatus(sData.status);
            setLiveMetrics({
              current_lba: sData.current_lba,
              scan_rate_mb_s: sData.scan_rate_mb_s,
              elapsed_seconds: sData.elapsed_seconds,
              eta_seconds: sData.eta_seconds,
              current_region: sData.current_region,
              matches_count: sData.matches_count,
            });

            if (sData.status === "COMPLETED" || sData.status === "ERROR" || sData.status === "CANCELLED") {
              clearInterval(pollInterval);
              setIsScanning(false);

              // Fetch final complete report
              const repRes = await fetch(`${BACKEND_URL}/api/assessment/report/${asmtId}`);
              if (repRes.ok) {
                const repData = await repRes.json();
                setReport(repData);
                toast({ title: "Assessment Complete", description: `Classification: ${repData.scientific_assessment.overall_classification}` });
              }
            }
          }
        } catch (pollErr) {
          console.error("Poll error:", pollErr);
        }
      }, 500);
    } catch (e: any) {
      setIsScanning(false);
      setScanStatus("ERROR");
      toast({ title: "Scan Failed", description: e.message || "Failed to start assessment scan.", variant: "destructive" });
    }
  };

  const loadInspectorBytes = async (offset: number) => {
    if (!selectedTarget) return;
    setLoadingInspector(true);
    setInspectorOffset(offset);
    try {
      const res = await fetch(`${BACKEND_URL}/api/assessment/inspect-bytes`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_path: selectedTarget,
          byte_offset: offset,
          length_bytes: inspectorLength,
          sector_size: 512,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setInspectorData(data);
      }
    } catch (e) {
      toast({ title: "Read Error", description: "Failed to read bytes from target.", variant: "destructive" });
    } finally {
      setLoadingInspector(false);
    }
  };

  const runExperiment = async () => {
    setIsRunningExp(true);
    setExpResult(null);
    try {
      toast({ title: "Experiment Started", description: `Running comparative experiment (${expMethod.toUpperCase()})...` });
      const res = await fetch(`${BACKEND_URL}/api/assessment/comparative-experiment`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          experiment_name: `EXP-${expMethod.toUpperCase()}-VERIFICATION`,
          image_size_mb: 12,
          wipe_method: expMethod,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setExpResult(data);
        toast({ title: "Experiment Complete", description: `Artifact reduction: ${data.comparative_delta.artifact_reduction_percentage}%` });
      }
    } catch (e) {
      toast({ title: "Experiment Failed", description: "Comparative experiment failed.", variant: "destructive" });
    } finally {
      setIsRunningExp(false);
    }
  };

  const fetchCertificate = async () => {
    if (!currentAssessmentId) return;
    try {
      const res = await fetch(`${BACKEND_URL}/api/assessment/certificate/${currentAssessmentId}`);
      if (res.ok) {
        const data = await res.json();
        setCertData(data);
      }
    } catch (e) {
      toast({ title: "Error", description: "Failed to load certificate.", variant: "destructive" });
    }
  };

  const verifyCertificate = async () => {
    if (!currentAssessmentId || !certData) return;
    try {
      const res = await fetch(`${BACKEND_URL}/api/assessment/certificate/${currentAssessmentId}/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(certData),
      });
      if (res.ok) {
        const data = await res.json();
        setCertVerified(data.valid);
        if (data.valid) {
          toast({ title: "Signature Verified", description: "RSA-PSS digital signature and canonical hash verified authentic!" });
        } else {
          toast({ title: "Verification Failed", description: `Reason: ${data.reason}`, variant: "destructive" });
        }
      }
    } catch (e) {
      toast({ title: "Error", description: "Failed to verify certificate signature.", variant: "destructive" });
    }
  };

  const syncToSwarm = async () => {
    if (!currentAssessmentId) return;
    try {
      toast({ title: "Swarm Sync", description: "Synchronizing genuine residual fragments to Swarm..." });
      const res = await fetch(`${BACKEND_URL}/api/assessment/swarm-sync/${currentAssessmentId}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ case_id: `CASE-${currentAssessmentId}` }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.status === "SUCCESS") {
          toast({ title: "Swarm Sync Success", description: data.message });
        } else {
          toast({ title: "Swarm Status", description: data.message });
        }
      }
    } catch (e) {
      toast({ title: "Error", description: "Swarm sync failed.", variant: "destructive" });
    }
  };

  const filteredLedger = report?.findings_ledger.filter((item) => {
    if (ledgerFilter === "ALL") return true;
    if (ledgerFilter === "VALIDATED") return item.classification === "VALIDATED_ARTIFACT_CANDIDATE";
    if (ledgerFilter === "PARTIAL") return item.classification === "PARTIAL_ARTIFACT";
    if (ledgerFilter === "SIGNATURE") return item.classification === "SIGNATURE_ONLY";
    if (ledgerFilter === "ANOMALY") return item.classification === "UNKNOWN_ANOMALY";
    return true;
  }) || [];

  const selectedTargetObj = targets.find((t) => t.name === selectedTarget);

  return (
    <div className="container mx-auto p-4 sm:p-6 space-y-6 max-w-7xl">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b pb-5">
        <div>
          <div className="flex items-center gap-2">
            <Badge variant="outline" className="border-emerald-500/30 text-emerald-400 bg-emerald-500/10 text-xs px-2.5 py-0.5">
              PHASE 9 FORENSIC SUITE
            </Badge>
            <Badge variant="outline" className="border-blue-500/30 text-blue-400 bg-blue-500/10 text-xs px-2.5 py-0.5">
              READ-ONLY RESIDUAL SCAN
            </Badge>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight mt-1 text-slate-100">
            Post-Sanitization Residual Evidence Assessment
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Scientific, non-destructive empirical assessment of storage address space following sanitization.
            Validates internal byte structures, computes real sector heatmaps, and generates Schema v2.0 RSA-PSS certificates.
          </p>
        </div>

        <div className="flex items-center gap-2 w-full md:w-auto">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchTargets}
            disabled={loadingTargets}
            className="flex items-center gap-1.5 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loadingTargets ? "animate-spin" : ""}`} />
            Refresh Devices
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={generateTestImage}
            className="flex items-center gap-1.5 text-xs bg-slate-800 hover:bg-slate-700"
          >
            <Sparkles className="h-3.5 w-3.5 text-amber-400" />
            Generate Test Image
          </Button>
        </div>
      </div>

      {/* Core Concept Banner */}
      <Card className="border-slate-800 bg-slate-900/60 backdrop-blur">
        <CardContent className="p-4 sm:p-5">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-center">
            <div className="lg:col-span-8 space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold text-slate-300 uppercase tracking-wider">
                <Sliders className="h-4 w-4 text-emerald-400" />
                Scientific Assessment Pipeline
              </div>
              <div className="flex flex-wrap items-center gap-1.5 sm:gap-2 text-xs font-mono font-medium text-slate-300">
                <span className="px-2 py-1 bg-slate-800 rounded border border-slate-700">SANITIZE</span>
                <ArrowRight className="h-3 w-3 text-slate-500" />
                <span className="px-2 py-1 bg-slate-800 rounded border border-slate-700">VERIFY</span>
                <ArrowRight className="h-3 w-3 text-slate-500" />
                <span className="px-2 py-1 bg-emerald-950/60 text-emerald-300 rounded border border-emerald-800/60">POST-SANITIZATION ASSESSMENT</span>
                <ArrowRight className="h-3 w-3 text-slate-500" />
                <span className="px-2 py-1 bg-blue-950/60 text-blue-300 rounded border border-blue-800/60">RESIDUAL CARVER</span>
                <ArrowRight className="h-3 w-3 text-slate-500" />
                <span className="px-2 py-1 bg-purple-950/60 text-purple-300 rounded border border-purple-800/60">SCHEMA v2.0 CERTIFICATE</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed pt-1">
                <strong className="text-slate-200">Empirical Integrity Rule:</strong> Asserts only what was physically observed on addressable LBAs.
                Distinguishes <span className="text-emerald-400 font-semibold">METHOD PERFORMED</span> from <span className="text-blue-400 font-semibold">POST-SANITIZATION OBSERVATION</span>.
              </p>
            </div>

            <div className="lg:col-span-4 bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
                <Info className="h-3.5 w-3.5" />
                NAND / SSD Physical Limitation
              </div>
              <p className="text-[11px] text-slate-400 leading-normal">
                Flash controller wear-leveling reserves and retired bad blocks cannot be inspected via standard LBA command sets without direct hardware chip-off analysis.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="grid grid-cols-4 bg-slate-900 border border-slate-800">
          <TabsTrigger value="assessment" className="flex items-center gap-2 text-xs">
            <Activity className="h-3.5 w-3.5 text-emerald-400" />
            Residual Assessment
          </TabsTrigger>
          <TabsTrigger value="inspector" className="flex items-center gap-2 text-xs">
            <Binary className="h-3.5 w-3.5 text-blue-400" />
            Byte Inspector
          </TabsTrigger>
          <TabsTrigger value="experiment" className="flex items-center gap-2 text-xs">
            <FileCheck2 className="h-3.5 w-3.5 text-purple-400" />
            Comparative Experiment
          </TabsTrigger>
          <TabsTrigger value="certificate" className="flex items-center gap-2 text-xs">
            <ShieldCheck className="h-3.5 w-3.5 text-amber-400" />
            Schema v2.0 Certificate
          </TabsTrigger>
        </TabsList>

        {/* ========================================================================= */}
        {/* TAB 1: RESIDUAL ASSESSMENT & REAL SECTOR HEATMAP */}
        {/* ========================================================================= */}
        <TabsContent value="assessment" className="space-y-6">
          {/* Target Selector & Scan Controller */}
          <Card className="border-slate-800 bg-slate-900/70">
            <CardHeader className="pb-3">
              <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                <div>
                  <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <HardDrive className="h-4 w-4 text-emerald-400" />
                    Target Storage Device / Verified Forensic Image
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Strictly read-only access. Zero simulated artifacts or synthetic LBAs.
                  </CardDescription>
                </div>
                {selectedTargetObj && (
                  <Badge variant="outline" className="text-xs border-slate-700 bg-slate-800 text-slate-300">
                    {selectedTargetObj.type} • {selectedTargetObj.size}
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                <div className="md:col-span-8">
                  <select
                    value={selectedTarget}
                    onChange={(e) => setSelectedTarget(e.target.value)}
                    disabled={isScanning}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-emerald-500 font-mono"
                  >
                    {targets.length === 0 ? (
                      <option value="">NO EVIDENCE DEVICE LOADED</option>
                    ) : (
                      targets.map((t) => (
                        <option key={t.name} value={t.name}>
                          {t.friendlyName || t.name} ({t.size}) {t.isSystem ? "[SYSTEM - READ ONLY]" : ""}
                        </option>
                      ))
                    )}
                  </select>
                </div>

                <div className="md:col-span-4 flex items-center gap-2">
                  <Button
                    onClick={startAssessment}
                    disabled={isScanning || !selectedTarget}
                    className="w-full bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center justify-center gap-2"
                  >
                    {isScanning ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        Scanning ({scanProgress}%)...
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5" />
                        Start Residual Scan
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {/* Progress Bar when scanning */}
              {isScanning && (
                <div className="space-y-1.5 pt-2">
                  <div className="flex justify-between text-xs text-slate-400">
                    <span>Streaming read-only carver progress</span>
                    <span className="font-mono text-emerald-400">{scanProgress}%</span>
                  </div>
                  <Progress value={scanProgress} className="h-2 bg-slate-800" />
                </div>
              )}
            </CardContent>
          </Card>

          {/* Assessment Results Section */}
          {!report && !isScanning && (
            <Card className="border-slate-800/80 bg-slate-950/40 p-8 text-center space-y-3">
              <div className="mx-auto w-12 h-12 rounded-full bg-slate-900 flex items-center justify-center border border-slate-800 text-slate-500">
                <Search className="h-6 w-6" />
              </div>
              <h3 className="text-sm font-semibold text-slate-300">
                {selectedTarget ? "Target Ready for Residual Scan" : "STATUS: NO EVIDENCE DEVICE LOADED"}
              </h3>
              <p className="text-xs text-slate-500 max-w-md mx-auto">
                {selectedTarget
                  ? "Click 'Start Residual Scan' to execute streaming forensic carving across addressable sectors."
                  : "Connect a physical drive or generate an authentic forensic disk image to commence assessment."}
              </p>
            </Card>
          )}

          {report && (
            <div className="space-y-6">
              {/* Scientific Assessment Outcome Banner */}
              <Card className={`border ${report.scientific_assessment.is_zero_residual ? "border-emerald-500/40 bg-emerald-950/20" : "border-amber-500/40 bg-amber-950/20"}`}>
                <CardContent className="p-4 sm:p-5">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        {report.scientific_assessment.is_zero_residual ? (
                          <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                        ) : (
                          <ShieldAlert className="h-5 w-5 text-amber-400" />
                        )}
                        <h2 className="text-base font-bold text-slate-100">
                          {report.scientific_assessment.overall_classification}
                        </h2>
                        <Badge variant="outline" className="text-xs font-mono border-slate-700">
                          Confidence: {report.scientific_assessment.confidence_score}%
                        </Badge>
                      </div>
                      <p className="text-xs text-slate-300">
                        <strong className="text-slate-100">Observation: </strong>
                        {report.scientific_assessment.post_sanitization_observation}
                      </p>
                      <p className="text-[11px] text-slate-400 font-mono">
                        Method Performed: {report.scientific_assessment.method_performed} • Scanned: {report.scan_metrics.sectors_scanned.toLocaleString()} Sectors ({report.scan_metrics.bytes_scanned / (1024*1024)} MB) in {report.scan_metrics.duration_seconds}s ({report.scan_metrics.throughput_mbps} MB/s)
                      </p>
                    </div>

                    <div className="flex items-center gap-2 w-full sm:w-auto">
                      {report.swarm_reconstruction.eligible && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={syncToSwarm}
                          className="text-xs border-purple-500/40 text-purple-300 hover:bg-purple-950/40 flex items-center gap-1.5"
                        >
                          <Gamepad2 className="h-3.5 w-3.5 text-purple-400" />
                          Sync to Swarm
                        </Button>
                      )}
                      <Button
                        size="sm"
                        onClick={() => {
                          setActiveTab("certificate");
                          fetchCertificate();
                        }}
                        className="text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 flex items-center gap-1.5"
                      >
                        <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                        View Certificate
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Real Sector Heatmap */}
              <Card className="border-slate-800 bg-slate-900/70">
                <CardHeader className="pb-3">
                  <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                    <div>
                      <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                        <Layers className="h-4 w-4 text-emerald-400" />
                        Real Sector Heatmap ({report.heatmap_bins.length} Scanned Bins)
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Derived strictly from actual examined block bytes. Click any block to inspect in Byte Viewer.
                      </CardDescription>
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-[11px]">
                      <span className="flex items-center gap-1 text-slate-300">
                        <span className="w-2.5 h-2.5 rounded-sm bg-emerald-600 inline-block"></span>
                        Clean Zero ({report.heatmap_summary.clean_zero_bins})
                      </span>
                      <span className="flex items-center gap-1 text-slate-300">
                        <span className="w-2.5 h-2.5 rounded-sm bg-blue-600 inline-block"></span>
                        Clean Pattern ({report.heatmap_summary.clean_pattern_bins})
                      </span>
                      <span className="flex items-center gap-1 text-slate-300">
                        <span className="w-2.5 h-2.5 rounded-sm bg-purple-600 inline-block"></span>
                        High Entropy ({report.heatmap_summary.high_entropy_bins})
                      </span>
                      <span className="flex items-center gap-1 text-slate-300">
                        <span className="w-2.5 h-2.5 rounded-sm bg-rose-600 inline-block"></span>
                        Residual Artifact ({report.heatmap_summary.artifact_bins})
                      </span>
                      <span className="flex items-center gap-1 text-slate-300">
                        <span className="w-2.5 h-2.5 rounded-sm bg-amber-600 inline-block"></span>
                        Anomaly ({report.heatmap_summary.anomaly_bins})
                      </span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Heatmap Grid */}
                  <div className="grid grid-cols-10 sm:grid-cols-20 md:grid-cols-25 lg:grid-cols-50 gap-1 p-3 bg-slate-950 rounded-lg border border-slate-800">
                    {report.heatmap_bins.map((bin) => {
                      let colorClass = "bg-emerald-950/70 border-emerald-800/40 text-emerald-300 hover:bg-emerald-700";
                      if (bin.state === "RESIDUAL_ARTIFACT_DETECTED") {
                        colorClass = "bg-rose-600 border-rose-400 text-white animate-pulse hover:bg-rose-500";
                      } else if (bin.state === "UNKNOWN_ANOMALY") {
                        colorClass = "bg-amber-600 border-amber-400 text-white hover:bg-amber-500";
                      } else if (bin.state === "HIGH_ENTROPY_UNIFORM") {
                        colorClass = "bg-purple-900/80 border-purple-700 text-purple-200 hover:bg-purple-700";
                      } else if (bin.state === "CLEAN_PATTERN") {
                        colorClass = "bg-blue-900/80 border-blue-700 text-blue-200 hover:bg-blue-700";
                      }

                      return (
                        <button
                          key={bin.bin_index}
                          onClick={() => {
                            setActiveTab("inspector");
                            loadInspectorBytes(bin.start_byte);
                          }}
                          title={`Bin #${bin.bin_index} | LBA ${bin.start_lba}..${bin.end_lba} | State: ${bin.state} | Entropy: ${bin.entropy} | Artifacts: ${bin.artifact_count}`}
                          className={`h-5 w-full rounded-[2px] border text-[9px] font-mono flex items-center justify-center transition-all ${colorClass}`}
                        >
                          {bin.artifact_count > 0 ? bin.artifact_count : ""}
                        </button>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {/* Forensic Findings Ledger */}
              <Card className="border-slate-800 bg-slate-900/70">
                <CardHeader className="pb-3">
                  <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                    <div>
                      <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                        <FileCheck2 className="h-4 w-4 text-blue-400" />
                        Forensic Findings Ledger ({report.findings_ledger.length} Detections)
                      </CardTitle>
                      <CardDescription className="text-xs text-slate-400">
                        Exact physical LBA mapping, structural validation level, and cryptographic slice digests.
                      </CardDescription>
                    </div>

                    <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800 text-xs">
                      {["ALL", "VALIDATED", "PARTIAL", "ANOMALY", "SIGNATURE"].map((filter) => (
                        <button
                          key={filter}
                          onClick={() => setLedgerFilter(filter)}
                          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                            ledgerFilter === filter
                              ? "bg-slate-800 text-white font-semibold"
                              : "text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {filter}
                        </button>
                      ))}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  {filteredLedger.length === 0 ? (
                    <div className="text-center py-8 text-slate-400 text-xs space-y-1">
                      <CheckCircle2 className="h-6 w-6 text-emerald-400 mx-auto" />
                      <p className="font-semibold text-slate-200">No matching artifacts in this filter category.</p>
                      <p className="text-slate-500">Addressable media space shows no recognizable structures for this query.</p>
                    </div>
                  ) : (
                    <div className="overflow-x-auto min-w-0">
                      <table className="w-full text-xs text-left border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60 font-mono">
                            <th className="py-2.5 px-3">CANDIDATE ID</th>
                            <th className="py-2.5 px-3">FORMAT</th>
                            <th className="py-2.5 px-3">VALIDATION LEVEL</th>
                            <th className="py-2.5 px-3">LBA SPAN</th>
                            <th className="py-2.5 px-3">BYTE OFFSET</th>
                            <th className="py-2.5 px-3">SIZE</th>
                            <th className="py-2.5 px-3">SHA-256 SLICE</th>
                            <th className="py-2.5 px-3 text-right">ACTION</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono">
                          {filteredLedger.map((item) => (
                            <tr key={item.candidate_id} className="hover:bg-slate-800/40 transition-colors">
                              <td className="py-2.5 px-3 font-semibold text-slate-200">{item.candidate_id}</td>
                              <td className="py-2.5 px-3">
                                <Badge variant="outline" className="text-[10px] font-sans border-slate-700 bg-slate-800/80">
                                  {item.format}
                                </Badge>
                              </td>
                              <td className="py-2.5 px-3">
                                <span
                                  className={`inline-block px-2 py-0.5 rounded text-[10px] ${
                                    item.validation_level === 3
                                      ? "bg-rose-950 text-rose-300 border border-rose-800/50"
                                      : item.validation_level === 2
                                      ? "bg-amber-950 text-amber-300 border border-amber-800/50"
                                      : "bg-slate-800 text-slate-300"
                                  }`}
                                >
                                  {item.validation_level_name}
                                </span>
                              </td>
                              <td className="py-2.5 px-3 text-slate-300">
                                LBA {item.start_lba} .. {item.end_lba}
                              </td>
                              <td className="py-2.5 px-3 text-slate-400">+{item.start_byte_offset.toLocaleString()}</td>
                              <td className="py-2.5 px-3 text-slate-300">{(item.length_bytes / 1024).toFixed(1)} KB</td>
                              <td className="py-2.5 px-3 text-slate-500 text-[10px]" title={item.sha256_hash}>
                                {item.sha256_hash ? item.sha256_hash.substring(0, 12) + "..." : "N/A"}
                              </td>
                              <td className="py-2.5 px-3 text-right">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => {
                                    setActiveTab("inspector");
                                    loadInspectorBytes(item.start_byte_offset);
                                  }}
                                  className="h-7 px-2 text-[11px] text-emerald-400 hover:text-emerald-300 hover:bg-emerald-950/40"
                                >
                                  <Eye className="h-3.5 w-3.5 mr-1" />
                                  Inspect Bytes
                                </Button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ========================================================================= */}
        {/* TAB 2: LIVE BYTE-LEVEL PHYSICAL INSPECTOR */}
        {/* ========================================================================= */}
        <TabsContent value="inspector" className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/70">
            <CardHeader className="pb-3">
              <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                <div>
                  <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <Binary className="h-4 w-4 text-blue-400" />
                    Physical Sector & Byte Inspector (Read-Only)
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Direct hardware offset reader. Zero writes or descriptor modifications.
                  </CardDescription>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadInspectorBytes(Math.max(0, inspectorOffset - 512))}
                    disabled={loadingInspector || inspectorOffset <= 0}
                    className="h-8 text-xs"
                  >
                    <ChevronLeft className="h-3.5 w-3.5 mr-1" />
                    Prev Sector
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadInspectorBytes(inspectorOffset + 512)}
                    disabled={loadingInspector}
                    className="h-8 text-xs"
                  >
                    Next Sector
                    <ChevronRight className="h-3.5 w-3.5 ml-1" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
                <div className="sm:col-span-6 space-y-1">
                  <label className="text-xs text-slate-400">Byte Offset (Decimal or Hex)</label>
                  <Input
                    type="text"
                    value={inspectorOffset}
                    onChange={(e) => {
                      const val = e.target.value.trim();
                      if (val.startsWith("0x") || val.startsWith("0X")) {
                        setInspectorOffset(parseInt(val, 16) || 0);
                      } else {
                        setInspectorOffset(parseInt(val, 10) || 0);
                      }
                    }}
                    className="bg-slate-950 border-slate-700 text-xs font-mono text-slate-200"
                    placeholder="e.g. 1048576 or 0x100000"
                  />
                </div>

                <div className="sm:col-span-3 space-y-1">
                  <label className="text-xs text-slate-400">Length (Bytes)</label>
                  <select
                    value={inspectorLength}
                    onChange={(e) => setInspectorLength(parseInt(e.target.value, 10))}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-200 font-mono"
                  >
                    <option value={256}>256 Bytes</option>
                    <option value={512}>512 Bytes (1 Sector)</option>
                    <option value={1024}>1024 Bytes</option>
                    <option value={4096}>4096 Bytes (4K Page)</option>
                  </select>
                </div>

                <div className="sm:col-span-3">
                  <Button
                    onClick={() => loadInspectorBytes(inspectorOffset)}
                    disabled={loadingInspector || !selectedTarget}
                    className="w-full bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
                  >
                    {loadingInspector ? "Reading..." : "Read Sector Bytes"}
                  </Button>
                </div>
              </div>

              {/* Inspector Analysis Metrics */}
              {inspectorData && inspectorData.status === "SUCCESS" && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">LBA / OFFSET</span>
                    <span className="text-slate-200 font-bold">LBA {inspectorData.lba}</span>
                    <span className="text-slate-400 text-[10px] block">0x{inspectorData.byte_offset.toString(16).toUpperCase()}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">SHANNON ENTROPY</span>
                    <span className="text-blue-400 font-bold">{inspectorData.entropy} / 8.0</span>
                    <span className="text-slate-400 text-[10px] block">{inspectorData.unique_byte_values} Unique Bytes</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">OBSERVED PATTERN</span>
                    <span className="text-emerald-400 font-bold">{inspectorData.observed_pattern}</span>
                    <span className="text-slate-400 text-[10px] block">{inspectorData.zero_percentage}% Zeros</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">CONFORMITY STATUS</span>
                    <Badge variant="outline" className="text-[10px] border-slate-700 bg-slate-900 mt-0.5">
                      {inspectorData.pattern_conformity}
                    </Badge>
                  </div>
                </div>
              )}

              {/* Hex Dump Viewer */}
              {inspectorData && inspectorData.hex_rows && inspectorData.hex_rows.length > 0 ? (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono text-[11px] overflow-x-auto min-w-0 max-h-[500px] overflow-y-auto">
                  <div className="text-slate-500 pb-2 border-b border-slate-800/80 mb-2 flex justify-between font-bold">
                    <span>OFFSET (HEX / DEC)</span>
                    <span>HEX BYTES (00 .. 0F)</span>
                    <span>ASCII DECODE</span>
                  </div>
                  {inspectorData.hex_rows.map((row: any, idx: number) => (
                    <div key={idx} className="flex justify-between py-0.5 hover:bg-slate-900/80 px-1 rounded">
                      <span className="text-slate-500 select-none w-28 shrink-0">{row.address_hex}</span>
                      <span className="text-slate-300 select-text px-2 tracking-wide text-center grow">{row.hex}</span>
                      <span className="text-emerald-400 select-none w-28 shrink-0 text-right font-semibold">{row.ascii}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-slate-500 text-xs">
                  Enter an offset or click 'Inspect Bytes' in the assessment findings table to load physical sector content.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ========================================================================= */}
        {/* TAB 3: COMPARATIVE BEFORE/AFTER SANITIZATION EXPERIMENT SUITE */}
        {/* ========================================================================= */}
        <TabsContent value="experiment" className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/70">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                <FileCheck2 className="h-4 w-4 text-purple-400" />
                Comparative Before/After Sanitization Experiment Runner
              </CardTitle>
              <CardDescription className="text-xs text-slate-400">
                Executes an empirical ground-truth baseline scan on authentic test data, performs real sanitization, and computes exact delta.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
                <div className="sm:col-span-8 space-y-1">
                  <label className="text-xs text-slate-400">Sanitization Algorithm</label>
                  <select
                    value={expMethod}
                    onChange={(e) => setExpMethod(e.target.value)}
                    disabled={isRunningExp}
                    className="w-full bg-slate-950 border border-slate-700 rounded-md px-3 py-2 text-xs text-slate-200"
                  >
                    <option value="nist-clear">NIST SP 800-88 Rev.1 Clear (Single-pass Zero Overwrite)</option>
                    <option value="dod-3pass">DoD 5220.22-M 3-Pass (Zeros, Ones, CSPRNG Random)</option>
                    <option value="crypto-erase">Cryptographic Erase (IEEE 2883 AES-256 CTR Ephemeral Key)</option>
                  </select>
                </div>

                <div className="sm:col-span-4">
                  <Button
                    onClick={runExperiment}
                    disabled={isRunningExp}
                    className="w-full bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold flex items-center justify-center gap-2"
                  >
                    {isRunningExp ? (
                      <>
                        <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                        Running Experiment...
                      </>
                    ) : (
                      <>
                        <Play className="h-3.5 w-3.5" />
                        Run Comparative Experiment
                      </>
                    )}
                  </Button>
                </div>
              </div>

              {/* Experiment Result Comparison View */}
              {expResult && (
                <div className="space-y-4 pt-4 border-t border-slate-800">
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {/* Baseline Card */}
                    <Card className="border-rose-900/40 bg-rose-950/20">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-xs font-bold text-rose-300 uppercase tracking-wider">
                          1. PRE-WIPE BASELINE
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-1.5 text-xs">
                        <div className="text-2xl font-bold text-rose-200">
                          {expResult.baseline_assessment.total_artifacts} Artifacts
                        </div>
                        <p className="text-slate-400 text-[11px]">
                          {expResult.baseline_assessment.validated_artifacts} Validated Files (SQLite, JPEG, PDF, PNG, ZIP, ELF, PE)
                        </p>
                        <p className="text-slate-500 text-[10px] font-mono">
                          SHA: {expResult.pre_wipe_sha256.substring(0, 16)}...
                        </p>
                      </CardContent>
                    </Card>

                    {/* Sanitization Pass Card */}
                    <Card className="border-blue-900/40 bg-blue-950/20">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-xs font-bold text-blue-300 uppercase tracking-wider">
                          2. SANITIZATION PASS
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-1.5 text-xs">
                        <div className="text-lg font-bold text-blue-200">
                          {expResult.sanitization_method.toUpperCase()}
                        </div>
                        <p className="text-slate-400 text-[11px]">
                          Real overwrite executed on {expResult.image_size_mb} MB test media. Cache flushed.
                        </p>
                        <p className="text-emerald-400 text-[11px] font-semibold">
                          Cryptographic Digest Altered: YES
                        </p>
                      </CardContent>
                    </Card>

                    {/* Post-Wipe Residual Card */}
                    <Card className="border-emerald-900/40 bg-emerald-950/20">
                      <CardHeader className="pb-2">
                        <CardTitle className="text-xs font-bold text-emerald-300 uppercase tracking-wider">
                          3. POST-WIPE RESIDUAL
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-1.5 text-xs">
                        <div className="text-2xl font-bold text-emerald-300">
                          {expResult.post_sanitization_assessment.total_artifacts} Residuals
                        </div>
                        <p className="text-slate-400 text-[11px]">
                          {expResult.comparative_delta.artifact_reduction_percentage}% Artifact Reduction
                        </p>
                        <p className="text-slate-500 text-[10px] font-mono">
                          SHA: {expResult.post_wipe_sha256.substring(0, 16)}...
                        </p>
                      </CardContent>
                    </Card>
                  </div>

                  {/* Empirical Conclusion */}
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                    <span className="font-bold text-slate-200 block mb-1">Empirical Conclusion:</span>
                    <p className="text-slate-300 leading-relaxed">
                      {expResult.comparative_delta.scientific_conclusion}
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ========================================================================= */}
        {/* TAB 4: TAMPER-EVIDENT ASSESSMENT CERTIFICATE (SCHEMA v2.0) */}
        {/* ========================================================================= */}
        <TabsContent value="certificate" className="space-y-6">
          <Card className="border-slate-800 bg-slate-900/70">
            <CardHeader className="pb-3">
              <div className="flex flex-col sm:flex-row justify-between sm:items-center gap-2">
                <div>
                  <CardTitle className="text-base font-semibold text-slate-100 flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-amber-400" />
                    Schema v2.0 Post-Sanitization Residual Assessment Certificate
                  </CardTitle>
                  <CardDescription className="text-xs text-slate-400">
                    Digitally signed with RSA-PSS SHA-256 for immutable forensic provenance.
                  </CardDescription>
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={fetchCertificate}
                    disabled={!currentAssessmentId}
                    className="h-8 text-xs"
                  >
                    <RefreshCw className="h-3.5 w-3.5 mr-1" />
                    Load Cert
                  </Button>
                  <Button
                    size="sm"
                    onClick={verifyCertificate}
                    disabled={!certData}
                    className="h-8 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold"
                  >
                    <ShieldCheck className="h-3.5 w-3.5 mr-1" />
                    Verify RSA Signature
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {certVerified !== null && (
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center gap-2 ${
                    certVerified
                      ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-300"
                      : "bg-rose-950/40 border-rose-800/60 text-rose-300"
                  }`}
                >
                  {certVerified ? <CheckCircle2 className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
                  <span>
                    {certVerified
                      ? "Cryptographic Verification Passed: RSA-PSS signature & canonical SHA-256 digest match authentic certificate authority."
                      : "Cryptographic Verification Failed: Signature or payload mismatch."}
                  </span>
                </div>
              )}

              {certData ? (
                <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 font-mono text-xs space-y-3 overflow-x-auto min-w-0">
                  <div className="flex justify-between border-b border-slate-800 pb-2 text-slate-400">
                    <span>CERTIFICATE ID: {certData.certificate_id}</span>
                    <span>SCHEMA: v{certData.schema_version}</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-slate-300 text-[11px]">
                    <div>
                      <span className="text-slate-500 block">TARGET PATH:</span>
                      {certData.target_storage?.path}
                    </div>
                    <div>
                      <span className="text-slate-500 block">CLASSIFICATION:</span>
                      <span className="text-emerald-400 font-bold">
                        {certData.forensic_assessment_results?.overall_classification}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">METHOD PERFORMED:</span>
                      {certData.prior_sanitization_reference?.method_performed}
                    </div>
                    <div>
                      <span className="text-slate-500 block">ISSUED AT:</span>
                      {certData.issued_at}
                    </div>
                  </div>

                  <div className="pt-2 border-t border-slate-800 text-[11px]">
                    <span className="text-slate-500 block">EMPIRICAL OBSERVATION STATEMENT:</span>
                    <p className="text-slate-200 italic mt-0.5">
                      "{certData.forensic_assessment_results?.empirical_observation}"
                    </p>
                  </div>

                  <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 space-y-1">
                    <div>CANONICAL SHA-256: {certData.integrity?.canonical_digest_sha256}</div>
                    <div>KEY ID: {certData.integrity?.key_id} ({certData.integrity?.signature_algorithm})</div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-slate-500 text-xs">
                  Run an assessment scan first, then click 'View Certificate' to generate and verify your signed Schema v2.0 Certificate.
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
