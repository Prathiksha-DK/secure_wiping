"use client";

import React, { useState, useEffect, useRef } from "react";
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
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ShieldCheck,
  Search,
  Database,
  HardDrive,
  FileCheck2,
  FolderTree,
  FileText,
  Download,
  Terminal,
  RefreshCw,
  Play,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Info,
  Timer,
  Lock,
  Layers,
  Folder,
  FileCode,
  FileCheck,
  ArrowRight,
  ExternalLink,
} from "lucide-react";
import { isFarisLocked, setFarisLock, showNavigationLockedAlert } from "@/lib/faris-lock";
import { cn } from "@/lib/utils";

const FARIS_SERVERS = [
  process.env.NEXT_PUBLIC_FARIS_API_URL || "http://localhost:8760",
  "http://localhost:9758",
];

async function fetchFaris(path: string, options?: RequestInit): Promise<Response> {
  const normPath = path.startsWith("/") ? path : `/${path}`;
  let lastErr: any = null;
  for (const base of FARIS_SERVERS) {
    try {
      const res = await fetch(`${base}${normPath}`, options);
      return res;
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error("Cannot connect to FARIS service on port 8760 or 9758");
}

const RECOVERY_BRANCHES = [
  { id: 1, key: "recovery_branch_1", name: "Metadata Recovery" },
  { id: 2, key: "recovery_branch_2", name: "File Carving" },
  { id: 3, key: "recovery_branch_3", name: "Structure & Fragment Recovery" },
  { id: 4, key: "recovery_branch_4", name: "AI/Statistical Fragment Ranking" },
  { id: 5, key: "recovery_branch_5", name: "Database Recovery" },
  { id: 6, key: "recovery_branch_6", name: "RAM / VMEM Memory Recovery" },
  { id: 7, key: "recovery_branch_7", name: "Headerless Stream Extraction" },
  { id: 8, key: "recovery_branch_8", name: "SQLite Deep Recovery" },
  { id: 9, key: "recovery_branch_9", name: "Correlation & Graph Reconstruction" },
  { id: 10, key: "recovery_branch_10", name: "Deep & Anti-Forensic Recovery" },
];

const SANITIZATION_STAGES = [
  { code: "A", key: "sanitization_a", name: "Overwrite Pattern Analysis" },
  { code: "B", key: "sanitization_b", name: "Residual Data / Remnant Analysis" },
  { code: "C", key: "sanitization_c", name: "Sector / Block-Level Recovery" },
  { code: "D", key: "sanitization_d", name: "Multi-Pass Pattern Analysis" },
  { code: "E", key: "sanitization_e", name: "File-System Journal / Log Analysis" },
  { code: "F", key: "sanitization_f", name: "SSD / NAND Remnant Analysis" },
  { code: "G", key: "sanitization_g", name: "Wear-Leveling Analysis" },
  { code: "H", key: "sanitization_h", name: "Hidden / Unallocated Area Analysis" },
  { code: "I", key: "sanitization_i", name: "Previous-State Reconstruction" },
  { code: "J", key: "sanitization_j", name: "Cryptographic-Erasure Analysis" },
];

interface LogEntry {
  timestamp: string;
  stage: string;
  status: string;
  pct: number;
  message: string;
}

interface StepLogEntry {
  timestamp: string;
  icon: string;
  text: string;
  type: "start" | "success" | "fail" | "na" | "info" | "branch";
}

interface CaseSummary {
  case_id: string;
  case_name: string;
  examiner: string;
  created_at: string;
  description: string;
}

export default function FarisRecoveryPage() {
  const [activeTab, setActiveTab] = useState<string>("pipeline");
  const [engineStatus, setEngineStatus] = useState<any>(null);
  const [devices, setDevices] = useState<any[]>([]);
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loadingStatus, setLoadingStatus] = useState<boolean>(true);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Recovery Scope Mode: "DEVICE" vs "FOLDER"
  const [recoveryScope, setRecoveryScope] = useState<"DEVICE" | "FOLDER">("DEVICE");
  const [folderPath, setFolderPath] = useState<string>("E:\\SecureWipe_Test");
  const [folderScopeData, setFolderScopeData] = useState<any>(null);
  const [isResolvingScope, setIsResolvingScope] = useState<boolean>(false);
  const [folderMethods, setFolderMethods] = useState<string[]>([
    "fs_hierarchy",
    "scoped_carving",
    "directory_slack",
    "fragment_correlation",
    "sha256_validation",
  ]);

  // Mandatory Pre-Start Form Inputs (Physical Device Only)
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [caseNumber, setCaseNumber] = useState<string>("");
  const [evidenceNumber, setEvidenceNumber] = useState<string>("");
  const [examinerName, setExaminerName] = useState<string>("");
  const [caseDescription, setCaseDescription] = useState<string>("");
  const [caseNotes, setCaseNotes] = useState<string>("");
  const [recoveryOutputPath, setRecoveryOutputPath] = useState<string>("D:/FARIS_Recovery_Output");
  const [partitionOffset, setPartitionOffset] = useState<string>("");

  // Pipeline Execution State
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [pipelineState, setPipelineState] = useState<any>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [stepLogs, setStepLogs] = useState<StepLogEntry[]>([]);
  const [isRunning, setIsRunning] = useState<boolean>(false);

  // Real Process Elapsed Timer
  const [startTimeMs, setStartTimeMs] = useState<number | null>(null);
  const [elapsedSeconds, setElapsedSeconds] = useState<number>(0);

  const logTerminalRef = useRef<HTMLDivElement>(null);
  const stepTerminalRef = useRef<HTMLDivElement>(null);

  // Case Explorer / Export State
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  const [caseDetails, setCaseDetails] = useState<any>(null);
  const [exportDestDir, setExportDestDir] = useState<string>("D:/FARIS_Recovery_Output");
  const [exportStatus, setExportStatus] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState<boolean>(false);

  // Read URL query params on mount for pre-populating folder scope from Storage Inspector
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const scopeParam = params.get("scope");
      const targetFolderParam = params.get("target_folder");
      const targetDeviceParam = params.get("target_device");

      if (scopeParam === "folder" || targetFolderParam) {
        setRecoveryScope("FOLDER");
        if (targetFolderParam) {
          setFolderPath(targetFolderParam);
          if (!caseNumber) {
            const folderBase = targetFolderParam.replace(/\\/g, "/").split("/").filter(Boolean).pop() || "FOLDER";
            setCaseNumber(`FARIS-FLD-${folderBase.toUpperCase()}`);
            setEvidenceNumber(`EVID-${folderBase.toUpperCase()}`);
          }
          handleResolveScope(targetFolderParam, targetDeviceParam || "");
        }
      }
    }
    refreshEnvironment();
  }, []);

  const refreshEnvironment = async () => {
    setLoadingStatus(true);
    setErrorMsg(null);
    try {
      // 1. Engine Inventory Status
      const engRes = await fetchFaris("/api/faris/engine-status");
      if (engRes.ok) {
        const engData = await engRes.json();
        setEngineStatus(engData);
      } else {
        setErrorMsg(`FARIS Service not responding. Ensure FARIS backend is active.`);
      }

      // 2. Discovered Physical Storage Media
      const devRes = await fetchFaris("/api/faris/devices");
      if (devRes.ok) {
        const devData = await devRes.json();
        const physicalDevs = devData.physical_devices || [];
        setDevices(physicalDevs);
        if (physicalDevs.length > 0 && !selectedDevice) {
          const removable = physicalDevs.find((d: any) => d.is_removable);
          const defaultDev = removable || physicalDevs[0];
          setSelectedDevice(defaultDev.device_id || defaultDev.physical_path);
        }
      }

      // 3. Existing Case Catalog
      const casesRes = await fetchFaris("/api/faris/cases");
      if (casesRes.ok) {
        const casesData = await casesRes.json();
        setCases(casesData.cases || []);
      }
    } catch (err: any) {
      setErrorMsg(`Cannot connect to FARIS backend: ${err.message}.`);
    } finally {
      setLoadingStatus(false);
    }
  };

  const handleResolveScope = async (pathOverride?: string, devOverride?: string) => {
    const targetP = pathOverride || folderPath;
    if (!targetP.trim()) {
      setErrorMsg("Please enter a valid folder path to inspect.");
      return;
    }
    setIsResolvingScope(true);
    setErrorMsg(null);
    try {
      const res = await fetchFaris("/api/faris/folder/resolve-scope", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          folder_path: targetP.trim(),
          target_device: devOverride || selectedDevice || undefined,
        }),
      });
      const data = await res.json();
      if (res.ok && data.status !== "ERROR") {
        setFolderScopeData(data);
        if (data.device_path && !selectedDevice) {
          setSelectedDevice(data.device_path);
        }
      } else {
        setErrorMsg(data.error || data.message || "Failed to resolve folder scope.");
      }
    } catch (e: any) {
      setErrorMsg(`Error resolving folder scope: ${e.message}`);
    } finally {
      setIsResolvingScope(false);
    }
  };

  const loadCaseDetails = async (cId: string) => {
    if (!cId) return;
    try {
      const res = await fetchFaris(`/api/faris/cases/${cId}`);
      if (res.ok) {
        const data = await res.json();
        setCaseDetails(data.case);
      }
    } catch (e) {
      console.error("Error loading case details:", e);
    }
  };

  // Real Timer Interval
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (isRunning && startTimeMs) {
      interval = setInterval(() => {
        setElapsedSeconds(Math.floor((Date.now() - startTimeMs) / 1000));
      }, 1000);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isRunning, startTimeMs]);

  const formatElapsed = (totalSecs: number): string => {
    const hrs = Math.floor(totalSecs / 3600);
    const mins = Math.floor((totalSecs % 3600) / 60);
    const secs = totalSecs % 60;
    return `${hrs.toString().padStart(2, "0")}:${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  // Build structured Step Logs from real engine events
  const updateStepLogs = (rawLogs: LogEntry[], job: any) => {
    const steps: StepLogEntry[] = [];
    rawLogs.forEach((log) => {
      steps.push({
        timestamp: log.timestamp || "00:00:00",
        icon: log.status === "COMPLETED" ? "✓" : log.status === "FAILED" ? "✗" : "▶",
        text: log.message,
        type: log.status === "COMPLETED" ? "success" : log.status === "FAILED" ? "fail" : "info",
      });
    });
    setStepLogs(steps);
  };

  // Prevent accidental navigation / reload during active execution
  useEffect(() => {
    const handleBeforeUnload = (e: BeforeUnloadEvent) => {
      if (isRunning) {
        e.preventDefault();
        e.returnValue = "Navigation is disabled while FARIS recovery is in progress. Please wait until the process is completed.";
        return e.returnValue;
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, [isRunning]);

  // Unified Polling for both Device Pipeline and Folder Recovery jobs
  useEffect(() => {
    if (!activeJobId || !isRunning) return;

    const interval = setInterval(async () => {
      try {
        const isFld = activeJobId.startsWith("JOB-FLD-");
        const statusUrl = isFld
          ? `/api/faris/folder/jobs/${activeJobId}`
          : `/api/faris/pipeline/status/${activeJobId}`;

        const res = await fetchFaris(statusUrl);
        if (res.ok) {
          const job = await res.json();
          setPipelineState(job);
          const currentRawLogs = job.logs || [];
          setLogs(currentRawLogs);
          updateStepLogs(currentRawLogs, job);

          if (job.status === "SUCCESS" || job.status === "FAILED") {
            setIsRunning(false);
            setFarisLock(false);
            if (job.start_time && job.end_time) {
              setElapsedSeconds(Math.max(1, Math.round(job.end_time - job.start_time)));
            }
            refreshEnvironment();
            if (job.case_id) {
              setSelectedCaseId(job.case_id);
              loadCaseDetails(job.case_id);
            }
          }
        }
      } catch (err) {
        console.error("Pipeline polling error:", err);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [activeJobId, isRunning]);

  // Auto scroll logs terminals
  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [logs]);

  useEffect(() => {
    if (stepTerminalRef.current) {
      stepTerminalRef.current.scrollTop = stepTerminalRef.current.scrollHeight;
    }
  }, [stepLogs]);

  // Start Device Pipeline
  const handleStartPipeline = async () => {
    setErrorMsg(null);

    if (!selectedDevice) {
      setErrorMsg("No physical target storage device selected. Please select a valid device.");
      return;
    }
    if (!caseNumber.trim()) {
      setErrorMsg("Case Number / Case ID is mandatory. Please enter a valid case identifier.");
      return;
    }
    if (!evidenceNumber.trim()) {
      setErrorMsg("Evidence Number / ID is mandatory. Please enter a valid evidence identifier.");
      return;
    }
    if (!examinerName.trim()) {
      setErrorMsg("Examiner Name is mandatory. Please enter the forensic investigator's name.");
      return;
    }
    if (!recoveryOutputPath.trim()) {
      setErrorMsg("Recovery Output Path is mandatory. Specify where recovered files should be saved.");
      return;
    }

    const cleanOutput = recoveryOutputPath.trim().toLowerCase();
    const cleanSource = selectedDevice.trim().toLowerCase();
    if (cleanOutput === cleanSource || (cleanSource.length > 2 && cleanOutput.includes(cleanSource))) {
      setErrorMsg("SAFETY VIOLATION: Recovery output destination cannot reside on or inside the source evidence device.");
      return;
    }

    const payload = {
      case_id: caseNumber.trim(),
      evidence_id: evidenceNumber.trim(),
      examiner: examinerName.trim(),
      description: caseDescription.trim() || `Forensic Case ${caseNumber.trim()}`,
      notes: caseNotes.trim(),
      is_physical: true,
      source_type: "Physical Storage Device",
      source_path: selectedDevice,
      recovery_output_path: recoveryOutputPath.trim(),
      export_destination: recoveryOutputPath.trim(),
      partition_offset: partitionOffset.trim() ? parseInt(partitionOffset.trim(), 10) : null,
    };

    try {
      const now = Date.now();
      setStartTimeMs(now);
      setElapsedSeconds(0);
      setIsRunning(true);
      setFarisLock(true);
      setLogs([]);

      const res = await fetchFaris("/api/faris/pipeline/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || "Failed to start FARIS pipeline");
      }

      const data = await res.json();
      setActiveJobId(data.job_id);
    } catch (err: any) {
      setIsRunning(false);
      setFarisLock(false);
      setErrorMsg(err.message);
    }
  };

  // Start Folder Recovery
  const handleStartFolderRecovery = async () => {
    setErrorMsg(null);

    if (!folderPath.trim()) {
      setErrorMsg("Target folder path is required for folder recovery.");
      return;
    }
    if (!caseNumber.trim()) {
      setErrorMsg("Case Number / Case ID is mandatory.");
      return;
    }
    if (!recoveryOutputPath.trim()) {
      setErrorMsg("Recovery Output Directory is mandatory.");
      return;
    }

    const srcLetter = folderPath.trim().substring(0, 2).toUpperCase();
    const destLetter = recoveryOutputPath.trim().substring(0, 2).toUpperCase();
    if (srcLetter.includes(":") && destLetter.includes(":") && srcLetter === destLetter) {
      setErrorMsg(`SAFETY VIOLATION: Recovery output destination cannot reside on the same drive (${destLetter}) as the source folder (${srcLetter}).`);
      return;
    }

    const payload = {
      case_id: caseNumber.trim(),
      folder_path: folderPath.trim(),
      target_device: selectedDevice || undefined,
      examiner: examinerName.trim() || "Forensic Examiner",
      recovery_output_path: recoveryOutputPath.trim(),
      export_destination: recoveryOutputPath.trim(),
      selected_methods: folderMethods,
    };

    try {
      const now = Date.now();
      setStartTimeMs(now);
      setElapsedSeconds(0);
      setIsRunning(true);
      setFarisLock(true);
      setLogs([]);

      const res = await fetchFaris("/api/faris/folder/recover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.message || "Failed to start FARIS folder recovery");
      }

      const data = await res.json();
      setActiveJobId(data.job_id);
    } catch (err: any) {
      setIsRunning(false);
      setFarisLock(false);
      setErrorMsg(err.message);
    }
  };

  const handleExportArtifacts = async () => {
    if (!selectedCaseId || !exportDestDir.trim()) return;
    setIsExporting(true);
    setExportStatus(null);
    try {
      const res = await fetchFaris("/api/faris/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          case_id: selectedCaseId,
          destination_dir: exportDestDir.trim(),
        }),
      });
      const data = await res.json();
      if (res.ok && data.status === "SUCCESS") {
        setExportStatus(`Exported ${data.exported_count} verified artifacts to ${data.destination} with SHA-256 verification.`);
      } else {
        setExportStatus(`Export failed: ${data.message || "Unknown error"}`);
      }
    } catch (e: any) {
      setExportStatus(`Export error: ${e.message}`);
    } finally {
      setIsExporting(false);
    }
  };

  const deviceStagesList = [
    { key: "setup", label: "1. Case Initialized" },
    { key: "acquisition", label: "2. Real Bit-Stream E01 Acquisition" },
    { key: "verification", label: "3. Cryptographic Verification (SHA-256)" },
    { key: "analysis", label: "4. Partition & Filesystem Analysis" },
    { key: "discovery", label: "5. Inode & Artifact Discovery (TSK)" },
    { key: "states", label: "6. Allocation State Classification" },
    { key: "recovery", label: "7. 10-Branch Adaptive Recovery" },
    { key: "sanitization", label: "8. Sanitization Verification (Stages A–J)" },
    { key: "validation", label: "9. Deep Format Validation" },
    { key: "hashing", label: "10. SHA-256 Manifest Hashing" },
    { key: "export", label: "11. Verified Artifacts Export" },
    { key: "reporting", label: "12. Multi-Format Reports Generated" },
  ];

  const folderStagesList = [
    { key: "setup", label: "1. Case Workspace Initialized" },
    { key: "scope_resolution", label: "2. Folder Allocation & LBA Mapping" },
    { key: "fs_recovery", label: "3. Pass 1: Filesystem Structure Extraction" },
    { key: "carving", label: "4. Pass 2: Scoped Forensic Carving" },
    { key: "validation", label: "5. Integrity & Confidence Validation" },
    { key: "hashing", label: "6. SHA-256 Cryptographic Manifest" },
    { key: "reporting", label: "7. Multi-Format Forensic Reporting" },
  ];

  const activeStagesList = recoveryScope === "FOLDER" ? folderStagesList : deviceStagesList;

  const getSelectedDeviceObj = () => {
    return devices.find((d: any) => (d.device_id || d.physical_path) === selectedDevice) || null;
  };

  return (
    <div className="flex flex-col gap-6 max-w-7xl mx-auto w-full pb-12">
      {/* Top Banner Header */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-6 bg-card border rounded-xl shadow-sm">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-600/10 text-blue-600 dark:text-blue-400 rounded-xl border border-blue-200 dark:border-blue-900">
            <Search className="w-8 h-8" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight">FARIS Forensic Recovery System</h1>
              <Badge variant="outline" className="border-blue-500 text-blue-600 dark:text-blue-400 font-mono">
                {recoveryScope === "FOLDER" ? "Folder-Level Scoped Recovery" : "Live Physical Device Pipeline"}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground mt-1">
              {recoveryScope === "FOLDER"
                ? "Filesystem Hierarchy Preservation · Cluster-to-LBA Extent Mapping · Scoped Carving · Bit-for-Bit Validation"
                : "Physical Device Discovery · Bit-Stream E01 Acquisition · 10-Branch Deep Recovery · Verification & Export"}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-muted/80 border rounded-lg font-mono text-xs shadow-sm">
            <Timer className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span className="text-muted-foreground">Elapsed:</span>
            <span className="font-bold text-foreground">{formatElapsed(elapsedSeconds)}</span>
          </div>

          <Badge variant={engineStatus?.status === "SUCCESS" ? "default" : "destructive"} className="gap-1.5 py-1.5 px-3">
            <ShieldCheck className="w-3.5 h-3.5" />
            {engineStatus?.status === "SUCCESS" ? "Engines Available" : "Engines Offline"}
          </Badge>
          <Button variant="outline" size="sm" onClick={refreshEnvironment} disabled={loadingStatus} className="gap-1.5">
            <RefreshCw className={`w-3.5 h-3.5 ${loadingStatus ? "animate-spin" : ""}`} />
            Refresh Devices
          </Button>
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-3 p-4 bg-red-500/10 border border-red-500/20 text-red-600 dark:text-red-400 rounded-lg text-sm">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <div className="flex-1 font-medium">{errorMsg}</div>
        </div>
      )}

      {/* Main Tabs Navigation */}
      <Tabs
        value={activeTab}
        onValueChange={(val) => {
          if (isRunning && val !== "pipeline") {
            showNavigationLockedAlert();
            return;
          }
          setActiveTab(val);
        }}
        className="w-full space-y-6"
      >
        <TabsList className="grid grid-cols-4 w-full h-11 bg-muted/60 p-1">
          <TabsTrigger value="pipeline" className="gap-2 text-xs md:text-sm">
            <Play className="w-4 h-4" />
            Recovery Pipeline
          </TabsTrigger>
          <TabsTrigger
            value="artifacts"
            disabled={isRunning}
            onClick={(e) => {
              if (isRunning) {
                e.preventDefault();
                showNavigationLockedAlert();
              }
            }}
            className={cn("gap-2 text-xs md:text-sm", isRunning && "opacity-60 cursor-not-allowed")}
          >
            {isRunning ? <Lock className="w-3.5 h-3.5 text-amber-500" /> : <FileCheck2 className="w-4 h-4" />}
            Recovered Artifacts & Validation
          </TabsTrigger>
          <TabsTrigger
            value="explorer"
            disabled={isRunning}
            onClick={(e) => {
              if (isRunning) {
                e.preventDefault();
                showNavigationLockedAlert();
              }
            }}
            className={cn("gap-2 text-xs md:text-sm", isRunning && "opacity-60 cursor-not-allowed")}
          >
            {isRunning ? <Lock className="w-3.5 h-3.5 text-amber-500" /> : <FolderTree className="w-4 h-4" />}
            Case Explorer & Reports
          </TabsTrigger>
          <TabsTrigger
            value="audit"
            disabled={isRunning}
            onClick={(e) => {
              if (isRunning) {
                e.preventDefault();
                showNavigationLockedAlert();
              }
            }}
            className={cn("gap-2 text-xs md:text-sm", isRunning && "opacity-60 cursor-not-allowed")}
          >
            {isRunning ? <Lock className="w-3.5 h-3.5 text-amber-500" /> : <ShieldCheck className="w-4 h-4" />}
            Chain of Custody & Audit
          </TabsTrigger>
        </TabsList>

        {/* TAB 1: LIVE RECOVERY PIPELINE */}
        <TabsContent value="pipeline" className="space-y-6">
          {/* Recovery Scope Switcher */}
          <div className="flex items-center justify-between p-3 bg-card border rounded-lg shadow-sm">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">Recovery Scope:</span>
              <div className="flex p-0.5 bg-muted rounded-md border">
                <Button
                  size="sm"
                  variant={recoveryScope === "DEVICE" ? "default" : "ghost"}
                  onClick={() => setRecoveryScope("DEVICE")}
                  disabled={isRunning}
                  className="h-8 text-xs font-semibold gap-1.5 px-3"
                >
                  <HardDrive className="h-3.5 w-3.5" /> Entire Physical Storage Device / Raw Image
                </Button>
                <Button
                  size="sm"
                  variant={recoveryScope === "FOLDER" ? "default" : "ghost"}
                  onClick={() => setRecoveryScope("FOLDER")}
                  disabled={isRunning}
                  className="h-8 text-xs font-semibold gap-1.5 px-3"
                >
                  <FolderTree className="h-3.5 w-3.5 text-amber-500" /> Selected Target Folder (Scoped Recovery)
                </Button>
              </div>
            </div>

            <Badge variant="outline" className="font-mono text-xs">
              {recoveryScope === "FOLDER" ? "Scope: Folder Extents Only" : "Scope: Whole Disk Bit-Stream"}
            </Badge>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Form Column */}
            <Card className="lg:col-span-5 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="w-5 h-5 text-primary" />
                  {recoveryScope === "FOLDER" ? "Folder Recovery Setup" : "Forensic Case & Evidence Details"}
                </CardTitle>
                <CardDescription>
                  {recoveryScope === "FOLDER"
                    ? "Specify target folder and inspect allocation scope before initiating recovery."
                    : "Select target physical drive and supply mandatory case parameters."}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Scope: FOLDER Setup Controls */}
                {recoveryScope === "FOLDER" ? (
                  <div className="space-y-3">
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                        Target Folder Path *
                      </label>
                      <div className="flex gap-2">
                        <Input
                          value={folderPath}
                          onChange={(e) => setFolderPath(e.target.value)}
                          placeholder="e.g. E:\SecureWipe_Test"
                          className="text-xs font-mono"
                        />
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => handleResolveScope()}
                          disabled={isResolvingScope || isRunning}
                          className="gap-1.5 text-xs font-semibold px-3"
                        >
                          <Search className={`w-3.5 h-3.5 ${isResolvingScope ? "animate-spin" : ""}`} />
                          Inspect Scope
                        </Button>
                      </div>
                    </div>

                    {/* Scope Overview Card */}
                    {folderScopeData && (
                      <div className="p-3 bg-muted/40 border rounded-lg space-y-2.5 text-xs font-mono">
                        <div className="flex items-center justify-between border-b pb-1.5">
                          <span className="font-bold text-foreground flex items-center gap-1.5">
                            <Folder className="w-3.5 h-3.5 text-amber-500" />
                            {folderScopeData.folder_name || folderPath}
                          </span>
                          <Badge variant="secondary" className="font-mono text-[10px]">
                            {folderScopeData.filesystem || "FAT32"} | {folderScopeData.device_path || "\\\\.\\PhysicalDrive1"}
                          </Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-[11px]">
                          <div>
                            <span className="text-muted-foreground">Directory Cluster:</span>{" "}
                            <span className="font-semibold text-amber-600 dark:text-amber-400">
                              {folderScopeData.directory_allocation?.starting_cluster ?? "OS-Managed"}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Directory LBA:</span>{" "}
                            <span className="font-semibold text-primary">
                              {folderScopeData.directory_allocation?.starting_lba ?? "N/A"}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Active Files:</span>{" "}
                            <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                              {folderScopeData.child_files_count || 0}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Deleted Entries:</span>{" "}
                            <span className={cn(
                              "font-semibold",
                              (folderScopeData.deleted_files_count || 0) > 0
                                ? "text-purple-600 dark:text-purple-400 font-bold"
                                : "text-muted-foreground"
                            )}>
                              {folderScopeData.deleted_files_count || 0}
                            </span>
                          </div>
                          <div className="col-span-2">
                            <span className="text-muted-foreground">Total Mapped Sectors:</span>{" "}
                            <span className="font-semibold">
                              {folderScopeData.combined_storage_map?.total_sectors || 0} ({((folderScopeData.combined_storage_map?.total_sectors || 0) * (folderScopeData.bytes_per_sector || 512)).toLocaleString()} bytes)
                            </span>
                          </div>
                        </div>

                        {/* Child Active Files Breakdown */}
                        {folderScopeData.child_files && folderScopeData.child_files.length > 0 && (
                          <div className="pt-2 border-t space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] uppercase font-bold text-muted-foreground tracking-wider flex items-center gap-1">
                                <FileCheck className="w-3 h-3 text-emerald-500" />
                                Active Files ({folderScopeData.child_files.length}):
                              </span>
                            </div>
                            <div className="max-h-24 overflow-y-auto space-y-1 pr-1">
                              {folderScopeData.child_files.map((cf: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between p-1.5 bg-background border rounded text-[10px]"
                                >
                                  <span className="font-semibold truncate max-w-[130px]" title={cf.full_path || cf.name}>
                                    {cf.name || cf.relative_path}
                                  </span>
                                  <div className="flex items-center gap-1.5 text-muted-foreground">
                                    <span>Clus {cf.starting_cluster ?? "?"}</span>
                                    <span className="text-primary font-semibold">
                                      LBA {cf.starting_lba ?? "N/A"}
                                    </span>
                                    <span>{cf.size ? `${cf.size}B` : "0B"}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Deleted Directory Entries Breakdown */}
                        {folderScopeData.deleted_entries && folderScopeData.deleted_entries.length > 0 && (
                          <div className="pt-2 border-t space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] uppercase font-bold text-purple-600 dark:text-purple-400 tracking-wider flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3 text-purple-500" />
                                Discovered Deleted Entries ({folderScopeData.deleted_entries.length}):
                              </span>
                              <Badge variant="outline" className="text-[9px] bg-purple-500/10 text-purple-600 border-purple-500/30 px-1 py-0">
                                0xE5 Marker Detected
                              </Badge>
                            </div>
                            <div className="max-h-28 overflow-y-auto space-y-1 pr-1">
                              {folderScopeData.deleted_entries.map((df: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="flex items-center justify-between p-1.5 bg-purple-500/5 border border-purple-500/20 rounded text-[10px]"
                                >
                                  <div className="flex items-center gap-1 truncate max-w-[130px]">
                                    <Badge variant="secondary" className="text-[8px] bg-purple-500/20 text-purple-700 dark:text-purple-300 font-mono px-1 py-0">
                                      DEL
                                    </Badge>
                                    <span className="font-semibold truncate text-purple-900 dark:text-purple-200" title={df.full_path || df.name}>
                                      {df.name || df.relative_path}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-1.5 text-muted-foreground">
                                    <span>Clus {df.starting_cluster ?? "0"}</span>
                                    <span className="text-primary font-semibold">
                                      LBA {df.starting_lba ?? "N/A"}
                                    </span>
                                    <span>{df.size ? `${df.size}B` : "0B"}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        <div className="pt-1 flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>Layer: {folderScopeData.mapping_layer || "Device Logical LBA"}</span>
                          <a
                            href={`/inspector?drive=${encodeURIComponent(folderPath.substring(0, 2))}&mode=folder&folder_path=${encodeURIComponent(folderPath)}`}
                            className="text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1 font-sans"
                            target="_blank"
                            rel="noreferrer"
                          >
                            Open in Sector Inspector <ExternalLink className="w-2.5 h-2.5" />
                          </a>
                        </div>
                      </div>
                    )}

                    {/* Forensic Methods Checklist */}
                    <div className="space-y-1.5 pt-1">
                      <label className="text-xs font-semibold text-muted-foreground">Forensic Recovery Methods</label>
                      <div className="grid grid-cols-1 gap-1.5 text-xs bg-muted/30 p-2.5 rounded-lg border">
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={folderMethods.includes("fs_hierarchy")}
                            onChange={(e) => {
                              if (e.target.checked) setFolderMethods([...folderMethods, "fs_hierarchy"]);
                              else setFolderMethods(folderMethods.filter((m) => m !== "fs_hierarchy"));
                            }}
                            className="rounded"
                          />
                          <span>Pass 1: Filesystem Hierarchy & Extents Extraction</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={folderMethods.includes("scoped_carving")}
                            onChange={(e) => {
                              if (e.target.checked) setFolderMethods([...folderMethods, "scoped_carving"]);
                              else setFolderMethods(folderMethods.filter((m) => m !== "scoped_carving"));
                            }}
                            className="rounded"
                          />
                          <span>Pass 2: Scoped Forensic Signature Carving</span>
                        </label>
                        <label className="flex items-center gap-2 cursor-pointer">
                          <input
                            type="checkbox"
                            checked={folderMethods.includes("sha256_validation")}
                            onChange={(e) => {
                              if (e.target.checked) setFolderMethods([...folderMethods, "sha256_validation"]);
                              else setFolderMethods(folderMethods.filter((m) => m !== "sha256_validation"));
                            }}
                            className="rounded"
                          />
                          <span>Pass 3: Cryptographic SHA-256 Bit-for-Bit Validation</span>
                        </label>
                      </div>
                    </div>
                  </div>
                ) : (
                  /* Scope: DEVICE Physical Media Selector */
                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      Select Target Physical Storage Device *
                    </label>
                    {devices.length === 0 ? (
                      <div className="p-3 bg-muted/50 border rounded-md text-xs text-muted-foreground text-center">
                        Scanning storage subsystem... No physical drives found.
                      </div>
                    ) : (
                      <select
                        value={selectedDevice}
                        onChange={(e) => setSelectedDevice(e.target.value)}
                        className="w-full p-2.5 bg-background border rounded-md text-xs font-mono"
                      >
                        {devices.map((d: any, idx: number) => (
                          <option key={idx} value={d.device_id || d.physical_path}>
                            {d.model} ({d.size_formatted}) [{d.drive_letters || "No Volume"}] — {d.device_id}
                          </option>
                        ))}
                      </select>
                    )}
                    {getSelectedDeviceObj() && (
                      <div className="p-2.5 bg-muted/40 border rounded-md text-[11px] space-y-1 font-mono">
                        <div>Model: <span className="font-semibold">{getSelectedDeviceObj()?.model}</span></div>
                        <div>Capacity: <span className="font-semibold">{getSelectedDeviceObj()?.size_formatted}</span> ({getSelectedDeviceObj()?.size_bytes?.toLocaleString()} bytes)</div>
                        <div>Interface: {getSelectedDeviceObj()?.interface} | Type: {getSelectedDeviceObj()?.device_type}</div>
                        <div>Serial: {getSelectedDeviceObj()?.serial_number} | Volume: {getSelectedDeviceObj()?.drive_letters}</div>
                      </div>
                    )}
                  </div>
                )}

                {/* Shared Mandatory Case Details */}
                <div className="grid grid-cols-2 gap-3 pt-1">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground">Case Number *</label>
                    <Input
                      value={caseNumber}
                      onChange={(e) => {
                        const val = e.target.value;
                        setCaseNumber(val);
                        if (val.trim()) {
                          setRecoveryOutputPath(`D:/wiping/FARIS/cases/${val.trim()}/exported`);
                        }
                      }}
                      className="text-xs font-mono"
                      placeholder="e.g. CASE-2026-001"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground">Evidence Number *</label>
                    <Input
                      value={evidenceNumber}
                      onChange={(e) => setEvidenceNumber(e.target.value)}
                      className="text-xs font-mono"
                      placeholder="e.g. EVID-USB-01"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground">Examiner Name *</label>
                    <Input
                      value={examinerName}
                      onChange={(e) => setExaminerName(e.target.value)}
                      className="text-xs"
                      placeholder="e.g. Jane Doe, EnCE"
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-muted-foreground">Recovery Output Directory *</label>
                    <Input
                      value={recoveryOutputPath}
                      onChange={(e) => setRecoveryOutputPath(e.target.value)}
                      className="text-xs font-mono"
                      placeholder="e.g. D:/FARIS_Recovery_Output"
                    />
                  </div>
                </div>

                {/* Evidence Protection Box */}
                <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg text-[11px] space-y-1 text-blue-800 dark:text-blue-300">
                  <div className="font-bold flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                    Strict Read-Only & Output Isolation Guarantee
                  </div>
                  <div>• <span className="font-semibold">Source Media:</span> Strictly READ-ONLY (GENERIC_READ / No mutation)</div>
                  <div>• <span className="font-semibold">Destination:</span> Isolated output folder ({recoveryOutputPath || "D:/FARIS_Recovery_Output"})</div>
                </div>
              </CardContent>
              <CardFooter>
                <Button
                  onClick={recoveryScope === "FOLDER" ? handleStartFolderRecovery : handleStartPipeline}
                  disabled={isRunning}
                  className="w-full gap-2 font-semibold bg-blue-600 hover:bg-blue-700 text-white shadow"
                >
                  {isRunning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Executing Recovery ({formatElapsed(elapsedSeconds)})...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      {recoveryScope === "FOLDER" ? "START FOLDER FORENSIC RECOVERY" : "START FORENSIC ACQUISITION & RECOVERY"}
                    </>
                  )}
                </Button>
              </CardFooter>
            </Card>

            {/* Live Telemetry Column */}
            <div className="lg:col-span-7 flex flex-col gap-5">
              <Card className="shadow-sm">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base font-bold flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-blue-600" />
                        Live Recovery Telemetry
                      </CardTitle>
                      <CardDescription className="text-xs">
                        {activeJobId ? `Job ID: ${activeJobId} · Scope: ${pipelineState?.scope || recoveryScope}` : "Waiting to launch pipeline"}
                      </CardDescription>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1 px-2.5 py-1 bg-muted border rounded-md font-mono text-xs">
                        <Clock className="w-3.5 h-3.5 text-blue-600" />
                        <span className="font-bold">{formatElapsed(elapsedSeconds)}</span>
                      </div>
                      {pipelineState && (
                        <Badge
                          variant={
                            pipelineState.status === "SUCCESS"
                              ? "default"
                              : pipelineState.status === "FAILED"
                              ? "destructive"
                              : "outline"
                          }
                          className="font-mono text-xs"
                        >
                          {pipelineState.status}
                        </Badge>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-1.5">
                    <div className="flex justify-between text-xs font-medium">
                      <span>Overall Progress</span>
                      <span className="font-mono">{pipelineState?.progress_pct?.toFixed(0) || 0}%</span>
                    </div>
                    <Progress value={pipelineState?.progress_pct || 0} className="h-2.5" />
                  </div>

                  {/* Stage By Stage Tracker */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2">
                    {activeStagesList.map((st) => {
                      const stState = pipelineState?.stages?.[st.key];
                      const isComplete = stState?.status === "COMPLETED";
                      const isCurrent = stState?.status === "RUNNING";
                      const isFailed = stState?.status === "FAILED";
                      const isNA = stState?.status === "N/A";

                      return (
                        <div
                          key={st.key}
                          className={`flex items-center justify-between p-2 rounded-lg border text-xs transition-colors ${
                            isComplete
                              ? "bg-green-500/10 border-green-500/30 text-green-700 dark:text-green-300"
                              : isCurrent
                              ? "bg-blue-500/10 border-blue-500/40 text-blue-700 dark:text-blue-300 font-semibold"
                              : isFailed
                              ? "bg-red-500/10 border-red-500/30 text-red-700 dark:text-red-300"
                              : isNA
                              ? "bg-muted/40 border-dashed text-muted-foreground"
                              : "bg-card border-border text-muted-foreground opacity-60"
                          }`}
                        >
                          <div className="flex items-center gap-2 truncate">
                            {isComplete && <CheckCircle2 className="w-3.5 h-3.5 text-green-600 flex-shrink-0" />}
                            {isCurrent && <RefreshCw className="w-3.5 h-3.5 text-blue-600 animate-spin flex-shrink-0" />}
                            {isFailed && <XCircle className="w-3.5 h-3.5 text-red-600 flex-shrink-0" />}
                            {isNA && <Info className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />}
                            {!isComplete && !isCurrent && !isFailed && !isNA && (
                              <Clock className="w-3.5 h-3.5 flex-shrink-0" />
                            )}
                            <span className="truncate">{st.label}</span>
                          </div>
                          <Badge
                            variant={isComplete ? "default" : isCurrent ? "outline" : "secondary"}
                            className="text-[10px] uppercase font-mono px-1.5 py-0"
                          >
                            {stState?.status || "WAITING"}
                          </Badge>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>

              {/* Console Output Terminal */}
              <Card className="shadow-sm flex flex-col">
                <CardHeader className="py-2 px-3 bg-muted/40 border-b flex flex-row items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs font-mono font-semibold">
                    <Terminal className="w-3.5 h-3.5 text-blue-500" />
                    FARIS Live Engine Execution Console
                  </div>
                  <Badge variant="outline" className="text-[10px] font-mono">
                    {logs.length} events
                  </Badge>
                </CardHeader>
                <CardContent className="p-0">
                  <div
                    ref={logTerminalRef}
                    className="h-44 p-3 bg-zinc-950 text-zinc-200 font-mono text-[11px] leading-relaxed overflow-y-auto space-y-1"
                  >
                    {logs.length === 0 ? (
                      <div className="text-zinc-500 italic">
                        Ready. Fill case parameters and click &apos;START RECOVERY&apos; to begin.
                      </div>
                    ) : (
                      logs.map((log, idx) => (
                        <div key={idx} className="flex items-start gap-2">
                          <span className="text-zinc-500 select-none">[{log.timestamp}]</span>
                          <span className="text-blue-400 font-semibold select-none">[{log.stage}]</span>
                          <span
                            className={
                              log.status === "COMPLETED"
                                ? "text-green-400"
                                : log.status === "FAILED"
                                ? "text-red-400 font-bold"
                                : "text-zinc-200"
                            }
                          >
                            {log.message}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* ITEMIZE FORENSIC ARTIFACT LEDGER (When Folder Recovery finishes or has items) */}
          {pipelineState?.result?.recovered_items && pipelineState.result.recovered_items.length > 0 && (
            <Card className="shadow-sm">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="text-base font-bold flex items-center gap-2">
                      <FileCheck2 className="w-4 h-4 text-emerald-600" />
                      Recovered Folder Artifacts & Cryptographic Verification Ledger
                    </CardTitle>
                    <CardDescription className="text-xs font-mono">
                      Destination: {pipelineState.result.destination_directory} · Total Items: {pipelineState.result.total_recovered_count}
                    </CardDescription>
                  </div>
                  <Badge variant="outline" className="text-xs bg-emerald-500/10 text-emerald-600 border-emerald-500/30">
                    {pipelineState.result.recovered_files_count} FS Files | {pipelineState.result.carved_artifacts_count} Scoped Carved
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs text-left border-collapse">
                    <thead className="bg-muted/50 text-muted-foreground uppercase text-[10px] font-semibold border-y">
                      <tr>
                        <th className="py-2.5 px-4">Relative Path</th>
                        <th className="py-2.5 px-3">State</th>
                        <th className="py-2.5 px-3">Status</th>
                        <th className="py-2.5 px-3">Validation</th>
                        <th className="py-2.5 px-3">Size</th>
                        <th className="py-2.5 px-3">Start Cluster</th>
                        <th className="py-2.5 px-3">Device Logical LBA</th>
                        <th className="py-2.5 px-3">SHA-256 Digest</th>
                        <th className="py-2.5 px-3">Recovery Source & Method</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y font-mono text-[11px]">
                      {pipelineState.result.recovered_items.map((item: any, idx: number) => {
                        const isDel = item.state === "DELETED" || item.recovery_source?.includes("Deleted") || item.recovery_source?.includes("1B");
                        const isCarved = item.state === "CARVED" || item.recovery_source?.includes("Carving") || item.recovery_source?.includes("Pass 2");
                        
                        return (
                          <tr key={idx} className={cn("hover:bg-muted/30 transition-colors", isDel && "bg-purple-500/5 hover:bg-purple-500/10")}>
                            <td className="py-2 px-4 font-semibold text-foreground flex items-center gap-1.5">
                              {isDel ? (
                                <span className="text-purple-600 dark:text-purple-400 font-bold" title="Deleted Directory Entry">🗑️</span>
                              ) : isCarved ? (
                                <span className="text-amber-500" title="Signature Carved">⚡</span>
                              ) : (
                                <span className="text-emerald-500" title="Active File">📄</span>
                              )}
                              <span className="truncate max-w-[200px]" title={item.relative_path || item.name}>
                                {item.relative_path || item.name}
                              </span>
                            </td>
                            <td className="py-2 px-3">
                              {isDel ? (
                                <Badge variant="outline" className="text-[9px] bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30 px-1.5 py-0 font-bold">
                                  DELETED
                                </Badge>
                              ) : isCarved ? (
                                <Badge variant="outline" className="text-[9px] bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30 px-1.5 py-0 font-bold">
                                  CARVED
                                </Badge>
                              ) : (
                                <Badge variant="outline" className="text-[9px] bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30 px-1.5 py-0 font-bold">
                                  ACTIVE
                                </Badge>
                              )}
                            </td>
                            <td className="py-2 px-3">
                              <Badge
                                variant={item.status === "RECOVERED" ? "default" : "secondary"}
                                className="text-[10px] uppercase"
                              >
                                {item.status || "OK"}
                              </Badge>
                            </td>
                            <td className="py-2 px-3">
                              <Badge
                                variant="outline"
                                className={cn(
                                  "text-[9px] font-mono px-1.5 py-0",
                                  item.confidence === "HIGH"
                                    ? "bg-green-500/10 text-green-700 dark:text-green-300 border-green-500/30"
                                    : item.confidence === "MEDIUM"
                                    ? "bg-yellow-500/10 text-yellow-700 dark:text-yellow-300 border-yellow-500/30"
                                    : "bg-muted text-muted-foreground"
                                )}
                              >
                                {item.validation || item.confidence || "VALID"}
                              </Badge>
                            </td>
                            <td className="py-2 px-3">{item.size_bytes !== undefined ? `${item.size_bytes.toLocaleString()} B` : "N/A"}</td>
                            <td className="py-2 px-3 text-amber-600 dark:text-amber-400">
                              {item.starting_cluster ?? "N/A"}
                            </td>
                            <td className="py-2 px-3 text-primary">
                              {item.starting_lba ? `${item.starting_lba} – ${item.ending_lba || item.starting_lba}` : "N/A"}
                            </td>
                            <td className="py-2 px-3 truncate max-w-[160px]" title={item.sha256}>
                              {item.sha256 ? (
                                <span className="text-emerald-700 dark:text-emerald-300 font-mono text-[10px]">{item.sha256.substring(0, 16)}...</span>
                              ) : (
                                <span className="text-muted-foreground italic">None</span>
                              )}
                            </td>
                            <td className="py-2 px-3 font-sans text-[11px] text-muted-foreground truncate max-w-[180px]" title={item.recovery_method || item.recovery_source}>
                              {item.recovery_source || item.recovery_method}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* TAB 2: RECOVERED ARTIFACTS & VALIDATION */}
        <TabsContent value="artifacts" className="space-y-6">
          {!selectedCaseId || !caseDetails ? (
            <Card className="p-8 text-center text-muted-foreground text-sm">
              No case selected. Select or create a case from the Case Explorer tab to inspect verified artifacts.
            </Card>
          ) : (
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base font-bold flex items-center gap-2">
                  <FileCheck2 className="w-4 h-4 text-emerald-600" />
                  Case {selectedCaseId} — Verified Artifact Inventory
                </CardTitle>
                <CardDescription className="text-xs">
                  Validation report and structural confidence scores.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="p-4 bg-muted/40 border rounded-lg text-xs font-mono space-y-2">
                  <div><span className="text-muted-foreground">CASE ID:</span> {selectedCaseId}</div>
                  <div><span className="text-muted-foreground">EXAMINER:</span> {caseDetails.metadata?.examiner || "Examiner"}</div>
                  <div><span className="text-muted-foreground">REPORTS:</span> {Object.keys(caseDetails.reports || {}).join(", ") || "None"}</div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* TAB 3: CASE EXPLORER & REPORTS */}
        <TabsContent value="explorer" className="space-y-6">
          <Card className="shadow-sm">
            <CardHeader>
              <CardTitle className="text-base font-bold flex items-center gap-2">
                <FolderTree className="w-4 h-4 text-primary" />
                Case Catalog & Multi-Format Reports
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {cases.map((c: any, idx: number) => (
                  <div
                    key={idx}
                    onClick={() => {
                      setSelectedCaseId(c.case_id);
                      loadCaseDetails(c.case_id);
                    }}
                    className={`p-3 border rounded-lg cursor-pointer transition-all ${
                      selectedCaseId === c.case_id ? "bg-primary/10 border-primary" : "bg-card hover:bg-muted/40"
                    }`}
                  >
                    <div className="font-bold text-xs">{c.case_id}</div>
                    <div className="text-[11px] text-muted-foreground">{c.case_name}</div>
                    <div className="text-[10px] text-muted-foreground mt-1">Examiner: {c.examiner}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* TAB 4: CHAIN OF CUSTODY & AUDIT */}
        <TabsContent value="audit" className="space-y-6">
          <Card className="shadow-sm">
            <CardHeader>
              <CardTitle className="text-base font-bold flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-600" />
                Cryptographically Chained Audit Trail
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">
                All forensic actions, scope resolutions, carving operations, and exports are recorded in immutable SHA-256 hash-chained ledgers.
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
