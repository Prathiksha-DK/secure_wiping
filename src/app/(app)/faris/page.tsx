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
} from "lucide-react";
import { isFarisLocked, setFarisLock, showNavigationLockedAlert } from "@/lib/faris-lock";
import { cn } from "@/lib/utils";

const FARIS_API = process.env.NEXT_PUBLIC_FARIS_API_URL || "http://localhost:8760";

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

  // Load Engines & Discovered Devices on Mount
  useEffect(() => {
    refreshEnvironment();
  }, []);

  const refreshEnvironment = async () => {
    setLoadingStatus(true);
    setErrorMsg(null);
    try {
      // 1. Engine Inventory Status
      const engRes = await fetch(`${FARIS_API}/api/faris/engine-status`);
      if (engRes.ok) {
        const engData = await engRes.json();
        setEngineStatus(engData);
      } else {
        setErrorMsg(`FARIS Service not responding on ${FARIS_API}. Ensure port 8760 is running.`);
      }

      // 2. Discovered Physical Storage Media
      const devRes = await fetch(`${FARIS_API}/api/faris/devices`);
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
      const casesRes = await fetch(`${FARIS_API}/api/faris/cases`);
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

  const loadCaseDetails = async (cId: string) => {
    if (!cId) return;
    try {
      const res = await fetch(`${FARIS_API}/api/faris/cases/${cId}`);
      if (res.ok) {
        const data = await res.json();
        setCaseDetails(data.case);
      }
    } catch (e) {
      console.error("Error loading case details:", e);
    }
  };

  // Real Timer Interval: Tracks actual elapsed duration
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

  // Format Elapsed Seconds as HH:MM:SS
  const formatElapsed = (totalSecs: number): string => {
    const hrs = Math.floor(totalSecs / 3600);
    const mins = Math.floor((totalSecs % 3600) / 60);
    const secs = totalSecs % 60;
    return `${hrs.toString().padStart(2, "0")}:${mins.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  };

  // Build structured Step Logs from real engine events
  const updateStepLogs = (rawLogs: LogEntry[], job: any) => {
    const steps: StepLogEntry[] = [];

    // Track state of each recovery branch from real backend logs
    const branchStates: Record<number, { status: string; text: string; timestamp: string }> = {};
    RECOVERY_BRANCHES.forEach((b) => {
      branchStates[b.id] = { status: "WAITING", text: "", timestamp: "" };
    });

    // Track state of each sanitization stage from real backend logs
    const sanitizationStates: Record<string, { status: string; text: string; timestamp: string }> = {};
    SANITIZATION_STAGES.forEach((s) => {
      sanitizationStates[s.code] = { status: "WAITING", text: "", timestamp: "" };
    });

    rawLogs.forEach((log) => {
      if (log.stage && log.stage.startsWith("recovery_branch_")) {
        const branchNum = parseInt(log.stage.replace("recovery_branch_", ""), 10);
        if (branchNum >= 1 && branchNum <= 10) {
          branchStates[branchNum] = {
            status: log.status,
            text: log.message,
            timestamp: log.timestamp,
          };
        }
      } else if (log.stage && log.stage.startsWith("sanitization_")) {
        const stageCode = log.stage.replace("sanitization_", "").toUpperCase();
        if (sanitizationStates[stageCode]) {
          sanitizationStates[stageCode] = {
            status: log.status,
            text: log.message,
            timestamp: log.timestamp,
          };
        }
      }
    });

    // 1. Initial Device Selection & Setup
    if (selectedDevice) {
      steps.push({
        timestamp: rawLogs[0]?.timestamp || "00:00:00",
        icon: "✓",
        text: `Device selected: ${selectedDevice}`,
        type: "info",
      });
    }

    // 2. Iterate standard pipeline stages
    rawLogs.forEach((log) => {
      // Skip individual branch and sanitization sub-logs here as they are rendered in blocks
      if (log.stage && (log.stage.startsWith("recovery_branch_") || log.stage.startsWith("sanitization_"))) {
        return;
      }

      if (log.stage === "recovery") {
        // Render 10-Branch Adaptive Engine Container and individual branches
        steps.push({
          timestamp: log.timestamp,
          icon: log.status === "COMPLETED" ? "✓" : "▶",
          text: log.message,
          type: log.status === "COMPLETED" ? "success" : "start",
        });

        // Add each of the 10 branches in order
        RECOVERY_BRANCHES.forEach((b) => {
          const bs = branchStates[b.id];
          let icon = "○";
          let type: StepLogEntry["type"] = "branch";
          let statusLabel = bs.status;

          if (bs.status === "COMPLETED") {
            icon = "✓";
            type = "success";
            statusLabel = "COMPLETED";
          } else if (bs.status === "RUNNING") {
            icon = "▶";
            type = "start";
            statusLabel = "RUNNING";
          } else if (bs.status === "N/A") {
            icon = "○";
            type = "na";
            statusLabel = "N/A";
          } else if (bs.status === "FAILED") {
            icon = "✗";
            type = "fail";
            statusLabel = "FAILED";
          } else {
            icon = "○";
            type = "branch";
            statusLabel = "WAITING";
          }

          const paddedNum = `${b.id}/10`.padEnd(5, " ");
          const paddedName = b.name.padEnd(32, " ");
          const branchText = `  ${icon} Step ${paddedNum} ${paddedName} ${statusLabel}`;

          steps.push({
            timestamp: bs.timestamp || log.timestamp,
            icon,
            text: branchText,
            type,
          });
        });

        // Render Specialized Sanitization Recovery Stages A through J
        steps.push({
          timestamp: log.timestamp,
          icon: "▶",
          text: "8. Specialized Sanitization Recovery Execution",
          type: "start",
        });

        SANITIZATION_STAGES.forEach((s) => {
          const ss = sanitizationStates[s.code];
          let icon = "○";
          let type: StepLogEntry["type"] = "branch";
          let statusLabel = ss.status;

          if (ss.status === "COMPLETED" || ss.status === "RESIDUAL_EVIDENCE_FOUND") {
            icon = "✓";
            type = "success";
            statusLabel = ss.status;
          } else if (ss.status === "RUNNING") {
            icon = "▶";
            type = "start";
            statusLabel = "RUNNING";
          } else if (ss.status === "N/A" || ss.status === "NOT_APPLICABLE" || ss.status === "NOT_ACCESSIBLE" || ss.status === "NO_RECOVERABLE_EVIDENCE") {
            icon = "○";
            type = "na";
            statusLabel = ss.status;
          } else if (ss.status === "FAILED") {
            icon = "✗";
            type = "fail";
            statusLabel = "FAILED";
          } else {
            icon = "○";
            type = "branch";
            statusLabel = "WAITING";
          }

          const paddedCode = `${s.code}/10`.padEnd(5, " ");
          const paddedName = s.name.padEnd(32, " ");
          const stageText = `  ${icon} Stage ${paddedCode} ${paddedName} ${statusLabel}`;

          steps.push({
            timestamp: ss.timestamp || log.timestamp,
            icon,
            text: stageText,
            type,
          });
        });

        return;
      }

      let icon = "▶";
      let type: StepLogEntry["type"] = "start";

      if (log.status === "COMPLETED") {
        icon = "✓";
        type = "success";
      } else if (log.status === "FAILED") {
        icon = "✗";
        type = "fail";
      } else if (log.status === "N/A") {
        icon = "○";
        type = "na";
      } else {
        icon = "▶";
        type = "start";
      }

      steps.push({
        timestamp: log.timestamp,
        icon,
        text: log.message,
        type,
      });
    });

    if (job?.status === "SUCCESS") {
      const lastTs = rawLogs[rawLogs.length - 1]?.timestamp || "";
      steps.push({
        timestamp: lastTs,
        icon: "✓",
        text: "FARIS Master Recovery Pipeline Completed Successfully",
        type: "success",
      });
    } else if (job?.status === "FAILED") {
      const lastTs = rawLogs[rawLogs.length - 1]?.timestamp || "";
      steps.push({
        timestamp: lastTs,
        icon: "✗",
        text: `Pipeline Execution Failed: ${job.error || "Unknown Error"}`,
        type: "fail",
      });
    }

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

  // Pipeline Polling
  useEffect(() => {
    if (!activeJobId || !isRunning) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${FARIS_API}/api/faris/pipeline/status/${activeJobId}`);
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

  const handleStartPipeline = async () => {
    setErrorMsg(null);

    // Validate mandatory pre-start form fields
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
    if (!caseDescription.trim()) {
      setErrorMsg("Case / Evidence Description is mandatory. Please provide a brief description.");
      return;
    }
    if (!recoveryOutputPath.trim()) {
      setErrorMsg("Recovery Output Path is mandatory. Specify where recovered files should be saved.");
      return;
    }

    // Safety Verification: Ensure recovery output path is not on the source evidence device
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
      description: caseDescription.trim(),
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
      setStepLogs([
        {
          timestamp: new Date(now).toTimeString().split(" ")[0],
          icon: "✓",
          text: `Device selected: ${selectedDevice}`,
          type: "info",
        },
        {
          timestamp: new Date(now).toTimeString().split(" ")[0],
          icon: "▶",
          text: `Initializing Case ${caseNumber.trim()}...`,
          type: "start",
        },
      ]);

      const res = await fetch(`${FARIS_API}/api/faris/pipeline/start`, {
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

  const handleExportArtifacts = async () => {
    if (!selectedCaseId || !exportDestDir.trim()) return;
    setIsExporting(true);
    setExportStatus(null);
    try {
      const res = await fetch(`${FARIS_API}/api/faris/export`, {
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

  const stagesList = [
    { key: "setup", label: "1. Case Initialized" },
    { key: "acquisition", label: "2. Real Forensic Bit-Stream Acquisition (EWF/E01)" },
    { key: "verification", label: "3. Cryptographic Verification (SHA-256)" },
    { key: "analysis", label: "4. Partition & Filesystem Structural Analysis" },
    { key: "discovery", label: "5. Inode & Artifact Discovery (TSK fls)" },
    { key: "states", label: "6. Allocation State Classification (TSK istat)" },
    { key: "recovery", label: "7. 10-Branch Adaptive Recovery Execution" },
    { key: "sanitization", label: "8. Specialized Sanitization Recovery (Stages A–J)" },
    { key: "validation", label: "9. Deep Format Structural Validation" },
    { key: "hashing", label: "10. SHA-256 Case Manifest Hashing" },
    { key: "export", label: "11. Verified Artifacts Export to Recovery Path" },
    { key: "reporting", label: "12. Multi-Format Reports Generated (JSON/CSV/HTML)" },
  ];

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
                Live Physical Device Pipeline
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground mt-1">
              Physical Device Discovery · Bit-Stream E01 Acquisition · 10-Branch Deep Recovery · Verification & Export
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Real Elapsed Time Badge */}
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
            Physical Device & Recovery
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

        {/* TAB 1: LIVE DEVICE ACQUISITION & RECOVERY PIPELINE */}
        <TabsContent value="pipeline" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Pre-Start Form */}
            <Card className="lg:col-span-5 shadow-sm">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="w-5 h-5 text-primary" />
                  Forensic Case & Evidence Details
                </CardTitle>
                <CardDescription>
                  Select target physical drive and supply mandatory case parameters.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Physical Device Selector Only */}
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

                {/* Mandatory Case Details */}
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
                    <label className="text-xs font-semibold text-muted-foreground">Partition Offset</label>
                    <Input
                      value={partitionOffset}
                      onChange={(e) => setPartitionOffset(e.target.value)}
                      className="text-xs font-mono"
                      placeholder="Auto-detect (leave blank)"
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground">Case / Evidence Description *</label>
                  <Input
                    value={caseDescription}
                    onChange={(e) => setCaseDescription(e.target.value)}
                    className="text-xs"
                    placeholder="e.g. Physical forensic acquisition and artifact recovery"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground">Case Notes</label>
                  <Input
                    value={caseNotes}
                    onChange={(e) => setCaseNotes(e.target.value)}
                    className="text-xs"
                    placeholder="e.g. Unattended acquisition using bundled ewfacquire with SHA-256"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-semibold text-muted-foreground">
                    Recovery Output Directory *
                  </label>
                  <Input
                    value={recoveryOutputPath}
                    onChange={(e) => setRecoveryOutputPath(e.target.value)}
                    className="text-xs font-mono"
                    placeholder="e.g. D:/FARIS_Recovery_Output"
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Separate writable folder where all recovered artifacts will physically be exported.
                  </p>
                </div>

                {/* Pre-Start Confirmation Summary Box */}
                <div className="p-3 bg-muted/60 border rounded-lg text-xs space-y-1.5 font-mono">
                  <div className="font-bold text-foreground text-[11px] uppercase tracking-wider mb-1 flex items-center gap-1.5">
                    <Info className="w-3.5 h-3.5 text-blue-600" />
                    Pre-Start Verification Summary
                  </div>
                  <div><span className="text-muted-foreground">SOURCE DEVICE:</span> <span className="font-semibold">{selectedDevice || "None Selected"}</span></div>
                  <div><span className="text-muted-foreground">CASE NUMBER:</span> <span className="font-semibold">{caseNumber || "(Required)"}</span></div>
                  <div><span className="text-muted-foreground">EVIDENCE NUMBER:</span> <span className="font-semibold">{evidenceNumber || "(Required)"}</span></div>
                  <div><span className="text-muted-foreground">EXAMINER:</span> <span className="font-semibold">{examinerName || "(Required)"}</span></div>
                  <div><span className="text-muted-foreground">RECOVERY OUTPUT:</span> <span className="font-semibold">{recoveryOutputPath || "(Required)"}</span></div>
                </div>

                {/* Clear Boundary Notice */}
                <div className="p-3 bg-blue-500/5 border border-blue-500/20 rounded-lg text-[11px] space-y-1 text-blue-800 dark:text-blue-300">
                  <div className="font-bold flex items-center gap-1">
                    <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
                    Evidence Protection Architecture
                  </div>
                  <div>• <span className="font-semibold">Original Source:</span> READ-ONLY / Never Modified</div>
                  <div>• <span className="font-semibold">Acquired Image (.E01):</span> Writable Case Evidence Destination</div>
                  <div>• <span className="font-semibold">Recovery Output:</span> Writable User-Selected Destination</div>
                </div>
              </CardContent>
              <CardFooter>
                <Button
                  onClick={handleStartPipeline}
                  disabled={isRunning}
                  className="w-full gap-2 font-semibold bg-blue-600 hover:bg-blue-700 text-white shadow"
                >
                  {isRunning ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Executing FARIS Pipeline ({formatElapsed(elapsedSeconds)})...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4" />
                      START FORENSIC ACQUISITION & RECOVERY
                    </>
                  )}
                </Button>
              </CardFooter>
            </Card>

            {/* Live Progress & Execution Telemetry */}
            <div className="lg:col-span-7 flex flex-col gap-5">
              {/* Progress Overview */}
              <Card className="shadow-sm">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <CardTitle className="text-base font-bold flex items-center gap-2">
                        <Cpu className="w-4 h-4 text-blue-600" />
                        Live Pipeline Execution Telemetry
                      </CardTitle>
                      <CardDescription className="text-xs">
                        {activeJobId ? `Job ID: ${activeJobId} · Case: ${pipelineState?.case_id || caseNumber || "Pending"}` : "Waiting to launch pipeline"}
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
                      <span>Overall Pipeline Progress</span>
                      <span className="font-mono">{pipelineState?.progress_pct?.toFixed(0) || 0}%</span>
                    </div>
                    <Progress value={pipelineState?.progress_pct || 0} className="h-2.5" />
                  </div>

                  {/* Stage By Stage Tracker */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-2">
                    {stagesList.map((st, i) => {
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
                        Ready. Fill case details and click &apos;START FORENSIC ACQUISITION & RECOVERY&apos; to begin live physical acquisition and recovery.
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

              {/* Small Live Step Progress Terminal (CHANGE 2) */}
              <Card className="shadow-sm flex flex-col">
                <CardHeader className="py-2 px-3 bg-muted/60 border-b flex flex-row items-center justify-between">
                  <div className="flex items-center gap-1.5 text-xs font-mono font-bold tracking-tight text-foreground">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />
                    FARIS STEP PROGRESS
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono text-muted-foreground">
                      Elapsed: <span className="font-bold text-foreground">{formatElapsed(elapsedSeconds)}</span>
                    </span>
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {stepLogs.length} steps
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="p-0">
                  <div
                    ref={stepTerminalRef}
                    className="h-36 p-3 bg-zinc-950 text-zinc-300 font-mono text-[11px] leading-relaxed overflow-y-auto space-y-1 border-t"
                  >
                    {stepLogs.length === 0 ? (
                      <div className="text-zinc-500 italic">
                        Waiting for pipeline execution... Stage steps will appear here in real-time.
                      </div>
                    ) : (
                      stepLogs.map((step, idx) => (
                        <div key={idx} className="flex items-start gap-2">
                          <span className="text-zinc-500 select-none">[{step.timestamp}]</span>
                          <span
                            className={`font-bold select-none ${
                              step.type === "success"
                                ? "text-emerald-400"
                                : step.type === "fail"
                                ? "text-red-400"
                                : step.type === "na"
                                ? "text-zinc-500"
                                : "text-blue-400"
                            }`}
                          >
                            {step.icon}
                          </span>
                          <span
                            className={
                              step.type === "success"
                                ? "text-emerald-300 font-medium"
                                : step.type === "fail"
                                ? "text-red-300 font-bold"
                                : step.type === "na"
                                ? "text-zinc-400"
                                : "text-zinc-100"
                            }
                          >
                            {step.text}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </TabsContent>

        {/* TAB 2: RECOVERED ARTIFACTS & DEEP VALIDATION */}
        <TabsContent value="artifacts" className="space-y-6">
          {!selectedCaseId || !caseDetails ? (
            <Card className="shadow-sm border-dashed">
              <CardContent className="flex flex-col items-center justify-center p-12 text-center space-y-4">
                <div className="p-4 bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded-full border border-blue-200 dark:border-blue-900">
                  <FileCheck2 className="w-8 h-8" />
                </div>
                <div className="space-y-1.5 max-w-md">
                  <h3 className="text-lg font-bold tracking-tight">Perform Recovery to View Results</h3>
                  <p className="text-sm text-muted-foreground">
                    No recovered artifacts to display. Please configure your physical device and perform a forensic recovery from the &apos;Physical Device &amp; Recovery&apos; tab to view results.
                  </p>
                </div>
                <Button
                  onClick={() => setActiveTab("pipeline")}
                  className="gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm"
                >
                  <Play className="w-4 h-4" />
                  Go to Physical Device &amp; Recovery
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              <Card className="lg:col-span-4 shadow-sm">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">Forensic Cases</CardTitle>
                  <CardDescription className="text-xs">Select case to view validated recovered artifacts.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2 max-h-[500px] overflow-y-auto">
                  {cases.length === 0 ? (
                    <div className="text-xs text-muted-foreground p-3 text-center">No cases created yet.</div>
                  ) : (
                    cases.map((c) => (
                      <div
                        key={c.case_id}
                        onClick={() => {
                          setSelectedCaseId(c.case_id);
                          loadCaseDetails(c.case_id);
                        }}
                        className={`p-3 rounded-lg border cursor-pointer text-xs space-y-1 transition-colors ${
                          selectedCaseId === c.case_id
                            ? "bg-blue-500/10 border-blue-500/50 text-blue-700 dark:text-blue-300"
                            : "hover:bg-muted/50"
                        }`}
                      >
                        <div className="font-bold flex items-center justify-between">
                          <span>{c.case_id}</span>
                          <Badge variant="outline" className="text-[10px]">{c.examiner}</Badge>
                        </div>
                        <div className="text-muted-foreground truncate">{c.case_name || c.description}</div>
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>

              <Card className="lg:col-span-8 shadow-sm">
                <CardHeader className="pb-3 flex flex-row items-center justify-between">
                  <div>
                    <CardTitle className="text-base">Validated Forensic Recoveries</CardTitle>
                    <CardDescription className="text-xs">
                      Case: <span className="font-mono font-semibold">{selectedCaseId || "None"}</span> ·{" "}
                      Total Recovered: {caseDetails?.validation_report?.total_validated || 0}
                    </CardDescription>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handleExportArtifacts()}
                      disabled={isExporting || !selectedCaseId}
                      className="gap-1.5 text-xs"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Export Verified Files
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {exportStatus && (
                    <div className="p-3 bg-green-500/10 border border-green-500/30 text-green-700 dark:text-green-300 rounded-md text-xs">
                      {exportStatus}
                    </div>
                  )}

                  <div className="rounded-lg border overflow-x-auto max-h-[450px]">
                    <table className="w-full text-xs text-left">
                      <thead className="bg-muted/60 text-muted-foreground font-semibold border-b sticky top-0">
                        <tr>
                          <th className="p-2.5">File Name</th>
                          <th className="p-2.5">Method / Branch</th>
                          <th className="p-2.5">Size</th>
                          <th className="p-2.5">Validation</th>
                          <th className="p-2.5">Confidence</th>
                          <th className="p-2.5">SHA-256 Digest</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y font-mono">
                        {!caseDetails?.validation_report?.artifacts?.length ? (
                          <tr>
                            <td colSpan={6} className="p-6 text-center text-muted-foreground font-sans">
                              No recovered artifacts found for this case. Run the master recovery pipeline first.
                            </td>
                          </tr>
                        ) : (
                          caseDetails.validation_report.artifacts.map((art: any, i: number) => (
                            <tr key={i} className="hover:bg-muted/30">
                              <td className="p-2.5 font-sans font-medium text-foreground truncate max-w-[180px]">
                                {art.file || art.filename || `Artifact_${i+1}`}
                              </td>
                              <td className="p-2.5 text-muted-foreground text-[11px] truncate max-w-[140px]">
                                {art.recovery_method || art.source_branch || "Signature/Inode"}
                              </td>
                              <td className="p-2.5 whitespace-nowrap">
                                {art.size_bytes !== undefined ? `${(art.size_bytes / 1024).toFixed(1)} KB` : "N/A"}
                              </td>
                              <td className="p-2.5">
                                <Badge
                                  variant={
                                    art.validation_status === "VALID"
                                      ? "default"
                                      : art.validation_status === "PARTIALLY_VALID"
                                      ? "secondary"
                                      : "destructive"
                                  }
                                  className="text-[10px] px-1.5 py-0"
                                >
                                  {art.validation_status || "UNKNOWN"}
                                </Badge>
                              </td>
                              <td className="p-2.5 font-bold">
                                {art.confidence_score ? `${art.confidence_score}%` : (art.confidence || "HIGH")}
                              </td>
                              <td className="p-2.5 text-[10px] text-muted-foreground truncate max-w-[120px]" title={art.sha256}>
                                {art.sha256 || "N/A"}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* TAB 3: CASE EXPLORER & REPORTS */}
        <TabsContent value="explorer" className="space-y-6">
          {!selectedCaseId || !caseDetails ? (
            <Card className="shadow-sm border-dashed">
              <CardContent className="flex flex-col items-center justify-center p-12 text-center space-y-4">
                <div className="p-4 bg-blue-500/10 text-blue-600 dark:text-blue-400 rounded-full border border-blue-200 dark:border-blue-900">
                  <FileText className="w-8 h-8" />
                </div>
                <div className="space-y-1.5 max-w-md">
                  <h3 className="text-lg font-bold tracking-tight">Perform Recovery to View Results</h3>
                  <p className="text-sm text-muted-foreground">
                    No case reports generated yet. Forensic reports (JSON, CSV, HTML) and evidence manifests will be compiled once forensic recovery is performed.
                  </p>
                </div>
                <Button
                  onClick={() => setActiveTab("pipeline")}
                  className="gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm"
                >
                  <Play className="w-4 h-4" />
                  Go to Physical Device &amp; Recovery
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <FileText className="w-5 h-5 text-blue-600" />
                  Case Reports & Documentation
                </CardTitle>
                <CardDescription className="text-xs">
                  Download official forensic reports generated for Case: <span className="font-mono font-semibold">{selectedCaseId}</span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <a
                    href={`${FARIS_API}/api/faris/report/${selectedCaseId}/json`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-4 border rounded-xl bg-card hover:bg-muted/50 flex flex-col gap-2 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="font-mono text-xs">JSON</Badge>
                      <Download className="w-4 h-4 text-blue-600" />
                    </div>
                    <div className="font-bold text-sm">Machine-Readable Case JSON</div>
                    <p className="text-xs text-muted-foreground">Complete case metadata, hash manifests, and recovery logs.</p>
                  </a>

                  <a
                    href={`${FARIS_API}/api/faris/report/${selectedCaseId}/csv`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-4 border rounded-xl bg-card hover:bg-muted/50 flex flex-col gap-2 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="font-mono text-xs">CSV</Badge>
                      <Download className="w-4 h-4 text-blue-600" />
                    </div>
                    <div className="font-bold text-sm">Recovered Artifacts Spreadsheet</div>
                    <p className="text-xs text-muted-foreground">Tabular list of all recovered files, hashes, sizes, and validation status.</p>
                  </a>

                  <a
                    href={`${FARIS_API}/api/faris/report/${selectedCaseId}/html`}
                    target="_blank"
                    rel="noreferrer"
                    className="p-4 border rounded-xl bg-card hover:bg-muted/50 flex flex-col gap-2 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="font-mono text-xs">HTML</Badge>
                      <Download className="w-4 h-4 text-blue-600" />
                    </div>
                    <div className="font-bold text-sm">Official Forensic Court Report</div>
                    <p className="text-xs text-muted-foreground">Printable court-ready HTML report with chain of custody and statistics.</p>
                  </a>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* TAB 4: CHAIN OF CUSTODY & AUDIT */}
        <TabsContent value="audit" className="space-y-6">
          {!selectedCaseId || !caseDetails ? (
            <Card className="shadow-sm border-dashed">
              <CardContent className="flex flex-col items-center justify-center p-12 text-center space-y-4">
                <div className="p-4 bg-green-500/10 text-green-600 dark:text-green-400 rounded-full border border-green-200 dark:border-green-900">
                  <ShieldCheck className="w-8 h-8" />
                </div>
                <div className="space-y-1.5 max-w-md">
                  <h3 className="text-lg font-bold tracking-tight">Perform Recovery to View Results</h3>
                  <p className="text-sm text-muted-foreground">
                    Chain of custody logs are generated during live physical device acquisition and recovery. Perform a recovery to view cryptographic audit trails.
                  </p>
                </div>
                <Button
                  onClick={() => setActiveTab("pipeline")}
                  className="gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs shadow-sm"
                >
                  <Play className="w-4 h-4" />
                  Go to Physical Device &amp; Recovery
                </Button>
              </CardContent>
            </Card>
          ) : (
            <Card className="shadow-sm">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-green-600" />
                  Immutable SHA-256 Chain of Custody Audit Log
                </CardTitle>
                <CardDescription className="text-xs">
                  Forward-hash chained tamper-evident audit record for Case: <span className="font-mono font-semibold">{selectedCaseId}</span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="p-4 bg-muted/40 border rounded-lg text-xs font-mono space-y-2 max-h-96 overflow-y-auto">
                  <div className="text-muted-foreground font-sans">
                    Total cryptographic audit entries: {caseDetails?.audit_trail_count || 0}
                  </div>
                  <div className="text-[11px] leading-relaxed text-foreground">
                    Audit events are recorded in real-time under <code className="bg-background px-1.5 py-0.5 rounded">FARIS/cases/{selectedCaseId}/audit/audit_trail.jsonl</code> with forward-linked SHA-256 signatures ensuring verifiable legal provenance.
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}
