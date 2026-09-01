"use client";

import React, { useState, useEffect, useCallback, useRef, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  HardDrive,
  Shield,
  CheckCircle,
  XCircle,
  Loader,
  ChevronRight,
  ChevronLeft,
  AlertTriangle,
  FileText,
  Folder,
  FolderOpen,
  Search,
  RefreshCw,
  Info,
  Lock,
  Cpu,
  BarChart3,
  ClipboardList,
  Activity,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Usb,
  Server,
  MemoryStick,
  Upload,
  ArrowUp,
  Home,
  Monitor,
  CornerDownRight,
  ExternalLink,
  Layers,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { useToast } from "@/hooks/use-toast";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type TargetType = "file" | "folder" | "disk";

type SanitizationMethod = {
  id: string;
  label: string;
  passes: number;
  description: string;
};

type Device = {
  id: string;
  name: string;
  friendlyName?: string;
  size: string;
  type?: string;
  isSystem?: boolean;
};

type PipelineStage =
  | "idle"
  | "device_detection"
  | "sanitization"
  | "verification"
  | "recovery_assessment"
  | "decision"
  | "final_classification"
  | "complete";

type FinalState =
  | "SANITIZED_AND_REUSABLE"
  | "SANITIZATION_NOT_VERIFIABLE"
  | "NON_SANITIZABLE"
  | null;

type RecoveryClassification =
  | "NO_RECOVERABLE_DATA_DETECTED"
  | "PARTIAL_DATA_RECOVERED"
  | "SIGNIFICANT_DATA_RECOVERED"
  | "RECOVERY_TEST_FAILED"
  | "ASSESSMENT_NOT_CONCLUSIVE"
  | null;

type SessionResult = {
  session_id: string;
  sanitization_method?: string;
  sanitization_method_label?: string;
  final_state: FinalState;
  final_reason: string;
  software_version: string;
  start_time: string;
  end_time: string;
  total_iterations: number;
  tamper_hash: string;
  device_info: {
    target_type: string;
    size_bytes: number;
    device_technology: string;
    model?: string;
    serial?: string;
  };
  iterations: Array<{
    iteration: number;
    sanitization: { label: string; success: boolean; message: string };
    verification: { status: string; checks: string[]; warnings: string[]; errors: string[] };
    recovery_assessment: {
      classification: RecoveryClassification;
      techniques_used: string[];
      fragments_found: number;
      detail: string;
    };
    decision: { action: string; final_state: FinalState; reason: string };
  }>;
};

type FsItem = {
  name: string;
  path: string;
  is_dir: boolean;
  size_bytes: number;
  modified: number;
};

type FsRoot = {
  name: string;
  path: string;
  is_dir: boolean;
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_METHODS: SanitizationMethod[] = [
  { id: "nist-clear", label: "NIST 800-88 Rev.1 — Clear", passes: 1, description: "Single-pass overwrite with zeros. Suitable for non-sensitive media." },
  { id: "dod-3pass", label: "DoD 5220.22-M (3-Pass)", passes: 3, description: "3-pass DoD overwrite: zeros, ones, random. Approved overwrite method." },
  { id: "dod-7pass", label: "DoD 5220.22-M ECE (7-Pass)", passes: 7, description: "7-pass extended DoD overwrite for maximum magnetic media assurance." },
  { id: "crypto-erase", label: "Cryptographic Erase (IEEE 2883)", passes: 1, description: "Encrypt with ephemeral AES-256 key then discard key. Renders data cryptographically inaccessible." },
  { id: "gutmann", label: "Gutmann 35-Pass", passes: 35, description: "35-pass overwrite for maximum assurance on magnetic media." },
  { id: "ieee-purge", label: "IEEE 2883-2022 Purge", passes: 1, description: "IEEE 2883-2022 purge procedure using media-specific secure erase commands." },
];

const PIPELINE_STAGES: { key: PipelineStage; label: string; icon: React.ElementType }[] = [
  { key: "device_detection", label: "Device Detection", icon: HardDrive },
  { key: "sanitization", label: "Sanitization", icon: Shield },
  { key: "verification", label: "Verification", icon: CheckCircle },
  { key: "recovery_assessment", label: "Recovery Assessment", icon: Search },
  { key: "decision", label: "Decision", icon: BarChart3 },
  { key: "final_classification", label: "Final Classification", icon: ClipboardList },
];

const STAGE_ORDER: PipelineStage[] = [
  "device_detection",
  "sanitization",
  "verification",
  "recovery_assessment",
  "decision",
  "final_classification",
];

const API_BASE = "http://localhost:9758";

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

function formatBytes(bytes: number) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function getDeviceIcon(type?: string) {
  const t = (type || "").toUpperCase();
  if (t.includes("USB")) return Usb;
  if (t.includes("SSD") || t.includes("NVME")) return Cpu;
  if (t.includes("HDD")) return Server;
  if (t.includes("SD") || t.includes("CARD")) return MemoryStick;
  return HardDrive;
}

function getFinalStateConfig(state: FinalState) {
  switch (state) {
    case "SANITIZED_AND_REUSABLE":
      return {
        icon: ShieldCheck,
        label: "SANITIZED — REUSABLE",
        emoji: "🟢",
        color: "text-green-600 dark:text-green-400",
        bg: "bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800",
        badge: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      };
    case "SANITIZATION_NOT_VERIFIABLE":
      return {
        icon: ShieldAlert,
        label: "SANITIZATION NOT VERIFIABLE — POLICY REVIEW REQUIRED",
        emoji: "🟡",
        color: "text-yellow-600 dark:text-yellow-400",
        bg: "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800",
        badge: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200",
      };
    case "NON_SANITIZABLE":
      return {
        icon: ShieldX,
        label: "SANITIZATION FAILED — DO NOT REUSE / CONTROLLED DISPOSAL",
        emoji: "🔴",
        color: "text-red-600 dark:text-red-400",
        bg: "bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800",
        badge: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
      };
    default:
      return {
        icon: ShieldAlert,
        label: "UNKNOWN STATE",
        emoji: "⚪",
        color: "text-gray-600",
        bg: "bg-gray-50 border-gray-200",
        badge: "bg-gray-100 text-gray-800",
      };
  }
}

function getRecoveryBadge(cls: RecoveryClassification) {
  switch (cls) {
    case "NO_RECOVERABLE_DATA_DETECTED":
      return <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200">✓ No Recoverable Data</Badge>;
    case "PARTIAL_DATA_RECOVERED":
      return <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">⚠ Partial Data Recovered</Badge>;
    case "SIGNIFICANT_DATA_RECOVERED":
      return <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200">✗ Significant Data Recovered</Badge>;
    case "RECOVERY_TEST_FAILED":
      return <Badge className="bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200">! Recovery Test Failed</Badge>;
    default:
      return <Badge variant="secondary">~ Assessment Inconclusive</Badge>;
  }
}

// ---------------------------------------------------------------------------
// Pipeline Progress Indicator
// ---------------------------------------------------------------------------

function PipelineProgress({ currentStage, iterations }: { currentStage: PipelineStage; iterations: number }) {
  const currentIdx = STAGE_ORDER.indexOf(currentStage);
  return (
    <div className="w-full mb-8">
      <div className="flex items-center justify-between relative">
        <div className="absolute top-5 left-0 right-0 h-0.5 bg-border" />
        <div
          className="absolute top-5 left-0 h-0.5 bg-primary transition-all duration-700"
          style={{ width: `${currentIdx < 0 ? 0 : (currentIdx / (STAGE_ORDER.length - 1)) * 100}%` }}
        />
        {PIPELINE_STAGES.map((stage, idx) => {
          const stageIdx = STAGE_ORDER.indexOf(stage.key);
          const done = currentIdx > stageIdx;
          const active = currentIdx === stageIdx;
          const Icon = stage.icon;
          return (
            <div key={stage.key} className="flex flex-col items-center gap-1 relative z-10">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center border-2 transition-all duration-300 ${
                  done
                    ? "bg-primary border-primary text-primary-foreground"
                    : active
                    ? "bg-primary/10 border-primary text-primary animate-pulse"
                    : "bg-background border-border text-muted-foreground"
                }`}
              >
                {done ? <CheckCircle className="h-5 w-5" /> : <Icon className="h-4 w-4" />}
              </div>
              <span className={`text-[10px] font-medium text-center max-w-[70px] leading-tight ${active ? "text-primary font-semibold" : done ? "text-foreground" : "text-muted-foreground"}`}>
                {stage.label}
              </span>
              {active && iterations > 1 && (
                <Badge variant="outline" className="text-[9px] px-1 py-0">
                  Pass {iterations}
                </Badge>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

function WipePageComponent() {
  const router = useRouter();
  const { toast } = useToast();
  const searchParams = useSearchParams();
  const deviceNameFromQuery = searchParams.get("device");

  // Step wizard: 1 = target selection, 2 = method config, 3 = execution
  const [step, setStep] = useState(1);

  // Target configuration
  const [targetType, setTargetType] = useState<TargetType>("disk");
  const [targetPath, setTargetPath] = useState("");
  const [selectedDevice, setSelectedDevice] = useState<string | undefined>(deviceNameFromQuery || undefined);
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesLoading, setDevicesLoading] = useState(false);

  // Method configuration
  const [methods, setMethods] = useState<SanitizationMethod[]>(DEFAULT_METHODS);
  const [selectedMethod, setSelectedMethod] = useState("dod-3pass");
  const [maxIterations, setMaxIterations] = useState(3);
  const [operator, setOperator] = useState("Operator");

  // Pipeline execution state
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [currentStage, setCurrentStage] = useState<PipelineStage>("idle");
  const [currentIteration, setCurrentIteration] = useState(0);
  const [sessionResult, setSessionResult] = useState<SessionResult | null>(null);
  const [pollingTimer, setPollingTimer] = useState<NodeJS.Timeout | null>(null);

  // File / Folder Browser Dialog State
  const [browserOpen, setBrowserOpen] = useState(false);
  const [browserMode, setBrowserMode] = useState<"file" | "folder">("file");
  const [browserCurrentPath, setBrowserCurrentPath] = useState("");
  const [browserParentPath, setBrowserParentPath] = useState<string | null>(null);
  const [browserItems, setBrowserItems] = useState<FsItem[]>([]);
  const [browserRoots, setBrowserRoots] = useState<FsRoot[]>([]);
  const [browserLoading, setBrowserLoading] = useState(false);
  const [browserSearch, setBrowserSearch] = useState("");
  const [browserSelectedFile, setBrowserSelectedFile] = useState<string>("");
  const [nativePickerLoading, setNativePickerLoading] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Computed target
  const effectiveTarget = targetType === "disk" ? (selectedDevice || "") : targetPath;

  // ---------------------------------------------------------------------------
  // Initial fetch
  // ---------------------------------------------------------------------------

  useEffect(() => {
    async function fetchDevices() {
      setDevicesLoading(true);
      try {
        const res = await fetch(`${API_BASE}/api/devices`, { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          setDevices(data.map((d: any) => ({
            id: d.name,
            name: d.name,
            friendlyName: d.friendlyName || d.name,
            size: d.size,
            type: d.type,
            isSystem: d.isSystem,
          })));
        }
      } catch {
        setDevices([]);
      } finally {
        setDevicesLoading(false);
      }
    }

    async function fetchMethods() {
      try {
        const res = await fetch(`${API_BASE}/api/sanitization/methods`, { cache: "no-store" });
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data) && data.length > 0) setMethods(data);
        }
      } catch {
        // Fallback to defaults
      }
    }

    fetchDevices();
    fetchMethods();
  }, []);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollingTimer) clearInterval(pollingTimer);
    };
  }, [pollingTimer]);

  // ---------------------------------------------------------------------------
  // File & Folder Explorer functions
  // ---------------------------------------------------------------------------

  const loadDirectory = async (path: string = "") => {
    setBrowserLoading(true);
    try {
      const url = path ? `${API_BASE}/api/fs/browse?path=${encodeURIComponent(path)}` : `${API_BASE}/api/fs/browse`;
      const res = await fetch(url, { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setBrowserCurrentPath(data.current_path);
        setBrowserParentPath(data.parent_path);
        setBrowserItems(data.items || []);
        setBrowserSelectedFile("");
      }
    } catch (e: any) {
      toast({
        variant: "destructive",
        title: "Directory access error",
        description: e.message || "Failed to list directory contents",
      });
    } finally {
      setBrowserLoading(false);
    }
  };

  const openExplorer = async (mode: "file" | "folder") => {
    setBrowserMode(mode);
    setBrowserSearch("");
    setBrowserOpen(true);

    // Fetch quick roots
    try {
      const rootsRes = await fetch(`${API_BASE}/api/fs/roots`, { cache: "no-store" });
      if (rootsRes.ok) {
        const rootsData = await rootsRes.json();
        setBrowserRoots(rootsData);
      }
    } catch {
      // Ignore
    }

    // Load initial directory
    const startPath = targetPath ? (targetPath.includes("/") || targetPath.includes("\\") ? targetPath : "") : "";
    await loadDirectory(startPath);
  };

  const handleNativePicker = async (mode: "file" | "folder") => {
    setNativePickerLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/fs/picker`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: mode }),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.status === "selected" && data.path) {
          setTargetPath(data.path);
          toast({
            title: `${mode === "file" ? "File" : "Folder"} Selected`,
            description: data.path,
          });
        }
      }
    } catch (e: any) {
      toast({
        variant: "destructive",
        title: "OS Picker Error",
        description: e.message || "Could not open system file chooser",
      });
    } finally {
      setNativePickerLoading(false);
    }
  };

  const confirmExplorerSelection = () => {
    if (browserMode === "folder") {
      setTargetPath(browserCurrentPath);
    } else if (browserSelectedFile) {
      setTargetPath(browserSelectedFile);
    } else {
      toast({
        variant: "destructive",
        title: "No file selected",
        description: "Please click on a file from the list to select it.",
      });
      return;
    }
    setBrowserOpen(false);
  };

  // ---------------------------------------------------------------------------
  // Pipeline stage inference
  // ---------------------------------------------------------------------------

  const inferStageFromLog = useCallback((log: string): PipelineStage | null => {
    if (log.includes("[STAGE 0]")) return "device_detection";
    if (log.includes("[STAGE 1]")) return "sanitization";
    if (log.includes("[STAGE 2]")) return "verification";
    if (log.includes("[STAGE 3]")) return "recovery_assessment";
    if (log.includes("[STAGE 4]") || log.includes("[DECISION]")) return "decision";
    if (log.includes("[FINAL]")) return "final_classification";
    return null;
  }, []);

  const inferIterationFromLog = useCallback((log: string): number | null => {
    const m = log.match(/pass (\d+)\//i) || log.match(/iteration (\d+)/i);
    return m ? parseInt(m[1]) : null;
  }, []);

  // ---------------------------------------------------------------------------
  // Start Sanitization
  // ---------------------------------------------------------------------------

  const handleStartSanitization = async () => {
    if (!effectiveTarget) return;

    setStep(3);
    setIsRunning(true);
    setProgress(0);
    setLogs([]);
    setCurrentStage("device_detection");
    setCurrentIteration(1);
    setSessionResult(null);
    setSessionId(null);

    try {
      const res = await fetch(`${API_BASE}/api/sanitization/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: effectiveTarget,
          method: selectedMethod,
          maxIterations: maxIterations,
          operator: operator,
        }),
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.message || "Failed to start sanitization session");
      }

      const data = await res.json();
      const sid = data.session_id;
      setSessionId(sid);

      const timer = setInterval(async () => {
        try {
          const statusRes = await fetch(`${API_BASE}/api/sanitization/status/${sid}`, { cache: "no-store" });
          if (!statusRes.ok) return;
          const statusData = await statusRes.json();

          const newLogs: string[] = statusData.logs || [];
          setLogs(newLogs);
          setProgress(statusData.progress || 0);

          for (let i = newLogs.length - 1; i >= 0; i--) {
            const stage = inferStageFromLog(newLogs[i]);
            if (stage) {
              setCurrentStage(stage);
              break;
            }
          }

          for (let i = newLogs.length - 1; i >= 0; i--) {
            const iter = inferIterationFromLog(newLogs[i]);
            if (iter) {
              setCurrentIteration(iter);
              break;
            }
          }

          if (statusData.status === "complete" || statusData.status === "error") {
            clearInterval(timer);
            setPollingTimer(null);
            setIsRunning(false);
            setProgress(100);
            setCurrentStage("final_classification");

            if (statusData.result) {
              setSessionResult(statusData.result as SessionResult);
            }

            if (statusData.status === "error") {
              toast({
                variant: "destructive",
                title: "Sanitization Error",
                description: "An error occurred during the sanitization pipeline.",
              });
            }
          }
        } catch {
          // Ignore transient polling errors
        }
      }, 1000);

      setPollingTimer(timer);
    } catch (err: any) {
      setIsRunning(false);
      setCurrentStage("idle");
      toast({
        variant: "destructive",
        title: "Failed to Start Sanitization",
        description: err.message,
      });
    }
  };

  const selectedMethodConfig = methods.find((m) => m.id === selectedMethod);

  const renderTargetIcon = (type: TargetType) => {
    switch (type) {
      case "file": return <FileText className="h-5 w-5 text-primary" />;
      case "folder": return <Folder className="h-5 w-5 text-primary" />;
      case "disk": return <HardDrive className="h-5 w-5 text-primary" />;
    }
  };

  // Filtered browser items
  const filteredBrowserItems = browserItems.filter((it) =>
    browserSearch ? it.name.toLowerCase().includes(browserSearch.toLowerCase()) : true
  );

  // ---------------------------------------------------------------------------
  // Step 1: Target Selection
  // ---------------------------------------------------------------------------

  const renderStep1 = () => (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-primary" />
            Step 1: Select Sanitization Target
          </CardTitle>
          <CardDescription>
            Choose what to sanitize: browse and pick a single file, an entire folder/directory, or a storage disk.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Target type selection */}
          <div>
            <Label className="text-sm font-medium text-muted-foreground mb-3 block">Granularity Level</Label>
            <RadioGroup
              value={targetType}
              onValueChange={(v) => {
                setTargetType(v as TargetType);
                setTargetPath("");
                setSelectedDevice(undefined);
              }}
              className="grid grid-cols-3 gap-3"
            >
              {(["file", "folder", "disk"] as TargetType[]).map((t) => (
                <Label
                  key={t}
                  htmlFor={`type-${t}`}
                  className="flex flex-col items-center gap-2 rounded-lg border-2 p-4 cursor-pointer hover:bg-accent transition-colors [&:has([data-state=checked])]:border-primary [&:has([data-state=checked])]:bg-primary/5"
                >
                  <RadioGroupItem value={t} id={`type-${t}`} className="sr-only" />
                  {renderTargetIcon(t)}
                  <span className="font-medium capitalize">{t}</span>
                  <span className="text-xs text-muted-foreground text-center">
                    {t === "file" ? "Single confidential file" : t === "folder" ? "Full directory & contents" : "Entire physical device / disk"}
                  </span>
                </Label>
              ))}
            </RadioGroup>
          </div>

          {/* File Target Section */}
          {targetType === "file" && (
            <div className="space-y-4 rounded-xl border p-4 bg-muted/20">
              <div className="flex items-center justify-between">
                <Label htmlFor="target-file-path" className="text-sm font-semibold flex items-center gap-2">
                  <FileText className="h-4 w-4 text-primary" /> File to Sanitize
                </Label>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => openExplorer("file")}
                    className="h-8 gap-1.5"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    Browse File...
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => handleNativePicker("file")}
                    disabled={nativePickerLoading}
                    className="h-8 gap-1.5"
                  >
                    {nativePickerLoading ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <ExternalLink className="h-3.5 w-3.5" />}
                    OS Dialog
                  </Button>
                </div>
              </div>

              <div className="relative">
                <Input
                  id="target-file-path"
                  placeholder="/home/user/confidential_document.pdf or C:\Data\secrets.docx"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  className="font-mono text-xs pl-3"
                />
              </div>

              {/* Quick Preset Locations */}
              <div className="space-y-1.5 pt-1">
                <p className="text-xs text-muted-foreground">Quick Locations:</p>
                <div className="flex flex-wrap gap-2">
                  {["Desktop", "Documents", "Downloads", "/tmp"].map((loc) => (
                    <Button
                      key={loc}
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs px-2.5 bg-background border"
                      onClick={() => openExplorer("file")}
                    >
                      <Folder className="h-3 w-3 mr-1 text-muted-foreground" /> {loc}
                    </Button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Folder Target Section */}
          {targetType === "folder" && (
            <div className="space-y-4 rounded-xl border p-4 bg-muted/20">
              <div className="flex items-center justify-between">
                <Label htmlFor="target-folder-path" className="text-sm font-semibold flex items-center gap-2">
                  <Folder className="h-4 w-4 text-primary" /> Folder / Directory to Sanitize
                </Label>
                <div className="flex items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => openExplorer("folder")}
                    className="h-8 gap-1.5"
                  >
                    <FolderOpen className="h-3.5 w-3.5" />
                    Browse Folder...
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => handleNativePicker("folder")}
                    disabled={nativePickerLoading}
                    className="h-8 gap-1.5"
                  >
                    {nativePickerLoading ? <Loader className="h-3.5 w-3.5 animate-spin" /> : <ExternalLink className="h-3.5 w-3.5" />}
                    OS Dialog
                  </Button>
                </div>
              </div>

              <div className="relative">
                <Input
                  id="target-folder-path"
                  placeholder="/home/user/classified_project or D:\Sensitive_Data"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  className="font-mono text-xs pl-3"
                />
              </div>

              <p className="text-xs text-muted-foreground">
                All files and subdirectories contained in this folder will be individually overwritten according to the selected protocol and safely deleted.
              </p>
            </div>
          )}

          {/* Disk Selection */}
          {targetType === "disk" && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium">Connected Physical Storage Devices</Label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={async () => {
                    setDevicesLoading(true);
                    try {
                      const res = await fetch(`${API_BASE}/api/devices`, { cache: "no-store" });
                      if (res.ok) {
                        const data = await res.json();
                        setDevices(data.map((d: any) => ({
                          id: d.name,
                          name: d.name,
                          friendlyName: d.friendlyName || d.name,
                          size: d.size,
                          type: d.type,
                          isSystem: d.isSystem,
                        })));
                      }
                    } finally {
                      setDevicesLoading(false);
                    }
                  }}
                  className="h-7 text-xs gap-1"
                >
                  <RefreshCw className={`h-3 w-3 ${devicesLoading ? "animate-spin" : ""}`} /> Refresh
                </Button>
              </div>

              {devicesLoading ? (
                <div className="flex items-center gap-2 text-muted-foreground py-6 justify-center">
                  <Loader className="h-4 w-4 animate-spin text-primary" />
                  <span className="text-sm">Scanning block devices and storage buses...</span>
                </div>
              ) : devices.length === 0 ? (
                <div className="rounded-lg border border-dashed p-6 text-center">
                  <HardDrive className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="text-sm text-muted-foreground">No physical storage devices found.</p>
                  <p className="text-xs text-muted-foreground mt-1">Connect a USB drive or external device, or specify the device path manually below.</p>
                </div>
              ) : (
                <RadioGroup
                  value={selectedDevice}
                  onValueChange={setSelectedDevice}
                  className="grid gap-2"
                >
                  {devices.map((device) => {
                    const DevIcon = getDeviceIcon(device.type);
                    return (
                      <Label
                        key={device.id}
                        htmlFor={`dev-${device.id}`}
                        className="flex items-center gap-3 rounded-lg border p-3 cursor-pointer hover:bg-accent transition-colors [&:has([data-state=checked])]:border-primary [&:has([data-state=checked])]:bg-primary/5"
                      >
                        <DevIcon className="h-5 w-5 text-muted-foreground flex-shrink-0" />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <p className="font-semibold text-sm truncate">{device.friendlyName || device.name}</p>
                            {device.isSystem && (
                              <Badge variant="destructive" className="text-[10px] py-0 px-1.5">
                                OS Boot Device
                              </Badge>
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground font-mono mt-0.5">
                            {device.name} · {device.size} · {device.type || "Block Device"}
                          </p>
                        </div>
                        <RadioGroupItem value={device.name} id={`dev-${device.id}`} />
                      </Label>
                    );
                  })}
                </RadioGroup>
              )}

              <div className="pt-2">
                <Label htmlFor="manual-path" className="text-xs text-muted-foreground">
                  Manual block device path (e.g., /dev/sdb, /dev/sdc, \\.\PhysicalDrive1):
                </Label>
                <Input
                  id="manual-path"
                  placeholder="/dev/sdb or E:"
                  value={selectedDevice || ""}
                  onChange={(e) => setSelectedDevice(e.target.value || undefined)}
                  className="mt-1 font-mono text-xs"
                />
              </div>
            </div>
          )}

          {/* Safety notice */}
          <div className="flex items-start gap-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-3">
            <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
            <div className="text-xs text-amber-800 dark:text-amber-300">
              <p className="font-semibold mb-0.5">Safety & System Protection</p>
              <p>Operating system volumes and boot partitions are automatically locked. Sanitization is permanent and irreversibly destroys addressable data.</p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Interactive In-Browser File & Folder Explorer Modal */}
      <Dialog open={browserOpen} onOpenChange={setBrowserOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] flex flex-col p-0 overflow-hidden">
          <DialogHeader className="p-4 pb-2 border-b">
            <DialogTitle className="flex items-center gap-2 text-base">
              <FolderOpen className="h-5 w-5 text-primary" />
              {browserMode === "folder" ? "Browse & Select Folder" : "Browse & Select File"}
            </DialogTitle>
            <DialogDescription className="text-xs">
              Navigate your system storage to choose the {browserMode === "folder" ? "folder" : "file"} to sanitize.
            </DialogDescription>
          </DialogHeader>

          {/* Quick Roots Bar */}
          <div className="px-4 py-2 bg-muted/40 border-b flex items-center gap-2 overflow-x-auto text-xs">
            <span className="text-muted-foreground flex items-center gap-1 flex-shrink-0 font-medium">
              <Home className="h-3 w-3" /> Quick:
            </span>
            {browserRoots.map((root) => (
              <Button
                key={root.path}
                type="button"
                variant="ghost"
                size="sm"
                className="h-6 px-2 text-[11px] bg-background border flex-shrink-0"
                onClick={() => loadDirectory(root.path)}
              >
                {root.name}
              </Button>
            ))}
          </div>

          {/* Breadcrumb Path Bar & Up Button */}
          <div className="px-4 py-2 flex items-center gap-2 border-b bg-background">
            <Button
              type="button"
              variant="outline"
              size="icon"
              className="h-7 w-7 flex-shrink-0"
              disabled={!browserParentPath || browserLoading}
              onClick={() => browserParentPath && loadDirectory(browserParentPath)}
            >
              <ArrowUp className="h-3.5 w-3.5" />
            </Button>
            <div className="flex-1 font-mono text-xs bg-muted/50 px-2.5 py-1.5 rounded border truncate">
              {browserCurrentPath || "/"}
            </div>
            <div className="relative w-40 flex-shrink-0">
              <Search className="h-3 w-3 absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Filter items..."
                value={browserSearch}
                onChange={(e) => setBrowserSearch(e.target.value)}
                className="h-7 text-xs pl-7"
              />
            </div>
          </div>

          {/* Directory Items List */}
          <div className="flex-1 overflow-y-auto p-4 min-h-[260px] max-h-[360px]">
            {browserLoading ? (
              <div className="flex items-center justify-center h-full py-12 text-muted-foreground">
                <Loader className="h-6 w-6 animate-spin text-primary mr-2" />
                <span className="text-sm">Loading directory...</span>
              </div>
            ) : filteredBrowserItems.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground text-xs">
                No items found in this directory.
              </div>
            ) : (
              <div className="grid gap-1">
                {filteredBrowserItems.map((item) => {
                  const isSelected = browserSelectedFile === item.path;
                  return (
                    <div
                      key={item.path}
                      onClick={() => {
                        if (item.is_dir) {
                          loadDirectory(item.path);
                        } else if (browserMode === "file") {
                          setBrowserSelectedFile(item.path);
                        }
                      }}
                      className={`flex items-center justify-between p-2 rounded-md cursor-pointer transition-colors text-xs ${
                        isSelected
                          ? "bg-primary text-primary-foreground font-semibold"
                          : "hover:bg-muted/70"
                      }`}
                    >
                      <div className="flex items-center gap-2 min-w-0 flex-1">
                        {item.is_dir ? (
                          <Folder className="h-4 w-4 text-amber-500 flex-shrink-0" />
                        ) : (
                          <FileText className="h-4 w-4 text-blue-500 flex-shrink-0" />
                        )}
                        <span className="truncate">{item.name}</span>
                      </div>
                      <div className="flex items-center gap-3 text-muted-foreground text-[11px] flex-shrink-0 ml-2">
                        {!item.is_dir && <span>{formatBytes(item.size_bytes)}</span>}
                        {item.is_dir && (
                          <span className="text-[10px] bg-muted px-1.5 py-0.5 rounded">Folder</span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <DialogFooter className="p-3 border-t bg-muted/20 flex flex-row justify-between items-center">
            <div className="text-xs text-muted-foreground truncate max-w-[280px]">
              {browserMode === "folder" ? (
                <span>Folder: <strong>{browserCurrentPath}</strong></span>
              ) : browserSelectedFile ? (
                <span>Selected: <strong>{browserSelectedFile.split("/").pop() || browserSelectedFile}</strong></span>
              ) : (
                <span>Click a file to select</span>
              )}
            </div>
            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" onClick={() => setBrowserOpen(false)}>
                Cancel
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={confirmExplorerSelection}
                disabled={browserMode === "file" && !browserSelectedFile}
              >
                {browserMode === "folder" ? "Select This Folder" : "Select File"}
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );

  // ---------------------------------------------------------------------------
  // Step 2: Method Configuration
  // ---------------------------------------------------------------------------

  const renderStep2 = () => (
    <div className="grid md:grid-cols-3 gap-6">
      <div className="md:col-span-2 space-y-6">
        <Card className="bg-muted/40">
          <CardContent className="pt-4 pb-3">
            <div className="flex items-center gap-3">
              {renderTargetIcon(targetType)}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold truncate">Target: {effectiveTarget || "(not set)"}</p>
                <p className="text-xs text-muted-foreground capitalize">Type: {targetType}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="h-5 w-5 text-primary" />
              Step 2: Configure Sanitization Policy
            </CardTitle>
            <CardDescription>
              Choose the approved baseline erasure method. The forensic verification and recovery assessment framework will evaluate results independently.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-5">
            <RadioGroup
              value={selectedMethod}
              onValueChange={setSelectedMethod}
              className="grid gap-3"
            >
              {methods.map((method) => (
                <Label
                  key={method.id}
                  htmlFor={`method-${method.id}`}
                  className="flex flex-col rounded-lg border-2 p-4 cursor-pointer hover:bg-accent transition-colors [&:has([data-state=checked])]:border-primary [&:has([data-state=checked])]:bg-primary/5"
                >
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{method.label}</span>
                      <Badge variant="outline" className="text-xs">{method.passes} pass{method.passes !== 1 ? "es" : ""}</Badge>
                    </div>
                    <RadioGroupItem value={method.id} id={`method-${method.id}`} />
                  </div>
                  <p className="text-xs text-muted-foreground">{method.description}</p>
                </Label>
              ))}
            </RadioGroup>

            <div className="space-y-2 pt-2 border-t">
              <Label className="text-sm font-medium">Max Remediation Iterations</Label>
              <div className="flex items-center gap-4">
                <Input
                  type="number"
                  min={1}
                  max={5}
                  value={maxIterations}
                  onChange={(e) => setMaxIterations(Math.max(1, Math.min(5, parseInt(e.target.value) || 1)))}
                  className="w-24 font-mono text-center"
                />
                <p className="text-xs text-muted-foreground">
                  If the recovery assessment detects recoverable fragments, the engine will re-sanitize up to this limit before final classification.
                </p>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="operator" className="text-sm font-medium">Authorizing Officer / Operator</Label>
              <Input
                id="operator"
                placeholder="Officer Name or Service ID"
                value={operator}
                onChange={(e) => setOperator(e.target.value)}
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Sidebar Info */}
      <div className="space-y-4">
        <Card className="bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2 text-blue-900 dark:text-blue-300">
              <Activity className="h-4 w-4" />
              Adaptive Pipeline Sequence
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-xs text-blue-800 dark:text-blue-400">
              {[
                "Device Detection",
                "Sanitization Overwrite",
                "Verification Pass",
                "Forensic Recovery Scan",
                "Adaptive Decision",
                "Final Classification",
              ].map((s, i) => (
                <div key={s} className="flex items-center gap-2">
                  <span className="w-5 h-5 rounded-full bg-blue-200 dark:bg-blue-800 flex items-center justify-center text-[10px] font-bold flex-shrink-0">{i + 1}</span>
                  <span>{s}</span>
                  {i < 5 && <ChevronRight className="h-3 w-3 ml-auto opacity-60" />}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex items-center gap-2">
              <Info className="h-4 w-4" />
              Assurance Classifications
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2.5 text-xs">
            {[
              { emoji: "🟢", label: "SANITIZED — REUSABLE", desc: "Pass verification & zero recoverable traces." },
              { emoji: "🟡", label: "POLICY REVIEW REQUIRED", desc: "NAND / controller wear-leveling uncertainty." },
              { emoji: "🔴", label: "CONTROLLED DISPOSAL", desc: "Verification failed; data remnants persist." },
            ].map((s) => (
              <div key={s.label} className="flex items-start gap-2">
                <span className="text-base leading-none mt-0.5">{s.emoji}</span>
                <div>
                  <p className="font-semibold text-foreground">{s.label}</p>
                  <p className="text-muted-foreground">{s.desc}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  );

  // ---------------------------------------------------------------------------
  // Step 3: Execution & Results
  // ---------------------------------------------------------------------------

  const renderStep3 = () => {
    const finalConfig = sessionResult ? getFinalStateConfig(sessionResult.final_state) : null;
    const FinalIcon = finalConfig?.icon;
    const isComplete = !isRunning && sessionResult !== null;

    return (
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {isRunning && <Loader className="h-5 w-5 animate-spin text-primary" />}
              {isComplete && FinalIcon && <FinalIcon className={`h-5 w-5 ${finalConfig?.color}`} />}
              Adaptive Sanitization Assurance Pipeline
            </CardTitle>
            <CardDescription className="truncate">
              {isRunning
                ? `Executing adaptive pipeline for: ${effectiveTarget}`
                : isComplete
                ? `Pipeline execution finished for: ${effectiveTarget}`
                : "Initializing..."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <PipelineProgress currentStage={currentStage} iterations={currentIteration} />
            <Progress value={progress} className="h-2 mb-2" />
            <p className="text-xs text-muted-foreground">{progress}% complete</p>
          </CardContent>
        </Card>

        {/* Live Terminal Log */}
        <Accordion type="single" collapsible defaultValue="logs">
          <AccordionItem value="logs">
            <AccordionTrigger className="text-sm font-medium">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                Live Pipeline Execution Log
              </div>
            </AccordionTrigger>
            <AccordionContent>
              <div className="h-56 bg-gray-950 text-green-400 font-mono text-xs rounded-lg p-4 overflow-y-auto space-y-1">
                {logs.length === 0 && <p className="text-gray-500">Connecting to sanitization engine...</p>}
                {logs.map((log, i) => (
                  <p key={i} className={
                    log.includes("[ERROR]") ? "text-red-400 font-bold" :
                    log.includes("[FINAL]") ? "text-yellow-300 font-bold" :
                    log.includes("[DECISION]") ? "text-cyan-300" :
                    log.includes("[RECOVER]") ? "text-orange-300" :
                    log.includes("[VERIFY]") ? "text-blue-300 font-semibold" :
                    log.includes("[STAGE") ? "text-purple-300 font-bold" :
                    log.includes("[RETRY]") ? "text-yellow-400" :
                    "text-green-400"
                  }>
                    <span className="text-gray-600 mr-2">{String(i + 1).padStart(3, "0")}</span>
                    {log}
                  </p>
                ))}
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>

        {/* Final Assurance Banner & Result */}
        {isComplete && sessionResult && finalConfig && FinalIcon && (
          <div className="space-y-4 animate-fade-in">
            <div className={`rounded-xl border-2 p-6 ${finalConfig.bg}`}>
              <div className="flex items-center gap-4">
                <FinalIcon className={`h-12 w-12 ${finalConfig.color} flex-shrink-0`} />
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className="text-2xl">{finalConfig.emoji}</span>
                    <h3 className={`text-lg font-bold ${finalConfig.color}`}>{finalConfig.label}</h3>
                  </div>
                  <p className="text-sm text-foreground/80">{sessionResult.final_reason}</p>
                </div>
              </div>
            </div>

            {/* Iteration Pass Details */}
            {sessionResult.iterations && sessionResult.iterations.length > 0 && (
              <Accordion type="multiple" defaultValue={[`iter-${sessionResult.iterations.length}`]}>
                {sessionResult.iterations.map((iter) => (
                  <AccordionItem key={iter.iteration} value={`iter-${iter.iteration}`}>
                    <AccordionTrigger className="text-sm">
                      <div className="flex items-center gap-3">
                        <Badge variant="outline">Iteration {iter.iteration}</Badge>
                        <span className="font-normal">{iter.sanitization?.label}</span>
                        {iter.recovery_assessment && getRecoveryBadge(iter.recovery_assessment.classification)}
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      <div className="grid md:grid-cols-3 gap-4 text-xs">
                        <div className="space-y-1.5 p-3 rounded-lg bg-muted/40 border">
                          <p className="font-semibold flex items-center gap-1">
                            <Shield className="h-3.5 w-3.5 text-primary" /> Sanitization
                          </p>
                          <p className={iter.sanitization?.success ? "text-green-600 dark:text-green-400 font-medium" : "text-red-600 font-medium"}>
                            {iter.sanitization?.success ? "✓ Overwrite Completed" : "✗ Overwrite Failed"}
                          </p>
                          <p className="text-muted-foreground">{iter.sanitization?.message}</p>
                        </div>

                        <div className="space-y-1.5 p-3 rounded-lg bg-muted/40 border">
                          <p className="font-semibold flex items-center gap-1">
                            <CheckCircle className="h-3.5 w-3.5 text-green-600" /> Verification
                          </p>
                          <Badge className={
                            iter.verification?.status === "PASS" ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200" :
                            iter.verification?.status === "WARN" ? "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200" :
                            "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                          }>
                            VERIFICATION = {iter.verification?.status || "N/A"}
                          </Badge>
                          {iter.verification?.warnings?.map((w, wi) => (
                            <p key={wi} className="text-yellow-600 dark:text-yellow-400">⚠ {w}</p>
                          ))}
                          {iter.verification?.errors?.map((e, ei) => (
                            <p key={ei} className="text-red-600 dark:text-red-400">✗ {e}</p>
                          ))}
                        </div>

                        <div className="space-y-1.5 p-3 rounded-lg bg-muted/40 border">
                          <p className="font-semibold flex items-center gap-1">
                            <Search className="h-3.5 w-3.5 text-blue-600" /> Recovery Assessment
                          </p>
                          {getRecoveryBadge(iter.recovery_assessment?.classification || null)}
                          <p className="text-muted-foreground">{iter.recovery_assessment?.detail}</p>
                        </div>
                      </div>

                      {iter.decision && (
                        <div className="mt-3 pt-3 border-t">
                          <div className="flex items-center gap-2 text-xs">
                            <span className="font-semibold">Decision Engine:</span>
                            <Badge variant={iter.decision.action === "PASS" ? "default" : iter.decision.action === "RETRY" ? "secondary" : "destructive"}>
                              {iter.decision.action}
                            </Badge>
                            <span className="text-muted-foreground">{iter.decision.reason}</span>
                          </div>
                        </div>
                      )}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            )}

            {/* Audit Certificate Summary Card */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <ClipboardList className="h-4 w-4 text-primary" />
                  Audit Trail & Assurance Verification
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                  <div>
                    <p className="text-muted-foreground">Session ID</p>
                    <p className="font-mono font-bold text-primary">{sessionResult.session_id}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Software Version</p>
                    <p className="font-medium">{sessionResult.software_version}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Method Applied</p>
                    <p className="font-medium">{sessionResult.sanitization_method_label}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Total Passes / Iterations</p>
                    <p className="font-medium">{sessionResult.total_iterations}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Start Time</p>
                    <p className="font-mono">{sessionResult.start_time}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">End Time</p>
                    <p className="font-mono">{sessionResult.end_time}</p>
                  </div>
                  <div className="col-span-2 md:col-span-3">
                    <p className="text-muted-foreground">Tamper-Evident SHA-256 Digest</p>
                    <p className="font-mono text-[11px] bg-muted p-2 rounded break-all">{sessionResult.tamper_hash}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    );
  };

  // ---------------------------------------------------------------------------
  // Step indicator
  // ---------------------------------------------------------------------------

  const renderStepIndicator = () => (
    <div className="flex items-center gap-2 mb-6">
      {[
        { num: 1, label: "Select Target" },
        { num: 2, label: "Configure Method" },
        { num: 3, label: "Execute Pipeline" },
      ].map((s) => (
        <React.Fragment key={s.num}>
          <div className={`flex items-center gap-2 ${step === s.num ? "text-primary" : step > s.num ? "text-muted-foreground" : "text-muted-foreground/40"}`}>
            <div className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 ${step === s.num ? "border-primary bg-primary text-primary-foreground" : step > s.num ? "border-border bg-muted" : "border-border/40"}`}>
              {step > s.num ? <CheckCircle className="h-3.5 w-3.5" /> : s.num}
            </div>
            <span className="text-sm font-medium hidden sm:block">{s.label}</span>
          </div>
          {s.num < 3 && <ChevronRight className="h-4 w-4 text-muted-foreground/40 flex-shrink-0" />}
        </React.Fragment>
      ))}
    </div>
  );

  const canProceedStep1 = targetType === "disk" ? !!selectedDevice : !!targetPath;
  const canProceedStep2 = !!selectedMethod && !!operator;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Adaptive Sanitization Framework</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Government & NTRO-compliant data sanitization assurance platform · Multi-pass erasure with forensic recovery assessment
        </p>
      </div>

      {renderStepIndicator()}

      {step === 1 && renderStep1()}
      {step === 2 && renderStep2()}
      {step === 3 && renderStep3()}

      {/* Navigation Footer */}
      <div className="flex justify-between items-center pt-3 border-t">
        <Button
          variant="outline"
          onClick={() => setStep(step - 1)}
          disabled={step === 1 || isRunning}
        >
          <ChevronLeft className="mr-2 h-4 w-4" /> Back
        </Button>

        {step === 1 && (
          <Button onClick={() => setStep(2)} disabled={!canProceedStep1}>
            Configure Sanitization <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        )}

        {step === 2 && (
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button disabled={!canProceedStep2 || !effectiveTarget}>
                <Shield className="mr-2 h-4 w-4" />
                Start Sanitization Pipeline
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Confirm Irreversible Sanitization</AlertDialogTitle>
                <AlertDialogDescription className="space-y-2">
                  <p>You are initiating an adaptive sanitization assurance sequence on:</p>
                  <div className="rounded-md bg-muted p-3 text-xs space-y-1 font-mono">
                    <p><strong>Target:</strong> {effectiveTarget}</p>
                    <p><strong>Target Type:</strong> {targetType}</p>
                    <p><strong>Method:</strong> {selectedMethodConfig?.label}</p>
                    <p><strong>Max Iterations:</strong> {maxIterations}</p>
                    <p><strong>Operator:</strong> {operator}</p>
                  </div>
                  <p className="text-destructive font-semibold text-xs">
                    WARNING: All addressable data on this target will be destroyed. This operation cannot be reversed.
                  </p>
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={handleStartSanitization} className="bg-destructive hover:bg-destructive/90">
                  Confirm & Start Pipeline
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        )}

        {step === 3 && !isRunning && sessionResult && (
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={() => {
                setStep(1);
                setSessionResult(null);
                setLogs([]);
                setProgress(0);
                setCurrentStage("idle");
              }}
            >
              <RefreshCw className="mr-2 h-4 w-4" /> New Sanitization
            </Button>
            <Button onClick={() => router.push(`/history`)}>
              View History <ChevronRight className="ml-2 h-4 w-4" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export default function WipePage() {
  return (
    <Suspense fallback={<div className="flex items-center gap-2 p-8"><Loader className="animate-spin" /> Loading...</div>}>
      <WipePageComponent />
    </Suspense>
  );
}
