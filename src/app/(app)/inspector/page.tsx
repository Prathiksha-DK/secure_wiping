"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
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
  Lock,
  Search,
  Cpu,
  HardDrive,
  Layers,
  Activity,
  ArrowLeft,
  ArrowRight,
  ChevronsLeft,
  ChevronsRight,
  FileDown,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Binary,
  FolderTree,
  Eye,
  CheckCircle2,
  Folder,
  FileText,
  File,
  Info,
  Hash,
  Copy,
  Check,
  ExternalLink,
} from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";

interface HexRow {
  address: string;
  address_dec: number;
  hex: string;
  ascii: string;
  sector_index: number;
}

interface SectorAnalysis {
  detected_structure: string;
  entropy: number;
  total_bytes: number;
  zero_bytes: number;
  nonzero_bytes: number;
  ff_bytes: number;
  zero_percentage: number;
  ff_percentage: number;
  printable_ascii_percentage: number;
  unique_byte_values: number;
  top_byte_values: Array<{ byte_hex: string; count: number; pct: number }>;
  pattern_type: string;
  observed_pattern: string;
  details: string;
  sanitization_inspection?: {
    observed: string;
    expected: string;
    bytes_inspected: number;
    matching_bytes: number;
    match_percentage: number;
    statement: string;
  };
}

interface DeviceMetadata {
  target_path: string;
  target_type: string;
  exists: boolean;
  physical_identity: {
    model: string;
    serial: string;
    vendor: string;
    bus_interface: string;
    media_type: string;
    firmware_revision: string;
    capacity_bytes: number;
    logical_sector_size: number;
    physical_sector_size: number;
    partition_table_type: string;
    total_sectors: number;
  };
  os_metadata: {
    platform: string;
    read_only_access: boolean;
    is_block_device: boolean;
    is_file: boolean;
    is_directory: boolean;
    mount_point: string;
    filesystem_type: string;
    volume_label: string;
    uuid: string;
    size_formatted: string;
    permissions: string;
    inode: string;
    timestamps_applicable: boolean;
    created_time: string;
    modified_time: string;
    accessed_time: string;
  };
  health_capability?: {
    status: string;
    smart_supported: boolean;
    temperature: string;
    reallocated_sectors: string;
    wear_indicator: string;
    source: string;
  };
  partitions: Array<{
    partition_number: number;
    name: string;
    path: string;
    size_bytes: number;
    size_formatted: string;
    start_lba: number;
    end_lba: number;
    filesystem: string;
    mountpoint: string;
    uuid: string;
    label: string;
  }>;
  sanitization_certificate_link?: {
    has_certificate: boolean;
    session_id: string;
    method: string;
    status: string;
    final_state: string;
    timestamp: string;
    verified_lba: number;
  } | null;
  inspection_disclaimer: string;
}

export default function StorageInspectorPage() {
  const [target, setTarget] = useState<string>("");
  const [lba, setLba] = useState<number>(0);
  const [lbaInput, setLbaInput] = useState<string>("0");
  const [sectorSize, setSectorSize] = useState<number>(512);
  const [sectorCount, setSectorCount] = useState<number>(1);
  const [activeTab, setActiveTab] = useState<string>("hex");

  const [loading, setLoading] = useState<boolean>(false);
  const [hexData, setHexData] = useState<HexRow[]>([]);
  const [analysis, setAnalysis] = useState<SectorAnalysis | null>(null);
  const [currentSha256, setCurrentSha256] = useState<string>("");
  const [metadata, setMetadata] = useState<DeviceMetadata | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  // Connected devices from OS
  const [devices, setDevices] = useState<any[]>([]);

  // Search State
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [searchType, setSearchType] = useState<string>("text");
  const [searchMode, setSearchMode] = useState<string>("both"); // "both" | "filesystem" | "raw"
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searchSummary, setSearchSummary] = useState<any>(null);
  const [searching, setSearching] = useState<boolean>(false);

  // File / Folder Details Modal State
  const [detailsOpen, setDetailsOpen] = useState<boolean>(false);
  const [detailsLoading, setDetailsLoading] = useState<boolean>(false);
  const [detailsHashing, setDetailsHashing] = useState<boolean>(false);
  const [selectedDetails, setSelectedDetails] = useState<any>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    if (navigator?.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  const handleOpenDetails = async (filePath: string) => {
    if (!filePath) return;
    setDetailsOpen(true);
    setDetailsLoading(true);
    setSelectedDetails(null);
    try {
      const res = await fetch("http://localhost:9758/api/inspector/file-details", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: filePath, compute_hash: false, target_device: target }),
      });
      const data = await res.json();
      setSelectedDetails(data);
    } catch (e: any) {
      setSelectedDetails({ error: e.message, status: "ERROR" });
    } finally {
      setDetailsLoading(false);
    }
  };

  const handleComputeSha256 = async (filePath: string) => {
    if (!filePath) return;
    setDetailsHashing(true);
    try {
      const res = await fetch("http://localhost:9758/api/inspector/file-details", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: filePath, compute_hash: true, target_device: target }),
      });
      const data = await res.json();
      if (data) {
        setSelectedDetails((prev: any) => ({
          ...prev,
          ...data,
        }));
      }
    } catch (e: any) {
      console.error(e);
    } finally {
      setDetailsHashing(false);
    }
  };

  // Before / After Diff State
  const [beforeHex, setBeforeHex] = useState<string>("");
  const [afterHex, setAfterHex] = useState<string>("");
  const [diffResult, setDiffResult] = useState<any>(null);

  // Fetch real connected physical devices on mount
  useEffect(() => {
    fetch("http://localhost:9758/api/devices")
      .then((r) => r.json())
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setDevices(data);
          const firstRealDev = data[0].devicePath || data[0].name;
          setTarget(firstRealDev);
          loadDeviceAndSector(firstRealDev, 0, sectorSize, sectorCount);
        }
      })
      .catch(() => {});
  }, []);

  // Fetch metadata and hex from backend
  const loadDeviceAndSector = async (
    targetPath: string = target,
    sectorNum: number = lba,
    secSize: number = sectorSize,
    count: number = sectorCount
  ) => {
    if (!targetPath) return;
    setLoading(true);
    setErrorMsg("");

    try {
      // 1. Fetch Metadata
      const metaRes = await fetch("http://localhost:9758/api/inspector/device-info", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: targetPath }),
      });
      const metaData = await metaRes.json();
      if (metaData.error) {
        setErrorMsg(metaData.error);
      } else {
        setMetadata(metaData);
      }

      // 2. Fetch Hex Sector
      const hexRes = await fetch("http://localhost:9758/api/inspector/read-hex", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target: targetPath,
          lba: sectorNum,
          sector_size: secSize,
          sector_count: count,
        }),
      });
      const hexResp = await hexRes.json();
      if (hexResp.error) {
        setErrorMsg(hexResp.error);
        setHexData([]);
        setAnalysis(null);
        setCurrentSha256("");
      } else {
        setHexData(hexResp.rows || []);
        setAnalysis(hexResp.analysis || null);
        setCurrentSha256(hexResp.sha256 || "");
        setLba(sectorNum);
        setLbaInput(sectorNum.toString());
      }
    } catch (e: any) {
      setErrorMsg(`Failed to connect to inspector backend: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  // Jump handlers
  const handleJumpLba = () => {
    const parsed = parseInt(lbaInput, 10);
    if (!isNaN(parsed) && parsed >= 0) {
      loadDeviceAndSector(target, parsed, sectorSize, sectorCount);
    }
  };

  const handleNextSector = () => {
    const next = lba + sectorCount;
    loadDeviceAndSector(target, next, sectorSize, sectorCount);
  };

  const handlePrevSector = () => {
    const prev = Math.max(0, lba - sectorCount);
    loadDeviceAndSector(target, prev, sectorSize, sectorCount);
  };

  const handlePageForward = () => {
    const next = lba + 16;
    loadDeviceAndSector(target, next, sectorSize, sectorCount);
  };

  const handlePageBackward = () => {
    const prev = Math.max(0, lba - 16);
    loadDeviceAndSector(target, prev, sectorSize, sectorCount);
  };

  const handleJumpEnd = () => {
    if (metadata && metadata.physical_identity.total_sectors > 0) {
      const endLba = Math.max(0, metadata.physical_identity.total_sectors - 1);
      loadDeviceAndSector(target, endLba, sectorSize, sectorCount);
    }
  };

  // Search handler
  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const res = await fetch("http://localhost:9758/api/inspector/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          query: searchQuery,
          query_type: searchType,
          search_mode: searchMode,
          max_scan_bytes: 50 * 1024 * 1024,
          sector_size: sectorSize,
        }),
      });
      const data = await res.json();
      setSearchResults(data.matches || []);
      setSearchSummary({
        total: data.total_matches ?? (data.matches ? data.matches.length : 0),
        fsCount: data.filesystem_matches_count ?? 0,
        rawCount: data.raw_matches_count ?? 0,
        fsStatus: data.filesystem_status || "OK",
        rawStatus: data.raw_status || "OK",
      });
    } catch (err) {
      console.error(err);
    } finally {
      setSearching(false);
    }
  };

  // Compare handler
  const handleCompare = async () => {
    try {
      const res = await fetch("http://localhost:9758/api/inspector/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          before_hex: beforeHex,
          after_hex: afterHex,
          lba,
          sector_size: sectorSize,
        }),
      });
      const data = await res.json();
      setDiffResult(data);
    } catch (err) {
      console.error(err);
    }
  };

  // Export report
  const handleExportReport = async () => {
    try {
      const res = await fetch("http://localhost:9758/api/inspector/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          lba,
          sector_size: sectorSize,
          metadata,
          analysis,
        }),
      });
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SecureWipe-Inspector-${target.replace(/[^a-zA-Z0-9]/g, "_")}-LBA${lba}.json`;
      a.click();
    } catch (err) {
      console.error(err);
    }
  };

  const byteOffset = lba * sectorSize;
  const endByteOffset = byteOffset + sectorSize * sectorCount - 1;

  const isFlashMedia = metadata?.physical_identity.media_type.toLowerCase().includes("ssd") ||
    metadata?.physical_identity.media_type.toLowerCase().includes("flash") ||
    metadata?.physical_identity.bus_interface.toLowerCase().includes("nvme");

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner with Permanent Read-Only Indicator */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b pb-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight">Storage Memory & Sector Inspector</h1>
            <Badge variant="outline" className="bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 font-mono text-xs flex items-center gap-1.5 py-1">
              <Lock className="h-3.5 w-3.5" /> 🔒 READ-ONLY INSPECTION MODE
            </Badge>
          </div>
          <p className="text-muted-foreground text-xs mt-1">
            Forensic read-only storage observer, low-level sector analyzer, and sanitization pattern verifier. Write operations strictly prohibited.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link href="/assessment">
            <Button size="sm" className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs">
              <Activity className="h-4 w-4 mr-1.5" /> Residual Scan (Phase 9)
            </Button>
          </Link>
          <Button size="sm" variant="outline" onClick={() => loadDeviceAndSector(target, lba, sectorSize, sectorCount)} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-1.5 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button size="sm" onClick={handleExportReport}>
            <FileDown className="h-4 w-4 mr-1.5" /> Export Report
          </Button>
        </div>
      </div>

      {/* Device Technology Boundary Warning */}
      <div className="p-3 bg-muted/30 rounded-lg border text-xs text-muted-foreground flex items-start gap-2.5">
        <ShieldAlert className="h-4 w-4 text-amber-500 flex-shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-foreground">Device Technology Inspection Notice: </span>
          {isFlashMedia ? (
            <span>
              Logical sector contents shown here represent the addressable storage interface. This view does not expose controller-managed NAND, over-provisioned areas, retired blocks, or hidden physical flash pages.
            </span>
          ) : (
            <span>
              This inspector displays the addressable sectors exposed by the storage device. It does not directly inspect magnetic domains.
            </span>
          )}
        </div>
      </div>

      {/* Target Selector Card */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <div className="flex-1">
              <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block mb-1">
                Selected Storage Target (Physical Device, Partition, or File Path)
              </label>
              <div className="flex gap-2">
                <Input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="/dev/nvme0n1 or /dev/sda"
                  className="font-mono text-sm"
                />
                <Button onClick={() => loadDeviceAndSector(target, 0, sectorSize, sectorCount)}>Inspect</Button>
              </div>
            </div>

            {/* Quick Real Device Buttons */}
            {devices.length > 0 && (
              <div className="sm:border-l sm:pl-4">
                <label className="text-xs font-semibold text-muted-foreground uppercase tracking-wider block mb-1">
                  Connected Storage Devices
                </label>
                <div className="flex flex-wrap gap-1.5">
                  {devices.map((d) => {
                    const devTarget = d.devicePath || d.name;
                    const isSelected = target === devTarget || target === d.name || target === d.devicePath;
                    return (
                      <Button
                        key={d.deviceId || d.name}
                        size="sm"
                        variant={isSelected ? "default" : "outline"}
                        className="text-xs font-mono h-8"
                        onClick={() => {
                          setTarget(devTarget);
                          loadDeviceAndSector(devTarget, 0, sectorSize, sectorCount);
                        }}
                      >
                        <HardDrive className="h-3 w-3 mr-1" />
                        {d.friendlyName || d.name} ({d.size})
                      </Button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg text-xs space-y-2">
              <div className="flex items-center gap-2 text-red-600 dark:text-red-400 font-semibold">
                <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                <span>{errorMsg}</span>
              </div>
              {errorMsg.toLowerCase().includes("permission denied") && (
                <div className="text-muted-foreground space-y-1.5 pt-1.5 border-t border-red-500/20">
                  <p className="font-semibold text-foreground">Storage Access Permission Guidance:</p>
                  <p className="text-[11px]">
                    <strong>Windows:</strong> Launch backend with Administrator privileges (Right-click Terminal / PowerShell &rarr; <em>Run as administrator</em>, then run <code className="font-mono bg-muted/50 px-1 py-0.5 rounded">python app.py</code>). Alternatively, inspect accessible volume drive letters (e.g. <code className="font-mono bg-muted/50 px-1 py-0.5 rounded">\\.\E:</code>) or file containers.
                  </p>
                  <p className="text-[11px]">
                    <strong>Linux:</strong> Grant disk group read rights: <code className="font-mono bg-muted/50 px-1 py-0.5 rounded">sudo usermod -a -G disk $USER</code> or start backend with root: <code className="font-mono bg-muted/50 px-1 py-0.5 rounded">sudo python3 backend/app.py</code>
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Sanitization Certificate Integration Banner */}
          {metadata?.sanitization_certificate_link && (
            <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2 text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 className="h-4 w-4 text-emerald-600 flex-shrink-0" />
                <span>
                  <strong>Sanitization Certificate Available: </strong>
                  Session {metadata.sanitization_certificate_link.session_id} ({metadata.sanitization_certificate_link.method}) — {metadata.sanitization_certificate_link.final_state}
                </span>
              </div>
              <Button
                size="sm"
                variant="outline"
                className="h-7 text-xs border-emerald-500/40 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-500/20"
                onClick={() => {
                  setLba(metadata.sanitization_certificate_link?.verified_lba || 0);
                  setLbaInput((metadata.sanitization_certificate_link?.verified_lba || 0).toString());
                  loadDeviceAndSector(target, metadata.sanitization_certificate_link?.verified_lba || 0, sectorSize, sectorCount);
                  setActiveTab("hex");
                }}
              >
                Inspect Verified Region (LBA 0)
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-4 max-w-2xl">
          <TabsTrigger value="hex" className="flex items-center gap-1.5 text-xs">
            <Binary className="h-3.5 w-3.5" /> Hex / Sector Viewer
          </TabsTrigger>
          <TabsTrigger value="metadata" className="flex items-center gap-1.5 text-xs">
            <Cpu className="h-3.5 w-3.5" /> Device & OS Metadata
          </TabsTrigger>
          <TabsTrigger value="diff" className="flex items-center gap-1.5 text-xs">
            <Activity className="h-3.5 w-3.5" /> Before / After Diff
          </TabsTrigger>
          <TabsTrigger value="search" className="flex items-center gap-1.5 text-xs">
            <Search className="h-3.5 w-3.5" /> Search Storage
          </TabsTrigger>
        </TabsList>

        {/* ---------------- TAB 1: HEX / SECTOR VIEWER ---------------- */}
        <TabsContent value="hex" className="space-y-4 pt-2">
          {/* Address Calculator & Navigation Bar */}
          <Card>
            <CardContent className="p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-4">
                {/* LBA Jump Form */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-muted-foreground uppercase">Target LBA:</span>
                  <Input
                    type="number"
                    value={lbaInput}
                    onChange={(e) => setLbaInput(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleJumpLba()}
                    className="font-mono text-sm w-28 h-8"
                  />
                  <Button size="sm" variant="secondary" className="h-8 text-xs" onClick={handleJumpLba}>
                    Jump
                  </Button>
                </div>

                {/* Sector Size Controls */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-muted-foreground uppercase">Sector Size:</span>
                  <div className="flex rounded-lg border p-0.5 bg-muted/30">
                    <Button
                      size="sm"
                      variant={sectorSize === 512 ? "default" : "ghost"}
                      className="h-7 text-xs px-2.5"
                      onClick={() => {
                        setSectorSize(512);
                        loadDeviceAndSector(target, lba, 512, sectorCount);
                      }}
                    >
                      512 B
                    </Button>
                    <Button
                      size="sm"
                      variant={sectorSize === 4096 ? "default" : "ghost"}
                      className="h-7 text-xs px-2.5"
                      onClick={() => {
                        setSectorSize(4096);
                        loadDeviceAndSector(target, lba, 4096, sectorCount);
                      }}
                    >
                      4096 B (4K)
                    </Button>
                  </div>
                </div>

                {/* Sector Count */}
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-muted-foreground uppercase">Sectors Displayed:</span>
                  <div className="flex rounded-lg border p-0.5 bg-muted/30">
                    {[1, 2, 4].map((c) => (
                      <Button
                        key={c}
                        size="sm"
                        variant={sectorCount === c ? "default" : "ghost"}
                        className="h-7 text-xs px-2"
                        onClick={() => {
                          setSectorCount(c);
                          loadDeviceAndSector(target, lba, sectorSize, c);
                        }}
                      >
                        {c}
                      </Button>
                    ))}
                  </div>
                </div>

                {/* Navigation Buttons */}
                <div className="flex items-center gap-1">
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Jump to Beginning (LBA 0)" onClick={() => loadDeviceAndSector(target, 0, sectorSize, sectorCount)}>
                    <ChevronsLeft className="h-4 w-4" />
                  </Button>
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Page Backward (-16 LBAs)" onClick={handlePageBackward}>
                    -16
                  </Button>
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Previous Sector" onClick={handlePrevSector}>
                    <ArrowLeft className="h-4 w-4 mr-1" /> Prev
                  </Button>
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Next Sector" onClick={handleNextSector}>
                    Next <ArrowRight className="h-4 w-4 ml-1" />
                  </Button>
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Page Forward (+16 LBAs)" onClick={handlePageForward}>
                    +16
                  </Button>
                  <Button size="sm" variant="outline" className="h-8 px-2" title="Jump to End LBA" onClick={handleJumpEnd}>
                    <ChevronsRight className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {/* Exact Address Calculator */}
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs font-mono bg-muted/40 p-2.5 rounded-md border">
                <div>
                  <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">LBA (Sector):</span>
                  <span className="font-bold text-primary">{lba.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">Sector Size:</span>
                  <span>{sectorSize} bytes</span>
                </div>
                <div>
                  <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">Byte Offset:</span>
                  <span className="font-bold">{byteOffset.toLocaleString()} (0x{byteOffset.toString(16).toUpperCase()})</span>
                </div>
                <div>
                  <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">End Byte Offset:</span>
                  <span>{endByteOffset.toLocaleString()}</span>
                </div>
                <div>
                  <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">Device Capacity:</span>
                  <span className="font-bold">{metadata?.os_metadata.size_formatted || "N/A"}</span>
                </div>
              </div>

              {/* Live Sector SHA-256 Telemetry */}
              {currentSha256 && (
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 bg-muted/25 rounded-md border text-xs font-mono">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <ShieldCheck className="h-4 w-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                    <span className="text-muted-foreground font-sans uppercase font-semibold text-[10px] flex-shrink-0">
                      Live Sector SHA-256:
                    </span>
                    <span className="font-bold text-foreground select-all break-all text-[11px]">
                      {currentSha256}
                    </span>
                  </div>
                  <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30 flex-shrink-0 self-start sm:self-auto">
                    LIVE BUFFER HASH
                  </Badge>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Hex Editor Dump Table */}
          <Card>
            <CardHeader className="py-3 px-4 bg-muted/30 border-b flex flex-row items-center justify-between">
              <CardTitle className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                Raw Addressable Sector Dump (16 Bytes / Line)
              </CardTitle>
              <Badge variant="outline" className="font-mono text-[10px]">
                READ-ONLY BUFFER
              </Badge>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto font-mono text-xs max-h-[480px] overflow-y-auto">
                <table className="w-full text-left border-collapse">
                  <thead className="bg-muted/50 border-b sticky top-0 text-[11px] text-muted-foreground">
                    <tr>
                      <th className="py-1.5 px-4 w-28">Address</th>
                      <th className="py-1.5 px-4">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</th>
                      <th className="py-1.5 px-4 w-48">ASCII</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40">
                    {hexData.length > 0 ? (
                      hexData.map((row) => (
                        <tr key={row.address} className="hover:bg-muted/30 transition-colors">
                          <td className="py-1 px-4 text-muted-foreground select-none font-bold">{row.address}</td>
                          <td className="py-1 px-4 text-foreground tracking-wider select-text">{row.hex}</td>
                          <td className="py-1 px-4 text-emerald-600 dark:text-emerald-400 select-text font-semibold">{row.ascii}</td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={3} className="py-12 text-center text-muted-foreground text-sm">
                          {loading ? "Reading raw sector stream..." : "No data to display."}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Real-time Sector Content & Sanitization Pattern Analysis Cards */}
          {analysis && (
            <div className="grid md:grid-cols-2 gap-4">
              {/* Byte & Region Analysis */}
              <Card>
                <CardHeader className="py-3 px-4 bg-muted/20 border-b">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                    <Activity className="h-4 w-4 text-primary" />
                    Byte & Region Analysis (LBA {lba})
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-2.5 bg-muted/30 rounded border">
                      <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Total / Zero Bytes:</span>
                      <span className="font-bold">{analysis.total_bytes} bytes ({analysis.zero_bytes} zeros / {analysis.zero_percentage}%)</span>
                    </div>
                    <div className="p-2.5 bg-muted/30 rounded border">
                      <span className="text-muted-foreground block text-[10px] uppercase font-semibold">0xFF / Non-Zero Bytes:</span>
                      <span className="font-bold">{analysis.ff_bytes} (0xFF) / {analysis.nonzero_bytes} non-zero</span>
                    </div>
                    <div className="p-2.5 bg-muted/30 rounded border">
                      <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Shannon Entropy:</span>
                      <span className="font-bold text-primary">{analysis.entropy} / 8.000 bits/byte</span>
                    </div>
                    <div className="p-2.5 bg-muted/30 rounded border">
                      <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Unique Bytes & ASCII:</span>
                      <span className="font-bold">{analysis.unique_byte_values} unique ({analysis.printable_ascii_percentage}% ASCII)</span>
                    </div>
                  </div>

                  <div className="p-2.5 bg-muted/20 rounded border">
                    <span className="text-muted-foreground block text-[10px] uppercase font-semibold mb-1">Most Frequent Bytes:</span>
                    <div className="flex gap-2 font-mono">
                      {analysis.top_byte_values?.map((tb, i) => (
                        <span key={i} className="px-1.5 py-0.5 bg-muted rounded border text-[11px]">
                          {tb.byte_hex}: {tb.pct}%
                        </span>
                      ))}
                    </div>
                  </div>

                  <div className="p-2.5 bg-muted/20 rounded border">
                    <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Detected Structure:</span>
                    <span className="font-bold text-primary">{analysis.detected_structure}</span>
                    <p className="text-muted-foreground text-[11px] mt-0.5">{analysis.details}</p>
                  </div>
                </CardContent>
              </Card>

              {/* Sanitization Pattern Analysis */}
              <Card>
                <CardHeader className="py-3 px-4 bg-muted/20 border-b">
                  <CardTitle className="text-xs font-semibold uppercase tracking-wider flex items-center gap-2">
                    <Eye className="h-4 w-4 text-primary" />
                    Sanitization Pattern Analysis
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-4 space-y-3 text-xs">
                  {analysis.sanitization_inspection && (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-2.5 bg-muted/30 rounded border">
                          <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Observed Pattern:</span>
                          <span className="font-bold text-emerald-600 dark:text-emerald-400">{analysis.sanitization_inspection.observed}</span>
                        </div>
                        <div className="p-2.5 bg-muted/30 rounded border">
                          <span className="text-muted-foreground block text-[10px] uppercase font-semibold">Expected Pattern:</span>
                          <span className="font-mono font-bold">{analysis.sanitization_inspection.expected}</span>
                        </div>
                      </div>

                      <div className="p-2.5 bg-muted/30 rounded border flex justify-between items-center font-mono">
                        <div>
                          <span className="text-muted-foreground font-sans block text-[10px] uppercase font-semibold">Pattern Match:</span>
                          <span className="font-bold text-sm">{analysis.sanitization_inspection.matching_bytes} / {analysis.sanitization_inspection.bytes_inspected} bytes</span>
                        </div>
                        <Badge variant="outline" className="text-sm font-bold bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
                          {analysis.sanitization_inspection.match_percentage}% Match
                        </Badge>
                      </div>

                      <div className="p-3 bg-muted/10 rounded border text-muted-foreground text-[11px] space-y-1">
                        <span className="font-semibold text-foreground block">Assurance Statement:</span>
                        <p>{analysis.sanitization_inspection.statement}</p>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* ---------------- TAB 2: DEVICE & OS METADATA ---------------- */}
        <TabsContent value="metadata" className="space-y-4 pt-2">
          {metadata ? (
            <div className="space-y-4">
              <div className="grid md:grid-cols-2 gap-6">
                {/* Physical Identity Card */}
                <Card>
                  <CardHeader className="py-3 px-4 bg-muted/30 border-b">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Cpu className="h-4 w-4 text-primary" /> Physical Device Identity (Hardware Reported)
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-4 text-xs space-y-2">
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Model Name:</span>
                      <span className="font-medium">{metadata.physical_identity.model}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Serial Number:</span>
                      <span className="font-mono font-medium">{metadata.physical_identity.serial}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Vendor / Manufacturer:</span>
                      <span>{metadata.physical_identity.vendor}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Bus / Interface:</span>
                      <span className="font-mono font-bold">{metadata.physical_identity.bus_interface}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Media Classification:</span>
                      <span>{metadata.physical_identity.media_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Firmware Revision:</span>
                      <span className="font-mono">{metadata.physical_identity.firmware_revision}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Reported Capacity:</span>
                      <span className="font-mono font-bold">{metadata.os_metadata.size_formatted}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Logical Sector Size:</span>
                      <span className="font-mono">{metadata.physical_identity.logical_sector_size} bytes</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Physical Sector Size:</span>
                      <span className="font-mono">{metadata.physical_identity.physical_sector_size} bytes</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-muted-foreground">Total Addressable Sectors:</span>
                      <span className="font-mono font-bold">{metadata.physical_identity.total_sectors.toLocaleString()} LBAs</span>
                    </div>
                  </CardContent>
                </Card>

                {/* Operating System Metadata & Health */}
                <Card>
                  <CardHeader className="py-3 px-4 bg-muted/30 border-b">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <Layers className="h-4 w-4 text-primary" /> Operating System & Filesystem Metadata
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-4 text-xs space-y-2">
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Operating System:</span>
                      <span>{metadata.os_metadata.platform}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Current Mount Point:</span>
                      <span className="font-mono font-medium">{metadata.os_metadata.mount_point}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Detected Filesystem:</span>
                      <span className="font-medium">{metadata.os_metadata.filesystem_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Volume Label:</span>
                      <span className="font-mono">{metadata.os_metadata.volume_label}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Filesystem UUID:</span>
                      <span className="font-mono text-[11px]">{metadata.os_metadata.uuid}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Partition Table Type:</span>
                      <span className="font-mono font-semibold">{metadata.physical_identity.partition_table_type}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Device Health / Status:</span>
                      <span className="font-semibold text-emerald-600 dark:text-emerald-400">{metadata.health_capability?.status}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b">
                      <span className="text-muted-foreground">Timestamps:</span>
                      <span className="text-muted-foreground font-mono">{metadata.os_metadata.modified_time}</span>
                    </div>
                    <div className="flex justify-between py-1">
                      <span className="text-muted-foreground">Read-Only Safety Status:</span>
                      <span className="text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1">
                        <ShieldCheck className="h-3.5 w-3.5" /> Enforced by OS Descriptors
                      </span>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Partition Map Card */}
              {metadata.partitions.length > 0 && (
                <Card>
                  <CardHeader className="py-3 px-4 bg-muted/20 border-b">
                    <CardTitle className="text-sm font-semibold flex items-center gap-2">
                      <FolderTree className="h-4 w-4 text-primary" /> Detected Partition Layout & Addressable Ranges
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="p-0">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-muted/50 border-b text-[11px] text-muted-foreground">
                        <tr>
                          <th className="py-2 px-4">#</th>
                          <th className="py-2 px-4">Partition Name</th>
                          <th className="py-2 px-4">Start LBA</th>
                          <th className="py-2 px-4">End LBA</th>
                          <th className="py-2 px-4">Size</th>
                          <th className="py-2 px-4">Filesystem</th>
                          <th className="py-2 px-4">Mount Point</th>
                          <th className="py-2 px-4 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        {metadata.partitions.map((p) => (
                          <tr key={p.name} className="hover:bg-muted/20">
                            <td className="py-2 px-4 font-bold">{p.partition_number}</td>
                            <td className="py-2 px-4 font-mono font-bold">{p.name}</td>
                            <td className="py-2 px-4 font-mono">{p.start_lba.toLocaleString()}</td>
                            <td className="py-2 px-4 font-mono">{p.end_lba.toLocaleString()}</td>
                            <td className="py-2 px-4 font-mono">{p.size_formatted}</td>
                            <td className="py-2 px-4">{p.filesystem}</td>
                            <td className="py-2 px-4 font-mono">{p.mountpoint}</td>
                            <td className="py-2 px-4 text-right">
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs"
                                onClick={() => {
                                  setLba(p.start_lba);
                                  setLbaInput(p.start_lba.toString());
                                  loadDeviceAndSector(target, p.start_lba, sectorSize, sectorCount);
                                  setActiveTab("hex");
                                }}
                              >
                                Jump to LBA {p.start_lba}
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </CardContent>
                </Card>
              )}

              {/* Forensic Scope Disclaimer */}
              <div className="p-3 bg-muted/20 border rounded-lg text-xs text-muted-foreground space-y-1">
                <span className="font-bold text-foreground block">Forensic Boundary & Observation Reality:</span>
                <p>{metadata.inspection_disclaimer}</p>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">Select a target to load metadata.</p>
          )}
        </TabsContent>

        {/* ---------------- TAB 3: BEFORE / AFTER DIFF ---------------- */}
        <TabsContent value="diff" className="space-y-4 pt-2">
          <Card>
            <CardHeader className="py-3 px-4 bg-muted/30 border-b">
              <CardTitle className="text-sm font-semibold">Before vs. After Sanitization Hex Diff</CardTitle>
              <CardDescription className="text-xs">
                Compare sector byte dumps before and after a sanitization pass to compute exact byte changes and pattern transitions.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-semibold text-muted-foreground uppercase">Before State (Hex Bytes):</label>
                    <Button size="sm" variant="ghost" className="h-6 text-[11px]" onClick={() => setBeforeHex(hexData.map((r) => r.hex).join(" "))}>
                      Capture Current LBA
                    </Button>
                  </div>
                  <textarea
                    rows={6}
                    value={beforeHex}
                    onChange={(e) => setBeforeHex(e.target.value)}
                    placeholder="Paste before hex dump..."
                    className="w-full font-mono text-xs p-2.5 rounded-md border bg-muted/20"
                  />
                </div>

                <div className="space-y-1.5">
                  <div className="flex justify-between items-center">
                    <label className="text-xs font-semibold text-muted-foreground uppercase">After State (Hex Bytes):</label>
                    <Button size="sm" variant="ghost" className="h-6 text-[11px]" onClick={() => setAfterHex(hexData.map((r) => r.hex).join(" "))}>
                      Capture Current LBA
                    </Button>
                  </div>
                  <textarea
                    rows={6}
                    value={afterHex}
                    onChange={(e) => setAfterHex(e.target.value)}
                    placeholder="Paste after hex dump..."
                    className="w-full font-mono text-xs p-2.5 rounded-md border bg-muted/20"
                  />
                </div>
              </div>

              <Button size="sm" onClick={handleCompare}>
                Calculate Sector Diff
              </Button>

              {diffResult && (
                <div className="p-4 bg-muted/30 rounded-lg border space-y-3 text-xs">
                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-2.5 bg-muted/50 rounded border">
                      <span className="text-muted-foreground block text-[11px]">Bytes Modified:</span>
                      <span className="text-lg font-bold text-primary">{diffResult.bytes_changed} / {diffResult.compared_bytes}</span>
                    </div>
                    <div className="p-2.5 bg-muted/50 rounded border">
                      <span className="text-muted-foreground block text-[11px]">Percentage Altered:</span>
                      <span className="text-lg font-bold text-emerald-600 dark:text-emerald-400">{diffResult.percentage_changed}%</span>
                    </div>
                    <div className="p-2.5 bg-muted/50 rounded border">
                      <span className="text-muted-foreground block text-[11px]">Post-Wipe Pattern:</span>
                      <span className="text-sm font-bold block truncate">{diffResult.after?.observed_pattern}</span>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---------------- TAB 4: SEARCH STORAGE ---------------- */}
        <TabsContent value="search" className="space-y-4 pt-2">
          <Card>
            <CardHeader className="py-3 px-4 bg-muted/30 border-b">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Search className="h-4 w-4 text-primary" /> Read-Only In-Storage Byte & Filesystem Search
                  </CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    Search through directory structures, file names, file contents (ASCII/UTF-8), and addressable raw storage sectors.
                  </CardDescription>
                </div>
                <Badge variant="outline" className="font-mono text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
                  <Lock className="h-3 w-3 mr-1" /> STRICTLY READ-ONLY
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              {/* Search Controls */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
                {/* Search Mode */}
                <div className="md:col-span-3 space-y-1">
                  <label className="text-[11px] font-semibold text-muted-foreground uppercase">Search Layer / Mode:</label>
                  <select
                    value={searchMode}
                    onChange={(e) => setSearchMode(e.target.value)}
                    className="w-full h-9 rounded-md border text-xs px-2.5 bg-background"
                  >
                    <option value="both">Both (Filesystem + Raw Bytes)</option>
                    <option value="filesystem">Filesystem (Files, Folders & Content)</option>
                    <option value="raw">Raw Storage Bytes (Sector LBA)</option>
                  </select>
                </div>

                {/* Query Type */}
                <div className="md:col-span-2 space-y-1">
                  <label className="text-[11px] font-semibold text-muted-foreground uppercase">Query Type:</label>
                  <select
                    value={searchType}
                    onChange={(e) => setSearchType(e.target.value)}
                    className="w-full h-9 rounded-md border text-xs px-2.5 bg-background"
                  >
                    <option value="text">ASCII / UTF-8 Text</option>
                    <option value="hex">Hex Bytes (e.g. 55 AA)</option>
                  </select>
                </div>

                {/* Query Input & Button */}
                <div className="md:col-span-7 space-y-1">
                  <label className="text-[11px] font-semibold text-muted-foreground uppercase">Search Term / Pattern:</label>
                  <div className="flex gap-2">
                    <Input
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder={
                        searchType === "text"
                          ? searchMode === "raw"
                            ? "Search text in raw sectors (e.g. NTFS, FAT32)..."
                            : "Search folder names, file names, or text content..."
                          : "e.g. 4D 5A 90 00 or 55 AA"
                      }
                      className="text-xs font-mono"
                      onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                    />
                    <Button size="sm" onClick={handleSearch} disabled={searching} className="min-w-[90px]">
                      {searching ? (
                        <span className="flex items-center gap-1.5">
                          <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Scanning...
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5">
                          <Search className="h-3.5 w-3.5" /> Search
                        </span>
                      )}
                    </Button>
                  </div>
                </div>
              </div>

              {/* Search Summary Header */}
              {searchSummary && (
                <div className="flex flex-wrap items-center justify-between gap-2 p-2.5 bg-muted/30 rounded-lg border text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-foreground">
                      Total Matches: <Badge variant="secondary" className="font-mono">{searchSummary.total}</Badge>
                    </span>
                    <span className="text-muted-foreground">|</span>
                    <span className="text-muted-foreground">
                      Filesystem: <Badge variant="outline" className="font-mono text-emerald-600 dark:text-emerald-400">{searchSummary.fsCount}</Badge>
                    </span>
                    <span className="text-muted-foreground">
                      Raw Bytes: <Badge variant="outline" className="font-mono text-primary">{searchSummary.rawCount}</Badge>
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                    {searchSummary.fsStatus === "UNAVAILABLE" && (
                      <Badge variant="outline" className="text-amber-500 border-amber-500/30">
                        Filesystem scan unmounted for target
                      </Badge>
                    )}
                    {searchSummary.fsStatus === "ERROR" && (
                      <Badge variant="outline" className="text-destructive border-destructive/30">
                        Filesystem scan limited
                      </Badge>
                    )}
                  </div>
                </div>
              )}

              {/* Search Results Table */}
              {searchResults.length > 0 ? (
                <div className="space-y-2">
                  <div className="border rounded-lg overflow-hidden max-h-[440px] overflow-y-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead className="bg-muted/50 border-b text-[11px] text-muted-foreground sticky top-0">
                        <tr>
                          <th className="py-2 px-3 w-24">Type</th>
                          <th className="py-2 px-3">Name / Entity</th>
                          <th className="py-2 px-3">Match Type</th>
                          <th className="py-2 px-3">Size</th>
                          <th className="py-2 px-3">Filesystem</th>
                          <th className="py-2 px-3">Physical / LBA Offset</th>
                          <th className="py-2 px-3">Matched Value / Content Snippet</th>
                          <th className="py-2 px-3 text-right w-24">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                        {searchResults.map((m, idx) => {
                          const isFs = m.type === "file" || m.type === "folder";
                          const isRaw = m.type === "raw_sector";

                          return (
                            <tr key={idx} className="hover:bg-muted/30 transition-colors">
                              {/* Type Badge */}
                              <td className="py-2 px-3 font-sans">
                                {m.type === "folder" && (
                                  <Badge variant="outline" className="bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30 text-[10px] gap-1">
                                    <Folder className="h-3 w-3" /> FOLDER
                                  </Badge>
                                )}
                                {m.type === "file" && (
                                  <Badge variant="outline" className="bg-sky-500/10 text-sky-600 dark:text-sky-400 border-sky-500/30 text-[10px] gap-1">
                                    <FileText className="h-3 w-3" /> FILE
                                  </Badge>
                                )}
                                {isRaw && (
                                  <Badge variant="outline" className="bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30 text-[10px] gap-1">
                                    <Binary className="h-3 w-3" /> RAW SECTOR
                                  </Badge>
                                )}
                              </td>

                              {/* Name / Entity */}
                              <td className="py-2 px-3 font-sans font-medium text-foreground max-w-[180px] truncate" title={m.name || m.path}>
                                {m.name || (isRaw ? `LBA ${m.lba}` : "—")}
                              </td>

                              {/* Match Type */}
                              <td className="py-2 px-3 font-sans text-muted-foreground">
                                {m.match_type === "folder_name" && <span className="text-amber-600 dark:text-amber-400 font-semibold">Folder Name</span>}
                                {m.match_type === "file_name" && <span className="text-sky-600 dark:text-sky-400 font-semibold">File Name</span>}
                                {m.match_type === "file_content" && <span className="text-emerald-600 dark:text-emerald-400 font-semibold">Content Match</span>}
                                {m.match_type === "raw_byte_match" && <span className="text-purple-600 dark:text-purple-400 font-semibold">Raw Byte Match</span>}
                                {!m.match_type && (isRaw ? "Raw Match" : "Filesystem Match")}
                              </td>

                              {/* Size */}
                              <td className="py-2 px-3 text-muted-foreground font-mono">
                                {m.size_formatted || (m.size !== undefined && m.size !== null ? `${m.size.toLocaleString()} B` : "—")}
                              </td>

                              {/* Filesystem */}
                              <td className="py-2 px-3 font-sans text-muted-foreground">
                                {m.filesystem || "—"}
                              </td>

                              {/* Physical / LBA Offset */}
                              <td className="py-2 px-3 font-mono">
                                {isRaw ? (
                                  <span className="text-primary font-bold">
                                    LBA {m.lba.toLocaleString()} <span className="text-[10px] text-muted-foreground">(+{m.sector_offset}B)</span>
                                  </span>
                                ) : m.is_allocation_available && m.starting_lba !== null && m.starting_lba !== undefined ? (
                                  <div className="flex flex-col">
                                    <span className="text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1">
                                      LBA {m.starting_lba.toLocaleString()}
                                      {m.is_fragmented && (
                                        <Badge variant="outline" className="text-[9px] px-1 py-0 h-3.5 border-amber-500/40 text-amber-500">
                                          {m.extents?.length || 2} Extents
                                        </Badge>
                                      )}
                                    </span>
                                    <span className="text-[10px] text-muted-foreground font-sans">
                                      Cluster {m.starting_cluster !== null && m.starting_cluster !== undefined ? m.starting_cluster.toLocaleString() : "—"}
                                    </span>
                                  </div>
                                ) : (
                                  <span className="text-muted-foreground text-[10px] italic">
                                    Unavailable (FS Managed)
                                  </span>
                                )}
                              </td>

                              {/* Content Snippet / Matched Hex */}
                              <td className="py-2 px-3 max-w-[260px] truncate">
                                {m.snippet ? (
                                  <span className="text-foreground bg-muted/40 px-1.5 py-0.5 rounded font-mono text-[11px] block truncate" title={m.snippet}>
                                    {m.snippet}
                                  </span>
                                ) : m.matched_bytes_hex ? (
                                  <span className="text-emerald-600 dark:text-emerald-400 font-mono font-bold block truncate" title={m.matched_bytes_hex}>
                                    {m.matched_bytes_hex}
                                  </span>
                                ) : (
                                  <span className="text-muted-foreground font-sans text-[11px] truncate block" title={m.path}>
                                    {m.path || "—"}
                                  </span>
                                )}
                              </td>

                              {/* Actions */}
                              <td className="py-2 px-3 text-right space-x-1">
                                {isRaw && (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="h-6 text-[10px] px-2"
                                    onClick={() => {
                                      setLba(m.lba);
                                      setLbaInput(m.lba.toString());
                                      setActiveTab("hex");
                                      loadDeviceAndSector(target, m.lba, sectorSize, sectorCount);
                                    }}
                                  >
                                    View in Hex
                                  </Button>
                                )}
                                {isFs && (
                                  <>
                                    {m.starting_lba !== null && m.starting_lba !== undefined && (
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        className="h-6 text-[10px] px-2 text-primary border-primary/30 hover:bg-primary/10"
                                        title={`Jump to Sector LBA ${m.starting_lba} in Hex Viewer`}
                                        onClick={() => {
                                          const dev = m.device_path || target;
                                          setTarget(dev);
                                          setLba(m.starting_lba);
                                          setLbaInput(m.starting_lba.toString());
                                          setActiveTab("hex");
                                          loadDeviceAndSector(dev, m.starting_lba, sectorSize, sectorCount);
                                        }}
                                      >
                                        <Binary className="h-3 w-3 mr-1" /> Hex
                                      </Button>
                                    )}
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="h-6 text-[10px] px-2 bg-muted/40 hover:bg-muted"
                                      onClick={() => handleOpenDetails(m.path)}
                                    >
                                      <Info className="h-3 w-3 mr-1" /> Details
                                    </Button>
                                  </>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                !searching && searchSummary && (
                  <div className="py-8 text-center text-muted-foreground text-xs">
                    No matches found for &quot;{searchQuery}&quot; in {searchMode} mode.
                  </div>
                )
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* ---------------- FILE / FOLDER DETAILS READ-ONLY MODAL ---------------- */}
      <Dialog open={detailsOpen} onOpenChange={setDetailsOpen}>
        <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <div className="flex items-center justify-between">
              <DialogTitle className="text-base font-semibold flex items-center gap-2">
                {selectedDetails?.type === "folder" ? (
                  <Folder className="h-5 w-5 text-amber-500" />
                ) : (
                  <FileText className="h-5 w-5 text-sky-500" />
                )}
                <span>{selectedDetails?.name || "Filesystem Entity Details"}</span>
              </DialogTitle>
              <Badge variant="outline" className="font-mono text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
                <Lock className="h-3 w-3 mr-1" /> READ-ONLY
              </Badge>
            </div>
            <DialogDescription className="text-xs text-muted-foreground">
              Forensic read-only filesystem metadata, storage allocation mapping, content inspection, and cryptographic verification.
            </DialogDescription>
          </DialogHeader>

          {detailsLoading ? (
            <div className="py-12 flex flex-col items-center justify-center gap-2 text-xs text-muted-foreground">
              <RefreshCw className="h-6 w-6 animate-spin text-primary" />
              <span>Retrieving read-only filesystem attributes & storage mapping...</span>
            </div>
          ) : selectedDetails?.error ? (
            <div className="p-4 bg-destructive/10 border border-destructive/30 rounded-lg text-xs text-destructive">
              {selectedDetails.error}
            </div>
          ) : selectedDetails ? (
            <div className="space-y-4 text-xs">
              {/* Metadata Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 bg-muted/20 border rounded-lg">
                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Full Path:</span>
                  <div className="flex items-center gap-1 font-mono text-[11px] bg-muted/40 p-1 rounded break-all select-all">
                    <span>{selectedDetails.path}</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-5 w-5 p-0 ml-auto shrink-0"
                      onClick={() => copyToClipboard(selectedDetails.path, "path")}
                    >
                      {copiedKey === "path" ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                    </Button>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Parent Directory:</span>
                  <span className="font-mono text-[11px] block truncate text-muted-foreground" title={selectedDetails.parent}>
                    {selectedDetails.parent || "Root / None"}
                  </span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Entity Type / Extension:</span>
                  <span className="font-medium capitalize">{selectedDetails.type} ({selectedDetails.extension || "none"})</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Reported Size:</span>
                  <span className="font-mono font-semibold">{selectedDetails.size_formatted}</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Filesystem:</span>
                  <span className="font-medium">{selectedDetails.filesystem}</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">File Attributes:</span>
                  <span className="font-mono text-muted-foreground">{selectedDetails.attributes || "Standard"}</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Created Timestamp:</span>
                  <span className="font-mono text-muted-foreground">{selectedDetails.created_time || "—"}</span>
                </div>

                <div className="space-y-1">
                  <span className="text-[10px] uppercase font-semibold text-muted-foreground block">Modified Timestamp:</span>
                  <span className="font-mono text-muted-foreground">{selectedDetails.modified_time || "—"}</span>
                </div>
              </div>

              {/* STORAGE ALLOCATION & CLUSTER-TO-LBA MAPPING CARD */}
              <Card className="border shadow-none">
                <CardHeader className="py-2.5 px-3.5 bg-muted/30 border-b flex flex-row items-center justify-between space-y-0">
                  <div className="flex items-center gap-2">
                    <HardDrive className="h-4 w-4 text-emerald-500" />
                    <CardTitle className="text-xs font-semibold">Storage Location & Cluster Mapping</CardTitle>
                  </div>
                  <div className="flex items-center gap-1.5">
                    {selectedDetails.is_allocation_available ? (
                      <Badge variant="outline" className="text-[10px] bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30">
                        {selectedDetails.mapping_layer || "Device Logical LBA"}
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-[10px] text-muted-foreground">
                        UNAVAILABLE (DRIVER ABSTRACTION)
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="p-3.5 space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-2.5">
                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Filesystem:</span>
                      <span className="font-mono font-bold text-sm text-foreground">
                        {selectedDetails.filesystem || "FAT32"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Starting Cluster:</span>
                      <span className="font-mono font-bold text-sm text-foreground">
                        {selectedDetails.starting_cluster !== null && selectedDetails.starting_cluster !== undefined
                          ? selectedDetails.starting_cluster.toLocaleString()
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Starting LBA / Sector:</span>
                      <span className="font-mono font-bold text-sm text-primary">
                        {selectedDetails.starting_lba !== null && selectedDetails.starting_lba !== undefined
                          ? selectedDetails.starting_lba.toLocaleString()
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Ending LBA / Sector:</span>
                      <span className="font-mono font-bold text-sm text-primary">
                        {selectedDetails.ending_lba !== null && selectedDetails.ending_lba !== undefined
                          ? selectedDetails.ending_lba.toLocaleString()
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Byte Offset (Hex):</span>
                      <span className="font-mono font-bold text-sm text-foreground truncate block" title={selectedDetails.byte_offset_hex}>
                        {selectedDetails.byte_offset_hex || "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Byte Offset (Decimal):</span>
                      <span className="font-mono font-bold text-sm text-foreground truncate block">
                        {selectedDetails.byte_offset !== null && selectedDetails.byte_offset !== undefined
                          ? `${selectedDetails.byte_offset.toLocaleString()} B`
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Sectors Occupied:</span>
                      <span className="font-mono font-semibold text-foreground">
                        {selectedDetails.sectors_occupied !== null && selectedDetails.sectors_occupied !== undefined
                          ? `${selectedDetails.sectors_occupied.toLocaleString()} ${selectedDetails.allocated_sectors_extent ? `(${selectedDetails.allocated_sectors_extent} alloc)` : ""}`
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Clusters Occupied:</span>
                      <span className="font-mono font-semibold text-foreground">
                        {selectedDetails.clusters_occupied !== null && selectedDetails.clusters_occupied !== undefined
                          ? `${selectedDetails.clusters_occupied.toLocaleString()} ${selectedDetails.allocated_clusters_extent ? `(${selectedDetails.allocated_clusters_extent} alloc)` : ""}`
                          : "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border md:col-span-2">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Cluster Chain / Extents:</span>
                      <span className="font-mono text-xs text-foreground truncate block" title={selectedDetails.cluster_chain}>
                        {selectedDetails.cluster_chain || "Unavailable"}
                      </span>
                    </div>

                    <div className="p-2 bg-muted/20 rounded border md:col-span-2">
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">Mapping Layer / Target:</span>
                      <span className="font-mono text-xs text-foreground truncate block" title={selectedDetails.device_path}>
                        {selectedDetails.mapping_layer || "Device Logical LBA"} {selectedDetails.device_path ? `(${selectedDetails.device_path})` : ""}
                      </span>
                    </div>
                  </div>

                  {/* Raw LBA Content Verification Box */}
                  {selectedDetails.raw_lba_verification && selectedDetails.raw_lba_verification !== "UNVERIFIED" && (
                    <div className={`p-2.5 rounded border text-xs flex items-center justify-between gap-2 ${
                      selectedDetails.raw_lba_verification.includes("PASS")
                        ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-700 dark:text-emerald-300"
                        : "bg-destructive/10 border-destructive/30 text-destructive"
                    }`}>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
                        <div>
                          <span className="font-bold block">
                            Raw LBA Content Verification: {selectedDetails.raw_lba_verification}
                          </span>
                          <span className="text-[11px] opacity-90 block">
                            {selectedDetails.verification_statement}
                          </span>
                        </div>
                      </div>
                      <Badge variant="outline" className="font-mono text-[10px] bg-background/50 shrink-0">
                        {selectedDetails.raw_lba_verification}
                      </Badge>
                    </div>
                  )}

                  {/* Extents breakdown table if fragmented / available */}
                  {selectedDetails.extents && selectedDetails.extents.length > 0 && (
                    <div className="space-y-1.5">
                      <span className="text-[10px] font-semibold text-muted-foreground uppercase block">
                        Allocated Extent Map ({selectedDetails.extents.length} {selectedDetails.extents.length === 1 ? "Extent" : "Extents"}):
                      </span>
                      <div className="border rounded overflow-hidden max-h-32 overflow-y-auto">
                        <table className="w-full text-left text-[11px] font-mono">
                          <thead className="bg-muted/40 border-b text-[10px] text-muted-foreground">
                            <tr>
                              <th className="py-1 px-2.5">#</th>
                              <th className="py-1 px-2.5">Cluster Range</th>
                              <th className="py-1 px-2.5">LBA Range</th>
                              <th className="py-1 px-2.5">Sectors</th>
                              <th className="py-1 px-2.5">Byte Offset Range</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border/30">
                            {selectedDetails.extents.map((ext: any, extIdx: number) => (
                              <tr key={extIdx} className="hover:bg-muted/20">
                                <td className="py-1 px-2.5 font-bold">{extIdx + 1}</td>
                                <td className="py-1 px-2.5">{ext.start_cluster} → {ext.end_cluster} ({ext.cluster_count} clus)</td>
                                <td className="py-1 px-2.5 text-primary font-bold">{ext.start_lba.toLocaleString()} → {ext.end_lba.toLocaleString()}</td>
                                <td className="py-1 px-2.5">{ext.sector_count.toLocaleString()}</td>
                                <td className="py-1 px-2.5 text-muted-foreground">{ext.start_byte_offset_hex || `0x${ext.start_byte_offset.toString(16).toUpperCase()}`} → {ext.end_byte_offset_hex || `0x${ext.end_byte_offset.toString(16).toUpperCase()}`}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {/* Jump Action Button */}
                  {selectedDetails.starting_lba !== null && selectedDetails.starting_lba !== undefined && (
                    <div className="flex items-center justify-between pt-1">
                      <Button
                        size="sm"
                        className="gap-1.5 text-xs h-7"
                        onClick={() => {
                          const jumpLba = selectedDetails.starting_lba;
                          const targetDev = selectedDetails.device_path || target;
                          setTarget(targetDev);
                          setLba(jumpLba);
                          setLbaInput(jumpLba.toString());
                          setDetailsOpen(false);
                          setActiveTab("hex");
                          loadDeviceAndSector(targetDev, jumpLba, sectorSize, sectorCount);
                        }}
                      >
                        <Binary className="h-3.5 w-3.5" /> View Starting LBA {selectedDetails.starting_lba} in Hex Viewer
                      </Button>
                      <span className="text-[11px] text-muted-foreground">
                        Byte Offset: <strong className="font-mono text-foreground">{selectedDetails.byte_offset_hex}</strong>
                      </span>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Forensic Storage Mapping Hierarchy & Flash Disclaimer */}
              <div className="p-3 bg-muted/20 border rounded-lg text-xs text-muted-foreground space-y-1.5">
                <div className="flex items-center gap-1.5 font-bold text-foreground">
                  <Layers className="h-3.5 w-3.5 text-primary" />
                  <span>Forensic Storage Layer Hierarchy & Physical Reality:</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px] pt-1">
                  <div className="p-2 bg-muted/40 rounded border space-y-0.5">
                    <span className="font-semibold text-foreground block">1. Filesystem Logical</span>
                    <p className="text-muted-foreground">FAT32 cluster allocation mapped via FAT directory and allocation tables.</p>
                  </div>
                  <div className="p-2 bg-muted/40 rounded border space-y-0.5">
                    <span className="font-semibold text-foreground block">2. Device Logical (LBA)</span>
                    <p className="text-muted-foreground">Partition-relative and device LBA used by operating system for sector I/O.</p>
                  </div>
                  <div className="p-2 bg-muted/40 rounded border space-y-0.5">
                    <span className="font-semibold text-foreground block">3. Physical NAND Flash</span>
                    <p className="text-muted-foreground">NOT directly observable: Flash Translation Layer (FTL) wear-leveling & remapping abstract silicon dies.</p>
                  </div>
                </div>
                {selectedDetails.allocation_disclaimer && (
                  <p className="text-[11px] italic pt-1 text-muted-foreground">
                    ℹ️ {selectedDetails.allocation_disclaimer}
                  </p>
                )}
              </div>

              {/* Content / Hex Preview */}
              {selectedDetails.type === "file" && (
                <div className="space-y-1.5">
                  <span className="text-[11px] font-semibold text-muted-foreground uppercase flex items-center justify-between">
                    <span>{selectedDetails.is_text ? "Read-Only Text Content Preview" : "Read-Only Hex Header Preview"}:</span>
                    <Badge variant="outline" className="text-[10px]">
                      {selectedDetails.is_text ? "UTF-8 / ASCII" : "Binary"}
                    </Badge>
                  </span>

                  {selectedDetails.is_text ? (
                    <pre className="p-3 bg-muted/30 border rounded font-mono text-[11px] max-h-48 overflow-y-auto whitespace-pre-wrap select-text">
                      {selectedDetails.text_preview || "Empty file content."}
                    </pre>
                  ) : (
                    <div className="p-3 bg-muted/30 border rounded font-mono text-[11px] max-h-36 overflow-y-auto tracking-wider text-muted-foreground select-text">
                      {selectedDetails.hex_preview || "No binary content available."}
                    </div>
                  )}
                </div>
              )}

              {/* Live SHA-256 Digest */}
              {selectedDetails.type === "file" && (
                <div className="p-3 bg-muted/20 border rounded-lg space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] font-semibold text-muted-foreground uppercase flex items-center gap-1.5">
                      <Hash className="h-3.5 w-3.5 text-primary" /> Live File SHA-256 Digest:
                    </span>
                    {!selectedDetails.sha256 && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 text-[11px] px-2.5"
                        disabled={detailsHashing}
                        onClick={() => handleComputeSha256(selectedDetails.path)}
                      >
                        {detailsHashing ? (
                          <span className="flex items-center gap-1">
                            <RefreshCw className="h-3 w-3 animate-spin" /> Computing...
                          </span>
                        ) : (
                          "Compute SHA-256 (Read-Only)"
                        )}
                      </Button>
                    )}
                  </div>

                  {selectedDetails.sha256 ? (
                    <div className="flex items-center gap-2 font-mono text-[11px] bg-muted/40 p-2 rounded border text-emerald-600 dark:text-emerald-400 break-all select-all">
                      <span className="font-bold">{selectedDetails.sha256}</span>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-5 w-5 p-0 ml-auto shrink-0 text-foreground"
                        onClick={() => copyToClipboard(selectedDetails.sha256, "sha256")}
                      >
                        {copiedKey === "sha256" ? <Check className="h-3 w-3 text-emerald-500" /> : <Copy className="h-3 w-3" />}
                      </Button>
                    </div>
                  ) : (
                    <p className="text-[11px] text-muted-foreground">
                      Click the button above to calculate the cryptographic SHA-256 hash of this file without modifying any file access or modified timestamps.
                    </p>
                  )}
                </div>
              )}
            </div>
          ) : null}

          <div className="flex justify-end pt-2">
            <Button size="sm" variant="outline" onClick={() => setDetailsOpen(false)}>
              Close
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}


