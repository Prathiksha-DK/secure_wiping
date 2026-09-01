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
} from "lucide-react";

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
  const [metadata, setMetadata] = useState<DeviceMetadata | null>(null);
  const [errorMsg, setErrorMsg] = useState<string>("");

  // Connected devices from OS
  const [devices, setDevices] = useState<any[]>([]);

  // Search State
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [searchType, setSearchType] = useState<string>("text");
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searching, setSearching] = useState<boolean>(false);

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
          const firstRealDev = data[0].name;
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
      } else {
        setHexData(hexResp.rows || []);
        setAnalysis(hexResp.analysis || null);
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
          max_scan_bytes: 50 * 1024 * 1024,
          sector_size: sectorSize,
        }),
      });
      const data = await res.json();
      setSearchResults(data.matches || []);
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
                  {devices.map((d) => (
                    <Button
                      key={d.name}
                      size="sm"
                      variant={target === d.name ? "default" : "outline"}
                      className="text-xs font-mono h-8"
                      onClick={() => {
                        setTarget(d.name);
                        loadDeviceAndSector(d.name, 0, sectorSize, sectorCount);
                      }}
                    >
                      <HardDrive className="h-3 w-3 mr-1" />
                      {d.name} ({d.size})
                    </Button>
                  ))}
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
                <div className="text-muted-foreground space-y-1 pt-1 border-t border-red-500/20">
                  <p className="font-medium text-foreground">To grant raw block device read permissions on Linux:</p>
                  <p className="font-mono text-[11px] bg-muted/60 p-2 rounded">
                    sudo usermod -a -G disk $USER
                  </p>
                  <p className="text-[11px]">Or run the backend with sudo: <code className="font-mono">sudo python3 backend/app.py</code></p>
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
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Search className="h-4 w-4 text-primary" /> Read-Only In-Storage Byte & Text Search
              </CardTitle>
              <CardDescription className="text-xs">
                Search through addressable storage for specific ASCII strings, UTF-8 text, or hexadecimal byte patterns.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="w-36">
                  <select
                    value={searchType}
                    onChange={(e) => setSearchType(e.target.value)}
                    className="w-full h-9 rounded-md border text-xs px-2.5 bg-background"
                  >
                    <option value="text">ASCII / UTF-8 Text</option>
                    <option value="hex">Hex Bytes (e.g. 55 AA)</option>
                  </select>
                </div>
                <div className="flex-1 flex gap-2">
                  <Input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder={searchType === "text" ? "Search for keyword, signature, filename..." : "e.g. 4D 5A 90 00 or 55 AA"}
                    className="text-xs font-mono"
                    onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                  />
                  <Button size="sm" onClick={handleSearch} disabled={searching}>
                    {searching ? "Scanning..." : "Search"}
                  </Button>
                </div>
              </div>

              {/* Search Results */}
              {searchResults.length > 0 && (
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-muted-foreground uppercase">
                    Found {searchResults.length} match(es):
                  </span>
                  <div className="border rounded-lg overflow-hidden max-h-64 overflow-y-auto">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-muted/50 border-b text-[11px]">
                        <tr>
                          <th className="py-1.5 px-3">Byte Offset</th>
                          <th className="py-1.5 px-3">LBA (Sector)</th>
                          <th className="py-1.5 px-3">Sector Offset</th>
                          <th className="py-1.5 px-3">Matched Hex Bytes</th>
                          <th className="py-1.5 px-3 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y">
                        {searchResults.map((m, idx) => (
                          <tr key={idx} className="hover:bg-muted/30">
                            <td className="py-1.5 px-3 font-bold text-primary">{m.offset_hex} ({m.offset.toLocaleString()})</td>
                            <td className="py-1.5 px-3">{m.lba.toLocaleString()}</td>
                            <td className="py-1.5 px-3">+{m.sector_offset} bytes</td>
                            <td className="py-1.5 px-3 text-emerald-600 dark:text-emerald-400">{m.matched_bytes_hex}</td>
                            <td className="py-1.5 px-3 text-right">
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-6 text-[11px]"
                                onClick={() => {
                                  setLba(m.lba);
                                  setLbaInput(m.lba.toString());
                                  setActiveTab("hex");
                                  loadDeviceAndSector(target, m.lba, sectorSize, sectorCount);
                                }}
                              >
                                View in Hex
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
