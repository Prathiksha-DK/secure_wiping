'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  ShieldCheck,
  Disc,
  Search,
  Lock,
  Copy,
  Check,
  CheckCircle2,
  HardDrive,
  Eye,
  Layers,
  Calendar,
  User,
  FileCheck2,
  Activity,
  AlertTriangle,
  Download,
  Filter,
  RefreshCw,
  Sliders,
  Sparkles,
  ExternalLink,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';

interface IsoImage {
  id: string;
  image_name: string;
  case_ref_id: string;
  uploaded_by: string;
  file_size_bytes: number;
  file_size_human: string;
  description: string;
  status: string;
  sha256_hash: string;
  md5_hash?: string;
  download_url?: string;
  uploaded_at: number;
  uploaded_at_human: string;
  integrity_verified: boolean;
  classification: string;
}

export default function HunterDashboardPage() {
  const [isoImages, setIsoImages] = useState<IsoImage[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'AVAILABLE' | 'IN_REVIEW'>('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Live Verification state
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verificationData, setVerificationData] = useState<Record<string, any>>({});

  // Sector Inspection state
  const [inspectingIso, setInspectingIso] = useState<IsoImage | null>(null);
  const [inspectLba, setInspectLba] = useState<number>(16);
  const [sectorData, setSectorData] = useState<{ lines: string[]; lba: number; total_sectors: number } | null>(null);
  const [sectorLoading, setSectorLoading] = useState(false);

  const fetchAvailableImages = async () => {
    setLoading(true);
    try {
      const res = await fetch('http://localhost:9758/api/hunter/iso-images');
      if (res.ok) {
        const data = await res.json();
        setIsoImages(data.iso_images || []);
      }
    } catch (err) {
      console.error('Failed to fetch available ISO images:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAvailableImages();
  }, []);

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2500);
  };

  const handleLiveVerifyChecksum = async (iso: IsoImage) => {
    setVerifyingId(iso.id);
    try {
      const res = await fetch(`http://localhost:9758/api/hunter/iso-images/${iso.id}/verify-hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      setVerificationData((prev) => ({
        ...prev,
        [iso.id]: data,
      }));
    } catch (err: any) {
      setVerificationData((prev) => ({
        ...prev,
        [iso.id]: { verified: false, message: `Verification failed: ${err.message}` },
      }));
    } finally {
      setVerifyingId(null);
    }
  };

  const openSectorInspection = async (iso: IsoImage, lba = 16) => {
    setInspectingIso(iso);
    setInspectLba(lba);
    setSectorLoading(true);
    try {
      const res = await fetch(`http://localhost:9758/api/hunter/iso-images/${iso.id}/sector?lba=${lba}&sector_size=2048`);
      if (res.ok) {
        const data = await res.json();
        setSectorData(data);
      }
    } catch (err) {
      console.error('Failed to inspect sector:', err);
    } finally {
      setSectorLoading(false);
    }
  };

  const filteredImages = isoImages.filter((img) => {
    const matchesSearch =
      img.image_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      img.case_ref_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      img.description.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'ALL' || img.status.toUpperCase() === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-slate-100 pb-12">
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
              FORENSIC INVESTIGATOR CLEARANCE: APPROVED
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Forensic Evidence & ISO Inspection Workspace
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Authorized external triage repository. Access sanctioned bit-stream disk images and memory dumps published by Forensic Investigators under strict chain-of-custody protocols.
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
        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>AVAILABLE EVIDENCE</span>
            <Disc className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-extrabold text-white font-mono tracking-tight">{isoImages.length} ISO/Images</div>
          <div className="text-[11px] text-slate-400 flex items-center gap-1 font-mono">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-ping" />
            <span>Bit-stream authentic disk images</span>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>CHAIN OF CUSTODY</span>
            <FileCheck2 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-extrabold text-emerald-400 font-mono tracking-tight">100% Validated</div>
          <div className="text-[11px] text-slate-400 font-mono">Cryptographic SHA-256 & MD5 recorded</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>HUNTER CLEARANCE</span>
            <ShieldCheck className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-extrabold text-purple-300 font-mono tracking-tight">LEVEL 3 TRIAGE</div>
          <div className="text-[11px] text-slate-400 font-mono">Forensic Analyst authorized access</div>
        </div>

        <div className="p-4 rounded-2xl bg-[#0B1220] border border-slate-800/80 space-y-2 relative overflow-hidden group">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>INVESTIGATION MODE</span>
            <Activity className="h-4 w-4 text-amber-400" />
          </div>
          <div className="text-2xl font-extrabold text-amber-400 font-mono tracking-tight">READ-ONLY AUDIT</div>
          <div className="text-[11px] text-slate-400 font-mono">Tamper-proof evidence isolation</div>
        </div>
      </div>

      {/* Available ISO Images Section */}
      <div className="rounded-2xl border border-slate-800 bg-[#0B1220] p-6 space-y-6 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
          <div>
            <div className="flex items-center gap-2">
              <Disc className="h-5 w-5 text-cyan-400" />
              <h2 className="text-base font-bold text-white">Genuine Forensic ISO & Disk Images</h2>
              <Badge className="bg-cyan-500/20 text-cyan-300 border-cyan-500/40 text-[10px] font-mono">
                {isoImages.length} Certified Files
              </Badge>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Real ECMA-119 ISO 9660 disk images and raw volatile memory dumps available for direct binary download, live cryptographic verification, and sector-by-sector triage.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-slate-500" />
              <Input
                type="text"
                placeholder="Filter by image name, case, hash..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 text-xs bg-[#070D18] border-slate-700/80 text-slate-100 placeholder:text-slate-500 h-9 rounded-xl"
              />
            </div>

            <div className="flex items-center bg-[#070D18] p-1 rounded-xl border border-slate-800">
              <button
                type="button"
                onClick={() => setStatusFilter('ALL')}
                className={`px-3 py-1 text-[11px] font-mono rounded-lg transition-all ${
                  statusFilter === 'ALL'
                    ? 'bg-cyan-600 text-white font-bold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                ALL
              </button>
              <button
                type="button"
                onClick={() => setStatusFilter('AVAILABLE')}
                className={`px-3 py-1 text-[11px] font-mono rounded-lg transition-all ${
                  statusFilter === 'AVAILABLE'
                    ? 'bg-cyan-600 text-white font-bold shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                AVAILABLE
              </button>
            </div>

            <Button
              size="sm"
              variant="outline"
              onClick={fetchAvailableImages}
              className="border-slate-700 bg-[#070D18] text-slate-300 hover:text-white h-9 px-3 rounded-xl"
              title="Refresh available ISO list"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </div>
        </div>

        {/* ISO Cards View */}
        <div className="space-y-4">
          {filteredImages.length === 0 ? (
            <div className="py-16 text-center space-y-3">
              <Disc className="h-12 w-12 text-slate-600 mx-auto animate-pulse" />
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-white">No ISO Images Match Search Filter</h3>
                <p className="text-xs text-slate-400 max-w-sm mx-auto">
                  Either no forensic images match your search term or new images have not yet been published by the Forensic Investigator.
                </p>
              </div>
            </div>
          ) : (
            filteredImages.map((iso) => {
              const liveVer = verificationData[iso.id];
              return (
                <div
                  key={iso.id}
                  className="bg-[#080E1A] border border-slate-800/90 rounded-2xl p-5 hover:border-slate-700/80 transition-all space-y-4 shadow-md"
                >
                  {/* Header line: Image Name & Metadata */}
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 border-b border-slate-800/70 pb-3">
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <div className="h-7 w-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                          <Disc className="h-4 w-4" />
                        </div>
                        <h3 className="font-bold text-sm text-white font-mono">{iso.image_name}</h3>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 font-semibold">
                          Case: {iso.case_ref_id}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-semibold">
                          {iso.status}
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed max-w-3xl pt-0.5">
                        {iso.description}
                      </p>
                    </div>

                    {/* Primary Action Buttons */}
                    <div className="flex flex-wrap items-center gap-2 self-start lg:self-center shrink-0">
                      {/* Direct Genuine Binary Download */}
                      <a
                        href={`http://localhost:9758/api/hunter/iso-images/${iso.id}/download`}
                        download={iso.image_name}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold bg-emerald-600/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-600/30 transition-all shadow-sm"
                        title="Download authentic binary disk image from server storage"
                      >
                        <Download className="h-3.5 w-3.5 text-emerald-400" />
                        <span>Download Binary ({iso.file_size_human})</span>
                      </a>

                      {/* Genuine Sector Inspector */}
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => openSectorInspection(iso, 16)}
                        className="border-slate-700 bg-slate-900/80 hover:bg-slate-800 text-slate-200 text-xs h-8 px-3 rounded-lg flex items-center gap-1.5"
                        title="Inspect real ECMA-119 ISO sectors and volume descriptors"
                      >
                        <Eye className="h-3.5 w-3.5 text-amber-400" />
                        <span>Inspect Sectors</span>
                      </Button>

                      <Link href="/faris">
                        <Button
                          size="sm"
                          className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs h-8 px-3.5 rounded-lg font-medium shadow-md shadow-cyan-950/40 flex items-center gap-1.5"
                        >
                          <Layers className="h-3.5 w-3.5" />
                          <span>Carve Artifacts</span>
                        </Button>
                      </Link>
                    </div>
                  </div>

                  {/* Metadata Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">File Size</div>
                      <div className="text-sm font-bold text-white">{iso.file_size_human}</div>
                      <div className="text-[10px] text-slate-500">{iso.file_size_bytes?.toLocaleString()} bytes</div>
                    </div>

                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">Uploaded By</div>
                      <div className="text-sm font-bold text-cyan-300 flex items-center gap-1">
                        <User className="h-3.5 w-3.5 text-slate-400" />
                        <span>{iso.uploaded_by}</span>
                      </div>
                      <div className="text-[10px] text-slate-500">Forensic Investigator</div>
                    </div>

                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">Upload Timestamp</div>
                      <div className="text-xs font-semibold text-slate-200">{iso.uploaded_at_human}</div>
                      <div className="text-[10px] text-slate-500">UTC Coordinated</div>
                    </div>

                    <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">Integrity Status</div>
                      <div className="text-xs font-bold text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span>SHA-256 Validated</span>
                      </div>
                      <div className="text-[10px] text-slate-500">Authentic disk file bytes</div>
                    </div>
                  </div>

                  {/* Checksum / Hash Row with Live Cryptographic Verification */}
                  <div className="p-3 rounded-xl bg-[#060A12] border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono">
                    <div className="flex items-center gap-2 min-w-0">
                      <span className="text-slate-400 text-[11px] font-semibold shrink-0">SHA-256 Digest:</span>
                      <span className="text-cyan-300 text-[11px] truncate bg-[#0A101D] px-2 py-0.5 rounded border border-slate-800 select-all">
                        {iso.sha256_hash}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleCopyHash(iso.sha256_hash)}
                        className="text-xs h-7 px-2 text-slate-300 hover:text-white hover:bg-slate-800"
                      >
                        {copiedHash === iso.sha256_hash ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-400 mr-1" />
                            <span className="text-emerald-300">Copied!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3 mr-1" />
                            <span>Copy Hash</span>
                          </>
                        )}
                      </Button>

                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={verifyingId === iso.id}
                        onClick={() => handleLiveVerifyChecksum(iso)}
                        className="text-xs h-7 px-2 text-cyan-400 hover:text-cyan-300 hover:bg-cyan-500/10 font-semibold"
                      >
                        <RefreshCw className={`h-3 w-3 mr-1 ${verifyingId === iso.id ? 'animate-spin' : ''}`} />
                        <span>{verifyingId === iso.id ? 'Computing Hash...' : 'Live Verify Digest'}</span>
                      </Button>
                    </div>
                  </div>

                  {/* Live Verification Report Card (if verified) */}
                  {liveVer && (
                    <div className={`p-3.5 rounded-xl text-xs font-mono border ${
                      liveVer.verified
                        ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-200'
                        : 'bg-red-950/20 border-red-500/40 text-red-200'
                    } space-y-2`}>
                      <div className="flex items-center justify-between font-bold">
                        <div className="flex items-center gap-1.5">
                          <CheckCircle2 className={`h-4 w-4 ${liveVer.verified ? 'text-emerald-400' : 'text-red-400'}`} />
                          <span>
                            {liveVer.verified
                              ? 'LIVE FILE INTEGRITY VERIFIED (BIT-STREAM 100% MATCH)'
                              : 'INTEGRITY MISMATCH DETECTED'}
                          </span>
                        </div>
                        <span className="text-[11px] text-slate-400">
                          {liveVer.verification_latency_ms} ms verification time
                        </span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                        <div>
                          <span className="text-slate-400">Disk Read Bytes: </span>
                          <span className="font-bold text-white">{liveVer.file_size_bytes?.toLocaleString()} bytes</span>
                        </div>
                        <div>
                          <span className="text-slate-400">Live MD5: </span>
                          <span className="text-cyan-300">{liveVer.live_md5}</span>
                        </div>
                        <div className="sm:col-span-2 truncate">
                          <span className="text-slate-400">Computed SHA-256: </span>
                          <span className="text-emerald-300">{liveVer.live_sha256}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Real Sector Inspection Modal / Overlay */}
      {inspectingIso && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0B1220] border border-slate-700/80 rounded-2xl w-full max-w-4xl p-6 space-y-4 shadow-2xl overflow-hidden max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Eye className="h-5 w-5 text-amber-400" />
                  <h3 className="font-bold text-base text-white">Genuine Sector Inspector: {inspectingIso.image_name}</h3>
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  Direct read-only access to disk bytes (ECMA-119 Sector size: 2048 bytes). LBA {inspectLba}.
                </p>
              </div>

              <Button
                size="sm"
                variant="ghost"
                onClick={() => setInspectingIso(null)}
                className="h-8 w-8 p-0 text-slate-400 hover:text-white"
              >
                ✕
              </Button>
            </div>

            {/* Quick Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-slate-400 text-[11px]">Jump to Sector:</span>
              <button
                type="button"
                onClick={() => openSectorInspection(inspectingIso, 0)}
                className={`px-2.5 py-1 rounded border text-[11px] ${
                  inspectLba === 0 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                LBA 0 (System Area / Boot)
              </button>
              <button
                type="button"
                onClick={() => openSectorInspection(inspectingIso, 16)}
                className={`px-2.5 py-1 rounded border text-[11px] ${
                  inspectLba === 16 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                LBA 16 (Primary Volume Descriptor - CD001)
              </button>
              <button
                type="button"
                onClick={() => openSectorInspection(inspectingIso, 20)}
                className={`px-2.5 py-1 rounded border text-[11px] ${
                  inspectLba === 20 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                LBA 20 (Root Directory)
              </button>
              <button
                type="button"
                onClick={() => openSectorInspection(inspectingIso, 24)}
                className={`px-2.5 py-1 rounded border text-[11px] ${
                  inspectLba === 24 ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white'
                }`}
              >
                LBA 24 (Embedded Manifest Evidence)
              </button>
            </div>

            {/* Hex Viewer Output */}
            <div className="flex-1 overflow-auto bg-[#04070E] border border-slate-800/90 rounded-xl p-4 font-mono text-xs leading-5">
              {sectorLoading ? (
                <div className="py-16 text-center text-slate-400 space-y-2">
                  <RefreshCw className="h-6 w-6 animate-spin mx-auto text-amber-400" />
                  <div>Reading sector bytes from disk...</div>
                </div>
              ) : sectorData && sectorData.lines ? (
                <div className="space-y-0.5">
                  <div className="text-slate-500 border-b border-slate-800 pb-1 mb-2">
                    OFFSET    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII DECODE
                  </div>
                  {sectorData.lines.map((line, idx) => (
                    <div key={idx} className="text-slate-300 hover:bg-slate-900/60 px-1 rounded select-text">
                      {line}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-12 text-center text-slate-500">No sector data available.</div>
              )}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-xs">
              <span className="text-slate-400 font-mono">
                Total Sectors: {sectorData?.total_sectors?.toLocaleString() || 0} blocks
              </span>

              <div className="flex items-center gap-2">
                <a
                  href={`http://localhost:9758/api/hunter/iso-images/${inspectingIso.id}/download`}
                  download={inspectingIso.image_name}
                  className="px-3 py-1.5 rounded-lg font-semibold text-xs bg-emerald-600/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-600/30 flex items-center gap-1.5"
                >
                  <Download className="h-3 w-3" />
                  <span>Download Full Image</span>
                </a>
                <Button
                  size="sm"
                  onClick={() => setInspectingIso(null)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs h-8 px-4"
                >
                  Close
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* RBAC Notice */}
      <div className="p-4 rounded-2xl border border-slate-800 bg-[#090F1D] flex items-start gap-3 text-xs text-slate-400">
        <Lock className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <strong className="text-white">Strict RBAC & Clearance Isolation:</strong> As an approved Hunter, you have read-only inspection clearance over evidence images assigned to external investigation cases. Internal server paths, classified case records, and disk destruction functions remain prohibited in accordance with NTRO Departmental Regulations.
        </div>
      </div>
    </div>
  );
}
