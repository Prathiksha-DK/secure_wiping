"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import Link from "next/link";
import {
  FolderOpen,
  X,
  Plus,
  Search,
  FileText,
  Hash,
  Eye,
  ClipboardList,
  Loader2,
  ChevronRight,
  Link2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";

const API_BASE = "http://localhost:9758";

const EVIDENCE_TYPES = [
  "Forensic Image", "Recovered File", "Recovered Folder", "Deleted File",
  "Memory Image", "Carved Artifact", "Filesystem Artifact",
  "Metadata Artifact", "Hash Result", "Timeline Artifact",
  "Tool Analysis Result", "Investigation Report",
];

const STATUSES = ["COLLECTED", "RECOVERED", "VERIFIED", "ANALYZED", "CORRELATED", "SUBMITTED", "ACCEPTED", "REQUIRES_REVIEW"];
const CONFIDENCE_LEVELS = ["HIGH", "MEDIUM", "LOW", "UNCONFIRMED"];

const CONFIDENCE_COLOR: Record<string, string> = {
  HIGH: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  MEDIUM: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  LOW: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  UNCONFIRMED: "bg-slate-500/15 text-slate-300 border-slate-500/30",
};

function getRoleFromCookie(): string {
  if (typeof window === "undefined") return "individual";
  const roleMatch = document.cookie.match(/(?:^|; )userRole=([^;]*)/);
  if (roleMatch) return decodeURIComponent(roleMatch[1]);
  return "individual";
}

interface EvidenceItem {
  evidence_id: string;
  label: string;
  case_id: string;
  evidence_number: number;
  name: string;
  description: string;
  evidence_type: string;
  source_path: string;
  file_size: number | null;
  sha256: string;
  md5: string;
  status: string;
  confidence: string | null;
  conclusion: string;
  notes: string;
  added_by: string;
  created_at: number;
}

export default function EvidenceWorkspacePanel() {
  const [role, setRole] = useState<string>("individual");
  const [open, setOpen] = useState(false);
  const [hunterCaseId, setHunterCaseId] = useState<string>("");
  const [caseIdInput, setCaseIdInput] = useState("");
  const [activeCaseId, setActiveCaseId] = useState("");

  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");

  const [selected, setSelected] = useState<EvidenceItem | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [addForm, setAddForm] = useState({ name: "", evidence_type: "Forensic Image", description: "", source_path: "" });
  const [adding, setAdding] = useState(false);

  const [conclusion, setConclusion] = useState<any | null>(null);
  const [stats, setStats] = useState<any | null>(null);

  useEffect(() => {
    setRole(getRoleFromCookie());
    fetch(`${API_BASE}/api/devices/current`, { credentials: "include", cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        const active = data?.hunter_active_case;
        if (active?.case_id) {
          setHunterCaseId(active.case_id);
          setActiveCaseId(active.case_id);
        }
      })
      .catch(() => {});
  }, []);

  const fetchEvidence = useCallback(async (caseId: string) => {
    if (!caseId.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      if (search) params.set("search", search);
      if (typeFilter !== "ALL") params.set("type", typeFilter);
      if (statusFilter !== "ALL") params.set("status", statusFilter);
      const res = await fetch(`${API_BASE}/api/case-evidence/${encodeURIComponent(caseId)}?${params.toString()}`, {
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Failed to load evidence.");
      setItems(data.evidence || []);
    } catch (err: any) {
      setItems([]);
      setError(err.message || "Failed to load evidence.");
    } finally {
      setLoading(false);
    }
  }, [search, typeFilter, statusFilter]);

  const fetchConclusion = useCallback(async (caseId: string) => {
    if (!caseId.trim()) return;
    try {
      const res = await fetch(`${API_BASE}/api/case-evidence/${encodeURIComponent(caseId)}/conclusion`, {
        credentials: "include",
      });
      const data = await res.json();
      if (res.ok && data.status === "success") {
        setStats(data.stats);
        setConclusion(data.conclusion);
      }
    } catch {
      /* non-fatal */
    }
  }, []);

  useEffect(() => {
    if (open && activeCaseId) {
      fetchEvidence(activeCaseId);
      fetchConclusion(activeCaseId);
    }
  }, [open, activeCaseId, fetchEvidence, fetchConclusion]);

  const handleLoadCase = () => {
    if (caseIdInput.trim()) setActiveCaseId(caseIdInput.trim());
  };

  const handleAddEvidence = async () => {
    if (!activeCaseId || !addForm.name.trim()) return;
    setAdding(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/case-evidence/${encodeURIComponent(activeCaseId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(addForm),
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Failed to add evidence.");
      setShowAddForm(false);
      setAddForm({ name: "", evidence_type: "Forensic Image", description: "", source_path: "" });
      await fetchEvidence(activeCaseId);
      await fetchConclusion(activeCaseId);
    } catch (err: any) {
      setError(err.message || "Failed to add evidence.");
    } finally {
      setAdding(false);
    }
  };

  const handleUpdateEvidence = async (evidenceId: string, patch: Record<string, any>) => {
    try {
      const res = await fetch(`${API_BASE}/api/case-evidence/${encodeURIComponent(activeCaseId)}/${encodeURIComponent(evidenceId)}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(patch),
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Update failed.");
      setSelected(data.evidence);
      await fetchEvidence(activeCaseId);
      await fetchConclusion(activeCaseId);
    } catch (err: any) {
      setError(err.message || "Update failed.");
    }
  };

  // Only relevant for Hunter / Forensic Investigator roles.
  if (role !== "hunter" && role !== "forensic") return null;

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-40 flex items-center gap-2 px-4 py-3 rounded-full bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-950/40 text-xs font-semibold transition-all hover:scale-105"
      >
        <FolderOpen className="h-4 w-4" />
        <span>Evidence</span>
        {items.length > 0 && (
          <Badge className="bg-white/20 text-white border-0 text-[10px] px-1.5 py-0">{items.length}</Badge>
        )}
      </button>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent className="bg-[#0D1527] border-slate-800 text-white w-full sm:max-w-lg overflow-y-auto">
          <SheetHeader>
            <SheetTitle className="text-white flex items-center gap-2">
              <FolderOpen className="h-4 w-4 text-cyan-400" />
              Case Evidence Workspace
            </SheetTitle>
            <SheetDescription>
              {role === "hunter"
                ? "Evidence for your currently claimed case."
                : "Enter a Case ID to view or add evidence."}
            </SheetDescription>
          </SheetHeader>

          <div className="mt-4 space-y-4 text-xs">
            {role === "forensic" && (
              <div className="flex gap-2">
                <Input
                  placeholder="Case ID (e.g. CASE-2026-F248)"
                  value={caseIdInput}
                  onChange={(e) => setCaseIdInput(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLoadCase()}
                  className="bg-[#060A12] border-slate-700 text-white text-xs h-9"
                />
                <Button size="sm" onClick={handleLoadCase} className="bg-cyan-600 hover:bg-cyan-500 h-9">
                  Load
                </Button>
              </div>
            )}

            {role === "hunter" && !hunterCaseId && (
              <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-200">
                You have no active claimed case. Claim a case from your dashboard to use the Evidence Workspace.
              </div>
            )}

            {activeCaseId && (
              <>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-cyan-300 font-bold">{activeCaseId}</span>
                  <Button
                    size="sm"
                    onClick={() => setShowAddForm((v) => !v)}
                    className="bg-slate-800 hover:bg-slate-700 h-8 text-xs gap-1.5"
                  >
                    <Plus className="h-3.5 w-3.5" /> Add Evidence
                  </Button>
                </div>

                {showAddForm && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800 space-y-2">
                    <Input
                      placeholder="Evidence name (e.g. suspicious_file.exe)"
                      value={addForm.name}
                      onChange={(e) => setAddForm((f) => ({ ...f, name: e.target.value }))}
                      className="bg-[#0A101D] border-slate-700 text-white text-xs h-8"
                    />
                    <Select value={addForm.evidence_type} onValueChange={(v) => setAddForm((f) => ({ ...f, evidence_type: v }))}>
                      <SelectTrigger className="h-8 text-xs bg-[#0A101D] border-slate-700">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {EVIDENCE_TYPES.map((t) => (
                          <SelectItem key={t} value={t}>{t}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      placeholder="Source path (optional -- blank = case image itself)"
                      value={addForm.source_path}
                      onChange={(e) => setAddForm((f) => ({ ...f, source_path: e.target.value }))}
                      className="bg-[#0A101D] border-slate-700 text-white text-xs h-8 font-mono"
                    />
                    <Textarea
                      placeholder="Description"
                      value={addForm.description}
                      onChange={(e) => setAddForm((f) => ({ ...f, description: e.target.value }))}
                      className="bg-[#0A101D] border-slate-700 text-white text-xs min-h-[50px]"
                    />
                    <Button
                      size="sm"
                      disabled={adding || !addForm.name.trim()}
                      onClick={handleAddEvidence}
                      className="w-full bg-cyan-600 hover:bg-cyan-500 h-8 text-xs"
                    >
                      {adding ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : "Add Evidence"}
                    </Button>
                  </div>
                )}

                <div className="flex gap-2">
                  <div className="flex-1 flex items-center gap-1.5 px-2 h-8 rounded-md bg-[#060A12] border border-slate-700">
                    <Search className="h-3 w-3 text-slate-500" />
                    <input
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && fetchEvidence(activeCaseId)}
                      placeholder="Search evidence..."
                      className="bg-transparent text-xs outline-none flex-1 text-white placeholder:text-slate-500"
                    />
                  </div>
                  <Select value={statusFilter} onValueChange={(v) => { setStatusFilter(v); }}>
                    <SelectTrigger className="w-32 h-8 text-xs bg-[#060A12] border-slate-700">
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL">All statuses</SelectItem>
                      {STATUSES.map((s) => (
                        <SelectItem key={s} value={s}>{s}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {error && (
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-200">{error}</div>
                )}

                {loading ? (
                  <div className="text-center py-6 text-slate-500">Loading...</div>
                ) : items.length === 0 ? (
                  <div className="text-center py-6 text-slate-500">No evidence recorded yet for this case.</div>
                ) : (
                  <div className="space-y-1.5">
                    {items.map((item) => (
                      <button
                        key={item.evidence_id}
                        onClick={() => setSelected(item)}
                        className="w-full text-left p-2.5 rounded-lg bg-[#060A12] border border-slate-800 hover:border-slate-700 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-cyan-400 font-bold">{item.label}</span>
                            <span className="truncate text-slate-200">{item.name}</span>
                          </div>
                          <div className="text-[10px] text-slate-500 mt-0.5">{item.evidence_type} • {item.status}</div>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          {item.confidence && (
                            <Badge className={`text-[9px] ${CONFIDENCE_COLOR[item.confidence] || ""}`}>{item.confidence}</Badge>
                          )}
                          <ChevronRight className="h-3.5 w-3.5 text-slate-600" />
                        </div>
                      </button>
                    ))}
                  </div>
                )}

                {stats && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800 space-y-2">
                    <div className="flex items-center gap-1.5 font-bold text-white">
                      <ClipboardList className="h-3.5 w-3.5 text-cyan-400" /> Case Conclusion
                    </div>
                    <div className="grid grid-cols-2 gap-1.5 text-[10px] text-slate-400">
                      <div>Evidence: <span className="text-white">{stats.evidence_count}</span></div>
                      <div>Verified: <span className="text-white">{stats.verified_count}</span></div>
                      <div>High confidence: <span className="text-emerald-300">{stats.high_confidence}</span></div>
                      <div>Medium: <span className="text-amber-300">{stats.medium_confidence}</span></div>
                      <div>Low: <span className="text-rose-300">{stats.low_confidence}</span></div>
                      <div>Unconfirmed: <span className="text-slate-300">{stats.unconfirmed_confidence}</span></div>
                    </div>
                    {conclusion?.conclusion && (
                      <p className="text-[11px] text-slate-300 pt-1 border-t border-slate-800">{conclusion.conclusion}</p>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </SheetContent>
      </Sheet>

      {/* Evidence detail sheet */}
      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent className="bg-[#0D1527] border-slate-800 text-white w-full sm:max-w-md overflow-y-auto">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="text-white flex items-center gap-2">
                  <FileText className="h-4 w-4 text-cyan-400" />
                  {selected.label} — {selected.name}
                </SheetTitle>
                <SheetDescription>{selected.evidence_type}</SheetDescription>
              </SheetHeader>

              <div className="mt-4 space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800 space-y-1.5 font-mono">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <Hash className="h-3 w-3" /> SHA-256
                  </div>
                  <div className="text-[10px] text-white break-all">{selected.sha256}</div>
                  <div className="text-slate-400 pt-1">Size: <span className="text-white">{selected.file_size ? `${selected.file_size.toLocaleString()} bytes` : "Not calculated"}</span></div>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase text-slate-500">Status</label>
                  <Select value={selected.status} onValueChange={(v) => handleUpdateEvidence(selected.evidence_id, { status: v })}>
                    <SelectTrigger className="h-8 text-xs bg-[#060A12] border-slate-700"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {STATUSES.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase text-slate-500">Confidence</label>
                  <Select value={selected.confidence || ""} onValueChange={(v) => handleUpdateEvidence(selected.evidence_id, { confidence: v })}>
                    <SelectTrigger className="h-8 text-xs bg-[#060A12] border-slate-700"><SelectValue placeholder="Set confidence" /></SelectTrigger>
                    <SelectContent>
                      {CONFIDENCE_LEVELS.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase text-slate-500">Conclusion</label>
                  <Textarea
                    defaultValue={selected.conclusion}
                    placeholder="Evidence-supported conclusion (do not assert intent/guilt)"
                    className="bg-[#060A12] border-slate-700 text-white text-xs min-h-[60px]"
                    onBlur={(e) => {
                      if (e.target.value !== selected.conclusion) handleUpdateEvidence(selected.evidence_id, { conclusion: e.target.value });
                    }}
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase text-slate-500">Notes</label>
                  <Textarea
                    defaultValue={selected.notes}
                    placeholder="Investigator notes"
                    className="bg-[#060A12] border-slate-700 text-white text-xs min-h-[50px]"
                    onBlur={(e) => {
                      if (e.target.value !== selected.notes) handleUpdateEvidence(selected.evidence_id, { notes: e.target.value });
                    }}
                  />
                </div>

                {selected.evidence_type === "Forensic Image" && selected.source_path && (
                  <Link
                    href={`/inspector?device=${encodeURIComponent(selected.source_path)}&lba=0`}
                    className="inline-flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300"
                  >
                    <Eye className="h-3.5 w-3.5" /> View in Storage Inspector
                  </Link>
                )}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}
