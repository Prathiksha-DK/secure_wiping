"use client";

import React, { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import {
  Wrench,
  ArrowLeft,
  CheckCircle2,
  XCircle,
  Loader2,
  Play,
  Plus,
  Disc,
  HardDrive,
  Brain,
  Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";

const API_BASE = "http://localhost:9758";

interface ToolMeta {
  installed: boolean;
  version: string;
  status: string;
  license?: string;
  display_name?: string;
}

const CATEGORY_GROUPS: { label: string; icon: any; tools: string[] }[] = [
  { label: "Imaging", icon: Disc, tools: ["libewf", "ftk_imager"] },
  { label: "Memory Forensics", icon: Brain, tools: ["volatility"] },
  { label: "Disk / Filesystem Forensics", icon: HardDrive, tools: ["sleuthkit", "autopsy"] },
  { label: "Hashing / Utilities", icon: Wrench, tools: ["sqlite_runtime", "photorec", "python_runtime"] },
  { label: "Network Evidence", icon: Network, tools: ["wireshark", "tshark"] },
];

const SLEUTHKIT_TOOLS = ["mmls", "fsstat", "fls", "istat"];

export default function ForensicToolkitPage() {
  const [caseIdInput, setCaseIdInput] = useState("");
  const [activeCaseId, setActiveCaseId] = useState("");
  const [hunterLocked, setHunterLocked] = useState(false);
  const [inventory, setInventory] = useState<Record<string, ToolMeta>>({});
  const [loadingInventory, setLoadingInventory] = useState(true);
  const [running, setRunning] = useState<string | null>(null);
  const [result, setResult] = useState<{ tool: string; staged_output_path: string; data: any } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [addingEvidence, setAddingEvidence] = useState(false);
  const [addedMsg, setAddedMsg] = useState<string | null>(null);
  const [caseSummary, setCaseSummary] = useState<any | null>(null);
  const [caseLoadError, setCaseLoadError] = useState<string | null>(null);
  const [loadingCase, setLoadingCase] = useState(false);

  useEffect(() => {
    fetch(`${API_BASE}/api/forensic-tools/inventory`, { credentials: "include" })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "success") setInventory(data.inventory);
      })
      .finally(() => setLoadingInventory(false));

    fetch(`${API_BASE}/api/devices/current`, { credentials: "include", cache: "no-store" })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        const active = data?.hunter_active_case;
        if (active?.case_id) {
          setActiveCaseId(active.case_id);
          setHunterLocked(true);
        }
      })
      .catch(() => {});
  }, []);

  const handleLoadCase = async () => {
    const caseId = caseIdInput.trim();
    if (!caseId) return;
    setLoadingCase(true);
    setCaseLoadError(null);
    setCaseSummary(null);
    setActiveCaseId("");
    try {
      const res = await fetch(`${API_BASE}/api/forensic-tools/case-summary/${encodeURIComponent(caseId)}`, {
        credentials: "include",
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || `Case '${caseId}' was not found.`);
      }
      setCaseSummary(data.case);
      setActiveCaseId(caseId);
    } catch (err: any) {
      setCaseLoadError(err.message || "Failed to load case.");
    } finally {
      setLoadingCase(false);
    }
  };

  const runTool = useCallback(async (label: string, path: string) => {
    if (!activeCaseId) return;
    setRunning(label);
    setError(null);
    setResult(null);
    setAddedMsg(null);
    try {
      const res = await fetch(`${API_BASE}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ case_id: activeCaseId }),
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Tool execution failed.");
      setResult({ tool: label, staged_output_path: data.staged_output_path, data: data.result });
    } catch (err: any) {
      setError(err.message || "Tool execution failed.");
    } finally {
      setRunning(null);
    }
  }, [activeCaseId]);

  const handleAddToEvidence = async () => {
    if (!result || !activeCaseId) return;
    setAddingEvidence(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/case-evidence/${encodeURIComponent(activeCaseId)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          name: `${result.tool}_output.json`,
          evidence_type: "Tool Analysis Result",
          source_path: result.staged_output_path,
          source: result.tool,
          description: `Output of ${result.tool} run against case ${activeCaseId}.`,
        }),
      });
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Failed to add to evidence.");
      setAddedMsg(`Added as ${data.evidence.label} to the Evidence Workspace.`);
    } catch (err: any) {
      setError(err.message || "Failed to add to evidence.");
    } finally {
      setAddingEvidence(false);
    }
  };

  return (
    <div className="space-y-6 w-full max-w-7xl mx-auto text-foreground pb-12">
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
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <Wrench className="h-6 w-6 text-cyan-400" /> Forensic Toolkit
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl">
            Real, bundled forensic engines (Sleuth Kit, libewf, Volatility3) run only against the active case's
            authorized forensic source. Tools not installed on this system are shown honestly, never fabricated.
          </p>
        </div>
      </div>

      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-5 space-y-3">
        {hunterLocked ? (
          <div className="text-xs font-mono">
            <span className="text-slate-400">Active case (locked): </span>
            <span className="text-cyan-300 font-bold">{activeCaseId}</span>
          </div>
        ) : (
          <>
            <div className="flex gap-2">
              <Input
                placeholder="Case ID (e.g. CASE-2026-F248)"
                value={caseIdInput}
                onChange={(e) => setCaseIdInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleLoadCase()}
                className="bg-[#060A12] border-slate-700 text-white text-xs h-9 max-w-sm"
              />
              <Button size="sm" disabled={loadingCase} onClick={handleLoadCase} className="bg-cyan-600 hover:bg-cyan-500 h-9 gap-1.5">
                {loadingCase && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                Load Case
              </Button>
            </div>
            {caseLoadError && (
              <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200">
                {caseLoadError}
              </div>
            )}
            {caseSummary && (
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs font-mono text-emerald-200 flex flex-wrap gap-x-4 gap-y-1">
                <span className="flex items-center gap-1"><CheckCircle2 className="h-3.5 w-3.5" /> Case loaded: {caseSummary.case_id}</span>
                <span>Device: {caseSummary.device_model} ({caseSummary.device_id})</span>
                <span>Image: {caseSummary.image_filename}</span>
                <span>Status: {caseSummary.case_status}</span>
              </div>
            )}
          </>
        )}
      </div>

      {/* Tool inventory */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {CATEGORY_GROUPS.map((group) => (
          <div key={group.label} className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-4 space-y-2">
            <div className="flex items-center gap-1.5 text-xs font-bold text-white uppercase tracking-wide">
              <group.icon className="h-4 w-4 text-cyan-400" /> {group.label}
            </div>
            {loadingInventory ? (
              <div className="text-xs text-slate-500">Loading...</div>
            ) : (
              group.tools.map((key) => {
                const meta = inventory[key];
                if (!meta) return null;
                const isAvailable = meta.status === "AVAILABLE";
                return (
                  <div key={key} className="flex items-center justify-between p-2 rounded-lg bg-[#060A12] border border-slate-800 text-xs">
                    <div>
                      <div className="font-semibold text-slate-200">{meta.display_name || key}</div>
                      <div className="text-[10px] text-slate-500">{meta.version}</div>
                    </div>
                    <Badge className={isAvailable ? "bg-emerald-500/15 text-emerald-300 border-emerald-500/30" : "bg-slate-700/30 text-slate-400 border-slate-700"}>
                      {isAvailable ? <CheckCircle2 className="h-3 w-3 mr-1" /> : <XCircle className="h-3 w-3 mr-1" />}
                      {meta.status}
                    </Badge>
                  </div>
                );
              })
            )}
          </div>
        ))}
      </div>

      {/* Run panel */}
      {activeCaseId && (
        <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-5 space-y-4">
          <h2 className="text-sm font-bold text-white">Run Against Case Forensic Image</h2>
          <div className="flex flex-wrap gap-2">
            {SLEUTHKIT_TOOLS.map((tool) => (
              <Button
                key={tool}
                size="sm"
                disabled={running !== null || inventory.sleuthkit?.status !== "AVAILABLE"}
                onClick={() => runTool(tool, `/api/forensic-tools/sleuthkit/${tool}`)}
                className="bg-slate-800 hover:bg-slate-700 text-xs h-8 gap-1.5"
              >
                {running === tool ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                {tool}
              </Button>
            ))}
            <Button
              size="sm"
              disabled={running !== null || inventory.libewf?.status !== "AVAILABLE"}
              onClick={() => runTool("libewf_verify", "/api/forensic-tools/libewf/verify")}
              className="bg-slate-800 hover:bg-slate-700 text-xs h-8 gap-1.5"
            >
              {running === "libewf_verify" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
              Verify Image Hash (libewf)
            </Button>
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200">{error}</div>
          )}

          {result && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-white">{result.tool} output</span>
                <Button
                  size="sm"
                  disabled={addingEvidence}
                  onClick={handleAddToEvidence}
                  className="bg-cyan-600 hover:bg-cyan-500 text-xs h-8 gap-1.5"
                >
                  {addingEvidence ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
                  Add Result to Evidence
                </Button>
              </div>
              {addedMsg && (
                <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-200">{addedMsg}</div>
              )}
              <pre className="p-3 rounded-lg bg-[#060A12] border border-slate-800 text-[10px] text-slate-300 overflow-x-auto max-h-72 overflow-y-auto">
                {JSON.stringify(result.data, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
