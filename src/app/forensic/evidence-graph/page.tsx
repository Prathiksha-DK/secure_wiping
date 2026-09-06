"use client";

import React, { useState, useEffect, useMemo, useCallback } from "react";
import Link from "next/link";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  type Node,
  type Edge,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Network,
  Search,
  ArrowLeft,
  AlertTriangle,
  HardDrive,
  FileText,
  Disc,
  Database,
  Layers,
  Clock,
  CheckCircle2,
  Briefcase,
  Eye,
  Binary,
  X,
  FolderOpen,
  Link2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
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

type GraphNode = {
  id: string;
  type: string;
  label: string;
  confidence: "DIRECT" | "CORRELATED" | "POTENTIAL";
  source_ref?: Record<string, any>;
  [key: string]: any;
};

type GraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  confidence_level: "DIRECT" | "CORRELATED" | "POTENTIAL";
  evidence_source: string;
  supporting_evidence?: Record<string, any>;
};

type UnavailableType = { relationship_type: string; reason: string };

type GraphResponse = {
  status: string;
  case_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  unavailable_relationship_types: UnavailableType[];
  node_count: number;
  truncated: boolean;
  depth_applied: number;
  message?: string;
};

const NODE_TYPE_META: Record<string, { icon: any; label: string }> = {
  case: { icon: Briefcase, label: "Case" },
  device: { icon: HardDrive, label: "Device" },
  artifact: { icon: FileText, label: "Evidence Artifact" },
  iso_image: { icon: Disc, label: "ISO Image" },
  evidence: { icon: Database, label: "Evidence" },
  forensic_artifact: { icon: Search, label: "Forensic Artifact" },
  review_verdict: { icon: CheckCircle2, label: "Review Verdict" },
  fragment: { icon: Layers, label: "Fragment" },
  timeline_event: { icon: Clock, label: "Timeline Event" },
  case_evidence_item: { icon: FolderOpen, label: "Evidence Item" },
};

const RELATIONSHIP_TYPES = [
  "RELATED_TO", "DERIVED_FROM", "RECOVERED_FROM", "GENERATED_BY",
  "CORROBORATES", "CONTRADICTS",
];

const CONFIDENCE_COLOR: Record<string, string> = {
  DIRECT: "#10b981",
  CORRELATED: "#f59e0b",
  POTENTIAL: "#64748b",
};

function layoutNodes(nodes: GraphNode[], edges: GraphEdge[], centerId: string) {
  const adjacency: Record<string, string[]> = {};
  edges.forEach((e) => {
    (adjacency[e.source] ||= []).push(e.target);
    (adjacency[e.target] ||= []).push(e.source);
  });

  const dist: Record<string, number> = { [centerId]: 0 };
  const queue = [centerId];
  while (queue.length) {
    const cur = queue.shift() as string;
    for (const nb of adjacency[cur] || []) {
      if (!(nb in dist)) {
        dist[nb] = dist[cur] + 1;
        queue.push(nb);
      }
    }
  }

  const byHop: Record<number, string[]> = {};
  nodes.forEach((n) => {
    const h = dist[n.id] ?? 3;
    (byHop[h] ||= []).push(n.id);
  });

  const positions: Record<string, { x: number; y: number }> = {};
  Object.entries(byHop).forEach(([hopStr, ids]) => {
    const hop = Number(hopStr);
    if (hop === 0) {
      positions[ids[0]] = { x: 0, y: 0 };
      return;
    }
    const radius = hop * 240;
    ids.forEach((id, i) => {
      const angle = (2 * Math.PI * i) / ids.length - Math.PI / 2;
      positions[id] = { x: radius * Math.cos(angle), y: radius * Math.sin(angle) };
    });
  });

  return positions;
}

function NodeLabel({ node }: { node: GraphNode }) {
  const meta = NODE_TYPE_META[node.type] || { icon: Binary, label: node.type };
  const Icon = meta.icon;
  const color = CONFIDENCE_COLOR[node.confidence] || "#64748b";
  return (
    <div className="flex items-center gap-2 px-1">
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
      <div className="min-w-0">
        <div className="text-[11px] font-semibold text-white truncate max-w-[140px]">{node.label}</div>
        <div className="text-[9px] font-mono uppercase tracking-wide" style={{ color }}>
          {meta.label}
        </div>
      </div>
    </div>
  );
}

export default function EvidenceRelationshipGraphPage() {
  const [caseIdInput, setCaseIdInput] = useState("");
  const [activeCaseId, setActiveCaseId] = useState("");
  const [depth, setDepth] = useState<1 | 2>(1);
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");

  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedNodeDetail, setSelectedNodeDetail] = useState<any | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  const [showLinkForm, setShowLinkForm] = useState(false);
  const [linkTarget, setLinkTarget] = useState("");
  const [linkType, setLinkType] = useState("RELATED_TO");
  const [linkNotes, setLinkNotes] = useState("");
  const [linking, setLinking] = useState(false);

  const [nodesState, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edgesState, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  const fetchGraph = useCallback(async (caseId: string, d: number) => {
    if (!caseId.trim()) {
      setGraph(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/evidence-graph/${encodeURIComponent(caseId)}?depth=${d}`);
      const data = await res.json();
      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || `Case '${caseId}' was not found.`);
      }
      setGraph(data);
    } catch (err: any) {
      setGraph(null);
      setError(err.message || "Failed to load evidence graph.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const params = typeof window !== "undefined" ? new URLSearchParams(window.location.search) : null;
    const caseParam = params?.get("case") || "";
    if (caseParam) {
      setCaseIdInput(caseParam);
      setActiveCaseId(caseParam);
    }
  }, []);

  useEffect(() => {
    if (activeCaseId) fetchGraph(activeCaseId, depth);
  }, [activeCaseId, depth, fetchGraph]);

  const filteredNodes = useMemo(() => {
    if (!graph) return [];
    if (typeFilter === "ALL") return graph.nodes;
    return graph.nodes.filter((n) => n.type === typeFilter || n.type === "case");
  }, [graph, typeFilter]);

  useEffect(() => {
    if (!graph || filteredNodes.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }
    const centerId = `case:${graph.case_id}`;
    const positions = layoutNodes(filteredNodes, graph.edges, centerId);
    const keepIds = new Set(filteredNodes.map((n) => n.id));

    setNodes(
      filteredNodes.map((n) => ({
        id: n.id,
        position: positions[n.id] || { x: 0, y: 0 },
        data: { label: <NodeLabel node={n} /> },
        style: {
          background: "#0D1527",
          border: `1.5px solid ${CONFIDENCE_COLOR[n.confidence] || "#334155"}`,
          borderRadius: 10,
          padding: 6,
          width: n.id === centerId ? 190 : 170,
        },
      }))
    );

    setEdges(
      graph.edges
        .filter((e) => keepIds.has(e.source) && keepIds.has(e.target))
        .map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.relationship_type,
          animated: e.confidence_level === "DIRECT",
          style: {
            stroke: CONFIDENCE_COLOR[e.confidence_level] || "#64748b",
            strokeDasharray: e.confidence_level === "POTENTIAL" ? "4 3" : undefined,
          },
          labelStyle: { fill: "#94a3b8", fontSize: 10 },
          labelBgStyle: { fill: "#060A12" },
        }))
    );
  }, [graph, filteredNodes, setNodes, setEdges]);

  const handleNodeClick = useCallback(
    async (_: React.MouseEvent, node: Node) => {
      if (!graph) return;
      const found = graph.nodes.find((n) => n.id === node.id);
      if (!found) return;
      setSelectedNode(found);
      setSelectedEdge(null);
      try {
        const res = await fetch(
          `${API_BASE}/api/evidence-graph/${encodeURIComponent(graph.case_id)}/node/${encodeURIComponent(node.id)}`
        );
        const data = await res.json();
        if (res.ok && data.status === "success") setSelectedNodeDetail(data);
      } catch {
        setSelectedNodeDetail(null);
      }
    },
    [graph]
  );

  const evidenceItemNodes = useMemo(
    () => (graph ? graph.nodes.filter((n) => n.type === "case_evidence_item") : []),
    [graph]
  );

  const handleAddRelationship = async () => {
    if (!graph || !selectedNode || !linkTarget) return;
    setLinking(true);
    setError(null);
    try {
      const sourceEvidenceId = selectedNode.id.replace(/^case_evidence:/, "");
      const targetEvidenceId = linkTarget.replace(/^case_evidence:/, "");
      const res = await fetch(
        `${API_BASE}/api/case-evidence/${encodeURIComponent(graph.case_id)}/${encodeURIComponent(sourceEvidenceId)}/relationships`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ target_evidence_id: targetEvidenceId, relationship_type: linkType, notes: linkNotes }),
        }
      );
      const data = await res.json();
      if (!res.ok || data.status !== "success") throw new Error(data.message || "Failed to create relationship.");
      setShowLinkForm(false);
      setLinkTarget("");
      setLinkNotes("");
      await fetchGraph(graph.case_id, depth);
    } catch (err: any) {
      setError(err.message || "Failed to create relationship.");
    } finally {
      setLinking(false);
    }
  };

  const handleEdgeClick = useCallback(
    async (_: React.MouseEvent, edge: Edge) => {
      if (!graph) return;
      const found = graph.edges.find((e) => e.id === edge.id);
      if (!found) return;
      setSelectedEdge(found);
      setSelectedNode(null);
    },
    [graph]
  );

  const availableTypes = useMemo(() => {
    if (!graph) return [];
    const s = new Set(graph.nodes.map((n) => n.type).filter((t) => t !== "case"));
    return Array.from(s);
  }, [graph]);

  const handleSearchSubmit = () => {
    if (!activeCaseId || !searchQuery.trim() || !graph) return;
    const match = graph.nodes.find(
      (n) =>
        n.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
        n.id.toLowerCase().includes(searchQuery.toLowerCase())
    );
    if (match) {
      setTypeFilter("ALL");
      setSelectedNode(match);
    }
  };

  const caseNode = graph?.nodes.find((n) => n.type === "case");
  const hasAnyRelationship = (graph?.edges.length || 0) > 0;

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
            <span className="text-slate-600">•</span>
            <span className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-mono font-semibold border border-cyan-500/40 bg-cyan-500/15 text-cyan-300">
              <Network className="h-3.5 w-3.5 text-cyan-400" />
              Evidence Relationship Graph
            </span>
          </div>
          <h1 className="text-2xl md:text-3xl font-extrabold tracking-tight text-white">
            Evidence Relationship Graph
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-2xl font-normal leading-relaxed">
            Automatically connects evidence artifacts backed by real forensic data. No relationship shown here is
            fabricated — every node and edge traces back to a specific record in the case's own stores.
          </p>
        </div>
      </div>

      {/* Case selector bar */}
      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl shadow-2xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
          <div className="flex-1 flex items-center gap-2">
            <Input
              placeholder="Enter Case ID (e.g. CASE-2026-TEST8912)"
              value={caseIdInput}
              onChange={(e) => setCaseIdInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && setActiveCaseId(caseIdInput.trim())}
              className="bg-[#060A12] border-slate-700 text-white text-xs h-10 rounded-xl"
            />
            <Button
              onClick={() => setActiveCaseId(caseIdInput.trim())}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs h-10 px-4 rounded-xl shrink-0"
            >
              Load Case
            </Button>
          </div>

          {graph && (
            <>
              <div className="flex items-center gap-2">
                <Search className="h-3.5 w-3.5 text-slate-500" />
                <Input
                  placeholder="Search this graph..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleSearchSubmit()}
                  className="bg-[#060A12] border-slate-700 text-white text-xs h-10 rounded-xl w-48"
                />
              </div>

              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-44 h-10 text-xs bg-[#060A12] border-slate-700">
                  <SelectValue placeholder="Filter type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ALL">All node types</SelectItem>
                  {availableTypes.map((t) => (
                    <SelectItem key={t} value={t}>
                      {NODE_TYPE_META[t]?.label || t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={String(depth)} onValueChange={(v) => setDepth(Number(v) as 1 | 2)}>
                <SelectTrigger className="w-32 h-10 text-xs bg-[#060A12] border-slate-700">
                  <SelectValue placeholder="Depth" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 hop</SelectItem>
                  <SelectItem value="2">2 hops</SelectItem>
                </SelectContent>
              </Select>
            </>
          )}
        </div>

        {graph && (
          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-slate-400">
            <span>
              Case: <span className="text-cyan-300">{graph.case_id}</span>
            </span>
            <span>•</span>
            <span>{graph.node_count} nodes</span>
            <span>•</span>
            <span>{graph.edges.length} relationships</span>
            {caseNode?.case_status && (
              <>
                <span>•</span>
                <span className="text-amber-300">{caseNode.case_status}</span>
              </>
            )}
            {graph.truncated && (
              <Badge className="bg-amber-500/15 text-amber-300 border-amber-500/30">Truncated view</Badge>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-200 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading && (
        <div className="p-10 text-center text-xs text-slate-400 font-mono">Loading evidence graph...</div>
      )}

      {!loading && graph && !hasAnyRelationship && (
        <div className="bg-[#0D1527] border border-amber-500/30 rounded-2xl p-8 text-center space-y-3">
          <AlertTriangle className="h-8 w-8 text-amber-400 mx-auto" />
          <h3 className="text-base font-bold text-white">INSUFFICIENT RELATIONSHIP DATA</h3>
          <p className="text-xs text-slate-400 max-w-xl mx-auto">
            This case has no derivable relationships in the data checked below. Nothing is fabricated to fill the
            gap — here is exactly what was checked and why each came up empty:
          </p>
          <div className="max-w-xl mx-auto text-left space-y-1.5 pt-2">
            {graph.unavailable_relationship_types.map((u) => (
              <div key={u.relationship_type} className="p-2.5 rounded-lg bg-[#060A12] border border-slate-800 text-[11px]">
                <span className="font-mono text-amber-300">{u.relationship_type}</span>
                <span className="text-slate-400"> — {u.reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {!loading && graph && hasAnyRelationship && (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div className="lg:col-span-3 bg-[#0D1527] border border-slate-800/90 rounded-2xl overflow-hidden" style={{ height: 560 }}>
            <ReactFlow
              nodes={nodesState}
              edges={edgesState}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              onNodeClick={handleNodeClick}
              onEdgeClick={handleEdgeClick}
              fitView
              proOptions={{ hideAttribution: true }}
            >
              <Background color="#1e293b" gap={20} />
              <Controls />
              <MiniMap
                nodeColor={() => "#0ea5e9"}
                maskColor="rgba(6,10,18,0.85)"
                style={{ background: "#060A12" }}
              />
            </ReactFlow>
          </div>

          <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-4 space-y-3">
            <h3 className="text-xs font-bold text-white uppercase tracking-wide">Unchecked / Unavailable</h3>
            <div className="space-y-1.5 max-h-[500px] overflow-y-auto">
              {graph.unavailable_relationship_types.map((u) => (
                <div key={u.relationship_type} className="p-2 rounded-lg bg-[#060A12] border border-slate-800 text-[10px]">
                  <div className="font-mono text-amber-300">{u.relationship_type}</div>
                  <div className="text-slate-500 leading-snug">{u.reason}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {!loading && !graph && !error && (
        <div className="p-10 text-center text-xs text-slate-500 font-mono">
          Enter a Case ID above (e.g. from Seek Help or Hunter case lists) to build its evidence graph.
        </div>
      )}

      {/* Node detail panel */}
      <Sheet open={!!selectedNode} onOpenChange={(open) => !open && setSelectedNode(null)}>
        <SheetContent className="bg-[#0D1527] border-slate-800 text-white w-full sm:max-w-md overflow-y-auto">
          {selectedNode && (
            <>
              <SheetHeader>
                <SheetTitle className="text-white flex items-center gap-2">
                  {React.createElement(NODE_TYPE_META[selectedNode.type]?.icon || Binary, { className: "h-4 w-4 text-cyan-400" })}
                  {selectedNode.label}
                </SheetTitle>
                <SheetDescription>
                  {NODE_TYPE_META[selectedNode.type]?.label || selectedNode.type} ·{" "}
                  <span style={{ color: CONFIDENCE_COLOR[selectedNode.confidence] }}>{selectedNode.confidence}</span>
                </SheetDescription>
              </SheetHeader>

              <div className="mt-4 space-y-3 text-xs">
                {selectedNode.source_ref && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 mb-1">Source Reference</div>
                    <pre className="text-[10px] text-slate-300 whitespace-pre-wrap break-all">
                      {JSON.stringify(selectedNode.source_ref, null, 2)}
                    </pre>
                  </div>
                )}

                <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800">
                  <div className="text-[10px] uppercase text-slate-500 mb-1">Fields</div>
                  <pre className="text-[10px] text-slate-300 whitespace-pre-wrap break-all">
                    {JSON.stringify(
                      Object.fromEntries(
                        Object.entries(selectedNode).filter(([k]) => !["id", "source_ref", "type", "label", "confidence"].includes(k))
                      ),
                      null,
                      2
                    )}
                  </pre>
                </div>

                {selectedNodeDetail?.connected_edges?.length > 0 && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 mb-2">
                      Connections ({selectedNodeDetail.connected_edges.length})
                    </div>
                    <div className="space-y-1.5">
                      {selectedNodeDetail.connected_edges.map((e: GraphEdge) => (
                        <div key={e.id} className="text-[10px] font-mono text-slate-400">
                          <span style={{ color: CONFIDENCE_COLOR[e.confidence_level] }}>{e.relationship_type}</span>{" "}
                          → {e.source === selectedNode.id ? e.target : e.source}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-2">
                  {typeof selectedNode.offset === "number" && graph && (
                    <Link
                      href={`/inspector?device=${encodeURIComponent(caseNode?.device_id || "")}&lba=${selectedNode.offset}`}
                    >
                      <Button size="sm" className="bg-slate-800 hover:bg-slate-700 text-xs h-8 gap-1.5">
                        <Eye className="h-3.5 w-3.5" /> View Hex
                      </Button>
                    </Link>
                  )}
                  {selectedNode.type === "timeline_event" && graph && (
                    <Link href={`/faris?case_id=${encodeURIComponent(graph.case_id)}`}>
                      <Button size="sm" className="bg-slate-800 hover:bg-slate-700 text-xs h-8 gap-1.5">
                        <Clock className="h-3.5 w-3.5" /> View Timeline
                      </Button>
                    </Link>
                  )}
                  <Button
                    size="sm"
                    disabled
                    className="bg-slate-900 text-slate-600 text-xs h-8 gap-1.5 cursor-not-allowed"
                    title="Coming in Phase 2"
                  >
                    Send to Swarm
                  </Button>
                  {selectedNode.type === "case_evidence_item" && (
                    <Button
                      size="sm"
                      onClick={() => setShowLinkForm((v) => !v)}
                      className="bg-cyan-600 hover:bg-cyan-500 text-xs h-8 gap-1.5"
                    >
                      <Link2 className="h-3.5 w-3.5" /> Link to Evidence Item
                    </Button>
                  )}
                </div>

                {showLinkForm && selectedNode.type === "case_evidence_item" && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800 space-y-2">
                    <Select value={linkTarget} onValueChange={setLinkTarget}>
                      <SelectTrigger className="h-8 text-xs bg-[#0A101D] border-slate-700">
                        <SelectValue placeholder="Target evidence item" />
                      </SelectTrigger>
                      <SelectContent>
                        {evidenceItemNodes
                          .filter((n) => n.id !== selectedNode.id)
                          .map((n) => (
                            <SelectItem key={n.id} value={n.id}>{n.label}</SelectItem>
                          ))}
                      </SelectContent>
                    </Select>
                    <Select value={linkType} onValueChange={setLinkType}>
                      <SelectTrigger className="h-8 text-xs bg-[#0A101D] border-slate-700">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {RELATIONSHIP_TYPES.map((t) => (
                          <SelectItem key={t} value={t}>{t}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Input
                      placeholder="Notes (why are these related?)"
                      value={linkNotes}
                      onChange={(e) => setLinkNotes(e.target.value)}
                      className="bg-[#0A101D] border-slate-700 text-white text-xs h-8"
                    />
                    <Button
                      size="sm"
                      disabled={linking || !linkTarget}
                      onClick={handleAddRelationship}
                      className="w-full bg-cyan-600 hover:bg-cyan-500 h-8 text-xs"
                    >
                      Create Relationship
                    </Button>
                  </div>
                )}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      {/* Edge "why connected" panel */}
      <Sheet open={!!selectedEdge} onOpenChange={(open) => !open && setSelectedEdge(null)}>
        <SheetContent className="bg-[#0D1527] border-slate-800 text-white w-full sm:max-w-md overflow-y-auto">
          {selectedEdge && (
            <>
              <SheetHeader>
                <SheetTitle className="text-white">Why are these connected?</SheetTitle>
                <SheetDescription>
                  <span className="font-mono" style={{ color: CONFIDENCE_COLOR[selectedEdge.confidence_level] }}>
                    {selectedEdge.relationship_type}
                  </span>{" "}
                  · {selectedEdge.confidence_level}
                </SheetDescription>
              </SheetHeader>

              <div className="mt-4 space-y-3 text-xs">
                <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800">
                  <div className="text-[10px] uppercase text-slate-500 mb-1">Evidence Source</div>
                  <div className="text-slate-300 font-mono text-[11px]">{selectedEdge.evidence_source}</div>
                </div>
                {selectedEdge.supporting_evidence && (
                  <div className="p-3 rounded-lg bg-[#060A12] border border-slate-800">
                    <div className="text-[10px] uppercase text-slate-500 mb-1">Supporting Evidence</div>
                    <pre className="text-[10px] text-slate-300 whitespace-pre-wrap break-all">
                      {JSON.stringify(selectedEdge.supporting_evidence, null, 2)}
                    </pre>
                  </div>
                )}
                <div className="text-[10px] text-slate-500 flex items-center gap-1">
                  <span>{selectedEdge.source}</span>
                  <span>↔</span>
                  <span>{selectedEdge.target}</span>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
