"use client";

import React, { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import Link from "next/link";
import {
  HardDrive,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Server,
  Cpu,
  BarChart3,
  CheckCircle,
  XCircle,
  Loader2,
  Trash2,
  History,
  Activity,
  Usb,
  FileText,
  AlertTriangle,
  Search,
  Eye,
  ArrowRight,
  Shield,
  Layers,
  Sparkles
} from "lucide-react";

const API_BASE = "http://localhost:9758";

type Device = {
  name: string;
  friendlyName?: string;
  type: string;
  size: string;
  health: number;
  healthStatus: string;
  serial?: string;
  model?: string;
  isSystem?: boolean;
};

type Stats = {
  totalWipes: number;
  completed: number;
  warning: number;
  failed: number;
  inProgress: number;
  totalDevices: number;
  complianceRate: number;
  standardsBreakdown?: Record<string, number>;
  recentWipes?: Array<{
    id: string;
    device: string;
    method: string;
    status: string;
    finalState?: string;
    standard?: string;
    startTime: string;
    endTime: string;
    operatorName?: string;
  }>;
};

type SystemStatus = {
  hostname: string;
  os: string;
  timestamp: string;
  status: string;
};

export default function MasterDashboardPage() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAll() {
      setLoading(true);
      try {
        const [sysRes, devRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/api/system/status`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/devices`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/stats`, { cache: "no-store" }).catch(() => null),
        ]);
        if (sysRes?.ok) setSystemStatus(await sysRes.json());
        if (devRes?.ok) setDevices(await devRes.json());
        if (statsRes?.ok) setStats(await statsRes.json());
      } catch (e) {
        console.error("Failed to fetch master dashboard data:", e);
      } finally {
        setLoading(false);
      }
    }
    fetchAll();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-8 w-8 animate-spin text-primary" />
          <p className="text-xs text-muted-foreground">Loading master dashboard...</p>
        </div>
      </div>
    );
  }

  const totalWipes = stats?.totalWipes || 0;
  const completed = stats?.completed || 0;
  const warning = stats?.warning || 0;
  const failed = stats?.failed || 0;

  return (
    <div className="space-y-6 w-full min-w-0 max-w-full animate-fade-in">
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Badge variant="outline" className="text-primary border-primary/30 bg-primary/5 text-xs font-semibold">
              Master Operations Console
            </Badge>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
            Sanitization Operations Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-0.5">
            Enterprise Data Sanitization &amp; Forensic Verification Control Center
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild size="sm" className="gap-1.5 shadow-sm bg-primary">
            <Link href="/wipe">
              <Shield className="h-4 w-4" /> Start Secure Wipe
            </Link>
          </Button>
        </div>
      </div>

      {/* Assurance State Metrics Bar */}
      <div className="grid gap-4 grid-cols-2 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4 border shadow-sm">
          <div className="flex items-center justify-between pb-2">
            <span className="text-xs font-medium text-muted-foreground">Total Sessions</span>
            <Activity className="h-4 w-4 text-primary" />
          </div>
          <div className="text-2xl sm:text-3xl font-black">{totalWipes}</div>
          <p className="text-[11px] text-muted-foreground mt-1">Audit log records</p>
        </Card>

        <Card className="p-4 border shadow-sm">
          <div className="flex items-center justify-between pb-2">
            <span className="text-xs font-medium text-muted-foreground">Sanitized (Passed)</span>
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          </div>
          <div className="text-2xl sm:text-3xl font-black text-emerald-600 dark:text-emerald-400">
            {completed}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">100% Zero-remnant verified</p>
        </Card>

        <Card className="p-4 border shadow-sm">
          <div className="flex items-center justify-between pb-2">
            <span className="text-xs font-medium text-muted-foreground">Policy Review</span>
            <ShieldAlert className="h-4 w-4 text-amber-500" />
          </div>
          <div className="text-2xl sm:text-3xl font-black text-amber-600 dark:text-amber-400">
            {warning}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">Requires supervisor audit</p>
        </Card>

        <Card className="p-4 border shadow-sm">
          <div className="flex items-center justify-between pb-2">
            <span className="text-xs font-medium text-muted-foreground">Controlled Disposal</span>
            <ShieldX className="h-4 w-4 text-destructive" />
          </div>
          <div className="text-2xl sm:text-3xl font-black text-destructive">
            {failed}
          </div>
          <p className="text-[11px] text-muted-foreground mt-1">Non-sanitizable hardware</p>
        </Card>
      </div>

      {/* Quick Launchers */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="hover:border-primary/50 transition duration-200">
          <CardHeader className="p-4 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-bold">Secure Wiper</CardTitle>
            <div className="h-8 w-8 rounded-lg bg-destructive/10 text-destructive flex items-center justify-center">
              <Trash2 className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">
              Execute NIST SP 800-88 Purge, DoD 5220.22-M, and IEEE 2883 standards.
            </p>
            <Button size="sm" variant="outline" className="w-full text-xs" asChild>
              <Link href="/wipe">Launch Wiper</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition duration-200">
          <CardHeader className="p-4 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-bold">FARIS Recovery</CardTitle>
            <div className="h-8 w-8 rounded-lg bg-emerald-500/10 text-emerald-600 flex items-center justify-center">
              <Search className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">
              Deep forensic residual signature analysis &amp; multi-engine verification.
            </p>
            <Button size="sm" variant="outline" className="w-full text-xs" asChild>
              <Link href="/faris">Launch FARIS</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition duration-200">
          <CardHeader className="p-4 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-bold">Storage Inspector</CardTitle>
            <div className="h-8 w-8 rounded-lg bg-cyan-500/10 text-cyan-600 flex items-center justify-center">
              <Eye className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">
              Read-only sector preview, raw hex dump, and partition structure inspection.
            </p>
            <Button size="sm" variant="outline" className="w-full text-xs" asChild>
              <Link href="/inspector">Open Inspector</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition duration-200">
          <CardHeader className="p-4 pb-2 flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-bold">Audit &amp; Certificates</CardTitle>
            <div className="h-8 w-8 rounded-lg bg-amber-500/10 text-amber-600 flex items-center justify-center">
              <History className="h-4 w-4" />
            </div>
          </CardHeader>
          <CardContent className="p-4 pt-0 space-y-3">
            <p className="text-xs text-muted-foreground">
              Tamper-evident logs and asymmetric RSA-PSS digitally signed certificates.
            </p>
            <Button size="sm" variant="outline" className="w-full text-xs" asChild>
              <Link href="/history">View Audit Log</Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Main Grid: Workstation Status + Storage Devices */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-3">
        {/* Workstation & Node Status */}
        <Card className="border">
          <CardHeader className="p-5 pb-3">
            <CardTitle className="flex items-center gap-2 text-base font-bold">
              <Server className="h-4 w-4 text-primary" />
              Workstation &amp; Node Status
            </CardTitle>
          </CardHeader>
          <CardContent className="p-5 pt-0 space-y-4">
            {systemStatus ? (
              <>
                <div className="flex items-center gap-2.5 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-xs font-bold text-emerald-700 dark:text-emerald-300">
                    {systemStatus.status || "Operational & Ready"}
                  </span>
                </div>
                <div className="space-y-2.5 text-xs">
                  <div className="flex justify-between border-b pb-1.5">
                    <span className="text-muted-foreground">Hostname</span>
                    <span className="font-mono font-semibold">{systemStatus.hostname}</span>
                  </div>
                  <div className="flex justify-between border-b pb-1.5">
                    <span className="text-muted-foreground">Platform / OS</span>
                    <span className="font-medium">{systemStatus.os}</span>
                  </div>
                  <div className="flex justify-between border-b pb-1.5">
                    <span className="text-muted-foreground">Framework Version</span>
                    <span className="font-mono font-semibold">Enterprise Edition v2.0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">System Clock</span>
                    <span className="font-mono text-muted-foreground">{systemStatus.timestamp}</span>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-muted-foreground text-xs py-4">System status loading...</p>
            )}
          </CardContent>
        </Card>

        {/* Detected Storage Devices */}
        <Card className="lg:col-span-2 border">
          <CardHeader className="p-5 pb-3 flex flex-row items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive className="h-4 w-4 text-primary" />
              <CardTitle className="text-base font-bold">Detected Storage Devices</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-semibold">
              {devices.length} Connected
            </Badge>
          </CardHeader>
          <CardContent className="p-5 pt-0">
            {devices.length === 0 ? (
              <div className="text-center py-8 text-muted-foreground text-xs space-y-1">
                <HardDrive className="h-8 w-8 mx-auto text-muted-foreground/50 mb-2" />
                <p className="font-medium">No external storage devices detected.</p>
                <p className="text-[11px]">Connect a USB drive, SSD, or external storage device to begin.</p>
              </div>
            ) : (
              <div className="space-y-2.5 max-h-[260px] overflow-y-auto pr-1">
                {devices.map((dev) => (
                  <div
                    key={dev.name}
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-3 rounded-lg border bg-muted/20 gap-3"
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      {dev.type === "USB" ? (
                        <Usb className="h-5 w-5 text-primary shrink-0" />
                      ) : dev.type === "SSD" ? (
                        <Cpu className="h-5 w-5 text-primary shrink-0" />
                      ) : (
                        <HardDrive className="h-5 w-5 text-primary shrink-0" />
                      )}
                      <div className="min-w-0">
                        <p className="font-semibold text-xs truncate">{dev.friendlyName || dev.name}</p>
                        <p className="text-[11px] text-muted-foreground truncate">
                          {dev.size} · {dev.type} {dev.serial ? `· SN: ${dev.serial}` : ""}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                      {dev.isSystem && (
                        <Badge variant="destructive" className="text-[10px]">
                          OS Boot Disk
                        </Badge>
                      )}
                      <Button size="sm" variant="outline" className="h-7 text-xs" asChild>
                        <Link href={`/wipe?device=${encodeURIComponent(dev.name)}`}>Sanitize</Link>
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Recent Sanitization Audit Log */}
      <Card className="border">
        <CardHeader className="p-5 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base font-bold">
              <History className="h-4 w-4 text-primary" />
              Recent Sanitization Sessions
            </CardTitle>
            <CardDescription className="text-xs">
              Audit log of completed sanitization passes and forensic residual checks.
            </CardDescription>
          </div>
          <Button size="sm" variant="ghost" className="text-xs h-8 gap-1" asChild>
            <Link href="/history">
              View All <ArrowRight className="h-3 w-3" />
            </Link>
          </Button>
        </CardHeader>
        <CardContent className="p-0">
          {!stats?.recentWipes || stats.recentWipes.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground text-xs">
              No recent sanitization sessions recorded.
            </div>
          ) : (
            <div className="w-full overflow-x-auto">
              <table className="w-full text-xs min-w-[620px]">
                <thead>
                  <tr className="border-b bg-muted/40 text-muted-foreground">
                    <th className="text-left p-3 font-semibold">Session ID</th>
                    <th className="text-left p-3 font-semibold">Target Drive</th>
                    <th className="text-left p-3 font-semibold">Sanitization Standard</th>
                    <th className="text-left p-3 font-semibold">Assurance State</th>
                    <th className="text-left p-3 font-semibold">Timestamp</th>
                    <th className="text-right p-3 font-semibold">Report</th>
                  </tr>
                </thead>
                <tbody className="divide-y">
                  {stats.recentWipes.map((w) => (
                    <tr key={w.id} className="hover:bg-muted/30 transition">
                      <td className="p-3 font-mono font-bold text-primary">{w.id}</td>
                      <td className="p-3 font-medium truncate max-w-[160px]">{w.device}</td>
                      <td className="p-3 text-muted-foreground">{w.standard || w.method}</td>
                      <td className="p-3">
                        {w.finalState === "SANITIZED_AND_REUSABLE" || w.status === "Completed" ? (
                          <Badge className="bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border-emerald-200 text-[10px]">
                            ✓ Reusable
                          </Badge>
                        ) : w.finalState === "SANITIZATION_NOT_VERIFIABLE" || w.status === "Warning" ? (
                          <Badge variant="outline" className="bg-amber-50 text-amber-800 dark:bg-amber-950 dark:text-amber-300 border-amber-300 text-[10px]">
                            ⚠ Review Required
                          </Badge>
                        ) : (
                          <Badge variant="destructive" className="text-[10px]">
                            ✕ Disposal
                          </Badge>
                        )}
                      </td>
                      <td className="p-3 text-muted-foreground">{w.endTime || w.startTime}</td>
                      <td className="p-3 text-right">
                        <Link href={`/report/${w.id}`}>
                          <Button size="sm" variant="outline" className="h-7 text-[11px] px-2.5">
                            Certificate
                          </Button>
                        </Link>
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
  );
}

