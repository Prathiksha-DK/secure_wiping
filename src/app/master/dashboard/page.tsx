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
  Gamepad2,
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
        <Loader2 className="h-10 w-10 animate-spin text-primary" />
      </div>
    );
  }

  const totalWipes = stats?.totalWipes || 0;
  const completed = stats?.completed || 0;
  const warning = stats?.warning || 0;
  const failed = stats?.failed || 0;
  const complianceRate = stats?.complianceRate ?? (totalWipes > 0 ? Math.round((completed / totalWipes) * 100) : 100);

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Sanitization Operations Dashboard</h1>
        <p className="text-muted-foreground">
          Adaptive Sanitization & Forensic Recovery Verification Platform
        </p>
      </div>

      {/* Quick Launchers */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Adaptive Wiper</CardTitle>
            <Trash2 className="h-5 w-5 text-destructive" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">Sanitize files, folders, or physical drives with DoD/NIST protocols.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/wipe">Launch Wiper</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Connected Storage</CardTitle>
            <HardDrive className="h-5 w-5 text-primary" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">Inspect detected block devices, SSDs, HDDs, and USBs.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/dashboard">View Devices ({devices.length})</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">FARIS Recovery</CardTitle>
            <Search className="h-5 w-5 text-emerald-500" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">Perform forensic residual analysis and data reconstruction.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/faris">Launch FARIS</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Audit Certificates</CardTitle>
            <History className="h-5 w-5 text-amber-500" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">View verified certificates with tamper-evident hashes.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/history">View Audit Log</Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Assurance State Stats */}
      <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="glow-primary">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Operations</CardTitle>
            <Activity className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalWipes}</div>
            <p className="text-xs text-muted-foreground mt-1">Audit sessions recorded</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Reusable (Passed)</CardTitle>
            <ShieldCheck className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-emerald-500">{completed}</div>
            <p className="text-xs text-muted-foreground mt-1">Verified & reusable</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Policy Review</CardTitle>
            <ShieldAlert className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-500">{warning}</div>
            <p className="text-xs text-muted-foreground mt-1">NAND / not verifiable</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Controlled Disposal</CardTitle>
            <ShieldX className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-destructive">{failed}</div>
            <p className="text-xs text-muted-foreground mt-1">Non-sanitizable</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 grid-cols-1 lg:grid-cols-3">
        {/* Host Station Information */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Server className="h-5 w-5 text-primary" />
              Workstation & Node Status
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {systemStatus ? (
              <>
                <div className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full bg-emerald-500 status-online" />
                  <span className="font-semibold">{systemStatus.status}</span>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Hostname</span>
                    <span className="font-mono text-xs font-semibold">{systemStatus.hostname}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Platform / OS</span>
                    <span className="text-xs">{systemStatus.os}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Framework Version</span>
                    <span className="text-xs font-mono">v1.0.0 (NTRO/Govt)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">System Clock</span>
                    <span className="text-xs font-mono">{systemStatus.timestamp}</span>
                  </div>
                </div>
              </>
            ) : (
              <p className="text-muted-foreground text-sm">System status loading...</p>
            )}
          </CardContent>
        </Card>

        {/* Detected Storage Devices */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-base">
              <div className="flex items-center gap-2">
                <HardDrive className="h-5 w-5 text-primary" />
                Detected Storage Devices
              </div>
              <Badge variant="outline">{devices.length} Connected</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {devices.length === 0 ? (
              <div className="text-center py-6 text-muted-foreground text-sm">
                No external storage devices detected.
              </div>
            ) : (
              <div className="space-y-3">
                {devices.map((dev) => (
                  <div key={dev.name} className="flex items-center justify-between p-3 rounded-lg border bg-muted/20">
                    <div className="flex items-center gap-3">
                      {dev.type === "USB" ? (
                        <Usb className="h-5 w-5 text-primary flex-shrink-0" />
                      ) : dev.type === "SSD" ? (
                        <Cpu className="h-5 w-5 text-primary flex-shrink-0" />
                      ) : (
                        <HardDrive className="h-5 w-5 text-primary flex-shrink-0" />
                      )}
                      <div>
                        <p className="font-semibold text-sm">{dev.friendlyName || dev.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {dev.size} · {dev.type} {dev.serial ? `· SN: ${dev.serial}` : ""}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {dev.isSystem && (
                        <Badge variant="destructive" className="text-[10px]">
                          OS Boot Disk
                        </Badge>
                      )}
                      <Button size="sm" variant="outline" asChild>
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
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <History className="h-5 w-5 text-primary" />
              Recent Sanitization Sessions
            </div>
            <Button size="sm" variant="ghost" asChild>
              <Link href="/history">View All</Link>
            </Button>
          </CardTitle>
          <CardDescription>
            Audit log of completed sanitization passes and recovery assessments.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!stats?.recentWipes || stats.recentWipes.length === 0 ? (
            <div className="text-center py-6 text-muted-foreground text-sm">
              No recent sanitization sessions recorded.
            </div>
          ) : (
            <div className="rounded-lg border overflow-x-auto min-w-0">
              <table className="w-full text-sm min-w-[600px]">
                <thead>
                  <tr className="bg-muted/50 text-xs">
                    <th className="text-left p-3 font-medium">Session ID</th>
                    <th className="text-left p-3 font-medium">Target</th>
                    <th className="text-left p-3 font-medium">Standard / Method</th>
                    <th className="text-left p-3 font-medium">Assurance State</th>
                    <th className="text-left p-3 font-medium">Timestamp</th>
                    <th className="text-right p-3 font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recentWipes.map((w) => (
                    <tr key={w.id} className="border-t hover:bg-muted/30">
                      <td className="p-3 font-mono font-semibold text-primary text-xs">{w.id}</td>
                      <td className="p-3 font-medium text-xs truncate max-w-[180px]">{w.device}</td>
                      <td className="p-3 text-xs text-muted-foreground">{w.standard || w.method}</td>
                      <td className="p-3 text-xs">
                        {w.finalState === "SANITIZED_AND_REUSABLE" || w.status === "Completed" ? (
                          <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border-green-300">
                            🟢 Reusable
                          </Badge>
                        ) : w.finalState === "SANITIZATION_NOT_VERIFIABLE" || w.status === "Warning" ? (
                          <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-300">
                            🟡 Review Required
                          </Badge>
                        ) : (
                          <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-300">
                            🔴 Disposal
                          </Badge>
                        )}
                      </td>
                      <td className="p-3 text-xs text-muted-foreground">{w.endTime || w.startTime}</td>
                      <td className="p-3 text-right">
                        <Button size="sm" variant="ghost" asChild>
                          <Link href={`/report/${w.id}`}>Certificate</Link>
                        </Button>
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
