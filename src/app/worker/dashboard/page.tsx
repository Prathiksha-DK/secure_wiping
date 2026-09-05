"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import {
  HardDrive,
  Smartphone,
  Usb,
  Database,
  Shield,
  Activity,
  FileClock,
  PlusCircle,
  CheckCircle,
  XCircle,
  Clock,
  ServerCrash,
  ShieldCheck,
  ArrowRight,
  BarChart3,
  Loader2,
  Search,
  Eye,
  Gamepad2,
  Disc3,
  ShieldAlert
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";

const API_BASE = "http://localhost:9758";

const deviceIcons: { [key: string]: React.ElementType } = {
  SSD: HardDrive,
  HDD: Database,
  USB: Usb,
  "USB Drive": Usb,
  NVMe: HardDrive,
  Unspecified: HardDrive,
  "Android Storage": Smartphone,
};

type Device = {
  name: string;
  type: string;
  size: string;
  health: number;
  healthStatus: string;
};

type Stats = {
  totalWipes: number;
  completed: number;
  failed: number;
  inProgress: number;
  totalDevices: number;
  complianceRate: number;
  standardsBreakdown: { [key: string]: number };
  recentWipes: any[];
};

export default function WorkerDashboardPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAll() {
      setLoading(true);
      try {
        const [devRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/api/devices`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/stats`, { cache: "no-store" }).catch(() => null),
        ]);

        if (devRes?.ok) {
          const devData = await devRes.json();
          setDevices(devData);
        }
        if (statsRes?.ok) {
          const statsData = await statsRes.json();
          setStats(statsData);
        }
      } catch (e) {
        console.error("Failed to fetch dashboard data:", e);
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
          <p className="text-xs text-muted-foreground">Loading operator dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 w-full min-w-0 max-w-full animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Badge variant="outline" className="text-primary border-primary/30 bg-primary/5 text-xs font-semibold">
              Operator Station
            </Badge>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">Operator Dashboard</h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-0.5">
            Enterprise data sanitization overview &amp; real-time hardware status.
          </p>
        </div>
        <Button asChild size="sm" className="gap-1.5 shadow-sm bg-primary self-start sm:self-auto">
          <Link href="/worker/wipe">
            <Shield className="h-4 w-4" /> Start Sanitization
          </Link>
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 grid-cols-2 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4 border shadow-sm space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-medium">
            <span>Total Sanitizations</span>
            <BarChart3 className="h-4 w-4 text-primary" />
          </div>
          <div className="text-2xl sm:text-3xl font-black">{stats?.totalWipes || 0}</div>
          <p className="text-[11px] text-muted-foreground">Recorded sessions</p>
        </Card>

        <Card className="p-4 border shadow-sm space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-medium">
            <span>Verified Passes</span>
            <CheckCircle className="h-4 w-4 text-emerald-500" />
          </div>
          <div className="text-2xl sm:text-3xl font-black text-emerald-600 dark:text-emerald-400">
            {stats?.completed || 0}
          </div>
          <p className="text-[11px] text-muted-foreground">100% Zero residual</p>
        </Card>

        <Card className="p-4 border shadow-sm space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-medium">
            <span>Needs Attention</span>
            <XCircle className="h-4 w-4 text-red-500" />
          </div>
          <div className="text-2xl sm:text-3xl font-black text-red-600 dark:text-red-400">
            {stats?.failed || 0}
          </div>
          <p className="text-[11px] text-muted-foreground">Verification flags</p>
        </Card>

        <Card className="p-4 border shadow-sm space-y-1">
          <div className="flex items-center justify-between text-muted-foreground text-xs font-medium">
            <span>Compliance Rate</span>
            <ShieldCheck className="h-4 w-4 text-primary" />
          </div>
          <div className="text-2xl sm:text-3xl font-black">{stats?.complianceRate || 0}%</div>
          <Progress value={stats?.complianceRate || 0} className="mt-1 h-1.5" />
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-3">
        {/* Devices Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Connected Devices */}
          <Card className="border">
            <CardHeader className="p-5 pb-3 flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-primary" />
                <CardTitle className="text-base font-bold">Connected Devices</CardTitle>
              </div>
              <Badge variant="outline" className="text-xs">
                {devices.length} Detected
              </Badge>
            </CardHeader>
            <CardContent className="p-5 pt-0">
              {devices.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground text-xs space-y-1">
                  <ServerCrash className="h-8 w-8 mx-auto opacity-50 mb-2" />
                  <p className="font-medium">No external devices detected.</p>
                  <p className="text-[11px]">Connect a storage device to begin sanitization.</p>
                </div>
              ) : (
                <div className="grid gap-3 grid-cols-1 sm:grid-cols-2">
                  {devices.map((device) => {
                    const Icon = deviceIcons[device.type] || HardDrive;
                    const healthColor =
                      device.health > 80
                        ? "text-emerald-500"
                        : device.health > 50
                        ? "text-amber-500"
                        : "text-red-500";
                    return (
                      <div
                        key={device.name}
                        className="flex flex-col rounded-lg border p-3.5 transition-all hover:border-primary/40 hover:shadow-sm bg-card"
                      >
                        <div className="flex items-start justify-between mb-2 gap-2">
                          <div className="flex items-center gap-2.5 min-w-0">
                            <div className="p-2 rounded-lg bg-primary/10 shrink-0">
                              <Icon className="h-4 w-4 text-primary" />
                            </div>
                            <div className="min-w-0">
                              <p className="font-bold text-xs truncate">{device.name}</p>
                              <p className="text-[11px] text-muted-foreground truncate">
                                {device.type} — {device.size}
                              </p>
                            </div>
                          </div>
                          <Badge
                            variant="outline"
                            className={`text-[10px] shrink-0 ${healthColor}`}
                          >
                            {device.healthStatus}
                          </Badge>
                        </div>
                        <div className="space-y-1 mb-3">
                          <div className="flex justify-between text-[11px] text-muted-foreground">
                            <span>Health</span>
                            <span className={`font-mono font-semibold ${healthColor}`}>
                              {device.health}%
                            </span>
                          </div>
                          <Progress
                            value={device.health}
                            className="h-1"
                          />
                        </div>
                        <div className="flex gap-2 mt-auto pt-1">
                          <Button
                            variant="outline"
                            size="sm"
                            className="flex-1 text-[11px] h-7"
                            asChild
                          >
                            <Link href={`/worker/history?device=${device.name}`}>
                              <FileClock className="mr-1 h-3 w-3" /> History
                            </Link>
                          </Button>
                          <Button
                            size="sm"
                            className="flex-1 text-[11px] h-7 bg-primary"
                            asChild
                          >
                            <Link href={`/worker/wipe?device=${device.name}`}>
                              <Shield className="mr-1 h-3 w-3" /> Wipe
                            </Link>
                          </Button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Recent Wipe Activity */}
          <Card className="border">
            <CardHeader className="p-5 pb-3 flex flex-row items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                <CardTitle className="text-base font-bold">Recent Wipe Activity</CardTitle>
              </div>
              <Button variant="ghost" size="sm" className="h-8 text-xs gap-1" asChild>
                <Link href="/worker/history">
                  View All <ArrowRight className="h-3 w-3" />
                </Link>
              </Button>
            </CardHeader>
            <CardContent className="p-5 pt-0">
              {!stats?.recentWipes || stats.recentWipes.length === 0 ? (
                <p className="text-muted-foreground text-center py-6 text-xs">No wipe activity recorded yet.</p>
              ) : (
                <div className="space-y-2">
                  {stats.recentWipes.slice(0, 4).map((wipe: any) => (
                    <div
                      key={wipe.id}
                      className="flex items-center justify-between rounded-lg border p-3 transition-colors hover:bg-muted/40 gap-3"
                    >
                      <div className="flex items-center gap-3 min-w-0">
                        <div className={`p-1.5 rounded-full shrink-0 ${wipe.status === 'Completed' ? 'bg-emerald-500/10 text-emerald-500' : wipe.status === 'Failed' ? 'bg-red-500/10 text-red-500' : 'bg-amber-500/10 text-amber-500'}`}>
                          {wipe.status === "Completed" ? (
                            <CheckCircle className="h-3.5 w-3.5" />
                          ) : wipe.status === "Failed" ? (
                            <XCircle className="h-3.5 w-3.5" />
                          ) : (
                            <Clock className="h-3.5 w-3.5" />
                          )}
                        </div>
                        <div className="min-w-0">
                          <p className="font-semibold text-xs truncate">{wipe.device}</p>
                          <p className="text-[11px] text-muted-foreground truncate">{wipe.standard}</p>
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <Badge
                          variant={wipe.status === "Completed" ? "default" : wipe.status === "Failed" ? "destructive" : "secondary"}
                          className={wipe.status === "Completed" ? "bg-emerald-600 text-[10px]" : "text-[10px]"}
                        >
                          {wipe.status}
                        </Badge>
                        <p className="text-[10px] text-muted-foreground mt-0.5">{wipe.endTime || wipe.startTime}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Platform Status & Quick Tools */}
        <div className="space-y-6">
          {/* Sanitization Assurance Platform */}
          <Card className="border">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="flex items-center gap-2 text-base font-bold">
                <ShieldCheck className="h-4 w-4 text-primary" />
                Sanitization Assurance
              </CardTitle>
            </CardHeader>
            <CardContent className="p-5 pt-0 space-y-3.5">
              <div className="flex items-center gap-2.5 p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                <span className="text-xs font-bold text-emerald-700 dark:text-emerald-300">
                  Engine Active &amp; Ready
                </span>
              </div>
              <Separator />
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Framework</span>
                  <span className="font-mono font-semibold">Adaptive ASF v2.0</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Standards</span>
                  <span className="font-medium">NIST 800-88 / DoD 5220</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Verification</span>
                  <span className="font-medium">Forensic Carving Scan</span>
                </div>
              </div>
              <Button size="sm" className="w-full text-xs h-8" asChild>
                <Link href="/worker/wipe">
                  <Shield className="mr-1.5 h-3.5 w-3.5" />
                  Launch Wiper
                </Link>
              </Button>
            </CardContent>
          </Card>

          {/* Standards Breakdown */}
          <Card className="border">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-base font-bold">Standards Utilization</CardTitle>
            </CardHeader>
            <CardContent className="p-5 pt-0">
              {stats?.standardsBreakdown && Object.keys(stats.standardsBreakdown).length > 0 ? (
                <div className="space-y-2.5">
                  {Object.entries(stats.standardsBreakdown).map(([standard, count]) => (
                    <div key={standard} className="space-y-1">
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground truncate mr-2">{standard}</span>
                        <span className="font-mono font-semibold">{count}</span>
                      </div>
                      <Progress
                        value={(count / Math.max(stats.totalWipes, 1)) * 100}
                        className="h-1"
                      />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground text-xs text-center py-4">No operations recorded yet.</p>
              )}
            </CardContent>
          </Card>

          {/* Quick Tool Navigation */}
          <Card className="border">
            <CardHeader className="p-5 pb-3">
              <CardTitle className="text-base font-bold">Quick Tools</CardTitle>
            </CardHeader>
            <CardContent className="p-5 pt-0 grid gap-2">
              <Button variant="outline" size="sm" className="justify-start text-xs h-8.5" asChild>
                <Link href="/worker/wipe">
                  <Shield className="mr-2 h-3.5 w-3.5 text-primary" /> New Wipe Operation
                </Link>
              </Button>
              <Button variant="outline" size="sm" className="justify-start text-xs h-8.5" asChild>
                <Link href="/faris">
                  <Search className="mr-2 h-3.5 w-3.5 text-emerald-500" /> FARIS Recovery Scan
                </Link>
              </Button>
              <Button variant="outline" size="sm" className="justify-start text-xs h-8.5" asChild>
                <Link href="/inspector">
                  <Eye className="mr-2 h-3.5 w-3.5 text-cyan-500" /> Storage Inspector (Hex)
                </Link>
              </Button>
              <Button variant="outline" size="sm" className="justify-start text-xs h-8.5" asChild>
                <Link href="/swarm">
                  <Gamepad2 className="mr-2 h-3.5 w-3.5 text-purple-500" /> Fragment Hunter (Swarm)
                </Link>
              </Button>
              <Button variant="outline" size="sm" className="justify-start text-xs h-8.5" asChild>
                <Link href="/worker/history">
                  <FileClock className="mr-2 h-3.5 w-3.5 text-amber-500" /> View History &amp; Reports
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

