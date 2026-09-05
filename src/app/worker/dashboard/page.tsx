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
  TrendingUp,
  ServerCrash,
  ShieldCheck,
  Network,
  MonitorDot,
  ArrowRight,
  BarChart3,
  Loader2,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
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

export default function DashboardPage() {
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
        <div className="flex flex-col items-center gap-4">
          <Loader2 className="h-10 w-10 animate-spin text-primary" />
          <p className="text-muted-foreground text-lg">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">
            Enterprise data sanitization overview & compliance monitoring.
          </p>
        </div>
        <Button asChild>
          <Link href="/worker/wipe">
            <Shield className="mr-2 h-4 w-4" /> Start Wipe
          </Link>
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
        <Card className="glow-primary">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Wipes</CardTitle>
            <BarChart3 className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.totalWipes || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">All time operations</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Completed</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-emerald-500">{stats?.completed || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Successfully verified</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Failed</CardTitle>
            <XCircle className="h-4 w-4 text-red-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-red-500">{stats?.failed || 0}</div>
            <p className="text-xs text-muted-foreground mt-1">Requires attention</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Compliance</CardTitle>
            <ShieldCheck className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{stats?.complianceRate || 0}%</div>
            <Progress value={stats?.complianceRate || 0} className="mt-2 h-1.5" />
          </CardContent>
        </Card>
      </div>

      {/* Main Content Grid */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Devices Column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Connected Devices */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <HardDrive className="h-5 w-5 text-primary" />
                    Connected Devices
                  </CardTitle>
                  <CardDescription>
                    {devices.length} device{devices.length !== 1 ? "s" : ""} detected on this system.
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {devices.length === 0 ? (
                <div className="text-center py-10 text-muted-foreground">
                  <ServerCrash className="h-12 w-12 mx-auto mb-3 opacity-50" />
                  <p>No devices detected. Connect a storage device to begin.</p>
                </div>
              ) : (
                <div className="grid gap-4 md:grid-cols-2">
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
                        className="group flex flex-col rounded-lg border p-4 transition-all hover:border-primary/50 hover:shadow-md"
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center gap-3">
                            <div className="p-2 rounded-lg bg-primary/10">
                              <Icon className="h-5 w-5 text-primary" />
                            </div>
                            <div>
                              <p className="font-semibold text-sm">{device.name}</p>
                              <p className="text-xs text-muted-foreground">
                                {device.type} — {device.size}
                              </p>
                            </div>
                          </div>
                          <Badge
                            variant="outline"
                            className={`text-xs ${healthColor}`}
                          >
                            {device.healthStatus}
                          </Badge>
                        </div>
                        <div className="space-y-1 mb-3">
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>Health</span>
                            <span className={`font-mono font-semibold ${healthColor}`}>
                              {device.health}%
                            </span>
                          </div>
                          <Progress
                            value={device.health}
                            className="h-1.5"
                          />
                        </div>
                        <div className="flex gap-2 mt-auto">
                          <Button
                            variant="outline"
                            size="sm"
                            className="flex-1 text-xs"
                            asChild
                          >
                            <Link href={`/worker/history?device=${device.name}`}>
                              <FileClock className="mr-1 h-3 w-3" /> History
                            </Link>
                          </Button>
                          <Button
                            size="sm"
                            className="flex-1 text-xs"
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
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-primary" />
                  Recent Wipe Activity
                </CardTitle>
                <Button variant="ghost" size="sm" asChild>
                  <Link href="/worker/history">
                    View All <ArrowRight className="ml-1 h-3 w-3" />
                  </Link>
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              {!stats?.recentWipes || stats.recentWipes.length === 0 ? (
                <p className="text-muted-foreground text-center py-6">No wipe activity yet.</p>
              ) : (
                <div className="space-y-3">
                  {stats.recentWipes.slice(0, 5).map((wipe: any) => (
                    <div
                      key={wipe.id}
                      className="flex items-center justify-between rounded-lg border p-3 transition-colors hover:bg-muted/50"
                    >
                      <div className="flex items-center gap-3">
                        <div className={`p-1.5 rounded-full ${wipe.status === 'Completed' ? 'bg-emerald-500/10' : wipe.status === 'Failed' ? 'bg-red-500/10' : 'bg-amber-500/10'}`}>
                          {wipe.status === "Completed" ? (
                            <CheckCircle className="h-4 w-4 text-emerald-500" />
                          ) : wipe.status === "Failed" ? (
                            <XCircle className="h-4 w-4 text-red-500" />
                          ) : (
                            <Clock className="h-4 w-4 text-amber-500" />
                          )}
                        </div>
                        <div>
                          <p className="font-medium text-sm">{wipe.device}</p>
                          <p className="text-xs text-muted-foreground">{wipe.standard}</p>
                        </div>
                      </div>
                      <div className="text-right">
                        <Badge
                          variant={wipe.status === "Completed" ? "default" : wipe.status === "Failed" ? "destructive" : "secondary"}
                          className={wipe.status === "Completed" ? "bg-emerald-600 hover:bg-emerald-700" : ""}
                        >
                          {wipe.status}
                        </Badge>
                        <p className="text-xs text-muted-foreground mt-1">{wipe.endTime || wipe.startTime}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Sidebar */}
        <div className="space-y-6">
          {/* Sanitization Assurance Platform */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldCheck className="h-5 w-5 text-primary" />
                Sanitization Assurance
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500 status-online" />
                <span className="text-sm font-medium">Engine Active & Ready</span>
              </div>
              <Separator />
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Framework</span>
                  <span className="font-mono text-xs font-semibold">Adaptive ASF</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Standards</span>
                  <span className="text-xs">DoD 5220 / NIST 800-88</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Verification</span>
                  <span className="text-xs">Forensic Recovery Scan</span>
                </div>
              </div>
              <Button variant="outline" size="sm" className="w-full" asChild>
                <Link href="/worker/wipe">
                  <Shield className="mr-2 h-3 w-3" />
                  Launch Wiper
                </Link>
              </Button>
            </CardContent>
          </Card>

          {/* Compliance Standards */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <ShieldCheck className="h-5 w-5 text-primary" />
                Standards Used
              </CardTitle>
            </CardHeader>
            <CardContent>
              {stats?.standardsBreakdown && Object.keys(stats.standardsBreakdown).length > 0 ? (
                <div className="space-y-3">
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
                <p className="text-muted-foreground text-sm text-center py-4">No data yet.</p>
              )}
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-2">
              <Button variant="outline" size="sm" className="justify-start" asChild>
                <Link href="/worker/wipe">
                  <Shield className="mr-2 h-4 w-4 text-primary" /> New Wipe Operation
                </Link>
              </Button>
              <Button variant="outline" size="sm" className="justify-start" asChild>
                <Link href="/worker/history">
                  <FileClock className="mr-2 h-4 w-4 text-emerald-500" /> View History & Reports
                </Link>
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
