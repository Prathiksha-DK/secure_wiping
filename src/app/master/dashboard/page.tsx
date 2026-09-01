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
  Network,
  Monitor,
  ShieldCheck,
  AlertTriangle,
  Server,
  Laptop,
  HardDrive,
  BarChart3,
  CheckCircle,
  XCircle,
  Loader2,
  Building2,
  Trash2,
  Undo,
  History,
} from "lucide-react";

const API_BASE = "http://localhost:9758";

type ADComputer = {
  name: string;
  ou: string;
  os: string;
  lastLogon: string;
  status: string;
  ipAddress: string;
  assignedUser: string;
};

type ADOU = {
  dn: string;
  name: string;
  computerCount: number;
  compliant: number;
  pendingWipe: number;
};

type ADStatus = {
  connected: boolean;
  domain: string;
  domainController: string;
  forestLevel: string;
  siteName: string;
  lastSync: string;
};

type Stats = {
  totalWipes: number;
  completed: number;
  failed: number;
  complianceRate: number;
};

export default function MasterDashboardPage() {
  const [adStatus, setAdStatus] = useState<ADStatus | null>(null);
  const [computers, setComputers] = useState<ADComputer[]>([]);
  const [ous, setOus] = useState<ADOU[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchAll() {
      setLoading(true);
      try {
        const [adRes, compRes, ouRes, statsRes] = await Promise.all([
          fetch(`${API_BASE}/api/ad/status`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/ad/computers`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/ad/ous`, { cache: "no-store" }).catch(() => null),
          fetch(`${API_BASE}/api/stats`, { cache: "no-store" }).catch(() => null),
        ]);
        if (adRes?.ok) setAdStatus(await adRes.json());
        if (compRes?.ok) setComputers(await compRes.json());
        if (ouRes?.ok) setOus(await ouRes.json());
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

  const totalComputers = ous.reduce((a, o) => a + o.computerCount, 0);
  const totalCompliant = ous.reduce((a, o) => a + o.compliant, 0);
  const totalPending = ous.reduce((a, o) => a + o.pendingWipe, 0);

  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Master Control Panel</h1>
        <p className="text-muted-foreground">
          Enterprise-wide data sanitization management with Active Directory integration.
        </p>
      </div>

      {/* Quick Actions / Local Device Management */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Local Devices</CardTitle>
            <HardDrive className="h-5 w-5 text-primary" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">View status of all connected drives.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/dashboard">Open Device List</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Secure Wipe</CardTitle>
            <Trash2 className="h-5 w-5 text-destructive" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">Sanitize connected logical & physical disks.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/wipe">Launch Wiper</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Decrypt & Restore</CardTitle>
            <Undo className="h-5 w-5 text-emerald-500" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">Recover or decrypt device data from backup.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/restore">Launch Restore</Link>
            </Button>
          </CardContent>
        </Card>

        <Card className="hover:border-primary/50 transition-all">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-semibold">Sanitization History</CardTitle>
            <History className="h-5 w-5 text-amber-500" />
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-xs text-muted-foreground">View complete audit trails and wipe certificates.</p>
            <Button size="sm" className="w-full mt-2" asChild>
              <Link href="/history">View Logs & Reports</Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Stats Row */}
      <div className="grid gap-4 grid-cols-2 lg:grid-cols-4">
        <Card className="glow-primary">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">AD Computers</CardTitle>
            <Monitor className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{totalComputers}</div>
            <p className="text-xs text-muted-foreground mt-1">Managed devices</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Compliant</CardTitle>
            <CheckCircle className="h-4 w-4 text-emerald-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-emerald-500">{totalCompliant}</div>
            <p className="text-xs text-muted-foreground mt-1">Wiped & verified</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Pending Wipe</CardTitle>
            <AlertTriangle className="h-4 w-4 text-amber-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-amber-500">{totalPending}</div>
            <p className="text-xs text-muted-foreground mt-1">Awaiting sanitization</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Compliance Rate</CardTitle>
            <BarChart3 className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {totalComputers > 0 ? Math.round((totalCompliant / totalComputers) * 100) : 0}%
            </div>
            <Progress value={totalComputers > 0 ? (totalCompliant / totalComputers) * 100 : 0} className="mt-2 h-1.5" />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* AD Connection */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-5 w-5 text-primary" />
              Active Directory
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {adStatus ? (
              <>
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${adStatus.connected ? 'bg-emerald-500 status-online' : 'bg-red-500'}`} />
                  <span className="font-semibold">{adStatus.connected ? "Connected" : "Disconnected"}</span>
                </div>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between"><span className="text-muted-foreground">Domain</span><span className="font-mono text-xs">{adStatus.domain}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">DC</span><span className="font-mono text-xs">{adStatus.domainController}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Forest Level</span><span className="text-xs">{adStatus.forestLevel}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Site</span><span className="text-xs">{adStatus.siteName}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Last Sync</span><span className="text-xs">{adStatus.lastSync}</span></div>
                </div>
              </>
            ) : (
              <p className="text-muted-foreground">AD service unavailable.</p>
            )}
          </CardContent>
        </Card>

        {/* Organizational Units */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Building2 className="h-5 w-5 text-primary" />
              Organizational Units — Compliance
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {ous.map((ou) => {
                const compliance = ou.computerCount > 0 ? Math.round((ou.compliant / ou.computerCount) * 100) : 0;
                return (
                  <div key={ou.dn} className="space-y-2 p-3 rounded-lg border">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-semibold text-sm">{ou.name}</p>
                        <p className="text-xs text-muted-foreground font-mono">{ou.dn}</p>
                      </div>
                      <div className="text-right">
                        <Badge variant={compliance === 100 ? "default" : compliance > 50 ? "secondary" : "destructive"}
                          className={compliance === 100 ? "bg-emerald-600" : ""}
                        >
                          {compliance}%
                        </Badge>
                      </div>
                    </div>
                    <Progress value={compliance} className="h-1.5" />
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      <span>{ou.computerCount} computers</span>
                      <span className="text-emerald-500">{ou.compliant} compliant</span>
                      {ou.pendingWipe > 0 && <span className="text-amber-500">{ou.pendingWipe} pending</span>}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* AD Computer List */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5 text-primary" />
            AD-Managed Computers
          </CardTitle>
          <CardDescription>
            Computers discovered via Active Directory LDAP query.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="bg-muted/50 text-sm">
                  <th className="text-left p-3 font-medium">Computer</th>
                  <th className="text-left p-3 font-medium">OS</th>
                  <th className="text-left p-3 font-medium">OU</th>
                  <th className="text-left p-3 font-medium">IP Address</th>
                  <th className="text-left p-3 font-medium">Status</th>
                  <th className="text-left p-3 font-medium">User</th>
                  <th className="text-left p-3 font-medium">Last Logon</th>
                </tr>
              </thead>
              <tbody>
                {computers.map((c) => (
                  <tr key={c.name} className="border-t hover:bg-muted/30 text-sm">
                    <td className="p-3 font-mono font-semibold text-primary">{c.name}</td>
                    <td className="p-3 text-xs">{c.os}</td>
                    <td className="p-3">
                      <Badge variant="secondary" className="text-xs font-normal">
                        {c.ou.split(',')[0].replace('OU=', '')}
                      </Badge>
                    </td>
                    <td className="p-3 font-mono text-xs">{c.ipAddress}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${c.status === 'Online' ? 'bg-emerald-500 status-online' : 'bg-gray-400'}`} />
                        <span className={`text-xs ${c.status === 'Online' ? 'text-emerald-500' : 'text-gray-400'}`}>{c.status}</span>
                      </div>
                    </td>
                    <td className="p-3 text-xs">{c.assignedUser}</td>
                    <td className="p-3 text-xs text-muted-foreground">{c.lastLogon}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
