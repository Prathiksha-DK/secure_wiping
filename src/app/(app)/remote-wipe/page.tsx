"use client";

import React, { useState, useEffect } from "react";
import {
  Network,
  Monitor,
  HardDrive,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Cpu,
  Usb,
  ShieldAlert,
  FileText,
  Key,
  Shield,
  Activity,
  UserCheck
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

type Device = {
  id: string;
  name: string;
  size: string;
  type: string;
  letter: string;
  recommendedStrategy: string;
};

type Computer = {
  id: string;
  name: string;
  os: string;
  status: string;
  agent: string;
  devices: Device[];
};

export default function RemoteWipePage() {
  const [computers, setComputers] = useState<Computer[]>([]);
  const [selectedComputer, setSelectedComputer] = useState<Computer | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);

  // Workflow states
  const [authStatus, setAuthStatus] = useState<"none" | "pending" | "approved" | "denied">("none");
  const [jobStatus, setJobStatus] = useState<"idle" | "validating" | "wiping" | "verifying" | "complete">("idle");
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);

  // Dry run mode is enforced
  const isDryRun = true;
  const API_BASE = "http://localhost:9758/api/remote-wipe";

  useEffect(() => {
    // Poll computers list
    const fetchComputers = async () => {
      try {
        const res = await fetch(`${API_BASE}/computers`);
        if (res.ok) {
          const data = await res.json();
          setComputers(data);
        }
      } catch (e) {}
    };
    fetchComputers();
    const interval = setInterval(fetchComputers, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    // Poll job status if active
    let interval: any;
    if (currentJobId && (authStatus === "pending" || jobStatus === "wiping" || jobStatus === "validating")) {
      interval = setInterval(async () => {
        try {
          const res = await fetch(`${API_BASE}/job/${currentJobId}`);
          if (res.ok) {
            const data = await res.json();
            if (data.status === "approved" && authStatus === "pending") {
              setAuthStatus("approved");
            } else if (data.status === "denied" && authStatus === "pending") {
              setAuthStatus("denied");
            } else if (data.status === "wiping") {
              setJobStatus("wiping");
              setProgress(data.progress || 10);
              setLogs(data.logs || []);
            } else if (data.status === "complete") {
              setJobStatus("complete");
              setProgress(100);
              setLogs(data.logs || []);
              clearInterval(interval);
            }
          }
        } catch (e) {}
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [currentJobId, authStatus, jobStatus]);

  const handleSelectComputer = (comp: Computer) => {
    setSelectedComputer(comp);
    setSelectedDevice(null);
    setAuthStatus("none");
    setJobStatus("idle");
    setCurrentJobId(null);
  };

  const handleSelectDevice = (dev: Device) => {
    setSelectedDevice(dev);
    setAuthStatus("none");
    setJobStatus("idle");
    setCurrentJobId(null);
  };

  const handleRequestAuth = async () => {
    if (!selectedComputer || !selectedDevice) return;
    setAuthStatus("pending");
    try {
      const res = await fetch(`${API_BASE}/auth-request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          computer_id: selectedComputer.id,
          target: selectedDevice.id
        })
      });
      if (res.ok) {
        const data = await res.json();
        setCurrentJobId(data.job_id);
      }
    } catch (e) {}
  };

  const handleStartJob = async () => {
    if (authStatus !== "approved" || !currentJobId) return;
    setJobStatus("validating");
    try {
      await fetch(`${API_BASE}/job/${currentJobId}/start`, {
        method: "POST"
      });
    } catch (e) {}
  };

  const getDeviceIcon = (type: string) => {
    const t = type.toLowerCase();
    if (t.includes("system") || t.includes("nvme") || t.includes("ssd")) return <Cpu className="h-5 w-5 text-blue-500" />;
    if (t.includes("external")) return <Server className="h-5 w-5 text-purple-500" />;
    if (t.includes("removable") || t.includes("usb")) return <Usb className="h-5 w-5 text-orange-500" />;
    return <HardDrive className="h-5 w-5 text-gray-500" />;
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      <div className="flex flex-col gap-2">
        <h1 className="text-3xl font-bold tracking-tight flex items-center gap-2">
          <Network className="h-8 w-8 text-primary" />
          Virtual / Remote Wipe
        </h1>
        <p className="text-muted-foreground">
          Securely manage and sanitize storage devices on registered remote endpoints.
        </p>
      </div>

      {isDryRun && (
        <div className="bg-amber-500/15 border border-amber-500/50 text-amber-700 dark:text-amber-400 p-4 rounded-lg flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 mt-0.5 shrink-0" />
          <div>
            <h3 className="font-semibold">DEMONSTRATION MODE ACTIVE</h3>
            <p className="text-sm mt-1">
              Run the agent on a remote device to see it appear here. Destructive operations will be passed to the agent if authorized.
            </p>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
        {/* Left Column: Computers & Devices */}
        <div className="md:col-span-4 flex flex-col gap-6">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center justify-between">
                My Remote Computers
                <Button variant="outline" size="sm" className="h-7 text-xs">
                  {computers.length} Online
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {computers.length === 0 && (
                <div className="text-sm text-muted-foreground text-center py-4 border border-dashed rounded">
                  Waiting for agent registration...<br/>
                  <code className="text-xs">python remote_wipe_agent/agent.py</code>
                </div>
              )}
              {computers.map((comp) => (
                <div
                  key={comp.id}
                  onClick={() => handleSelectComputer(comp)}
                  className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                    selectedComputer?.id === comp.id
                      ? "border-primary bg-primary/5"
                      : "hover:border-primary/50 hover:bg-accent/50"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2 font-medium">
                      <Monitor className="h-4 w-4" />
                      {comp.name}
                    </div>
                    <div className="flex items-center gap-1.5 text-xs font-medium text-green-600 dark:text-green-400">
                      <div className="h-2 w-2 rounded-full bg-green-500 animate-pulse" />
                      {comp.status}
                    </div>
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{comp.os}</span>
                    <Badge variant="outline" className="text-[10px] font-normal px-1.5 py-0">
                      Agent {comp.agent}
                    </Badge>
                  </div>
                  <div className="mt-2 text-xs text-muted-foreground">
                    {comp.devices.length} storage devices detected
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {selectedComputer && (
            <Card className="animate-in fade-in slide-in-from-left-4">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg">Physical Storage Devices</CardTitle>
                <CardDescription>Select exact physical device</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {selectedComputer.devices.map((dev, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectDevice(dev)}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors flex items-start gap-3 ${
                      selectedDevice?.id === dev.id
                        ? "border-primary bg-primary/5"
                        : "hover:border-primary/50 hover:bg-accent/50"
                    }`}
                  >
                    <div className="mt-1">{getDeviceIcon(dev.type)}</div>
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-sm truncate">{dev.id.toUpperCase()}</div>
                      <div className="text-sm font-semibold truncate">{dev.name}</div>
                      <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                        <Badge variant="secondary" className="text-[10px] px-1 py-0">{dev.size}</Badge>
                        <span>{dev.type}</span>
                        <span>{dev.letter}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Right Column: Workflow */}
        <div className="md:col-span-8">
          {selectedDevice ? (
            <div className="flex flex-col gap-6 animate-in fade-in slide-in-from-right-4">
              {/* Device Info & Strategy */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <HardDrive className="h-5 w-5 text-primary" />
                    Target Device Information
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4 mb-6">
                    <div className="space-y-1">
                      <div className="text-sm text-muted-foreground">Identity</div>
                      <div className="font-medium">{selectedDevice.id.toUpperCase()} - {selectedDevice.name}</div>
                    </div>
                    <div className="space-y-1">
                      <div className="text-sm text-muted-foreground">Capacity / Type</div>
                      <div className="font-medium">{selectedDevice.size} / {selectedDevice.type}</div>
                    </div>
                  </div>
                  
                  <div className="p-4 rounded-lg bg-muted/30 border space-y-2">
                    <div className="flex items-center gap-2 font-medium text-sm">
                      <Shield className="h-4 w-4 text-primary" />
                      Recommended Sanitization Strategy
                    </div>
                    <p className="text-sm text-muted-foreground">
                      Based on device detection, the existing engine recommends:
                    </p>
                    <Badge variant="default" className="mt-2 text-sm">
                      {selectedDevice.recommendedStrategy}
                    </Badge>
                  </div>
                </CardContent>
              </Card>

              {/* Authorization Workflow */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="h-5 w-5 text-primary" />
                    Owner Authorization
                  </CardTitle>
                  <CardDescription>
                    Remote sanitization requires explicit consent from the device owner.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {authStatus === "none" && (
                    <Button onClick={handleRequestAuth} className="w-full sm:w-auto">
                      Send Owner Authorization Request
                    </Button>
                  )}

                  {authStatus === "pending" && (
                    <div className="space-y-4">
                      <div className="flex items-center gap-3 text-amber-600 dark:text-amber-500">
                        <Clock className="h-5 w-5 animate-pulse" />
                        <span className="font-medium">Waiting for owner approval on {selectedComputer?.name}...</span>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        A prompt has been displayed on the remote agent. Please await the owner's response.
                      </p>
                    </div>
                  )}

                  {authStatus === "denied" && (
                    <div className="p-4 bg-red-50 dark:bg-red-950/20 text-red-600 dark:text-red-400 rounded-lg border border-red-200 dark:border-red-900 flex items-center gap-3">
                      <XCircle className="h-5 w-5" />
                      <span className="font-medium">Authorization Denied by Owner. Operation aborted.</span>
                      <Button variant="outline" size="sm" className="ml-auto" onClick={() => setAuthStatus("none")}>
                        Reset
                      </Button>
                    </div>
                  )}

                  {authStatus === "approved" && (
                    <div className="space-y-6 animate-in fade-in">
                      <div className="p-4 bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-400 rounded-lg border border-green-200 dark:border-green-900 flex items-center gap-3">
                        <CheckCircle className="h-5 w-5" />
                        <div>
                          <div className="font-semibold">Authorization Approved</div>
                          <div className="text-sm opacity-90">Bound to device identity. Agent ready.</div>
                        </div>
                      </div>

                      <div className="border rounded-lg p-6 space-y-6">
                        <div className="flex items-center justify-between">
                          <h4 className="font-semibold text-lg flex items-center gap-2">
                            <Activity className="h-5 w-5" /> Sanitization Job
                          </h4>
                          {jobStatus === "idle" && (
                            <Button onClick={handleStartJob} className="gap-2">
                              <Play className="h-4 w-4" /> Start Remote Wipe
                            </Button>
                          )}
                        </div>

                        {jobStatus !== "idle" && (
                          <div className="space-y-6">
                            <div className="space-y-2">
                              <div className="flex justify-between text-sm font-medium">
                                <span>
                                  {jobStatus === "validating" && "Agent Validating Target..."}
                                  {jobStatus === "wiping" && "Executing Strategy..."}
                                  {jobStatus === "verifying" && "Performing Verification..."}
                                  {jobStatus === "complete" && "Job Complete"}
                                </span>
                                <span>{progress}%</span>
                              </div>
                              <Progress value={progress} className="h-2" />
                            </div>

                            <div className="bg-black text-green-400 font-mono text-xs p-4 rounded-md h-32 overflow-y-auto space-y-1 shadow-inner flex flex-col-reverse">
                              {/* Show logs in reverse order or just scroll to bottom */}
                              <div className="flex flex-col gap-1">
                                {logs.map((log, i) => (
                                  <div key={i}>{">"} {log}</div>
                                ))}
                                {jobStatus === "complete" && <div className="text-blue-400">{">"} Remote audit report generated.</div>}
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                      {jobStatus === "complete" && (
                        <Card className="border-green-200 dark:border-green-900 bg-green-50/50 dark:bg-green-950/10">
                          <CardContent className="pt-6 flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <ShieldCheck className="h-8 w-8 text-green-600 dark:text-green-500" />
                              <div>
                                <h4 className="font-semibold text-green-800 dark:text-green-400">Sanitization Verified</h4>
                                <p className="text-sm text-green-600/80 dark:text-green-500/80">
                                  Remote agent confirmed successful execution.
                                </p>
                              </div>
                            </div>
                            <Button variant="outline" className="gap-2">
                              <FileText className="h-4 w-4" /> View Audit Report
                            </Button>
                          </CardContent>
                        </Card>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-muted-foreground border-2 border-dashed rounded-xl p-12 text-center bg-muted/10">
              {selectedComputer ? (
                <>
                  <HardDrive className="h-12 w-12 mb-4 opacity-50" />
                  <h3 className="text-lg font-medium text-foreground mb-1">Select a Physical Device</h3>
                  <p className="max-w-sm">Choose a storage device from the list to view its capabilities and initiate the remote wipe workflow.</p>
                </>
              ) : (
                <>
                  <Monitor className="h-12 w-12 mb-4 opacity-50" />
                  <h3 className="text-lg font-medium text-foreground mb-1">Select a Remote Computer</h3>
                  <p className="max-w-sm">Choose a registered computer from your account to view its attached physical storage devices.</p>
                </>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
