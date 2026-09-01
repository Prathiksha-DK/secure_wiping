"use client";

import React, { useState, useEffect } from "react";
import { HardDrive, Shield, Cpu, Loader2, CheckCircle, ShieldCheck, AlertTriangle, Bomb } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";

const API_BASE = "http://localhost:9758";

type Step = "select_drive" | "select_method" | "confirm" | "wiping" | "complete";

type Device = {
  name: string;
  size: string;
  type: string;
};

const methods = [
  { id: "nist-clear", label: "NIST 800-88 Clear (1-Pass)", icon: ShieldCheck },
  { id: "dod-3pass", label: "DoD 5220.22-M (3-Pass)", icon: Shield },
  { id: "gutmann", label: "Gutmann 35-Pass (Maximum)", icon: AlertTriangle },
  { id: "bomb-mode", label: "Bomb Mode — Scatter Overwrite", icon: Bomb },
];

export default function IsoModePage() {
  const [step, setStep] = useState<Step>("select_drive");
  const [drives, setDrives] = useState<Device[]>([]);
  const [loadingDrives, setLoadingDrives] = useState(true);
  const [selectedDrive, setSelectedDrive] = useState<string | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    async function fetchDrives() {
      setLoadingDrives(true);
      try {
        const res = await fetch(`${API_BASE}/api/devices`, { cache: "no-store" });
        if (!res.ok) throw new Error("Failed to fetch");
        const data = await res.json();
        setDrives(data.map((d: any) => ({
          name: d.name,
          size: d.size,
          type: d.type || "Unknown",
        })));
      } catch {
        setDrives([]);
      } finally {
        setLoadingDrives(false);
      }
    }
    fetchDrives();
  }, []);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (step === 'wiping' && progress < 100) {
      timer = setTimeout(() => {
        setProgress(prev => prev + 1);
      }, 200);
    } else if (progress >= 100) {
      setStep('complete');
    }
    return () => clearTimeout(timer);
  }, [step, progress]);

  const handleStartWipe = () => {
    setStep('wiping');
  };

  const renderContent = () => {
    switch (step) {
      case "select_drive":
        return (
          <>
            <HardDrive className="w-16 h-16 mb-4 text-primary" />
            <h1 className="text-4xl font-bold mb-8">Select Drive to Wipe</h1>
            {loadingDrives ? (
              <div className="flex items-center gap-2">
                <Loader2 className="h-6 w-6 animate-spin" />
                <span className="text-lg">Scanning for drives...</span>
              </div>
            ) : drives.length === 0 ? (
              <p className="text-lg text-muted-foreground">No drives detected.</p>
            ) : (
              <div className="grid grid-cols-1 gap-4 w-full max-w-md">
                {drives.map((drive) => (
                  <Button
                    key={drive.name}
                    variant="outline"
                    className="h-16 text-xl justify-between p-6"
                    onClick={() => {
                      setSelectedDrive(`${drive.name} — ${drive.size}`);
                      setStep("select_method");
                    }}
                  >
                    <span>{drive.name}</span>
                    <Badge variant="secondary">{drive.size} {drive.type}</Badge>
                  </Button>
                ))}
              </div>
            )}
          </>
        );
      case "select_method":
        return (
          <>
            <Cpu className="w-16 h-16 mb-4 text-primary" />
            <h1 className="text-4xl font-bold mb-2">Select Wipe Method</h1>
            <p className="text-muted-foreground mb-8">For drive: <span className="font-semibold text-foreground">{selectedDrive}</span></p>
            <div className="grid grid-cols-1 gap-4 w-full max-w-md">
              {methods.map((method) => {
                const Icon = method.icon;
                return (
                  <Button
                    key={method.id}
                    variant="outline"
                    className="h-16 text-xl justify-start gap-3"
                    onClick={() => {
                      setSelectedMethod(method.label);
                      setStep("confirm");
                    }}
                  >
                    <Icon className="h-5 w-5" />
                    {method.label}
                  </Button>
                );
              })}
            </div>
          </>
        );
      case "confirm":
        return (
            <Card className="w-full max-w-2xl text-center shadow-2xl">
                <CardHeader>
                    <CardTitle className="text-4xl font-bold text-destructive">FINAL WARNING</CardTitle>
                    <CardDescription className="text-lg">This action is irreversible.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 text-left p-8">
                    <p className="text-xl">You are about to permanently erase all data on:</p>
                    <div className="bg-muted p-4 rounded-lg">
                        <p className="font-mono text-2xl">{selectedDrive}</p>
                    </div>
                    <p className="text-xl">Using the method:</p>
                    <div className="bg-muted p-4 rounded-lg">
                        <p className="font-semibold text-2xl">{selectedMethod}</p>
                    </div>
                     <p className="text-destructive font-bold text-center pt-4 text-xl">PROCEED WITH EXTREME CAUTION.</p>
                </CardContent>
                <div className="flex justify-between p-6 bg-muted/50">
                    <Button variant="secondary" className="h-16 text-xl px-12" onClick={() => setStep('select_method')}>
                        Back
                    </Button>
                    <Button variant="destructive" className="h-16 text-xl px-12" onClick={handleStartWipe}>
                        <Shield className="mr-4 w-8 h-8"/> Start Wipe
                    </Button>
                </div>
            </Card>
        );
      case 'wiping':
        return (
            <div className="w-full max-w-2xl text-center">
                <Loader2 className="w-16 h-16 mb-4 text-primary animate-spin" />
                <h1 className="text-4xl font-bold mb-2">Wiping in Progress...</h1>
                <p className="text-muted-foreground mb-8">Erasing <span className="font-semibold text-foreground">{selectedDrive}</span>. Do not power off.</p>
                <Progress value={progress} className="h-4" />
                <p className="text-2xl font-mono mt-4">{progress}%</p>
            </div>
        );
      case 'complete':
        return (
            <div className="w-full max-w-2xl text-center">
                <CheckCircle className="w-16 h-16 mb-4 text-green-500" />
                <h1 className="text-4xl font-bold mb-2">Wipe Complete</h1>
                <p className="text-muted-foreground mb-8">The drive <span className="font-semibold text-foreground">{selectedDrive}</span> has been securely erased.</p>
                <Button className="h-16 text-xl px-12" onClick={() => {
                  setStep('select_drive');
                  setSelectedDrive(null);
                  setSelectedMethod(null);
                  setProgress(0);
                }}>
                    Wipe Another Drive
                </Button>
            </div>
        )
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-background text-foreground p-8">
      <div className="absolute top-8 left-8 flex items-center gap-2">
        <ShieldCheck className="w-8 h-8 text-primary" />
        <h1 className="text-2xl font-bold">SecureWipe <span className="text-base font-normal text-muted-foreground">ISO Mode</span></h1>
      </div>
      {renderContent()}
    </div>
  );
}
