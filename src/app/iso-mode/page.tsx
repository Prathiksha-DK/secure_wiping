"use client";

import React, { useState } from "react";
import { HardDrive, ShieldCheck , Shield , Cpu, Loader2, CheckCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";

type Step = "select_drive" | "select_method" | "confirm" | "wiping" | "complete";

const drives = [
  "sda - 512GB KINGSTON-SSD",
  "sdb - 2TB SEAGATE-HDD",
  "sdc - 64GB SANDISK-USB",
];
const methods = ["Single Pass (Quick)", "DoD 3-Pass (Secure)", "Gutmann 35-Pass (Maximum)"];

export default function IsoModePage() {
  const [step, setStep] = useState<Step>("select_drive");
  const [selectedDrive, setSelectedDrive] = useState<string | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  React.useEffect(() => {
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
            <div className="grid grid-cols-1 gap-4 w-full max-w-md">
              {drives.map((drive) => (
                <Button
                  key={drive}
                  variant="outline"
                  className="h-16 text-xl justify-start p-6"
                  onClick={() => {
                    setSelectedDrive(drive);
                    setStep("select_method");
                  }}
                >
                  {drive}
                </Button>
              ))}
            </div>
          </>
        );
      case "select_method":
        return (
          <>
            <Cpu className="w-16 h-16 mb-4 text-primary" />
            <h1 className="text-4xl font-bold mb-2">Select Wipe Method</h1>
            <p className="text-muted-foreground mb-8">For drive: <span className="font-semibold text-foreground">{selectedDrive}</span></p>
            <div className="grid grid-cols-1 gap-4 w-full max-w-md">
              {methods.map((method) => (
                <Button
                  key={method}
                  variant="outline"
                  className="h-16 text-xl"
                  onClick={() => {
                    setSelectedMethod(method);
                    setStep("confirm");
                  }}
                >
                  {method}
                </Button>
              ))}
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
