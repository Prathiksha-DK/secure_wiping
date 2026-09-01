
"use client";

import React, { useState, useEffect, useMemo, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import {
  HardDrive,
  Shield,
  CheckCircle,
  XCircle,
  Loader,
  ChevronRight,
  ChevronLeft,
  FileQuestion,
  KeyRound,
  ShieldCheck,
  Trash2,
  Zap,
  Lock,
  FileWarning,
  Loader2,
  Bomb,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import {
  RadioGroup,
  RadioGroupItem,
} from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Separator } from "@/components/ui/separator";

const API_BASE = "http://localhost:9758";

type Device = {
  id: string;
  name: string;
  size: string;
  type: string;
};

const wipeMethodDetails: {[key: string]: {name: string, Icon: React.ElementType, description: string, standard: string, passCount: string, timeEstimate: string}} = {
  "nist-clear": {
    name: "NIST 800-88 Clear",
    Icon: ShieldCheck,
    description: "Applies logical techniques to sanitize data in all user-addressable storage locations. Protects against simple non-invasive data recovery.",
    standard: "NIST SP 800-88 Rev.1",
    passCount: "1 Pass",
    timeEstimate: "~5 min / GB",
  },
  "nist-purge": {
    name: "NIST 800-88 Purge",
    Icon: Trash2,
    description: "Physical or logical techniques that render target data recovery infeasible using state of the art laboratory techniques.",
    standard: "NIST SP 800-88 Rev.1",
    passCount: "3+ Passes",
    timeEstimate: "~15 min / GB",
  },
  "dod-3pass": {
    name: "DoD 5220.22-M (3-Pass)",
    Icon: Shield,
    description: "U.S. Department of Defense standard. Overwrites with zeros, ones, then random data. Verified after each pass.",
    standard: "DoD 5220.22-M",
    passCount: "3 Passes",
    timeEstimate: "~20 min / GB",
  },
  "dod-7pass": {
    name: "DoD 5220.22-M ECE (7-Pass)",
    Icon: Shield,
    description: "Extended version of DoD standard with 7 overwrite passes for maximum assurance on magnetic media.",
    standard: "DoD 5220.22-M ECE",
    passCount: "7 Passes",
    timeEstimate: "~45 min / GB",
  },
  "crypto-erase": {
    name: "Cryptographic Erasure",
    Icon: Lock,
    description: "Encrypts the entire drive with AES-256, then destroys the encryption key. Instant erasure for SED/OPAL compliant drives.",
    standard: "IEEE 2883-2022",
    passCount: "Instant",
    timeEstimate: "<1 min",
  },
  "ieee-purge": {
    name: "IEEE 2883 Purge",
    Icon: Zap,
    description: "Latest media sanitization standard. Uses media-specific commands to render data infeasible to recover.",
    standard: "IEEE 2883-2022",
    passCount: "Vendor Specific",
    timeEstimate: "~10 min / GB",
  },
  "gutmann": {
    name: "Gutmann 35-Pass",
    Icon: FileWarning,
    description: "Maximum overwrite method with 35 passes. Considered overkill for modern drives but provides highest theoretical security.",
    standard: "Peter Gutmann Method",
    passCount: "35 Passes",
    timeEstimate: "~2 hrs / GB",
  },
  "bomb-mode": {
    name: "Bomb Mode — Scatter Overwrite",
    Icon: Bomb,
    description: "Scatter-pattern overwrite inspired by the Bomber Game. Writes random data to randomized sectors across the disk in an unpredictable bombing pattern. Maximum entropy destruction.",
    standard: "SecureWipe Proprietary",
    passCount: "Random Scatter",
    timeEstimate: "~10 min / GB",
  },
};

const defaultMethod = {
  name: "System Determined",
  Icon: FileQuestion,
  description: "The most appropriate method will be automatically selected based on device type.",
  standard: "Auto",
  passCount: "Varies",
  timeEstimate: "Varies",
};


function WipePageComponent() {
  const router = useRouter();
  const { toast } = useToast();
  const searchParams = useSearchParams();
  const deviceNameFromQuery = searchParams.get("device");

  const [step, setStep] = useState(1);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string | undefined>(
    deviceNameFromQuery || undefined
  );
  const [determinedMethod, setDeterminedMethod] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [logs, setLogs] = useState<string[]>([]);
  const [isWiping, setIsWiping] = useState(false);
  const [isFetchingMethod, setIsFetchingMethod] = useState(false);
  const [wipeComplete, setWipeComplete] = useState(false);
  const [wipeSuccess, setWipeSuccess] = useState(false);
  const [loading, setLoading] = useState(true);
  const [reportId, setReportId] = useState<string | null>(null);

  useEffect(() => {
    async function fetchDevices() {
      setLoading(true);
      try {
        const res = await fetch(`${API_BASE}/api/devices`, { cache: 'no-store' });
        if (!res.ok) throw new Error('Failed to fetch devices');
        const data = await res.json();
        setDevices(data.map((d: any) => ({id: d.name, name: `${d.name} (${d.size})`, size: d.size, type: d.type})));
      } catch (error) {
        console.error("Failed to fetch devices:", error);
        setDevices([]);
        toast({
          variant: "destructive",
          title: "Failed to load devices",
          description: "Could not connect to the device manager. Please ensure it's running.",
        });
      } finally {
        setLoading(false);
      }
    }
    fetchDevices();
  }, [toast]);

  const selectedDeviceDetails = useMemo(() => {
    return devices.find((d) => d.name === selectedDevice);
  }, [selectedDevice, devices]);

  const handleNextStep = async () => {
    if (!selectedDeviceDetails) return;
    setIsFetchingMethod(true);
    setLogs(prev => [...prev, `[INFO] Analyzing device: ${selectedDeviceDetails.name}`]);
    setLogs(prev => [...prev, `[INFO] Querying device bus type, media type, and firmware capabilities...`]);
    try {
      const res = await fetch(`${API_BASE}/api/get-wipe-method`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device: selectedDeviceDetails.name }),
      });
      if (!res.ok) {
        const errorData = await res.json().catch(() => ({error: 'Failed to get wipe method.'}));
        throw new Error(errorData.error || 'An unknown error occurred.');
      }
      const data = await res.json();
      setDeterminedMethod(data.method);
      setLogs(prev => [...prev, `[OK] Recommended method: ${data.method}`]);
      setStep(2);
    } catch (error: any) {
      toast({
        variant: "destructive",
        title: "Could not determine wipe method",
        description: error.message,
      });
      setLogs(prev => [...prev, `[ERROR] ${error.message}`]);
    } finally {
      setIsFetchingMethod(false);
    }
  };

  const handleStartWipe = async () => {
    if (!selectedDeviceDetails || !determinedMethod) return;

    // Use device type from /api/devices as primary indicator
    const isUsbType = (selectedDeviceDetails as any).type === 'USB' || (selectedDeviceDetails as any).type === 'USB Drive';

    // Cross-check against pendrives list — only small FAT32 removable drives (<64 GB, non-NTFS)
    let matchedPendrive = null;
    if (isUsbType) {
      matchedPendrive = pendrives.find(p => p.size_gb < 64 && p.fstype !== 'NTFS');
    }

    if (isUsbType && matchedPendrive) {
      // --------------------------------------------------
      // Route A: USB / Removable drive -> port 8743
      // --------------------------------------------------
      const targetDevice = matchedPendrive.device.toUpperCase();
      // Hard safety: never allow C:, D: or NTFS volumes
      if (
        targetDevice.startsWith("C:") ||
        targetDevice.startsWith("D:") ||
        matchedPendrive.fstype === 'NTFS' ||
        matchedPendrive.size_gb > 64
      ) {
        toast({
          title: "Safety Block",
          description: `Operation aborted: ${matchedPendrive.device} is an internal drive.`,
          variant: "destructive"
        });
        return;
      }

      setStep(3);
      setIsWiping(true);
      setProgress(0);
      setWipeComplete(false);
      setWipeSuccess(false);
      setReportId(null);
      setLogs([`[START] Initiating Pendrive Boom Wipe for ${matchedPendrive.name} on port 8743...`]);

      try {
        const res = await fetch('http://localhost:8743/wipe-pendrive', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          // "E:/" bypasses the broken name-match in backend get_device_path (line 69)
          // and hits the fallback at line 76 which correctly returns \\.\E:
          body: JSON.stringify({ device: matchedPendrive.device.replace(/\\/g, '/') })
        });

        const data = await res.json();
        if (!res.ok || data.status !== 'success') {
          throw new Error(data.message || "Failed to start wipe on port 8743");
        }

        const wipeId = data.wipe_id;
        setLogs(prev => [...prev, `[OK] Detonation triggered. Wipe ID: ${wipeId}`]);
        setLogs(prev => [...prev, `[INFO] Polling progress...`]);

        // Start polling
        const pollInterval = setInterval(async () => {
          try {
            const statusRes = await fetch(`http://localhost:8743/wipe-status/${wipeId}`, { cache: 'no-store' });
            if (statusRes.ok) {
              const statusData = await statusRes.json();
              if (statusData.status === 'success' && statusData.wipe_status) {
                const s = statusData.wipe_status;
                const STATUS_LABELS: Record<string, string> = {
                  initializing: 'Initializing...',
                  scanning:     'Scanning files...',
                  erasing:      'Erasing files (DoD 3-Pass)',
                  formatting:   'Formatting drive...',
                  placing_bombs:'Erasing...',
                  completed:    'Completed',
                  failed:       'Failed',
                };
                const label = STATUS_LABELS[s.status] || s.status.replace(/_/g, ' ').toUpperCase();
                const fileInfo = s.total_files
                  ? ` | ${s.wiped_files ?? 0}/${s.total_files} files`
                  : '';
                const prog = Math.round(s.progress || 0);
                setProgress(prog);
                setLogs(prev => [
                  ...prev.slice(0, 4),
                  `[STATUS] ${label}${fileInfo} | Progress: ${prog}%`
                ]);

                if (s.status === 'completed' || s.status === 'failed') {
                  clearInterval(pollInterval);
                  setIsWiping(false);
                  setWipeComplete(true);
                  
                  if (s.status === 'completed') {
                    setWipeSuccess(true);
                    setProgress(100);
                    // Register in SQLite history db on port 9758
                    try {
                      const dbRegRes = await fetch(`${API_BASE}/api/verify-and-send`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          deviceName: selectedDeviceDetails.name,
                          wipeMethod: determinedMethod,
                          receiverEmail: "worker@example.com",
                          deviceSerial: `SN-USB-${wipeId.substring(14, 22)}`,
                          deviceType: 'USB Drive'
                        })
                      });
                      const dbRegData = await dbRegRes.json();
                      if (dbRegRes.ok && dbRegData.success) {
                        setReportId(dbRegData.certificate.reportId);
                        setLogs(prev => [...prev, `[OK] Sanitization certificate generated: ${dbRegData.certificate.reportId}`]);
                      }
                    } catch (dbErr) {
                      console.error("Failed to register certificate in history db:", dbErr);
                    }
                  } else {
                    setWipeSuccess(false);
                    setLogs(prev => [...prev, `[ERROR] Wipe failed: ${s.error || 'Unknown error'}`]);
                  }
                }
              }
            }
          } catch (pollErr: any) {
            console.error("Polling error:", pollErr);
          }
        }, 1000);

      } catch (err: any) {
        setIsWiping(false);
        setLogs(prev => [...prev, `[ERROR] ${err.message}`]);
        toast({
          variant: "destructive",
          title: "Pendrive Wipe Failed",
          description: err.message
        });
      }
    } else {
      // --------------------------------------------------
      // Route B: Internal SSD/HDD -> port 9758 (Original Flow)
      // --------------------------------------------------
      setStep(3);
      setIsWiping(true);
      setProgress(0);
      setWipeComplete(false);
      setWipeSuccess(false);
      setReportId(null);

      const method = wipeMethodDetails[determinedMethod] || defaultMethod;
      setLogs([
        `[START] Wipe initiated for: ${selectedDeviceDetails.name}`,
        `[INFO] Standard: ${method.standard}`,
        `[INFO] Method: ${method.name} (${method.passCount})`,
        `[INFO] Connecting to device...`,
      ]);

      const progressInterval = setInterval(() => {
        setProgress(p => Math.min(p + 1, 99));
      }, 200);

      try {
        const isBombMode = determinedMethod === 'bomb-mode';
        const wipeEndpoint = isBombMode ? `${API_BASE}/api/bomb-wipe` : `${API_BASE}/api/wipe`;
        setLogs(prev => [...prev, `[INFO] Sending ${isBombMode ? 'BOMB MODE' : 'wipe'} command to API...`]);
        const response = await fetch(wipeEndpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ device: selectedDeviceDetails.name, method: determinedMethod }),
        });

        const result = await response.json();
        clearInterval(progressInterval);

        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || "Wipe operation failed");
        }

        setWipeSuccess(true);
        setReportId(result.reportId || null);
        setLogs(prev => [
          ...prev,
          `[OK] ${result.message}`,
          `[OK] Verification complete. Certificate ID: ${result.reportId || 'N/A'}`,
          `[DONE] All operations completed successfully.`,
        ]);

      } catch(e: any) {
        clearInterval(progressInterval);
        setWipeSuccess(false);
        setLogs(prev => [...prev, `[ERROR] ${e.message}`]);
        toast({
          variant: "destructive",
          title: "Wipe Failed",
          description: e.message || "An unknown error occurred.",
        });
      } finally {
        setProgress(100);
        setIsWiping(false);
        setWipeComplete(true);
      }
    }
  };

  const renderStep = () => {
    switch (step) {
      case 1:
        return (
          <Card className="animate-fade-in">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <HardDrive className="h-5 w-5 text-primary" />
                Step 1: Select Target Device
              </CardTitle>
              <CardDescription>
                Choose the storage device you want to securely sanitize.
              </CardDescription>
            </CardHeader>
            <CardContent>
             {loading ? (
               <div className="flex items-center justify-center py-10">
                 <Loader2 className="h-6 w-6 animate-spin text-primary mr-3" />
                 <span className="text-muted-foreground">Scanning for devices...</span>
               </div>
             ) : devices.length === 0 ? (
               <div className="text-center py-10 text-muted-foreground">
                 <HardDrive className="h-10 w-10 mx-auto mb-3 opacity-40" />
                 <p>No devices detected. Please connect a storage device.</p>
               </div>
             ) : (
              <RadioGroup
                value={selectedDevice}
                onValueChange={setSelectedDevice}
                className="grid gap-3"
              >
                {devices.map((device) => (
                  <Label
                    key={device.id}
                    htmlFor={device.id}
                    className="flex items-center gap-4 rounded-lg border p-4 cursor-pointer transition-all hover:bg-accent/5 hover:border-primary/50 [&:has([data-state=checked])]:border-primary [&:has([data-state=checked])]:bg-primary/5"
                  >
                    <div className="p-2 rounded-lg bg-muted">
                      <HardDrive className="h-5 w-5 text-primary" />
                    </div>
                    <div className="flex-1">
                      <p className="font-medium">{device.name}</p>
                      <p className="text-xs text-muted-foreground">{device.type}</p>
                    </div>
                    <RadioGroupItem value={device.name} id={device.id} />
                  </Label>
                ))}
              </RadioGroup>
              )}
            </CardContent>
          </Card>
        );
      case 2:
        const methodKey = determinedMethod || 'unknown';
        const method = wipeMethodDetails[methodKey] || defaultMethod;
        const MethodIcon = method.Icon;
        return (
          <Card className="animate-fade-in">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-primary" />
                Step 2: Review Sanitization Plan
              </CardTitle>
              <CardDescription>
                The system has analyzed the device and recommends the following sanitization method.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Selected Device */}
              <div>
                <Label className="text-sm font-medium text-muted-foreground">Target Device</Label>
                <div className="flex items-center gap-3 rounded-lg border p-4 mt-2">
                  <div className="p-2 rounded-lg bg-muted">
                    <HardDrive className="h-5 w-5 text-primary" />
                  </div>
                  <span className="font-semibold">{selectedDeviceDetails?.name}</span>
                </div>
              </div>

              {/* Recommended Method */}
              <div>
                <Label className="text-sm font-medium text-muted-foreground">Recommended Method</Label>
                <div className="rounded-lg border p-5 mt-2 space-y-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10">
                      <MethodIcon className="h-5 w-5 text-primary" />
                    </div>
                    <div>
                      <p className="font-semibold text-lg">{method.name}</p>
                      <Badge variant="secondary" className="mt-1">{method.standard}</Badge>
                    </div>
                  </div>
                  <p className="text-sm text-muted-foreground">{method.description}</p>
                  <Separator />
                  <div className="grid grid-cols-3 gap-4 text-center">
                    <div>
                      <p className="text-xs text-muted-foreground">Passes</p>
                      <p className="font-semibold text-sm">{method.passCount}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Est. Time</p>
                      <p className="font-semibold text-sm">{method.timeEstimate}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">Standard</p>
                      <p className="font-semibold text-sm">{method.standard}</p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
            <CardFooter>
              <AlertDialog>
                <AlertDialogTrigger asChild>
                  <Button className="w-full" size="lg">
                    <Shield className="mr-2 h-4 w-4" /> Begin Sanitization
                  </Button>
                </AlertDialogTrigger>
                <AlertDialogContent>
                  <AlertDialogHeader>
                    <AlertDialogTitle className="flex items-center gap-2">
                      <FileWarning className="h-5 w-5 text-destructive" />
                      Confirm Data Destruction
                    </AlertDialogTitle>
                    <AlertDialogDescription>
                      This action will <span className="font-bold text-destructive">permanently destroy all data</span> on{" "}
                      <span className="font-bold">{selectedDeviceDetails?.name}</span> using the{" "}
                      <span className="font-bold">{method.name}</span> method.
                      <br /><br />
                      This process is <span className="font-bold text-destructive">irreversible</span>.
                      A certificate of destruction will be generated upon completion.
                    </AlertDialogDescription>
                  </AlertDialogHeader>
                  <AlertDialogFooter>
                    <AlertDialogCancel>Cancel</AlertDialogCancel>
                    <AlertDialogAction onClick={handleStartWipe} className="bg-destructive hover:bg-destructive/90">
                      Confirm & Destroy
                    </AlertDialogAction>
                  </AlertDialogFooter>
                </AlertDialogContent>
              </AlertDialog>
            </CardFooter>
          </Card>
        );
      case 3:
        return (
          <Card className="animate-fade-in">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {isWiping && <Loader className="animate-spin text-primary" />}
                {wipeComplete &&
                  (wipeSuccess ? (
                    <CheckCircle className="text-emerald-500" />
                  ) : (
                    <XCircle className="text-red-500" />
                  ))}
                Sanitization: {selectedDeviceDetails?.name}
              </CardTitle>
              <CardDescription>
                {wipeComplete
                  ? `Process ${wipeSuccess ? "completed successfully" : "failed"}.`
                  : "Processing data sanitization. Do not disconnect the device."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-muted-foreground">Progress</span>
                  <span className="font-mono font-semibold">{progress}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
              <Accordion type="single" collapsible className="w-full" defaultValue="logs">
                <AccordionItem value="logs">
                  <AccordionTrigger className="text-sm">Operation Log</AccordionTrigger>
                  <AccordionContent>
                    <div className="h-52 bg-gray-950 text-gray-300 font-mono text-xs rounded-lg p-4 overflow-y-auto border border-gray-800">
                      {logs.map((log, i) => (
                        <p key={i} className={`${log.startsWith('[ERROR]') ? 'text-red-400' : log.startsWith('[OK]') || log.startsWith('[DONE]') ? 'text-emerald-400' : log.startsWith('[START]') ? 'text-amber-400' : 'text-gray-400'}`}>
                          {log}
                        </p>
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            </CardContent>
          </Card>
        );
    }
  };

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      {/* Step Indicator */}
      <div className="flex items-center justify-center gap-2">
        {[1, 2, 3].map((s) => (
          <React.Fragment key={s}>
            <div className={`flex items-center justify-center w-8 h-8 rounded-full text-xs font-bold transition-all ${
              step >= s ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground'
            }`}>
              {s}
            </div>
            {s < 3 && (
              <div className={`w-16 h-0.5 transition-all ${step > s ? 'bg-primary' : 'bg-muted'}`} />
            )}
          </React.Fragment>
        ))}
      </div>

      {renderStep()}

      <div className="flex justify-between items-center">
        <Button
          variant="outline"
          onClick={() => setStep(step - 1)}
          disabled={step === 1 || isWiping}
        >
          <ChevronLeft className="mr-2 h-4 w-4" /> Back
        </Button>

        {step === 1 && (
          <Button onClick={handleNextStep} disabled={!selectedDevice || isFetchingMethod}>
            {isFetchingMethod ? (
              <><Loader className="mr-2 h-4 w-4 animate-spin" /> Analyzing...</>
            ) : (
              <>Next <ChevronRight className="ml-2 h-4 w-4" /></>
            )}
          </Button>
        )}

        {wipeComplete && wipeSuccess && reportId && (
          <Button onClick={() => router.push(`/worker/report/${reportId}`)}>
            View Certificate <ChevronRight className="ml-2 h-4 w-4" />
          </Button>
        )}
      </div>
    </div>
  );
}


export default function WipePage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center min-h-[50vh]">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    }>
      <WipePageComponent />
    </Suspense>
  );
}
