
"use client";

import React, { useState, useEffect } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import {
  FileLock, Loader2, CheckCircle, XCircle, Key, Copy, Check,
  HardDrive, Shield, Info,
} from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";

const API_BASE = "http://localhost:9758";

type Device = {
  id: string;
  name: string;
  size: string;
};

type EncryptionResult = {
  status: "idle" | "encrypting" | "success" | "error";
  message: string;
  key: string;
  files: { name: string; size: number; status: string }[];
};

export default function EncryptFilesPage() {
  const { toast } = useToast();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState("");
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [result, setResult] = useState<EncryptionResult>({
    status: "idle",
    message: "",
    key: "",
    files: [],
  });
  const [progress, setProgress] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    async function fetchDevices() {
      setLoadingDevices(true);
      try {
        const res = await fetch(`${API_BASE}/api/devices`, { cache: "no-store" });
        if (!res.ok) throw new Error("Failed to fetch");
        const data = await res.json();
        setDevices(data.map((d: any) => ({ id: d.name, name: `${d.name} (${d.size})`, size: d.size })));
      } catch {
        setDevices([]);
      } finally {
        setLoadingDevices(false);
      }
    }
    fetchDevices();
  }, []);

  const handleEncrypt = async () => {
    if (!selectedDevice) return;

    setResult({ status: "encrypting", message: "", key: "", files: [] });
    setProgress(0);

    try {
      // Call the encrypt-and-wipe API which backs up, encrypts, and wipes
      const res = await fetch(`${API_BASE}/api/encrypt-and-wipe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ device: selectedDevice }),
      });

      const data = await res.json();

      // Simulate progress
      for (let i = 0; i <= 100; i += 10) {
        await new Promise(r => setTimeout(r, 200));
        setProgress(i);
      }

      if (!res.ok || data.status !== "success") {
        throw new Error(data.message || "Encryption failed");
      }

      setResult({
        status: "success",
        message: data.message,
        key: data.message.includes("Key saved to:") ?
          data.message.split("Key saved to:")[1]?.trim() || "" : "",
        files: [],
      });

      toast({
        title: "Encryption Complete",
        description: data.message,
      });
    } catch (e: any) {
      setProgress(100);
      setResult({
        status: "error",
        message: e.message,
        key: "",
        files: [],
      });
      toast({
        variant: "destructive",
        title: "Encryption Failed",
        description: e.message,
      });
    }
  };

  const handleCopyKey = () => {
    if (!result.key) return;
    navigator.clipboard.writeText(result.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Encrypt & Backup</h1>
        <p className="text-muted-foreground">
          Encrypt files on a device using AES-256-GCM, create a backup, and securely delete originals.
        </p>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>How it works</AlertTitle>
        <AlertDescription>
          This process will: (1) scan the selected device for files, (2) encrypt each file with AES-256-GCM,
          (3) save encrypted backups locally, (4) generate a decryption key, and (5) delete the original files.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileLock className="h-5 w-5 text-primary" />
            Encrypt Device Files
          </CardTitle>
          <CardDescription>
            Select a device to encrypt all files and create a secure backup.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label>Target Device</Label>
            <Select
              value={selectedDevice}
              onValueChange={setSelectedDevice}
              disabled={result.status === "encrypting" || loadingDevices}
            >
              <SelectTrigger>
                <SelectValue placeholder={loadingDevices ? "Loading devices..." : "Select a device"} />
              </SelectTrigger>
              <SelectContent>
                {devices.map((device) => (
                  <SelectItem key={device.id} value={device.name}>
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4" />
                      {device.name}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {result.status === "encrypting" && (
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Encrypting files...</span>
                <span className="font-mono">{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
        </CardContent>
        <CardFooter>
          <Button
            onClick={handleEncrypt}
            disabled={!selectedDevice || result.status === "encrypting"}
            className="w-full"
            size="lg"
          >
            {result.status === "encrypting" ? (
              <><Loader2 className="mr-2 h-4 w-4 animate-spin" /> Encrypting...</>
            ) : (
              <><FileLock className="mr-2 h-4 w-4" /> Encrypt & Backup</>
            )}
          </Button>
        </CardFooter>
      </Card>

      {result.status === "success" && (
        <Card className="border-emerald-500/30">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-emerald-600 dark:text-emerald-400">
              <CheckCircle className="h-5 w-5" />
              Encryption Complete
            </CardTitle>
            <CardDescription>{result.message}</CardDescription>
          </CardHeader>
          {result.key && (
            <CardContent>
              <div className="p-4 border rounded-lg bg-muted/50">
                <h4 className="font-semibold flex items-center gap-2 mb-2">
                  <Key className="h-4 w-4" /> Backup Location
                </h4>
                <p className="text-sm text-muted-foreground mb-2">
                  Your decryption key is saved at the path below.
                  <strong className="text-destructive"> Store it securely.</strong>
                </p>
                <div className="flex items-center gap-2 p-3 bg-background border rounded-md">
                  <code className="text-xs font-mono flex-grow break-all">{result.key}</code>
                  <Button variant="ghost" size="icon" onClick={handleCopyKey}>
                    {copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </CardContent>
          )}
        </Card>
      )}

      {result.status === "error" && (
        <Alert variant="destructive">
          <XCircle className="h-4 w-4" />
          <AlertTitle>Error</AlertTitle>
          <AlertDescription>{result.message}</AlertDescription>
        </Alert>
      )}
    </div>
  );
}
