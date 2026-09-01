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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { KeyRound, HardDrive, Loader2, CheckCircle, XCircle, ShieldAlert, Info } from "lucide-react";
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
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

const API_BASE = "http://localhost:9758";

type Device = {
  id: string;
  name: string;
  size: string;
};

type RestoreStatus = "idle" | "pending" | "success" | "error";

export default function RestorePage() {
  const { toast } = useToast();
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>("");
  const [decryptionKey, setDecryptionKey] = useState("");
  const [status, setStatus] = useState<RestoreStatus>("idle");
  const [loadingDevices, setLoadingDevices] = useState(true);
  const [resultMessage, setResultMessage] = useState("");

  useEffect(() => {
    async function fetchDevices() {
      setLoadingDevices(true);
      try {
        const res = await fetch(`${API_BASE}/api/devices`, { cache: 'no-store' });
        if (!res.ok) throw new Error('Failed to fetch devices');
        const data = await res.json();
        setDevices(data.map((d: any) => ({id: d.name, name: `${d.name} (${d.size})`, size: d.size})));
      } catch (error) {
        console.error("Failed to fetch devices:", error);
        setDevices([]);
        toast({
          variant: "destructive",
          title: "Failed to load devices",
          description: "Could not connect to the device manager.",
        });
      } finally {
        setLoadingDevices(false);
      }
    }
    fetchDevices();
  }, [toast]);

  const handleRestore = async () => {
    setStatus("pending");
    setResultMessage("");
    try {
      const res = await fetch(`${API_BASE}/api/decrypt-and-restore`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ device: selectedDevice, decryptionKey: decryptionKey }),
      });

      const result = await res.json();

      if (!res.ok || result.status !== 'success') {
        throw new Error(result.message || 'Decrypt & Restore process failed.');
      }

      setStatus("success");
      setResultMessage(result.message);
      toast({
        title: "Restore Successful",
        description: result.message,
      });

    } catch (error: any) {
      setStatus("error");
      setResultMessage(error.message);
      toast({
        variant: "destructive",
        title: "Restore Failed",
        description: error.message,
      });
    }
  };

  const isFormInvalid = !selectedDevice || !decryptionKey || status === 'pending';

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Decrypt & Restore</h1>
        <p className="text-muted-foreground">
          Restore encrypted backup data to a device using your decryption key.
        </p>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>Important</AlertTitle>
        <AlertDescription>
          You need the 256-bit AES decryption key that was generated during the encrypt-and-wipe process.
          This key is stored in the <code className="bg-muted px-1 py-0.5 rounded text-xs">decryption_key.txt</code> file in the backup directory.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            Restore Configuration
          </CardTitle>
          <CardDescription>
            Provide the decryption key and select the target device.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="decryption-key">Decryption Key (Hex)</Label>
            <Input
              id="decryption-key"
              type="password"
              placeholder="Enter your 256-bit AES key in hex format"
              value={decryptionKey}
              onChange={(e) => setDecryptionKey(e.target.value)}
              disabled={status === 'pending'}
              className="font-mono"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="device-select">Target Device</Label>
            <Select
              value={selectedDevice}
              onValueChange={setSelectedDevice}
              disabled={status === 'pending' || loadingDevices}
            >
              <SelectTrigger id="device-select">
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

          {status === 'success' && (
            <div className="flex items-center gap-3 text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/20 p-4 rounded-lg">
              <CheckCircle className="h-5 w-5 flex-shrink-0" />
              <p className="font-medium text-sm">{resultMessage || "Restore completed successfully."}</p>
            </div>
          )}
          {status === 'error' && (
            <div className="flex items-center gap-3 text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
              <XCircle className="h-5 w-5 flex-shrink-0" />
              <p className="font-medium text-sm">{resultMessage || "Restore failed."}</p>
            </div>
          )}
        </CardContent>
        <CardFooter>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button disabled={isFormInvalid} className="w-full" size="lg">
                {status === "pending" ? (
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                ) : (
                  <KeyRound className="mr-2 h-4 w-4" />
                )}
                {status === 'pending' ? 'Restoring...' : 'Decrypt & Restore'}
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle className="flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-amber-500" />
                  Confirm Restore
                </AlertDialogTitle>
                <AlertDialogDescription>
                  This will write decrypted data back to{' '}
                  <span className="font-bold">{selectedDevice}</span>.
                  Existing data on the device may be overwritten.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={handleRestore}>
                  Yes, Restore Data
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </CardFooter>
      </Card>
    </div>
  );
}
