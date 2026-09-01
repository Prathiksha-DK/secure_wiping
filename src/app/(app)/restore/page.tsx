
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
import { KeyRound, HardDrive, Loader2, CheckCircle, XCircle } from "lucide-react";
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

  useEffect(() => {
    async function fetchDevices() {
      setLoadingDevices(true);
      try {
        const res = await fetch('http://localhost:9758/api/devices', { cache: 'no-store' });
        if (!res.ok) {
           throw new Error('Failed to fetch devices');
        }
        const data = await res.json();
        setDevices(data.map((d: any) => ({id: d.name, name: `${d.name} (${d.size})`, size: d.size})));
      } catch (error) {
        console.error("Failed to fetch devices:", error);
        setDevices([]);
        toast({
            variant: "destructive",
            title: "Failed to load devices",
            description: "Could not connect to the device manager. Please ensure it's running.",
        });
      } finally {
        setLoadingDevices(false);
      }
    }
    fetchDevices();
  }, [toast]);

  const handleRestore = async () => {
    setStatus("pending");
    try {
        const res = await fetch('http://localhost:9758/api/decrypt-and-restore', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ device: selectedDevice, decryptionKey: decryptionKey }),
        });

        const result = await res.json();

        if (!res.ok || result.status !== 'success') {
            throw new Error(result.message || 'Decrypt & Restore process failed.');
        }

        setStatus("success");
        toast({
            title: "Restore Successful",
            description: `Data on ${selectedDevice} has been successfully restored.`,
        });

    } catch (error: any) {
        setStatus("error");
        toast({
          variant: "destructive",
          title: "Restore Failed",
          description: error.message || "An unexpected error occurred during the restore process.",
        })
    }
  };
  
  const isFormInvalid = !selectedDevice || !decryptionKey || status === 'pending';

  return (
    <Card className="max-w-2xl mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <KeyRound className="h-6 w-6" />
          Decrypt & Restore Data
        </CardTitle>
        <CardDescription>
          Restore encrypted data to a device using your backup decryption key.
          This action will overwrite existing data on the target device.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="decryption-key">Decryption Key</Label>
          <Input
            id="decryption-key"
            type="password"
            placeholder="Enter your 256-bit AES key"
            value={decryptionKey}
            onChange={(e) => setDecryptionKey(e.target.value)}
            disabled={status === 'pending'}
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
              <SelectValue placeholder={loadingDevices ? "Loading devices..." : "Select a device to restore to"} />
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
            <div className="flex items-center gap-3 text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                <CheckCircle className="h-6 w-6" />
                <p className="font-semibold">Restore completed successfully.</p>
            </div>
        )}
        {status === 'error' && (
            <div className="flex items-center gap-3 text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                <XCircle className="h-6 w-6" />
                <p className="font-semibold">Restore failed. Please check the logs and try again.</p>
            </div>
        )}
      </CardContent>
      <CardFooter>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button disabled={isFormInvalid} className="w-full">
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
              <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
              <AlertDialogDescription>
                This will overwrite all data on the device{' '}
                <span className="font-bold text-destructive">
                  {selectedDevice}
                </span>{' '}
                with the decrypted backup. This action cannot be undone.
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
  );
}
