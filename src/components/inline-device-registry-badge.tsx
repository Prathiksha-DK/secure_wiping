"use client";

import React, { useState, useEffect } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  HardDrive,
  CheckCircle2,
  AlertTriangle,
  PlusCircle,
  Copy,
  Check,
  Info,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

interface DeviceRecord {
  device_id: string;
  device_fingerprint: string;
  manufacturer: string;
  model: string;
  serial_number: string;
  capacity: number;
  capacity_readable: string;
  interface: string;
  device_type: string;
  connection_type: string;
  first_registered_at: number;
  last_seen_at: number;
  registration_status: string;
  created_by: string;
  identity_status?: string;
  current_connection_path?: string;
  mounted_volume?: string;
}

interface ConnectedDeviceItem {
  is_registered: boolean;
  device_id: string | null;
  record: DeviceRecord | null;
  raw_device: any;
  device_fingerprint: string;
  os_device_path: string;
  drive_letters: string[];
  display_name: string;
  proposed_device_id?: string;
  detected_metadata?: {
    manufacturer: string;
    model: string;
    serial_number: string;
    capacity: number;
    capacity_readable: string;
    interface: string;
    device_type: string;
    identity_status?: string;
    current_connection_path?: string;
    mounted_volume?: string;
  };
}

interface InlineDeviceRegistryBadgeProps {
  selectedDeviceIdentifier?: string; // name, friendlyName, devicePath, or drive letter
  rawDevice?: any;
  onRegistrationComplete?: (registeredId: string) => void;
  className?: string;
  compact?: boolean;
}

export default function InlineDeviceRegistryBadge({
  selectedDeviceIdentifier,
  rawDevice,
  onRegistrationComplete,
  className = "",
  compact = false,
}: InlineDeviceRegistryBadgeProps) {
  const [currentDevices, setCurrentDevices] = useState<ConnectedDeviceItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [showDetails, setShowDetails] = useState(!compact);

  const fetchRegistryStatus = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/devices/current", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setCurrentDevices(data.connected_devices || []);
      }
    } catch (err) {
      console.error("Failed to query central device registry:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRegistryStatus();
  }, [selectedDeviceIdentifier]);

  // Find matching device item from registry scan
  const matchedItem = currentDevices.find((item) => {
    if (!selectedDeviceIdentifier && !rawDevice) return false;
    const target = (selectedDeviceIdentifier || "").toLowerCase().trim();
    const rawName = (rawDevice?.name || "").toLowerCase().trim();
    const rawPath = (rawDevice?.devicePath || "").toLowerCase().trim();
    const rawSerial = (rawDevice?.serial || "").toLowerCase().trim();

    const devName = (item.raw_device?.name || "").toLowerCase().trim();
    const devPath = (item.os_device_path || item.raw_device?.devicePath || "").toLowerCase().trim();
    const devSerial = (item.raw_device?.serial || item.record?.serial_number || "").toLowerCase().trim();
    const letters = (item.drive_letters || []).map((l) => l.toLowerCase().trim());

    if (rawSerial && devSerial && rawSerial === devSerial && rawSerial !== "unknown") return true;
    if (target && (devName.includes(target) || target.includes(devName))) return true;
    if (target && devPath && (devPath.includes(target) || target.includes(devPath))) return true;
    if (target && letters.some((l) => target.includes(l) || l.includes(target))) return true;
    if (rawName && devName && (devName.includes(rawName) || rawName.includes(devName))) return true;
    if (rawPath && devPath && (devPath.includes(rawPath) || rawPath.includes(devPath))) return true;

    return false;
  });

  const handleCopy = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleConfirmRegister = async () => {
    if (!matchedItem && !rawDevice) return;
    setRegistering(true);

    const meta = matchedItem?.detected_metadata;
    const raw = matchedItem?.raw_device || rawDevice;

    const payload = {
      manufacturer: meta?.manufacturer || raw?.manufacturer || "Generic",
      model: meta?.model || raw?.name || raw?.friendlyName || "Unknown Storage Device",
      serial_number: meta?.serial_number || raw?.serial || "UNKNOWN",
      capacity: meta?.capacity || raw?.sizeBytes || 0,
      capacity_readable: meta?.capacity_readable || raw?.size || "Unknown",
      interface: meta?.interface || raw?.bus || "USB",
      device_type: meta?.device_type || raw?.type || "USB Storage",
      created_by: "operator",
    };

    try {
      const res = await fetch("http://localhost:9758/api/devices/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (res.ok && data.status === "success") {
        setModalOpen(false);
        await fetchRegistryStatus();
        if (onRegistrationComplete) {
          onRegistrationComplete(data.device_id);
        }
      }
    } catch (err) {
      console.error("Registration error:", err);
    } finally {
      setRegistering(false);
    }
  };

  if (!selectedDeviceIdentifier && !rawDevice) {
    return null;
  }

  const isRegistered = matchedItem?.is_registered ?? false;
  const deviceRecord = matchedItem?.record;
  const deviceId = matchedItem?.device_id || (isRegistered ? deviceRecord?.device_id : null);
  const meta = matchedItem?.detected_metadata;

  return (
    <div className={`rounded-xl border p-3.5 transition-all ${
      isRegistered
        ? "bg-emerald-950/20 border-emerald-500/40 text-slate-200"
        : "bg-amber-950/20 border-amber-500/40 text-slate-200"
    } ${className}`}>
      {/* Header Badge Row */}
      <div className="flex flex-wrap items-center justify-between gap-2.5">
        <div className="flex items-center gap-2">
          {isRegistered ? (
            <>
              <Badge className="bg-emerald-500/20 text-emerald-300 border-emerald-500/40 text-xs font-mono font-bold flex items-center gap-1.5 py-1 px-2.5">
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Registered Device:</span>
                <span className="font-extrabold text-white tracking-wider ml-0.5">{deviceId}</span>
              </Badge>
              <button
                type="button"
                onClick={() => handleCopy(deviceId || "")}
                className="text-slate-400 hover:text-white transition-colors"
                title="Copy SecureWipe Device ID"
              >
                {copiedId ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
              </button>
            </>
          ) : (
            <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/40 text-xs font-mono font-semibold flex items-center gap-1.5 py-1 px-2.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
              <span>New Device (Not registered in Central Registry)</span>
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-2">
          {!isRegistered && (
            <Button
              type="button"
              size="sm"
              onClick={() => setModalOpen(true)}
              className="h-7 text-xs bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg px-3 shadow-md shadow-cyan-950/50 flex items-center gap-1.5"
            >
              <PlusCircle className="h-3.5 w-3.5" />
              <span>Register Device</span>
            </Button>
          )}

          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => setShowDetails(!showDetails)}
            className="h-7 text-[11px] text-slate-400 hover:text-white px-2"
          >
            {showDetails ? (
              <span className="flex items-center gap-1">
                <span>Hide Info</span> <ChevronUp className="h-3 w-3" />
              </span>
            ) : (
              <span className="flex items-center gap-1">
                <span>Device Info</span> <ChevronDown className="h-3 w-3" />
              </span>
            )}
          </Button>
        </div>
      </div>

      {/* Expanded Device Information Section */}
      {showDetails && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-2 text-xs font-mono">
          <div className="text-[10px] uppercase font-bold text-slate-400 tracking-wider flex items-center justify-between">
            <span>DEVICE INFORMATION</span>
            <span className="text-emerald-400 font-normal">
              Identity Status: {deviceRecord?.identity_status || meta?.identity_status || "Verified"}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5 bg-[#060A12]/80 p-3 rounded-lg border border-slate-800/90 text-[11px]">
            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Live Status</span>
              <span className="text-emerald-400 font-semibold flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Connected
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Registration</span>
              <span className={isRegistered ? "text-emerald-300 font-bold" : "text-amber-400 font-bold"}>
                {isRegistered ? "Registered" : "Pending Confirmation"}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">SecureWipe ID</span>
              <span className="text-cyan-300 font-bold">{deviceId || "Unassigned"}</span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Manufacturer</span>
              <span className="text-white">
                {deviceRecord?.manufacturer || meta?.manufacturer || "HP"}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Model</span>
              <span className="text-white">
                {deviceRecord?.model || meta?.model || rawDevice?.name || "Storage Device"}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Capacity</span>
              <span className="text-white">
                {deviceRecord?.capacity_readable || meta?.capacity_readable || rawDevice?.size || "Unknown"}
              </span>
            </div>

            <div className="sm:col-span-2">
              <span className="text-slate-500 text-[10px] block uppercase">Serial Number</span>
              <span className="text-emerald-400 break-all font-mono">
                {deviceRecord?.serial_number || meta?.serial_number || rawDevice?.serial || "UNKNOWN"}
              </span>
            </div>

            <div>
              <span className="text-slate-500 text-[10px] block uppercase">Interface / Bus</span>
              <span className="text-slate-300">
                {deviceRecord?.interface || meta?.interface || rawDevice?.bus || "USB"}
              </span>
            </div>

            <div className="col-span-2 sm:col-span-3 pt-1 border-t border-slate-800/60 flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-400">
              <div>
                <span>Current Connection: </span>
                <strong className="text-slate-200">
                  {deviceRecord?.current_connection_path || meta?.current_connection_path || rawDevice?.devicePath || "\\\\.\\PhysicalDrive1"}
                </strong>
                {((matchedItem?.drive_letters && matchedItem.drive_letters.length > 0) || deviceRecord?.mounted_volume) && (
                  <>
                    <span className="mx-2">•</span>
                    <span>Mounted Volume: </span>
                    <strong className="text-cyan-300">
                      {deviceRecord?.mounted_volume || (matchedItem?.drive_letters || []).join(", ")}
                    </strong>
                  </>
                )}
              </div>
              <div>
                <span>Registered By: </span>
                <strong className="text-slate-300">{deviceRecord?.created_by || "citizen_user"}</strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Inline Registration Confirmation Dialog */}
      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent className="sm:max-w-md bg-[#0B1220] border-slate-800 text-slate-100 shadow-2xl">
          <DialogHeader>
            <div className="flex items-center gap-2 text-cyan-400 mb-1">
              <ShieldCheck className="h-5 w-5" />
              <span className="text-xs font-mono font-semibold uppercase tracking-wider">
                Central Registry Protocol
              </span>
            </div>
            <DialogTitle className="text-base font-bold text-white">
              Register Connected Storage Device
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              Bind this hardware device to a permanent SecureWipe Device ID across Wiping and Recovery workflows.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-3 py-2 text-xs font-mono">
            <div className="p-3 bg-[#060A12] border border-cyan-500/40 rounded-xl flex items-center justify-between">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Proposed SecureWipe ID</span>
                <span className="text-base font-bold text-cyan-300">
                  {matchedItem?.proposed_device_id || "SW-DEV-NEW"}
                </span>
              </div>
              <Badge className="bg-cyan-500/15 text-cyan-300 border-cyan-500/30 text-xs">
                Permanent
              </Badge>
            </div>

            <div className="grid grid-cols-2 gap-2 p-3 bg-[#070C16] border border-slate-800 rounded-xl text-[11px]">
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Hardware</span>
                <span className="text-white">{meta?.model || rawDevice?.name || "USB Drive"}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] block uppercase">Capacity</span>
                <span className="text-white">{meta?.capacity_readable || rawDevice?.size}</span>
              </div>
              <div className="col-span-2">
                <span className="text-slate-500 text-[10px] block uppercase">Serial Number</span>
                <span className="text-emerald-400">{meta?.serial_number || rawDevice?.serial || "UNKNOWN"}</span>
              </div>
            </div>

            <div className="p-2.5 bg-slate-900/60 border border-slate-800 rounded-lg text-[10px] text-slate-400 flex items-start gap-2">
              <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
              <span>
                <strong>Read-Only Metadata Registration:</strong> No sectors, partitions, or files on the physical device will be modified.
              </span>
            </div>
          </div>

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setModalOpen(false)}
              disabled={registering}
              className="border-slate-800 bg-[#060A12] text-xs text-slate-300"
            >
              Cancel
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={handleConfirmRegister}
              disabled={registering}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold px-4 shadow-md flex items-center gap-1.5"
            >
              {registering ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Registering...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>Confirm Registration</span>
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
