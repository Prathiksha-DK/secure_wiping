"use client";

import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  HardDrive,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  Copy,
  Check,
  Search,
  RefreshCw,
  PlusCircle,
  Database,
  Radio,
  Calendar,
  User,
  Hash,
  Cpu,
  Layers,
  ExternalLink,
} from "lucide-react";

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
  case_id?: string | null;
  evidence_id?: string | null;
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
  };
}

interface RegisteredDevicesModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentPersona?: "individual" | "government" | "forensic" | string;
  onDeviceSelect?: (deviceId: string) => void;
}

export default function RegisteredDevicesModal({
  open,
  onOpenChange,
  currentPersona = "individual",
  onDeviceSelect,
}: RegisteredDevicesModalProps) {
  const [allRegistered, setAllRegistered] = useState<DeviceRecord[]>([]);
  const [connectedDevices, setConnectedDevices] = useState<ConnectedDeviceItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [registering, setRegistering] = useState(false);
  const [targetToRegister, setTargetToRegister] = useState<ConnectedDeviceItem | null>(null);

  const fetchRegistryData = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/devices/current", { cache: "no-store" });
      if (res.ok) {
        const data = await res.json();
        setConnectedDevices(data.connected_devices || []);
        setAllRegistered(data.all_registered || []);
      }
    } catch (err) {
      console.error("Failed to load registered devices:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open) {
      fetchRegistryData();
    }
  }, [open]);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const handleRegisterNew = async (devItem: ConnectedDeviceItem) => {
    setRegistering(true);
    const meta = devItem.detected_metadata;
    const raw = devItem.raw_device;

    const payload = {
      manufacturer: meta?.manufacturer || "Generic",
      model: meta?.model || raw?.name || "Unknown Storage Device",
      serial_number: meta?.serial_number || raw?.serial || "UNKNOWN",
      capacity: meta?.capacity || raw?.sizeBytes || 0,
      capacity_readable: meta?.capacity_readable || raw?.size || "Unknown",
      interface: meta?.interface || raw?.bus || "USB",
      device_type: meta?.device_type || raw?.type || "USB Storage",
      created_by:
        currentPersona === "government"
          ? "gov_officer"
          : currentPersona === "forensic"
          ? "forensic_analyst"
          : "citizen_user",
    };

    try {
      const res = await fetch("http://localhost:9758/api/devices/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        await fetchRegistryData();
        setTargetToRegister(null);
      }
    } catch (err) {
      console.error("Registration error:", err);
    } finally {
      setRegistering(false);
    }
  };

  const formatDate = (timestampSec: number) => {
    if (!timestampSec) return "N/A";
    return new Date(timestampSec * 1000).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  // Filter registered devices by search query
  const filteredRegistered = allRegistered.filter((dev) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase().trim();
    return (
      (dev.device_id || "").toLowerCase().includes(q) ||
      (dev.manufacturer || "").toLowerCase().includes(q) ||
      (dev.model || "").toLowerCase().includes(q) ||
      (dev.serial_number || "").toLowerCase().includes(q) ||
      (dev.interface || "").toLowerCase().includes(q) ||
      (dev.created_by || "").toLowerCase().includes(q) ||
      (dev.mounted_volume || "").toLowerCase().includes(q)
    );
  });

  // Check if each registered device is currently connected
  const getDeviceLiveStatus = (devRecord: DeviceRecord) => {
    const connectedMatch = connectedDevices.find(
      (c) => c.is_registered && c.device_id === devRecord.device_id
    );
    if (connectedMatch) {
      const letters = connectedMatch.drive_letters || [];
      return {
        isConnected: true,
        mount: letters.length > 0 ? letters.join(", ") : "Attached",
        path: connectedMatch.os_device_path || "Live",
      };
    }
    return {
      isConnected: false,
      mount: devRecord.mounted_volume || "Offline",
      path: devRecord.current_connection_path || "Disconnected",
    };
  };

  // Connected but unregistered devices
  const unregisteredConnected = connectedDevices.filter((c) => !c.is_registered);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col p-0 overflow-hidden bg-[#090F1D] border-slate-800 text-slate-100 shadow-2xl">
        {/* Header */}
        <DialogHeader className="p-6 pb-4 border-b border-slate-800 bg-[#0D1527]">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
                <Database className="h-5 w-5" />
              </div>
              <div>
                <DialogTitle className="text-lg font-bold text-white flex items-center gap-2">
                  <span>Central Device Registry</span>
                  <Badge className="bg-cyan-500/15 text-cyan-300 border-cyan-500/40 text-xs font-mono">
                    {allRegistered.length} Registered
                  </Badge>
                </DialogTitle>
                <DialogDescription className="text-xs text-slate-400 mt-0.5">
                  Authoritative hardware identity ledger · Deterministic SW-DEV IDs shared across Individual, Government & Forensic workspaces.
                </DialogDescription>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={fetchRegistryData}
                disabled={loading}
                className="border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-300 text-xs h-8 px-3"
              >
                <RefreshCw className={`h-3.5 w-3.5 mr-1.5 text-cyan-400 ${loading ? "animate-spin" : ""}`} />
                <span>Refresh</span>
              </Button>
            </div>
          </div>

          {/* Search & Filter Bar */}
          <div className="mt-4 flex items-center gap-3">
            <div className="relative flex-1">
              <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <Input
                placeholder="Search by Device ID (SW-DEV-...), Model, Serial, Manufacturer, or Mount..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-9 pl-9 bg-[#060A12] border-slate-800 text-xs text-slate-200 placeholder:text-slate-500 rounded-lg focus-visible:ring-cyan-500"
              />
            </div>
            {searchQuery && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSearchQuery("")}
                className="text-xs text-slate-400 hover:text-white h-9 px-2.5"
              >
                Clear
              </Button>
            )}
          </div>
        </DialogHeader>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-5 max-h-[calc(90vh-180px)]">
          {/* Unregistered Connected Media Alert Banner (if any) */}
          {unregisteredConnected.length > 0 && (
            <div className="p-4 rounded-xl border border-amber-500/50 bg-gradient-to-r from-amber-950/40 via-[#0D1527] to-[#090F1D] space-y-3">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 text-amber-300 text-xs font-bold">
                  <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
                  <span>{unregisteredConnected.length} Connected Media Require Central Registration</span>
                </div>
                <Badge className="bg-amber-500/20 text-amber-300 border-amber-500/40 text-[10px] uppercase font-mono">
                  Action Required
                </Badge>
              </div>

              <div className="grid gap-2">
                {unregisteredConnected.map((item, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg border border-amber-500/30 bg-[#060A12]/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
                  >
                    <div>
                      <div className="font-semibold text-slate-200">
                        {item.detected_metadata?.manufacturer} {item.detected_metadata?.model || item.raw_device?.name}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 flex flex-wrap items-center gap-2 mt-0.5">
                        <span>Capacity: {item.detected_metadata?.capacity_readable || item.raw_device?.size}</span>
                        <span>•</span>
                        <span>Interface: {item.detected_metadata?.interface || item.raw_device?.bus}</span>
                        <span>•</span>
                        <span>Serial: {item.detected_metadata?.serial_number || item.raw_device?.serial}</span>
                        {item.drive_letters && item.drive_letters.length > 0 && (
                          <>
                            <span>•</span>
                            <span className="text-amber-400 font-bold">Mount: {item.drive_letters.join(", ")}</span>
                          </>
                        )}
                      </div>
                    </div>

                    <Button
                      size="sm"
                      onClick={() => handleRegisterNew(item)}
                      disabled={registering}
                      className="bg-amber-600 hover:bg-amber-500 text-white text-xs h-8 px-3 rounded-lg shrink-0 font-semibold flex items-center gap-1.5"
                    >
                      <PlusCircle className="h-3.5 w-3.5" />
                      <span>{registering ? "Registering..." : "Register Device"}</span>
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Registered Devices List */}
          {loading ? (
            <div className="py-12 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
              <RefreshCw className="h-6 w-6 animate-spin text-cyan-400" />
              <span>Querying Central Device Registry ledger...</span>
            </div>
          ) : filteredRegistered.length === 0 ? (
            <div className="py-12 text-center border border-dashed border-slate-800 rounded-xl space-y-2 bg-[#060A12]/50">
              <HardDrive className="h-8 w-8 mx-auto text-slate-600" />
              <div className="text-sm font-semibold text-slate-300">
                {searchQuery ? "No matching registered devices found" : "No Registered Devices in Registry"}
              </div>
              <p className="text-xs text-slate-500 max-w-sm mx-auto">
                {searchQuery
                  ? "Try searching for a different keyword or clear the search filter."
                  : "Connect a storage drive or USB device to register it into the central ledger."}
              </p>
            </div>
          ) : (
            <div className="grid gap-4">
              {filteredRegistered.map((dev) => {
                const liveStatus = getDeviceLiveStatus(dev);
                return (
                  <div
                    key={dev.device_id}
                    className="p-5 rounded-xl border border-slate-800/90 bg-gradient-to-br from-[#0D1527] to-[#060A12] hover:border-slate-700 transition-all space-y-3"
                  >
                    {/* Top Row: Device ID, Badges, Live Status */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 pb-3 border-b border-slate-800/80">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 shadow-sm">
                          <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
                          {dev.device_id}
                        </span>
                        <button
                          onClick={() => handleCopy(dev.device_id, `id-${dev.device_id}`)}
                          className="p-1 rounded text-slate-400 hover:text-white transition-colors"
                          title="Copy Device ID"
                        >
                          {copiedKey === `id-${dev.device_id}` ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                        <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[10px] uppercase font-mono">
                          {dev.registration_status}
                        </Badge>
                      </div>

                      <div className="flex items-center gap-2">
                        {liveStatus.isConnected ? (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
                            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                            LIVE CONNECTED ({liveStatus.mount})
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-mono text-slate-400 bg-slate-800/60 border border-slate-700">
                            <span className="h-2 w-2 rounded-full bg-slate-500" />
                            OFFLINE / DISCONNECTED
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Middle: Hardware Title & Specs Grid */}
                    <div>
                      <h4 className="text-sm font-bold text-white tracking-tight">
                        {dev.manufacturer} {dev.model}
                      </h4>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-2.5 text-xs font-mono">
                        <div className="p-2 rounded-lg bg-[#060A12] border border-slate-800/60">
                          <span className="text-[10px] text-slate-500 uppercase block">Capacity</span>
                          <span className="text-slate-200 font-bold">{dev.capacity_readable}</span>
                        </div>
                        <div className="p-2 rounded-lg bg-[#060A12] border border-slate-800/60">
                          <span className="text-[10px] text-slate-500 uppercase block">Bus Interface</span>
                          <span className="text-slate-200 font-bold">{dev.interface}</span>
                        </div>
                        <div className="p-2 rounded-lg bg-[#060A12] border border-slate-800/60">
                          <span className="text-[10px] text-slate-500 uppercase block">Device Type</span>
                          <span className="text-slate-200 font-bold">{dev.device_type}</span>
                        </div>
                        <div className="p-2 rounded-lg bg-[#060A12] border border-slate-800/60">
                          <span className="text-[10px] text-slate-500 uppercase block">Serial Number</span>
                          <span className="text-slate-200 font-bold truncate block">{dev.serial_number}</span>
                        </div>
                      </div>
                    </div>

                    {/* Bottom: SHA-256 Fingerprint, Registered By, Timestamps */}
                    <div className="pt-2 border-t border-slate-800/60 space-y-2 text-[11px] font-mono text-slate-400">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <div className="flex items-center gap-1.5 text-slate-500">
                          <Hash className="h-3 w-3 text-cyan-400" />
                          <span>Hardware SHA-256 Fingerprint:</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-slate-300 truncate max-w-xs sm:max-w-md bg-[#060A12] px-2 py-0.5 rounded border border-slate-800">
                            {dev.device_fingerprint}
                          </span>
                          <button
                            onClick={() => handleCopy(dev.device_fingerprint, `fp-${dev.device_id}`)}
                            className="text-cyan-400 hover:text-cyan-300 p-0.5"
                            title="Copy Fingerprint"
                          >
                            {copiedKey === `fp-${dev.device_id}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-500">
                        <div className="flex items-center gap-1.5">
                          <User className="h-3 w-3 text-slate-400" />
                          <span>Registered by: <strong className="text-slate-300">{dev.created_by}</strong></span>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="flex items-center gap-1">
                            <Calendar className="h-3 w-3 text-slate-400" />
                            <span>First Registered: {formatDate(dev.first_registered_at)}</span>
                          </div>
                          <span>•</span>
                          <div>Last Seen: {formatDate(dev.last_seen_at)}</div>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-[#0D1527] flex items-center justify-between">
          <div className="text-xs text-slate-400 font-mono">
            Showing {filteredRegistered.length} of {allRegistered.length} registered storage devices
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
            className="border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 text-xs h-8 px-4"
          >
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
