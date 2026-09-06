"use client";

import React, { useState, useEffect } from "react";
import {
  HardDrive,
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  PlusCircle,
  Copy,
  Check,
  Info,
  Layers,
  Sparkles,
  Lock,
  ArrowRight,
  Database,
  Radio,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import RegisteredDevicesModal from "@/components/registered-devices-modal";

interface DetectedMetadata {
  manufacturer: string;
  model: string;
  serial_number: string;
  capacity: number;
  capacity_readable: string;
  interface: string;
  device_type: string;
}

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
  detected_metadata?: DetectedMetadata;
}

interface CentralDeviceRegistryCardProps {
  currentPersona?: "individual" | "government" | "forensic" | string;
  onDeviceSelect?: (device: ConnectedDeviceItem) => void;
  className?: string;
}

export default function CentralDeviceRegistryCard({
  currentPersona = "individual",
  onDeviceSelect,
  className = "",
}: CentralDeviceRegistryCardProps) {
  const [connectedDevices, setConnectedDevices] = useState<ConnectedDeviceItem[]>([]);
  const [allRegistered, setAllRegistered] = useState<DeviceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [targetDeviceToRegister, setTargetDeviceToRegister] = useState<ConnectedDeviceItem | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ type: "success" | "error" | "info"; text: string } | null>(null);
  const [viewAllRegistry, setViewAllRegistry] = useState(false);
  const [popupModalOpen, setPopupModalOpen] = useState(false);

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9758/api/devices/current");
      if (res.ok) {
        const data = await res.json();
        setConnectedDevices(data.connected_devices || []);
        setAllRegistered(data.all_registered || []);
      }
    } catch (err) {
      console.error("Failed to query central device registry", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
    // Refresh device list every 15 seconds
    const interval = setInterval(fetchStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleOpenRegisterModal = (devItem: ConnectedDeviceItem) => {
    setTargetDeviceToRegister(devItem);
    setModalOpen(true);
  };

  const handleConfirmRegistration = async () => {
    if (!targetDeviceToRegister) return;
    setRegistering(true);
    setNotice(null);

    const meta = targetDeviceToRegister.detected_metadata;
    const raw = targetDeviceToRegister.raw_device;

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

      const data = await res.json();
      if (res.ok && data.status === "success") {
        setNotice({
          type: "success",
          text: `Device successfully registered: ${data.device_id}. All 3 workspaces now share this identity.`,
        });
        setModalOpen(false);
        setTargetDeviceToRegister(null);
        await fetchStatus();
      } else {
        setNotice({
          type: "error",
          text: data.message || "Registration failed. Please verify connection.",
        });
      }
    } catch (err: any) {
      setNotice({
        type: "error",
        text: err.message || "Failed to reach registration API service.",
      });
    } finally {
      setRegistering(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(text);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const personaColor =
    currentPersona === "government"
      ? "emerald"
      : currentPersona === "forensic"
      ? "amber"
      : "cyan";

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Main Section Header Card */}
      <div className="bg-[#0D1527] border border-slate-800/90 rounded-2xl p-5 shadow-xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-xl bg-${personaColor}-500/10 border border-${personaColor}-500/30 text-${personaColor}-400 shrink-0`}>
              <Database className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-white tracking-tight">Central Device Registry</h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 font-semibold">
                  Unified Hardware Ledger
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Single authoritative identity shared across Individual, Government & Forensic workspaces.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start sm:self-auto">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setPopupModalOpen(true)}
              className="border-cyan-500/40 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 text-xs h-8 px-3 rounded-lg font-semibold flex items-center gap-1.5"
            >
              <Database className="h-3.5 w-3.5 text-cyan-400" />
              <span>Registered Devices ({allRegistered.length})</span>
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={() => setViewAllRegistry(!viewAllRegistry)}
              className="border-slate-800 bg-[#060A12] hover:bg-slate-900 text-slate-300 text-xs h-8 px-3 rounded-lg"
            >
              <Layers className="h-3.5 w-3.5 mr-1.5 text-slate-400" />
              <span>{viewAllRegistry ? "Active Devices" : "Table View"}</span>
            </Button>

            <Button
              variant="outline"
              size="sm"
              onClick={fetchStatus}
              disabled={loading}
              className="border-slate-800 bg-[#060A12] hover:bg-slate-900 text-slate-300 text-xs h-8 px-3 rounded-lg"
              title="Rescan physical devices"
            >
              <RefreshCw className={`h-3.5 w-3.5 text-cyan-400 ${loading ? "animate-spin" : ""}`} />
            </Button>
          </div>
        </div>

        {/* Global Notification Banner */}
        {notice && (
          <div
            className={`mt-4 p-3 rounded-xl border text-xs flex items-center justify-between gap-3 ${
              notice.type === "success"
                ? "border-emerald-500/40 bg-emerald-950/30 text-emerald-200"
                : "border-rose-500/40 bg-rose-950/30 text-rose-200"
            }`}
          >
            <div className="flex items-center gap-2">
              {notice.type === "success" ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0" />
              )}
              <span>{notice.text}</span>
            </div>
            <button
              onClick={() => setNotice(null)}
              className="text-slate-400 hover:text-white text-xs font-mono font-bold"
            >
              ✕
            </button>
          </div>
        )}

        {/* Content: Active Connected Devices vs All Registered */}
        <div className="mt-4 space-y-3">
          {!viewAllRegistry ? (
            /* Active Connected Devices List */
            <>
              {connectedDevices.length > 0 ? (
                connectedDevices.map((dev, idx) => (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border transition-all ${
                      dev.is_registered
                        ? "border-emerald-500/30 bg-gradient-to-r from-emerald-950/20 via-[#0B1220] to-[#0D1527]"
                        : "border-amber-500/40 bg-gradient-to-r from-amber-950/20 via-[#0B1220] to-[#0D1527]"
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                      {/* Left: Device Info */}
                      <div className="flex items-start sm:items-center gap-3.5">
                        <div
                          className={`p-3 rounded-xl shrink-0 ${
                            dev.is_registered
                              ? "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"
                              : "bg-amber-500/10 border border-amber-500/30 text-amber-400"
                          }`}
                        >
                          <HardDrive className="h-6 w-6" />
                        </div>

                        <div className="space-y-1">
                          {/* Device Identity Badge & ID */}
                          <div className="flex flex-wrap items-center gap-2">
                            {dev.is_registered && dev.record ? (
                              <>
                                <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-emerald-500/15 border border-emerald-500/40 text-emerald-300">
                                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                                  {dev.record.device_id}
                                </span>
                                <button
                                  onClick={() => handleCopy(dev.record!.device_id)}
                                  className="text-slate-400 hover:text-white transition-colors"
                                  title="Copy Device ID"
                                >
                                  {copiedId === dev.record.device_id ? (
                                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="h-3.5 w-3.5" />
                                  )}
                                </button>
                                <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[10px] uppercase font-mono">
                                  REGISTERED
                                </Badge>
                              </>
                            ) : (
                              <>
                                <Badge className="bg-amber-500/15 text-amber-300 border-amber-500/40 text-xs font-mono font-bold">
                                  NEW DEVICE DETECTED
                                </Badge>
                                <span className="text-xs text-amber-400/90 font-medium">
                                  Registration Required
                                </span>
                              </>
                            )}
                          </div>

                          {/* Hardware Title */}
                          <div className="font-bold text-sm text-white">
                            {dev.is_registered && dev.record
                              ? `${dev.record.manufacturer} ${dev.record.model}`
                              : dev.raw_device?.name || "Unknown Physical Device"}
                          </div>

                          {/* Hardware Properties Line */}
                          <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3 font-mono">
                            <span>
                              Capacity:{" "}
                              <strong className="text-slate-200">
                                {dev.is_registered && dev.record
                                  ? dev.record.capacity_readable
                                  : dev.raw_device?.size || "Unknown"}
                              </strong>
                            </span>
                            <span>•</span>
                            <span>
                              Interface:{" "}
                              <strong className="text-slate-300">
                                {dev.is_registered && dev.record
                                  ? dev.record.interface
                                  : dev.raw_device?.bus || "USB"}
                              </strong>
                            </span>
                            <span>•</span>
                            <span>
                              Serial:{" "}
                              <strong className="text-slate-300">
                                {dev.is_registered && dev.record
                                  ? dev.record.serial_number
                                  : dev.raw_device?.serial || "UNKNOWN"}
                              </strong>
                            </span>
                            {dev.drive_letters && dev.drive_letters.length > 0 && (
                              <>
                                <span>•</span>
                                <span className="text-cyan-400 font-bold">
                                  Mount: {dev.drive_letters.join(", ")}
                                </span>
                              </>
                            )}
                          </div>

                          {/* Temporary OS mapping indicator */}
                          <div className="text-[11px] text-slate-500 font-mono flex items-center gap-1.5 pt-0.5">
                            <span className="text-slate-400">Current OS Path:</span>
                            <span className="text-slate-300">{dev.os_device_path || "Physical Media"}</span>
                            <span className="text-slate-600">|</span>
                            <span className="text-slate-400">Live Status:</span>
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              CONNECTED
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Right: Actions */}
                      <div className="flex items-center gap-2 self-end md:self-center shrink-0">
                        {dev.is_registered ? (
                          <div className="text-right">
                            <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400/90 font-mono">
                              <ShieldCheck className="h-3.5 w-3.5" />
                              Identified in Central Registry
                            </span>
                            <div className="text-[10px] text-slate-500 font-mono mt-0.5">
                              Registered by: {dev.record?.created_by || "citizen_user"}
                            </div>
                          </div>
                        ) : (
                          <Button
                            size="sm"
                            onClick={() => handleOpenRegisterModal(dev)}
                            className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold h-9 px-4 rounded-xl shadow-lg shadow-cyan-950/40 flex items-center gap-2 transition-all hover:scale-[1.02]"
                          >
                            <PlusCircle className="h-4 w-4" />
                            <span>REGISTER DEVICE</span>
                          </Button>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl space-y-2 bg-[#060A12]/50">
                  <div className="h-10 w-10 mx-auto rounded-full bg-slate-800/80 flex items-center justify-center text-slate-500">
                    <Radio className="h-5 w-5" />
                  </div>
                  <div className="text-xs font-semibold text-slate-300">No Physical Storage Device Connected</div>
                  <p className="text-[11px] text-slate-500 max-w-sm mx-auto">
                    Plug in a USB drive or external storage media. SecureWipe will automatically detect and check registration status.
                  </p>
                </div>
              )}
            </>
          ) : (
            /* All Registered Devices Historical View */
            <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-[#060A12]">
              <table className="w-full text-xs text-left">
                <thead className="bg-[#090F1D] text-slate-400 font-mono uppercase text-[10px] tracking-wider border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Device ID</th>
                    <th className="py-3 px-4">Hardware Model</th>
                    <th className="py-3 px-4">Capacity & Bus</th>
                    <th className="py-3 px-4">Serial Number</th>
                    <th className="py-3 px-4">Live State</th>
                    <th className="py-3 px-4">Registered By</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70 text-slate-300">
                  {allRegistered.map((r, i) => (
                    <tr key={i} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4 font-mono text-cyan-400 font-bold whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span>{r.device_id}</span>
                          <button
                            onClick={() => handleCopy(r.device_id)}
                            className="text-slate-500 hover:text-white"
                          >
                            {copiedId === r.device_id ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      </td>
                      <td className="py-3 px-4 font-medium text-white whitespace-nowrap">
                        {r.manufacturer} {r.model}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                        {r.capacity_readable} • {r.interface}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {r.serial_number}
                      </td>
                      <td className="py-3 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center gap-1.5 text-[10px] font-mono font-semibold px-2 py-0.5 rounded-full border ${
                            r.connection_type === "CONNECTED"
                              ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
                              : "border-slate-700 bg-slate-800 text-slate-400"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              r.connection_type === "CONNECTED" ? "bg-emerald-400" : "bg-slate-500"
                            }`}
                          />
                          {r.connection_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {r.created_by}
                      </td>
                    </tr>
                  ))}
                  {allRegistered.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 px-4 text-center text-slate-500 font-mono text-xs">
                        No devices registered in Central Registry yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Confirmation & Registration Modal */}
      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent className="sm:max-w-lg bg-[#0B1220] border-slate-800 text-slate-100 shadow-2xl">
          <DialogHeader>
            <div className="flex items-center gap-2 text-cyan-400 mb-1">
              <ShieldCheck className="h-5 w-5" />
              <span className="text-xs font-mono font-semibold uppercase tracking-wider">
                Central Registry Protocol
              </span>
            </div>
            <DialogTitle className="text-lg font-bold text-white">
              Confirm Device Registration
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400 leading-relaxed">
              Registering will bind this physical device to a permanent, collision-resistant SecureWipe Device ID across all 3 workspace logins.
            </DialogDescription>
          </DialogHeader>

          {targetDeviceToRegister && (
            <div className="space-y-4 py-2">
              {/* Proposed Device ID Banner */}
              <div className="p-4 rounded-xl bg-[#060A12] border border-cyan-500/40 flex items-center justify-between">
                <div>
                  <div className="text-[10px] text-slate-400 font-mono uppercase tracking-wider font-semibold">
                    SecureWipe Device ID
                  </div>
                  <div className="text-lg font-extrabold font-mono text-cyan-300 mt-0.5">
                    {targetDeviceToRegister.proposed_device_id || "SW-DEV-PROPOSED"}
                  </div>
                </div>
                <Badge className="bg-cyan-500/10 text-cyan-300 border-cyan-500/30 text-xs font-mono">
                  Permanent ID
                </Badge>
              </div>

              {/* Hardware Spec Grid */}
              <div className="grid grid-cols-2 gap-3 text-xs font-mono bg-[#070C16] p-4 rounded-xl border border-slate-800">
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Manufacturer</span>
                  <span className="text-white font-medium">
                    {targetDeviceToRegister.detected_metadata?.manufacturer || "Generic"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Model</span>
                  <span className="text-white font-medium">
                    {targetDeviceToRegister.detected_metadata?.model || targetDeviceToRegister.raw_device?.name}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Capacity</span>
                  <span className="text-white font-medium">
                    {targetDeviceToRegister.detected_metadata?.capacity_readable || targetDeviceToRegister.raw_device?.size}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px] uppercase block">Interface / Bus</span>
                  <span className="text-white font-medium">
                    {targetDeviceToRegister.detected_metadata?.interface || targetDeviceToRegister.raw_device?.bus}
                  </span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500 text-[10px] uppercase block">Hardware Serial</span>
                  <span className="text-emerald-400 font-medium break-all">
                    {targetDeviceToRegister.detected_metadata?.serial_number || targetDeviceToRegister.raw_device?.serial || "UNKNOWN"}
                  </span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] text-slate-400 flex items-start gap-2">
                <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Strict Read-Only Guarantee:</strong> This operation writes only metadata to the platform registry database. No sectors, files, or partitions on the physical device will be modified.
                </span>
              </div>
            </div>
          )}

          <DialogFooter className="gap-2 sm:gap-0">
            <Button
              variant="outline"
              onClick={() => setModalOpen(false)}
              disabled={registering}
              className="border-slate-800 bg-[#060A12] text-xs text-slate-300 hover:text-white"
            >
              CANCEL
            </Button>
            <Button
              onClick={handleConfirmRegistration}
              disabled={registering}
              className="bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold px-4 h-9 shadow-md shadow-cyan-950/40 flex items-center gap-2"
            >
              {registering ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  <span>Registering Device...</span>
                </>
              ) : (
                <>
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>CONFIRM REGISTRATION</span>
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Central Device Registry Popup Modal */}
      <RegisteredDevicesModal
        open={popupModalOpen}
        onOpenChange={setPopupModalOpen}
        currentPersona={currentPersona}
      />
    </div>
  );
}
