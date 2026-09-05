'use client';

import React from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  HardDrive,
  Cpu,
  ShieldCheck,
  CheckCircle2,
  ChevronLeft,
  Loader2,
  AlertTriangle,
  ArrowRight,
  Info,
  Lock
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { CommercialHeader } from '@/components/commercial-header';
import { CommercialFooter } from '@/components/commercial-footer';

const API_BASE = 'http://localhost:9758/api';

export default function RegisterDevicePage() {
  const router = useRouter();

  const [detectedDevices, setDetectedDevices] = React.useState<any[]>([]);
  const [loadingDetected, setLoadingDetected] = React.useState(true);
  const [selectedDetected, setSelectedDetected] = React.useState<string>('');

  // Form state
  const [manufacturer, setManufacturer] = React.useState('');
  const [model, setModel] = React.useState('');
  const [capacityGb, setCapacityGb] = React.useState('1000');
  const [deviceType, setDeviceType] = React.useState('NVMe');
  const [interfaceType, setInterfaceType] = React.useState('NVMe PCIe Gen 4');
  const [serial, setSerial] = React.useState('');
  const [confirmedSafe, setConfirmedSafe] = React.useState(false);

  const [submitting, setSubmitting] = React.useState(false);
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  // Auto-detect attached hardware from local agent
  React.useEffect(() => {
    async function detectHardware() {
      try {
        const res = await fetch(`${API_BASE}/devices`);
        if (res.ok) {
          const data = await res.json();
          // Filter out system disks to ensure safety
          const nonSystem = Array.isArray(data) ? data.filter((d: any) => !d.isSystem) : [];
          setDetectedDevices(nonSystem);
        }
      } catch (e) {
        console.warn('Local agent auto-detection unavailable.');
      } finally {
        setLoadingDetected(false);
      }
    }
    detectHardware();
  }, []);

  function handleAutoSelect(deviceName: string) {
    setSelectedDetected(deviceName);
    const d = detectedDevices.find((x) => x.name === deviceName);
    if (d) {
      setModel(d.model || d.name || '');
      setManufacturer(d.model?.split(' ')[0] || 'Generic');
      if (d.sizeBytes) {
        setCapacityGb(String(Math.round(d.sizeBytes / (1024 ** 3))));
      }
      setDeviceType(d.type || 'SSD');
      setSerial(d.serial || '');
    }
  }

  async function handleRegisterSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!model) {
      setErrorMsg('Device model is required.');
      return;
    }
    if (!confirmedSafe) {
      setErrorMsg('Please confirm that you want to onboard this device.');
      return;
    }

    setSubmitting(true);
    setErrorMsg(null);

    try {
      const capacityBytes = parseInt(capacityGb, 10) * (1024 ** 3);
      const res = await fetch(`${API_BASE}/marketplace/devices/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          manufacturer: manufacturer || 'Generic',
          model,
          capacity_bytes: capacityBytes,
          device_type: deviceType,
          interface: interfaceType,
          serial: serial || 'UNKNOWN',
          health_status: 'Healthy'
        })
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed to register device.');

      const newDeviceId = data.device?.device_id;
      // Navigate to wipe flow
      router.push(`/dashboard/devices/${newDeviceId}/wipe`);
    } catch (err: any) {
      setErrorMsg(err.message || 'Registration failed.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <CommercialHeader />

      <main className="flex-1 py-12">
        <div className="container mx-auto px-4 sm:px-8 max-w-3xl space-y-8">
          {/* Breadcrumb Back */}
          <Link href="/dashboard" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" />
            Back to Dashboard
          </Link>

          {/* Header */}
          <div className="space-y-2">
            <h1 className="text-3xl font-extrabold tracking-tight">Register Storage Device</h1>
            <p className="text-sm text-muted-foreground">
              Add your storage drive to SecureWipe. The platform assigns an anonymous Device ID, keeping your physical serial number private.
            </p>
          </div>

          {/* Step 1: Auto-Detect Hardware */}
          {detectedDevices.length > 0 && (
            <Card className="border-2 border-primary/20 bg-primary/5 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-primary uppercase tracking-wider flex items-center gap-1.5">
                  <Cpu className="h-4 w-4" /> Attached Drives Detected by Local Agent
                </span>
                <Badge variant="outline" className="text-[10px] bg-background">Auto-Detect</Badge>
              </div>

              <div className="space-y-2">
                <Select value={selectedDetected} onValueChange={handleAutoSelect}>
                  <SelectTrigger className="h-10 text-xs bg-background">
                    <SelectValue placeholder="Select an auto-detected connected device..." />
                  </SelectTrigger>
                  <SelectContent>
                    {detectedDevices.map((d) => (
                      <SelectItem key={d.name} value={d.name}>
                        {d.model || d.friendlyName || d.name} ({d.size || 'Unknown Size'} • {d.type})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-[11px] text-muted-foreground">
                  Selecting a detected drive will auto-populate the registration fields below.
                </p>
              </div>
            </Card>
          )}

          {/* Registration Form */}
          <Card className="border p-6 shadow-sm">
            <form onSubmit={handleRegisterSubmit} className="space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="manufacturer" className="text-xs">Manufacturer</Label>
                  <Input
                    id="manufacturer"
                    placeholder="e.g. Samsung, Western Digital, Crucial"
                    value={manufacturer}
                    onChange={(e) => setManufacturer(e.target.value)}
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="model" className="text-xs">Model Name / Number</Label>
                  <Input
                    id="model"
                    placeholder="e.g. 980 PRO NVMe 1TB"
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="type" className="text-xs">Device Type</Label>
                  <Select value={deviceType} onValueChange={setDeviceType}>
                    <SelectTrigger id="type" className="text-xs">
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="NVMe">NVMe M.2 SSD</SelectItem>
                      <SelectItem value="SSD">SATA 2.5&quot; SSD</SelectItem>
                      <SelectItem value="HDD">Mechanical Hard Disk (HDD)</SelectItem>
                      <SelectItem value="USB">External / USB Flash Drive</SelectItem>
                      <SelectItem value="SD">SD / MicroSD Card</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="capacity" className="text-xs">Capacity (GB)</Label>
                  <Input
                    id="capacity"
                    type="number"
                    min="1"
                    placeholder="1000"
                    value={capacityGb}
                    onChange={(e) => setCapacityGb(e.target.value)}
                    required
                  />
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="interface" className="text-xs">Interface</Label>
                  <Input
                    id="interface"
                    placeholder="PCIe 4.0, SATA 6Gb/s, USB 3.2"
                    value={interfaceType}
                    onChange={(e) => setInterfaceType(e.target.value)}
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="serial" className="text-xs flex items-center justify-between">
                  <span>Physical Serial Number</span>
                  <span className="text-muted-foreground text-[10px]">Will be masked for privacy (e.g. S4G****012)</span>
                </Label>
                <Input
                  id="serial"
                  placeholder="Hardware Serial (optional, for anti-misdirection verification)"
                  value={serial}
                  onChange={(e) => setSerial(e.target.value)}
                  className="font-mono text-xs"
                />
              </div>

              {/* Confirmation Checkbox */}
              <div className="pt-2">
                <label className="flex items-start gap-2.5 p-3 rounded-lg border bg-muted/40 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={confirmedSafe}
                    onChange={(e) => setConfirmedSafe(e.target.checked)}
                    className="mt-1 h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary"
                  />
                  <div className="text-xs space-y-0.5">
                    <span className="font-semibold text-foreground block">
                      This is the device I want to sanitize and verify.
                    </span>
                    <span className="text-muted-foreground block">
                      I understand that following registration, multi-pass sanitization will permanently erase all data.
                    </span>
                  </div>
                </label>
              </div>

              {errorMsg && (
                <Alert variant="destructive" className="text-xs">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{errorMsg}</AlertDescription>
                </Alert>
              )}

              <Button type="submit" disabled={submitting} className="w-full h-11 gap-2 bg-gradient-to-r from-primary to-blue-600">
                {submitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Registering Device...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="h-4 w-4" />
                    Register &amp; Proceed to Sanitization
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </Button>
            </form>
          </Card>
        </div>
      </main>

      <CommercialFooter />
    </div>
  );
}
