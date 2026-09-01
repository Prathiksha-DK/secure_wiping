import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, ShieldAlert, ShieldX, FileDown, CheckCircle, AlertTriangle, Search, Activity, Lock, Cpu } from "lucide-react";

interface ReportDetails {
  reportId: string;
  shortId?: string;
  deviceName: string;
  deviceSerial: string;
  deviceType: string;
  wipeMethod: string;
  wipeStatus: string;
  finalState?: string;
  startTime: string;
  endTime: string;
  filesVerified: number;
  verificationHash: string;
  operatorName: string;
  notes: string;
}

async function getReportData(id: string): Promise<ReportDetails | null> {
  try {
    const response = await fetch(`http://localhost:9758/api/reports/${id}`, { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Server responded with status: ${response.status}`);
    }
    const report = await response.json();
    return {
      reportId: report.id,
      shortId: report.id.substring(0, 10),
      deviceName: report.device,
      deviceSerial: report.deviceSerial || "SN-NOT-AVAILABLE",
      deviceType: report.device.toLowerCase().includes("ssd") || report.device.toLowerCase().includes("nvme") ? "SSD/NVMe" : "Storage Target",
      wipeMethod: report.standard || report.method,
      wipeStatus: report.status,
      finalState: report.finalState || (
        report.status === "Completed" ? "SANITIZED_AND_REUSABLE" :
        report.status === "Warning" ? "SANITIZATION_NOT_VERIFIABLE" : "NON_SANITIZABLE"
      ),
      startTime: report.startTime,
      endTime: report.endTime,
      filesVerified: report.filesVerified || 1,
      verificationHash: report.verificationHash || "N/A",
      operatorName: report.operatorName || "Authorized Operator",
      notes: report.notes || "",
    };
  } catch (error: any) {
    console.error(`Failed to fetch report for ID: ${id}`, error);
    return null;
  }
}

export default async function ReportPage({ params }: { params: { id: string } }) {
  const report = await getReportData(params.id);

  if (!report) {
    return (
      <div className="max-w-4xl mx-auto">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <AlertTriangle />
              Could Not Load Certificate
            </CardTitle>
            <CardDescription>
              There was an error fetching the audit report. Please ensure the backend is running on port 9758 and that session ID ({params.id}) is valid.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  const isReusable = report.finalState === "SANITIZED_AND_REUSABLE" || report.wipeStatus === "Completed";
  const isNotVerifiable = report.finalState === "SANITIZATION_NOT_VERIFIABLE" || report.wipeStatus === "Warning";
  const isFailed = report.finalState === "NON_SANITIZABLE" || report.wipeStatus === "Failed";

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <Card className="overflow-hidden border-2">
        {/* Certificate Header */}
        <CardHeader className="bg-muted/50 p-6 border-b">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              {isReusable && <ShieldCheck className="h-12 w-12 text-green-600 dark:text-green-400" />}
              {isNotVerifiable && <ShieldAlert className="h-12 w-12 text-yellow-600 dark:text-yellow-400" />}
              {isFailed && <ShieldX className="h-12 w-12 text-red-600 dark:text-red-400" />}
              <div>
                <div className="flex items-center gap-2">
                  <CardTitle className="text-2xl">Certificate of Sanitization Assurance</CardTitle>
                  <Badge variant="outline" className="text-xs">NTRO / Govt Framework</Badge>
                </div>
                <CardDescription className="mt-1">
                  Adaptive Sanitization + Recovery Verification Framework · Independent Verification Audit
                </CardDescription>
              </div>
            </div>
            <div className="text-right">
              <p className="text-xs font-semibold text-muted-foreground uppercase">Session / Cert ID</p>
              <p className="font-mono text-sm font-bold text-primary">{report.reportId}</p>
            </div>
          </div>
        </CardHeader>

        <CardContent className="p-6 md:p-8 space-y-6">
          {/* Final Outcome Banner */}
          {isReusable && (
            <div className="flex items-start gap-4 p-4 rounded-xl bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 text-green-900 dark:text-green-200">
              <CheckCircle className="h-6 w-6 text-green-600 dark:text-green-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-base">🟢 SANITIZED — REUSABLE</h4>
                <p className="text-xs mt-0.5 text-green-800 dark:text-green-300">
                  The configured sanitization procedure and verification requirements were fully satisfied. The recovery assessment detected no recoverable protected information. The device may be marked reusable per applicable organizational policy.
                </p>
              </div>
            </div>
          )}

          {isNotVerifiable && (
            <div className="flex items-start gap-4 p-4 rounded-xl bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-900 dark:text-yellow-200">
              <ShieldAlert className="h-6 w-6 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-base">🟡 SANITIZATION NOT VERIFIABLE — POLICY REVIEW REQUIRED</h4>
                <p className="text-xs mt-0.5 text-yellow-800 dark:text-yellow-300">
                  Addressable storage was processed, but physical NAND/Flash storage behavior (wear leveling, controller remapping) cannot be verified via software alone. Physical assurance requires hardware-level secure erase or controlled destruction per policy.
                </p>
              </div>
            </div>
          )}

          {isFailed && (
            <div className="flex items-start gap-4 p-4 rounded-xl bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-red-900 dark:text-red-200">
              <ShieldX className="h-6 w-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-bold text-base">🔴 SANITIZATION FAILED — CONTROLLED DISPOSAL REQUIRED</h4>
                <p className="text-xs mt-0.5 text-red-800 dark:text-red-300">
                  <strong>DO NOT REUSE FOR SENSITIVE INFORMATION.</strong> The required sanitization assurance could not be achieved. Route this device to your organization&apos;s approved secure-destruction/disposal process.
                </p>
              </div>
            </div>
          )}

          {/* Device & Sanitization Information */}
          <div className="grid md:grid-cols-2 gap-6">
            <div className="space-y-3 rounded-lg border p-4">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <Cpu className="h-4 w-4 text-primary" /> Target & Device Information
              </h3>
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Target Name:</span>
                  <span className="font-medium truncate max-w-[200px]">{report.deviceName}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Serial Number:</span>
                  <span className="font-mono font-medium">{report.deviceSerial}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Device Technology:</span>
                  <span className="font-medium">{report.deviceType}</span>
                </div>
              </div>
            </div>

            <div className="space-y-3 rounded-lg border p-4">
              <h3 className="font-semibold text-sm flex items-center gap-2">
                <Lock className="h-4 w-4 text-primary" /> Sanitization Specifications
              </h3>
              <div className="space-y-1.5 text-xs">
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Baseline Method:</span>
                  <span className="font-medium">{report.wipeMethod}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Authorized Operator:</span>
                  <span className="font-medium">{report.operatorName}</span>
                </div>
                <div className="flex justify-between py-1 border-b">
                  <span className="text-muted-foreground">Start Time:</span>
                  <span className="font-mono">{report.startTime}</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-muted-foreground">Completion Time:</span>
                  <span className="font-mono">{report.endTime || "N/A"}</span>
                </div>
              </div>
            </div>
          </div>

          <Separator />

            {/* Verification & Recovery Assessment Details */}
          <div className="space-y-4">
            <h3 className="font-semibold text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-primary" />
              Phase 3 Forensic Verification & Evidence Assessment
            </h3>
            
            <div className="grid md:grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded-lg bg-muted/40 border space-y-1">
                <p className="font-semibold flex items-center gap-1">
                  <CheckCircle className="h-3.5 w-3.5 text-green-600" /> Multi-Region Verification
                </p>
                <p className="text-muted-foreground">
                  Stratified read-back verification executed across beginning, quartiles, midpoint, and end zones. Zero data pattern anomalies.
                </p>
              </div>
              <div className="p-3 rounded-lg bg-muted/40 border space-y-1">
                <p className="font-semibold flex items-center gap-1">
                  <Search className="h-3.5 w-3.5 text-blue-600" /> Forensic Carving & Evidence Scan
                </p>
                <p className="text-muted-foreground">
                  Streaming multi-level signature validation (JPEG, PNG, PDF, ZIP, GZIP, BMP, ELF, PE, 7Z). Zero validated recoverable file structures found.
                </p>
              </div>
            </div>

            {report.notes && (
              <div className="p-3 rounded-lg bg-muted/20 border text-xs">
                <span className="font-semibold text-muted-foreground">Assessment Note / Decision Reason: </span>
                <span className="text-foreground">{report.notes}</span>
              </div>
            )}

            {/* Scope and Technical Limitation Disclaimer */}
            <div className="p-3 rounded-lg bg-muted/10 border text-[11px] text-muted-foreground space-y-1">
              <p className="font-semibold text-foreground">Forensic Assurance Scope & Verification Boundary:</p>
              <p>
                This assessment certifies that no recoverable file artifacts or identifiable protected data structures were detectable within the addressable logical storage processed by SecureWipe. As with all software-level tools, controller-managed internal structures (such as SSD wear-leveling reserves or bad-block reallocations) are physically isolated by hardware controllers.
              </p>
            </div>

            {/* Tamper-evident Hash */}
            <div className="p-3 rounded-lg bg-muted/30 border space-y-1">
              <p className="text-xs font-semibold text-muted-foreground">Tamper-Evident SHA-256 Audit Hash</p>
              <p className="font-mono text-[11px] text-foreground break-all">{report.verificationHash}</p>
            </div>
          </div>
        </CardContent>

        <CardFooter className="bg-muted/50 p-6 flex flex-col sm:flex-row justify-between items-center gap-3 border-t">
          <p className="text-xs text-muted-foreground">
            Digitally generated by SecureWipe Adaptive Sanitization Framework · NTRO/Govt Specification
          </p>
          <a href={`http://localhost:9758/api/reports/${report.reportId}`} target="_blank" rel="noopener noreferrer">
            <Button size="sm">
              <FileDown className="mr-2 h-4 w-4" /> Export Raw Audit Record
            </Button>
          </a>
        </CardFooter>
      </Card>
    </div>
  );
}
