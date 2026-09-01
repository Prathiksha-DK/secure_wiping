
import {
    Card,
    CardContent,
    CardDescription,
    CardHeader,
    CardTitle,
    CardFooter
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { ShieldCheck, FileDown, CheckCircle, AlertTriangle } from "lucide-react";

interface ReportDetails {
    reportId: string;
    shortId?: string;
    deviceName: string;
    deviceSerial: string;
    deviceType: string;
    wipeMethod: string;
    wipeStatus: string;
    startTime: string;
    endTime: string;
    filesVerified: number;
    verificationHashes: string[];
}

async function getReportData(id: string): Promise<ReportDetails | null> {
    try {
        const response = await fetch(`http://localhost:9758/api/reports/${id}`);
        if (!response.ok) {
            throw new Error(`Server responded with status: ${response.status}`);
        }
        const report = await response.json();
        return {
            reportId: report.id,
            shortId: report.id.substring(0, 8),
            deviceName: report.device,
            deviceSerial: report.deviceSerial || "SN-UNKNOWN",
            deviceType: report.device.toLowerCase().includes("ssd") ? "SSD" : "HDD",
            wipeMethod: report.standard || report.method,
            wipeStatus: report.status,
            startTime: report.startTime,
            endTime: report.endTime,
            filesVerified: report.filesVerified || 0,
            verificationHashes: report.verificationHash ? [report.verificationHash] : [],
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
                            Could Not Load Report
                        </CardTitle>
                        <CardDescription>
                            There was an error fetching the certificate data. Please ensure the backend server is running on port 9758 and that a valid report ID ({params.id}) was provided.
                        </CardDescription>
                    </CardHeader>
                </Card>
            </div>
        );
    }
    
    // Select a hash to display, for example the first one.
    const displayHash = report.verificationHashes && report.verificationHashes.length > 0
        ? report.verificationHashes[0]
        : 'No hash available';

    return (
        <div className="max-w-4xl mx-auto">
            <Card className="overflow-hidden">
                <CardHeader className="bg-muted/50 p-6">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <ShieldCheck className="h-12 w-12 text-primary" />
                            <div>
                                <CardTitle className="text-2xl">Certificate of Data Erasure</CardTitle>
                                <CardDescription>This document certifies that the data on the specified device has been securely erased.</CardDescription>
                            </div>
                        </div>
                        <div className="text-right">
                            <p className="font-semibold text-muted-foreground">Certificate No.</p>
                            <p className="font-mono text-sm">{report.shortId || report.reportId}</p>
                        </div>
                    </div>
                </CardHeader>
                <CardContent className="p-6 md:p-8">
                    <div className="grid md:grid-cols-2 gap-8">
                        <div className="space-y-4">
                            <h3 className="font-semibold text-lg">Device Information</h3>
                            <div className="grid grid-cols-2 gap-2 text-sm">
                                <p className="text-muted-foreground">Device Name</p><p className="font-medium">{report.deviceName}</p>
                                <p className="text-muted-foreground">Serial Number</p><p className="font-medium font-mono">{report.deviceSerial}</p>
                                <p className="text-muted-foreground">Device Type</p><p className="font-medium">{report.deviceType}</p>
                            </div>
                        </div>
                        <div className="space-y-4">
                            <h3 className="font-semibold text-lg">Wipe Details</h3>
                            <div className="grid grid-cols-2 gap-2 text-sm">
                                <p className="text-muted-foreground">Wipe Method</p><p className="font-medium">{report.wipeMethod}</p>
                                <p className="text-muted-foreground">Start Time</p><p className="font-medium">{report.startTime}</p>
                                <p className="text-muted-foreground">End Time</p><p className="font-medium">{report.endTime}</p>
                            </div>
                        </div>
                    </div>
                    <Separator className="my-8" />
                    <div className="space-y-4">
                        <h3 className="font-semibold text-lg">Verification</h3>
                        <div className="flex items-center gap-3 text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                            <CheckCircle className="h-6 w-6" />
                            <p className="font-semibold">Verification successful. {report.filesVerified} file hashes confirmed as erased.</p>
                        </div>
                        <div>
                             <p className="text-sm text-muted-foreground mb-1">Sample Verification Hash (SHA-256)</p>
                             <p className="font-mono text-xs bg-muted p-3 rounded-md break-all">{displayHash}</p>
                        </div>
                    </div>
                </CardContent>
                <CardFooter className="bg-muted/50 p-6 flex justify-between items-center">
                    <p className="text-sm text-muted-foreground">Digitally signed by SecureWipe | {new Date(report.endTime).toLocaleDateString()}</p>
                     <a href={`http://localhost:9758/api/reports/${report.reportId}`} target="_blank" rel="noopener noreferrer">
                        <Button><FileDown className="mr-2 h-4 w-4"/>View Certificate Data</Button>
                    </a>
                </CardFooter>
            </Card>
        </div>
    );
}
