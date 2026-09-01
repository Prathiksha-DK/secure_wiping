
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
import { Badge } from "@/components/ui/badge";
import { ShieldCheck, FileDown, CheckCircle, AlertTriangle, Network, User, Clock, HardDrive } from "lucide-react";

const API_BASE = "http://localhost:9758";

interface ReportDetails {
    id: string;
    device: string;
    deviceSerial: string;
    method: string;
    standard: string;
    status: string;
    startTime: string;
    endTime: string;
    filesVerified: number;
    verificationHash: string;
    adOU: string;
    adComputer: string;
    operatorName: string;
    notes: string;
}

async function getReportData(id: string): Promise<ReportDetails | null> {
    try {
        const response = await fetch(`${API_BASE}/api/reports/${id}`, { cache: 'no-store' });
        if (!response.ok) return null;
        const data = await response.json();
        if (data.error) return null;
        return data;
    } catch (error: any) {
        console.error(`Failed to fetch report for ID: ${id}`, error);
        return null;
    }
}


export default async function ReportPage({ params }: { params: { id: string } }) {
    const { id } = await params;
    const report = await getReportData(id);

    if (!report) {
         return (
            <div className="max-w-4xl mx-auto animate-fade-in">
                 <Card>
                    <CardHeader>
                        <CardTitle className="flex items-center gap-2 text-destructive">
                            <AlertTriangle />
                            Certificate Not Found
                        </CardTitle>
                        <CardDescription>
                            Could not load the certificate for ID: <span className="font-mono font-semibold">{id}</span>.
                            Please ensure the backend service is running on port 9758.
                        </CardDescription>
                    </CardHeader>
                </Card>
            </div>
        );
    }

    return (
        <div className="max-w-4xl mx-auto animate-fade-in">
            <Card className="overflow-hidden">
                {/* Certificate Header */}
                <CardHeader className="bg-gradient-to-r from-primary/5 to-accent/5 p-6 border-b">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-4">
                            <div className="p-3 rounded-xl bg-primary/10">
                                <ShieldCheck className="h-10 w-10 text-primary" />
                            </div>
                            <div>
                                <CardTitle className="text-xl">Certificate of Data Sanitization</CardTitle>
                                <CardDescription>
                                    This document certifies that data on the specified device has been securely destroyed
                                    in accordance with applicable standards.
                                </CardDescription>
                            </div>
                        </div>
                        <div className="text-right">
                            <p className="text-xs text-muted-foreground uppercase tracking-wider">Certificate No.</p>
                            <p className="font-mono text-lg font-bold text-primary">{report.id}</p>
                        </div>
                    </div>
                </CardHeader>

                <CardContent className="p-6 md:p-8 space-y-8">
                    {/* Information Grid */}
                    <div className="grid md:grid-cols-2 gap-8">
                        {/* Device Information */}
                        <div className="space-y-4">
                            <h3 className="font-semibold text-base flex items-center gap-2">
                                <HardDrive className="h-4 w-4 text-primary" />
                                Device Information
                            </h3>
                            <div className="space-y-3">
                                <div className="flex justify-between text-sm">
                                    <span className="text-muted-foreground">Device Name</span>
                                    <span className="font-medium">{report.device}</span>
                                </div>
                                <div className="flex justify-between text-sm">
                                    <span className="text-muted-foreground">Serial Number</span>
                                    <span className="font-mono text-xs">{report.deviceSerial}</span>
                                </div>
                            </div>
                        </div>

                        {/* Sanitization Details */}
                        <div className="space-y-4">
                            <h3 className="font-semibold text-base flex items-center gap-2">
                                <ShieldCheck className="h-4 w-4 text-primary" />
                                Sanitization Details
                            </h3>
                            <div className="space-y-3">
                                <div className="flex justify-between text-sm">
                                    <span className="text-muted-foreground">Standard</span>
                                    <Badge variant="secondary">{report.standard || report.method}</Badge>
                                </div>
                                <div className="flex justify-between text-sm">
                                    <span className="text-muted-foreground">Start Time</span>
                                    <span className="text-xs">{report.startTime}</span>
                                </div>
                                <div className="flex justify-between text-sm">
                                    <span className="text-muted-foreground">End Time</span>
                                    <span className="text-xs">{report.endTime}</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <Separator />

                    {/* Active Directory Information */}
                    {(report.adComputer || report.adOU) && (
                        <>
                            <div className="space-y-4">
                                <h3 className="font-semibold text-base flex items-center gap-2">
                                    <Network className="h-4 w-4 text-primary" />
                                    Active Directory Context
                                </h3>
                                <div className="grid md:grid-cols-2 gap-4">
                                    {report.adComputer && (
                                        <div className="flex justify-between text-sm">
                                            <span className="text-muted-foreground">AD Computer</span>
                                            <span className="font-mono text-xs">{report.adComputer}</span>
                                        </div>
                                    )}
                                    {report.adOU && (
                                        <div className="flex justify-between text-sm">
                                            <span className="text-muted-foreground">OU</span>
                                            <span className="font-mono text-xs truncate ml-2">{report.adOU}</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                            <Separator />
                        </>
                    )}

                    {/* Verification */}
                    <div className="space-y-4">
                        <h3 className="font-semibold text-base flex items-center gap-2">
                            <CheckCircle className="h-4 w-4 text-emerald-500" />
                            Verification
                        </h3>
                        <div className="flex items-center gap-3 bg-emerald-50 dark:bg-emerald-900/20 p-4 rounded-lg border border-emerald-200 dark:border-emerald-800">
                            <CheckCircle className="h-5 w-5 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
                            <p className="font-medium text-sm text-emerald-700 dark:text-emerald-300">
                                Verification successful. {report.filesVerified} sector{report.filesVerified !== 1 ? 's' : ''} confirmed as sanitized.
                            </p>
                        </div>
                        {report.verificationHash && (
                            <div>
                                <p className="text-xs text-muted-foreground mb-1">Verification Hash (SHA-256)</p>
                                <p className="font-mono text-xs bg-muted p-3 rounded-lg break-all border">{report.verificationHash}</p>
                            </div>
                        )}
                    </div>
                </CardContent>

                <CardFooter className="bg-muted/30 p-6 flex justify-between items-center border-t">
                    <div className="flex items-center gap-2 text-sm text-muted-foreground">
                        <User className="h-3 w-3" />
                        <span>Operator: {report.operatorName || 'System'}</span>
                        <span className="mx-2">|</span>
                        <Clock className="h-3 w-3" />
                        <span>{report.endTime}</span>
                    </div>
                    <Button variant="outline">
                        <FileDown className="mr-2 h-4 w-4" /> Download Certificate
                    </Button>
                </CardFooter>
            </Card>
        </div>
    );
}
