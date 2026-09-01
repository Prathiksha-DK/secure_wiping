"use client";

import * as React from "react";
import Link from "next/link";
import { MoreHorizontal, FileDown, Search, Download, ShieldCheck, ShieldAlert, ShieldX, Clock } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Input } from "@/components/ui/input";

type HistoryItem = {
  shortId: string;
  deviceName: string;
  deviceSerial: string;
  wipeStatus: string;
  finalState?: string;
  standard: string;
  createdAt: string;
  filesVerified: number;
  operatorName: string;
  notes: string;
};

export default function HistoryPage() {
  const [historyData, setHistoryData] = React.useState<HistoryItem[]>([]);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchHistory() {
      setLoading(true);
      try {
        const res = await fetch("http://localhost:9758/api/history", { cache: "no-store" });
        if (!res.ok) {
          throw new Error("Failed to fetch history from server.");
        }
        const data = await res.json();
        const mappedData = data.map((item: any) => ({
          shortId: item.id,
          deviceName: item.device,
          deviceSerial: item.deviceSerial || "",
          wipeStatus: item.status,
          finalState: item.finalState || (
            item.status === "Completed" ? "SANITIZED_AND_REUSABLE" :
            item.status === "Warning" ? "SANITIZATION_NOT_VERIFIABLE" :
            item.status === "Failed" ? "NON_SANITIZABLE" : ""
          ),
          standard: item.standard || item.method || "Adaptive Sanitization",
          createdAt: item.endTime || item.startTime || (item.created_at ? new Date(item.created_at * 1000).toISOString() : new Date().toISOString()),
          filesVerified: item.filesVerified || 0,
          operatorName: item.operatorName || "Worker",
          notes: item.notes || "",
        }));
        setHistoryData(mappedData);
      } catch (error) {
        console.error("Failed to fetch history data:", error);
        setHistoryData([]);
      } finally {
        setLoading(false);
      }
    }
    fetchHistory();
  }, []);

  const filteredHistory = historyData.filter((item) =>
    Object.values(item).some((value) =>
      String(value).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  const renderStatusBadge = (item: HistoryItem) => {
    const fs = item.finalState || "";
    if (fs === "SANITIZED_AND_REUSABLE" || item.wipeStatus === "Completed") {
      return (
        <Badge className="bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200 border-green-300">
          🟢 Reusable
        </Badge>
      );
    }
    if (fs === "SANITIZATION_NOT_VERIFIABLE" || item.wipeStatus === "Warning") {
      return (
        <Badge className="bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 border-yellow-300">
          🟡 Not Verifiable
        </Badge>
      );
    }
    if (fs === "NON_SANITIZABLE" || item.wipeStatus === "Failed") {
      return (
        <Badge className="bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200 border-red-300">
          🔴 Disposal Required
        </Badge>
      );
    }
    return (
      <Badge variant="outline" className="text-muted-foreground">
        <Clock className="h-3 w-3 mr-1" /> {item.wipeStatus}
      </Badge>
    );
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Sanitization Audit History</CardTitle>
            <CardDescription>
              Government-compliant audit log of all adaptive sanitization and recovery verification operations.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                type="search"
                placeholder="Search sessions or targets..."
                className="pl-8 sm:w-[300px]"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Session / Cert ID</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Method</TableHead>
              <TableHead>Assurance State</TableHead>
              <TableHead>Operator</TableHead>
              <TableHead>Date & Time</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                  Loading sanitization audit history...
                </TableCell>
              </TableRow>
            ) : filteredHistory.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                  No sanitization records found.
                </TableCell>
              </TableRow>
            ) : (
              filteredHistory.map((item) => (
                <TableRow key={item.shortId}>
                  <TableCell className="font-mono text-xs font-semibold">{item.shortId}</TableCell>
                  <TableCell>
                    <div className="font-medium text-sm truncate max-w-[200px]">{item.deviceName}</div>
                    {item.deviceSerial && (
                      <div className="text-[11px] text-muted-foreground font-mono">
                        SN: {item.deviceSerial}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{item.standard}</TableCell>
                  <TableCell>{renderStatusBadge(item)}</TableCell>
                  <TableCell className="text-xs">{item.operatorName}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(item.createdAt).toLocaleString()}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button aria-haspopup="true" size="icon" variant="ghost">
                          <MoreHorizontal className="h-4 w-4" />
                          <span className="sr-only">Toggle menu</span>
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuItem asChild>
                          <Link href={`/report/${item.shortId}`}>View Certificate</Link>
                        </DropdownMenuItem>
                        <DropdownMenuItem asChild>
                          <a href={`http://localhost:9758/api/reports/${item.shortId}`} target="_blank" rel="noopener noreferrer">
                            <Download className="mr-2 h-4 w-4" /> Export Audit JSON
                          </a>
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
