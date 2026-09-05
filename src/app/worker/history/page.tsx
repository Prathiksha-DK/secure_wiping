"use client";

import * as React from "react";
import Link from "next/link";
import { MoreHorizontal, FileDown, Search, ShieldCheck, Network, Filter, Loader2 } from "lucide-react";
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

const API_BASE = "http://localhost:9758";

type HistoryItem = {
    id: string;
    device: string;
    deviceSerial: string;
    method: string;
    standard: string;
    status: "Completed" | "Failed" | "In Progress";
    startTime: string;
    endTime: string;
    adOU: string;
    adComputer: string;
    operatorName: string;
    filesVerified: number;
};

export default function HistoryPage() {
  const [historyData, setHistoryData] = React.useState<HistoryItem[]>([]);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchHistory() {
      try {
        const res = await fetch(`${API_BASE}/api/history`, { cache: 'no-store' });
        if (!res.ok) throw new Error("Failed to fetch history");
        const data = await res.json();
        setHistoryData(Array.isArray(data) ? data : []);
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

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Wipe History & Audit Trail</h1>
        <p className="text-muted-foreground">
          Complete log of all data sanitization operations with compliance tracking.
        </p>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5 text-primary" />
              <CardTitle>Sanitization Records</CardTitle>
            </div>
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  type="search"
                  placeholder="Search records..."
                  className="pl-8 w-[250px]"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
              <Button variant="outline" size="sm">
                <FileDown className="mr-2 h-4 w-4" /> Export
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-muted/50">
                  <TableHead>Certificate ID</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Standard</TableHead>
                  <TableHead>Operator</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Date</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10">
                      <div className="flex items-center justify-center gap-2">
                        <Loader2 className="h-5 w-5 animate-spin text-primary" />
                        <span className="text-muted-foreground">Loading records...</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : filteredHistory.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                      No records found.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredHistory.map((item) => (
                    <TableRow key={item.id} className="hover:bg-muted/30">
                      <TableCell>
                        <span className="font-mono text-xs font-semibold text-primary">{item.id}</span>
                      </TableCell>
                      <TableCell>
                        <div className="font-medium text-sm">{item.device}</div>
                        <div className="text-xs text-muted-foreground font-mono">
                          {item.deviceSerial}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs font-normal">
                          {item.standard || item.method}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-xs">{item.operatorName || "Worker"}</span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            item.status === "Completed"
                              ? "default"
                              : item.status === "Failed"
                              ? "destructive"
                              : "secondary"
                          }
                          className={
                            item.status === "Completed"
                              ? "bg-emerald-600 hover:bg-emerald-700 text-white"
                              : ""
                          }
                        >
                          {item.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="text-sm">{item.endTime || item.startTime}</div>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button aria-haspopup="true" size="icon" variant="ghost">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Actions</DropdownMenuLabel>
                            <DropdownMenuItem asChild>
                              <Link href={`/worker/report/${item.id}`}>View Certificate</Link>
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
