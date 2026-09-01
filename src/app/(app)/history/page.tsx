
"use client";

import * as React from "react";
import Link from "next/link";
import { MoreHorizontal, FileDown, Search, Download } from "lucide-react";
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
    wipeStatus: "Completed" | "Failed" | "In Progress";
    createdAt: string;
    filesVerified: number;
    receiverEmail: string;
    emailSent: boolean;
};

export default function HistoryPage() {
  const [historyData, setHistoryData] = React.useState<HistoryItem[]>([]);
  const [searchTerm, setSearchTerm] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchHistory() {
      setLoading(true);
      try {
        const res = await fetch('http://localhost:9758/api/history', { cache: 'no-store' });
        if (!res.ok) {
            throw new Error("Failed to fetch history from server.");
        }
        const data = await res.json();
        const mappedData = data.map((item: any) => ({
            shortId: item.id,
            deviceName: item.device,
            wipeStatus: item.status,
            createdAt: item.endTime || item.startTime || (item.created_at ? new Date(item.created_at * 1000).toISOString() : new Date().toISOString()),
            filesVerified: item.filesVerified || 0,
            receiverEmail: item.notes || "system@securewipe.local",
            emailSent: item.status === "Completed"
        }));
        setHistoryData(mappedData);
      } catch (error) {
        console.error("Failed to fetch history data:", error);
        setHistoryData([]); // Clear data on error
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
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle>Wipe History</CardTitle>
            <CardDescription>
              A log of all data wiping operations recorded by the server.
            </CardDescription>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                type="search"
                placeholder="Search history..."
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
              <TableHead>Cert. No.</TableHead>
              <TableHead>Device</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Email Sent</TableHead>
              <TableHead>Date</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center">Loading report history...</TableCell>
              </TableRow>
            ) : filteredHistory.length === 0 ? (
                 <TableRow>
                    <TableCell colSpan={6} className="text-center">No reports found.</TableCell>
                 </TableRow>
            ) : (
              filteredHistory.map((item) => (
                <TableRow key={item.shortId}>
                  <TableCell className="font-mono">{item.shortId}</TableCell>
                  <TableCell>
                    <div className="font-medium">{item.deviceName}</div>
                    <div className="text-xs text-muted-foreground">
                      {item.receiverEmail}
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        item.wipeStatus === "Completed"
                          ? "default"
                          : "destructive"
                      }
                      className={
                        item.wipeStatus === "Completed"
                          ? "bg-green-600 hover:bg-green-700 text-white"
                          : ""
                      }
                    >
                      {item.wipeStatus}
                    </Badge>
                  </TableCell>
                  <TableCell>
                     <Badge variant={item.emailSent ? "secondary" : "outline"}>
                        {item.emailSent ? "Yes" : "No"}
                     </Badge>
                  </TableCell>
                  <TableCell>{new Date(item.createdAt).toLocaleString()}</TableCell>
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
                                <Download className="mr-2 h-4 w-4"/> View Report Data
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
