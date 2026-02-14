"use client";

import { cn } from "@/lib/utils";
import { Globe, Clock, ChevronRight, Search, FileText } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";

const mockScans = [
  {
    id: "1",
    url: "https://api.example.com",
    date: "2024-05-20 14:30",
    status: "COMPLETED",
    findings: 12,
    duration: "4m 20s",
  },
  {
    id: "2",
    url: "https://staging.myapp.io",
    date: "2024-05-19 09:15",
    status: "COMPLETED",
    findings: 3,
    duration: "2m 45s",
  },
  {
    id: "3",
    url: "https://dev-internal.net",
    date: "2024-05-18 16:45",
    status: "FAILED",
    findings: 0,
    duration: "1m 10s",
  },
];

export default function HistoryPage() {
  const router = useRouter();

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold tracking-tight">Scan History</h2>
        <p className="text-zinc-400">Review and analyze your previous security scans.</p>
      </div>

      <div className="grid gap-4">
        {mockScans.map((scan) => (
          <Card
            key={scan.id}
            className="bg-zinc-950/50 border-zinc-800 p-6 hover:bg-zinc-900/50 transition-colors cursor-pointer group"
            onClick={() => router.push(`/dashboard/scan?url=${encodeURIComponent(scan.url)}&id=${scan.id}`)}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div className="flex items-start gap-4">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-zinc-900 border border-zinc-800 group-hover:border-zinc-700 transition-colors">
                  <Globe className="h-6 w-6 text-zinc-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg text-zinc-200">{scan.url}</h3>
                  <div className="flex items-center gap-4 mt-1 text-sm text-zinc-500">
                    <div className="flex items-center gap-1">
                      <Clock className="h-3.5 w-3.5" />
                      {scan.date}
                    </div>
                    <div className="flex items-center gap-1">
                      <Search className="h-3.5 w-3.5" />
                      {scan.duration}
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between md:justify-end gap-6">
                <div className="text-right">
                  <div className="text-xs text-zinc-500 uppercase mb-1">Findings</div>
                  <div className="text-lg font-mono font-semibold text-zinc-200">{scan.findings}</div>
                </div>

                <Badge className={cn(
                  "px-3 py-1",
                  scan.status === "COMPLETED" ? "bg-green-500/10 text-green-500 border-green-500/20" :
                  scan.status === "FAILED" ? "bg-red-500/10 text-red-500 border-red-500/20" :
                  "bg-zinc-500/10 text-zinc-500 border-zinc-500/20"
                )}>
                  {scan.status}
                </Badge>

                <ChevronRight className="h-5 w-5 text-zinc-600 group-hover:text-zinc-400 transition-colors hidden md:block" />
              </div>
            </div>
          </Card>
        ))}
      </div>

      {mockScans.length === 0 && (
        <div className="text-center py-20 border border-dashed border-zinc-800 rounded-xl">
          <FileText className="h-12 w-12 text-zinc-700 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-zinc-400">No scans found</h3>
          <p className="text-sm text-zinc-500 mt-1 mb-6">Launch your first scan to see it here.</p>
          <Button onClick={() => router.push("/dashboard")} variant="outline" className="border-zinc-800 text-zinc-400 hover:text-white">
            Go to Dashboard
          </Button>
        </div>
      )}
    </div>
  );
}
