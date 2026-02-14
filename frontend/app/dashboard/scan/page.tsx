"use client";

import { Shield, Clock, Activity, AlertTriangle, X, Globe } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense } from "react";

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const targetUrl = searchParams.get("url") || "https://example.com";

  const [elapsed, setElapsed] = useState(0);
  const [requests, setRequests] = useState(0);

  useEffect(() => {
    // Simulate scan progress
    const timer = setInterval(() => {
      setElapsed((prev) => prev + 1);
      setRequests((prev) => prev + Math.floor(Math.random() * 3));
    }, 1000);

    return () => clearInterval(timer);
  }, []);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  };

  const handleCancel = () => {
    router.push("/dashboard");
  };

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Header */}
      <header className="border-b border-zinc-800 px-8 py-3">
        <div className="flex items-center justify-between">
          {/* Left: Logo and Status */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <h1 className="text-lg font-semibold">SENTINEL</h1>
              </div>
            </div>

            <Badge className="bg-yellow-500/10 text-yellow-500 border-yellow-500/20 hover:bg-yellow-500/10">
              <Activity className="h-3 w-3 mr-1 animate-pulse" />
              RUNNING
            </Badge>

            <div className="flex items-center gap-2 text-sm text-zinc-400">
              <Globe className="h-4 w-4" />
              <span>{targetUrl}</span>
            </div>
          </div>

          {/* Right: Stats and Cancel */}
          <div className="flex items-center gap-8">
            {/* Stats */}
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-xs text-zinc-500 uppercase mb-1">Elapsed</div>
                <div className="flex items-center gap-2">
                  <Clock className="h-4 w-4 text-zinc-400" />
                  <span className="text-lg font-mono font-semibold">{formatTime(elapsed)}</span>
                </div>
              </div>

              <div className="text-center">
                <div className="text-xs text-zinc-500 uppercase mb-1">Requests</div>
                <div className="text-lg font-mono font-semibold">{requests}</div>
              </div>

              <div className="text-center">
                <div className="text-xs text-zinc-500 uppercase mb-1">Findings</div>
                <div className="text-lg font-mono font-semibold">0</div>
              </div>

              <div className="text-center">
                <div className="text-xs text-zinc-500 uppercase mb-1">Score</div>
                <div
                  className="text-2xl font-bold font-mono rounded-full w-12 h-12 flex items-center justify-center border-2 border-zinc-700 text-zinc-500"
                >
                  -
                </div>
              </div>
            </div>

            {/* Cancel Button */}
            <Button
              onClick={handleCancel}
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              <X className="h-4 w-4 mr-2" />
              Cancel
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content - Scan Details */}
      <main className="container mx-auto max-w-6xl px-8 py-8">
        <div className="space-y-6">
          <div className="text-center py-12">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-zinc-900 border border-zinc-800 mb-4">
              <Activity className="h-8 w-8 text-zinc-400 animate-pulse" />
            </div>
            <h2 className="text-2xl font-bold mb-2">Scanning in Progress</h2>
            <p className="text-zinc-400">
              Three agents are analyzing the target application...
            </p>
          </div>

          {/* Agent Status Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-6">
              <div className="flex items-center gap-3 mb-2">
                <div className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse" />
                <h3 className="font-semibold">Exposure Mapper</h3>
              </div>
              <p className="text-sm text-zinc-400">Mapping attack surface...</p>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-6">
              <div className="flex items-center gap-3 mb-2">
                <div className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse" />
                <h3 className="font-semibold">Headers & TLS</h3>
              </div>
              <p className="text-sm text-zinc-400">Analyzing security headers...</p>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-6">
              <div className="flex items-center gap-3 mb-2">
                <div className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse" />
                <h3 className="font-semibold">Auth & Abuse</h3>
              </div>
              <p className="text-sm text-zinc-400">Testing authentication...</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function ScanPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-black text-white flex items-center justify-center">Loading...</div>}>
      <ScanContent />
    </Suspense>
  );
}
