"use client";

import { Shield, Clock, Activity, AlertTriangle, X, Globe, Search, ShieldCheck, Lock, Terminal, List, LayoutDashboard } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense, useRef, useCallback } from "react";
import { AgentCard } from "@/components/AgentCard";
import { SeverityBadge } from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";

interface LogEntry {
  id: string;
  timestamp: string;
  agent: string;
  message: string;
  type: "info" | "warning" | "error" | "success";
}

interface Finding {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  agent: string;
  description: string;
}

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const targetUrl = searchParams.get("url") || "https://example.com";

  const [elapsed, setElapsed] = useState(0);
  const [requests, setRequests] = useState(0);
  const [status, setStatus] = useState<"running" | "completed">("running");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);

  const scrollRef = useRef<HTMLDivElement>(null);

  const addLog = useCallback((agent: string, message: string, type: LogEntry["type"]) => {
    const newLog: LogEntry = {
      id: Math.random().toString(36).substring(2, 11),
      timestamp: new Date().toLocaleTimeString(),
      agent,
      message,
      type
    };
    setLogs(prev => [...prev, newLog]);
  }, []);

  const addFinding = useCallback((title: string, severity: Finding["severity"], agent: string, description: string) => {
    const newFinding: Finding = {
      id: Math.random().toString(36).substring(2, 11),
      title,
      severity,
      agent,
      description
    };
    setFindings(prev => [newFinding, ...prev]);
  }, []);

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((prev) => {
        if (prev >= 60) {
          setStatus("completed");
          clearInterval(timer);
          return prev;
        }
        return prev + 1;
      });
      setRequests((prev) => prev + Math.floor(Math.random() * 5));
    }, 1000);

    // Initial logs - wrap in timeout to avoid synchronous setState in effect
    const initLogs = setTimeout(() => {
      addLog("system", "Initializing Sentinel security engine...", "info");
      addLog("system", `Target: ${targetUrl}`, "info");
    }, 0);

    // Simulate events
    const timeouts = [
      setTimeout(() => addLog("exposure", "Starting subpath discovery...", "info"), 2000),
      setTimeout(() => addLog("headers", "Fetching security headers...", "info"), 3500),
      setTimeout(() => {
        addLog("headers", "Missing Content-Security-Policy header", "warning");
        addFinding("Missing CSP Header", "medium", "headers", "The application does not implement a Content Security Policy.");
      }, 7000),
      setTimeout(() => addLog("exposure", "Discovered 14 endpoints", "success"), 12000),
      setTimeout(() => {
        addLog("auth", "Testing for common administrative paths...", "info");
        addLog("auth", "Accessible /admin panel found without authentication!", "error");
        addFinding("Unauthenticated Admin Access", "critical", "auth", "The /admin endpoint is accessible without any authentication credentials.");
      }, 18000),
      setTimeout(() => addLog("headers", "TLS configuration is valid (v1.3)", "success"), 25000),
    ];

    return () => {
      clearInterval(timer);
      clearTimeout(initLogs);
      timeouts.forEach(t => clearTimeout(t));
    };
  }, [addLog, addFinding, targetUrl]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, "0")}:${String(secs).padStart(2, "0")}`;
  };

  return (
    <div className="space-y-6 pb-10">
      {/* Scan Header Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 bg-zinc-950 border border-zinc-800 rounded-2xl p-6">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-zinc-900 border border-zinc-800">
            <Activity className={cn("h-6 w-6", status === "running" ? "text-yellow-500 animate-pulse" : "text-green-500")} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white uppercase tracking-tight">
                {status === "running" ? "Scan in Progress" : "Scan Completed"}
              </h2>
              <Badge variant="outline" className={status === "running" ? "border-yellow-500/50 text-yellow-500" : "border-green-500/50 text-green-500"}>
                {status.toUpperCase()}
              </Badge>
            </div>
            <div className="flex items-center gap-2 text-sm text-zinc-500 mt-1">
              <Globe className="h-3.5 w-3.5" />
              <span>{targetUrl}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-8">
          <div className="text-center">
            <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">Elapsed</div>
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-zinc-400" />
              <span className="text-xl font-mono font-bold text-zinc-200">{formatTime(elapsed)}</span>
            </div>
          </div>

          <div className="text-center">
            <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">Requests</div>
            <div className="text-xl font-mono font-bold text-zinc-200">{requests}</div>
          </div>

          <div className="text-center">
            <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">Findings</div>
            <div className="text-xl font-mono font-bold text-red-500">{findings.length}</div>
          </div>

          <Button
            variant={status === "running" ? "destructive" : "outline"}
            onClick={() => router.push("/dashboard")}
            className="ml-4"
          >
            {status === "running" ? <><X className="h-4 w-4 mr-2" /> Stop</> : "Done"}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="bg-zinc-900 border border-zinc-800 mb-6 p-1">
          <TabsTrigger value="overview" className="data-[state=active]:bg-zinc-800">
            <LayoutDashboard className="h-4 w-4 mr-2" /> Overview
          </TabsTrigger>
          <TabsTrigger value="findings" className="data-[state=active]:bg-zinc-800">
            <List className="h-4 w-4 mr-2" /> Findings
            {findings.length > 0 && (
              <span className="ml-2 bg-red-500 text-white text-[10px] px-1.5 py-0.5 rounded-full">
                {findings.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="console" className="data-[state=active]:bg-zinc-800">
            <Terminal className="h-4 w-4 mr-2" /> Live Console
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <AgentCard
              icon={Search}
              title="Exposure Mapper"
              description={elapsed < 15 ? "Scanning endpoints..." : "Completed surface mapping"}
              status={elapsed < 15 ? "running" : "completed"}
            />
            <AgentCard
              icon={ShieldCheck}
              title="Headers & TLS"
              description={elapsed < 30 ? "Analyzing security headers..." : "Analysis finished"}
              status={elapsed < 30 ? "running" : "completed"}
            />
            <AgentCard
              icon={Lock}
              title="Auth & Abuse"
              description={status === "running" ? "Testing auth mechanisms..." : "Tests finished"}
              status={status === "running" ? "running" : "completed"}
            />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                Latest Findings
              </h3>
              <div className="space-y-4">
                {findings.slice(0, 3).map(finding => (
                  <div key={finding.id} className="flex items-center justify-between p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
                    <div>
                      <p className="font-medium text-sm text-zinc-200">{finding.title}</p>
                      <p className="text-xs text-zinc-500 uppercase mt-1">{finding.agent}</p>
                    </div>
                    <SeverityBadge severity={finding.severity} />
                  </div>
                ))}
                {findings.length === 0 && (
                  <p className="text-sm text-zinc-500 text-center py-10">No findings yet. Analysis in progress...</p>
                )}
              </div>
            </div>

            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <Terminal className="h-5 w-5 text-zinc-400" />
                Live Events
              </h3>
              <div className="space-y-2 font-mono text-[11px]">
                {logs.slice(-5).map(log => (
                  <div key={log.id} className="flex gap-3">
                    <span className="text-zinc-600">[{log.timestamp}]</span>
                    <span className={cn(
                      "font-bold uppercase w-16",
                      log.type === "info" && "text-blue-400",
                      log.type === "warning" && "text-yellow-400",
                      log.type === "error" && "text-red-400",
                      log.type === "success" && "text-green-400",
                    )}>{log.agent}</span>
                    <span className="text-zinc-300">{log.message}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="findings">
          <div className="space-y-4">
            {findings.map(finding => (
              <div key={finding.id} className="bg-zinc-950 border border-zinc-800 rounded-xl p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-bold text-zinc-200">{finding.title}</h3>
                      <SeverityBadge severity={finding.severity} />
                    </div>
                    <p className="text-xs text-zinc-500 uppercase tracking-widest">{finding.agent} Agent</p>
                  </div>
                </div>
                <p className="text-sm text-zinc-400 leading-relaxed max-w-3xl">
                  {finding.description}
                </p>
                <div className="mt-4 pt-4 border-t border-zinc-800 flex gap-2">
                  <Button size="sm" variant="outline" className="text-xs h-8 border-zinc-800">View Evidence</Button>
                  <Button size="sm" variant="outline" className="text-xs h-8 border-zinc-800">Remediation Guide</Button>
                </div>
              </div>
            ))}
            {findings.length === 0 && (
              <div className="text-center py-20 bg-zinc-950 border border-zinc-800 rounded-xl">
                <Shield className="h-12 w-12 text-zinc-800 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-zinc-400">No findings yet</h3>
                <p className="text-sm text-zinc-500 mt-1">The agents are still analyzing the application.</p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="console">
          <div className="bg-black border border-zinc-800 rounded-xl overflow-hidden">
            <div className="bg-zinc-900 px-4 py-2 border-b border-zinc-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex gap-1.5">
                  <div className="h-3 w-3 rounded-full bg-red-500/20 border border-red-500/40" />
                  <div className="h-3 w-3 rounded-full bg-yellow-500/20 border border-yellow-500/40" />
                  <div className="h-3 w-3 rounded-full bg-green-500/20 border border-green-500/40" />
                </div>
                <span className="text-[10px] text-zinc-500 font-mono ml-2 uppercase tracking-widest">Sentinel-Agent-Console</span>
              </div>
              <div className="text-[10px] text-zinc-500 font-mono">
                {logs.length} events logged
              </div>
            </div>
            <div
              ref={scrollRef}
              className="p-6 h-[500px] overflow-y-auto font-mono text-xs space-y-2"
            >
              {logs.map(log => (
                <div key={log.id} className="flex gap-4 group">
                  <span className="text-zinc-600 shrink-0">[{log.timestamp}]</span>
                  <span className={cn(
                    "font-bold uppercase w-20 shrink-0",
                    log.type === "info" && "text-blue-500",
                    log.type === "warning" && "text-yellow-500",
                    log.type === "error" && "text-red-500",
                    log.type === "success" && "text-green-500",
                  )}>{log.agent}</span>
                  <span className="text-zinc-300 group-hover:text-white transition-colors">{log.message}</span>
                </div>
              ))}
              {status === "running" && (
                <div className="flex gap-4 animate-pulse">
                  <span className="text-zinc-600">[{new Date().toLocaleTimeString()}]</span>
                  <span className="text-zinc-500 italic">Listening for events...</span>
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>
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
