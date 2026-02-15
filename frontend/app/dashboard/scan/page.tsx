"use client";

import {
  Shield, Clock, Activity, AlertTriangle, X, Globe, Terminal, List,
  LayoutDashboard, Database, Code, ShieldAlert, Search, FileWarning,
  Brain, Eye, Wifi, WifiOff, ChevronDown, ChevronUp
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense, useRef, useMemo } from "react";
import { SeverityBadge } from "@/components/SeverityBadge";
import { cn } from "@/lib/utils";
import { useWebSocket, AgentState } from "@/lib/useWebSocket";
import { stopScan } from "@/apis/scans";

// ---------------------------------------------------------------------------
// Agent Panel Component
// ---------------------------------------------------------------------------

const ROLE_ICONS: Record<string, any> = {
  sqli: Database,
  xss: Code,
  auth: ShieldAlert,
  idor: Search,
  csrf: FileWarning,
};

const ROLE_COLORS: Record<string, string> = {
  sqli: "text-red-400",
  xss: "text-amber-400",
  auth: "text-violet-400",
  idor: "text-blue-400",
  csrf: "text-emerald-400",
};

const ROLE_BORDER: Record<string, string> = {
  sqli: "border-red-500/20",
  xss: "border-amber-500/20",
  auth: "border-violet-500/20",
  idor: "border-blue-500/20",
  csrf: "border-emerald-500/20",
};

function AgentPanel({ agent }: { agent: AgentState }) {
  const Icon = ROLE_ICONS[agent.role] || Shield;
  const color = ROLE_COLORS[agent.role] || "text-zinc-400";
  const borderColor = ROLE_BORDER[agent.role] || "border-zinc-800";
  const [showScreenshot, setShowScreenshot] = useState(true);

  const statusLabel = {
    idle: "Waiting",
    started: "Initializing",
    thinking: "Thinking...",
    acting: "Executing",
    complete: "Complete",
    error: "Error",
  }[agent.status];

  const statusColor = {
    idle: "bg-zinc-600",
    started: "bg-blue-500",
    thinking: "bg-yellow-500 animate-pulse",
    acting: "bg-cyan-500 animate-pulse",
    complete: "bg-green-500",
    error: "bg-red-500",
  }[agent.status];

  return (
    <div className={cn(
      "rounded-xl border bg-zinc-950/80 overflow-hidden flex flex-col",
      borderColor,
      agent.status === "thinking" && "ring-1 ring-yellow-500/20",
      agent.status === "acting" && "ring-1 ring-cyan-500/20",
    )}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-zinc-800/50 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <div className={cn("flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800")}>
            <Icon className={cn("h-4 w-4", color)} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-zinc-200">{agent.name}</span>
              <div className={cn("h-2 w-2 rounded-full", statusColor)} />
            </div>
            <span className="text-[10px] text-zinc-500 uppercase tracking-widest">{statusLabel}</span>
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs font-mono text-zinc-400">
            {agent.iteration}/{agent.totalIterations}
          </div>
          {agent.findings.length > 0 && (
            <div className="text-[10px] font-bold text-red-400">
              {agent.findings.length} vuln{agent.findings.length > 1 ? "s" : ""}
            </div>
          )}
        </div>
      </div>

      {/* Screenshot */}
      {agent.screenshot && showScreenshot && (
        <div className="relative bg-black aspect-video">
          <img
            src={`data:image/png;base64,${agent.screenshot}`}
            alt={`${agent.name} browser view`}
            className="w-full h-full object-contain"
          />
          <div className="absolute top-2 right-2 flex gap-1">
            <button
              onClick={() => setShowScreenshot(false)}
              className="bg-black/60 rounded p-1 hover:bg-black/80 transition"
            >
              <ChevronUp className="h-3 w-3 text-zinc-400" />
            </button>
          </div>
          <div className="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/80 to-transparent p-2">
            <span className="text-[10px] text-zinc-400 font-mono truncate block">{agent.screenshot ? "Live Feed" : ""}</span>
          </div>
        </div>
      )}

      {!showScreenshot && agent.screenshot && (
        <button onClick={() => setShowScreenshot(true)} className="px-4 py-1.5 text-[10px] text-zinc-500 hover:text-zinc-300 transition flex items-center gap-1 border-b border-zinc-800/50">
          <Eye className="h-3 w-3" /> Show screenshot
        </button>
      )}

      {/* Current action / reasoning */}
      <div className="px-4 py-3 flex-1 space-y-2 min-h-[80px]">
        {agent.currentAction && (
          <div className="flex items-start gap-2">
            <Activity className="h-3.5 w-3.5 text-zinc-500 mt-0.5 shrink-0" />
            <p className="text-xs text-zinc-300 leading-relaxed line-clamp-2">{agent.currentAction}</p>
          </div>
        )}
        {agent.reasoning && (
          <div className="flex items-start gap-2">
            <Brain className="h-3.5 w-3.5 text-zinc-600 mt-0.5 shrink-0" />
            <p className="text-[11px] text-zinc-500 leading-relaxed line-clamp-3">{agent.reasoning}</p>
          </div>
        )}
        {!agent.currentAction && !agent.reasoning && (
          <p className="text-xs text-zinc-600 italic">Awaiting first action...</p>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Scan Content
// ---------------------------------------------------------------------------

function ScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId");
  const targetUrl = searchParams.get("url") || "https://example.com";

  const ws = useWebSocket(scanId);

  const [elapsed, setElapsed] = useState(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isStopping, setIsStopping] = useState(false);

  // Timer
  useEffect(() => {
    if (ws.scanStatus !== "running") return;
    const timer = setInterval(() => setElapsed((p) => p + 1), 1000);
    return () => clearInterval(timer);
  }, [ws.scanStatus]);

  // Auto-scroll console
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [ws.events]);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;
  };

  const handleStop = async () => {
    if (!scanId) return;
    setIsStopping(true);
    try {
      await stopScan(scanId);
    } catch { }
  };

  const agentsArray = useMemo(
    () => Object.values(ws.agents).sort((a, b) => a.id - b.id),
    [ws.agents]
  );

  const agentsComplete = agentsArray.filter(a => a.status === "complete").length;

  // Filter console-visible events
  const consoleEvents = useMemo(
    () => ws.events.filter(e =>
      ["agent.started", "agent.action", "agent.decision", "agent.error",
        "agent.log", "agent.complete", "vulnerability.found", "agent.thought",
        "agent.thinking", "agent.iteration", "scan.complete", "scan.stopped"
      ].includes(e.type)
    ),
    [ws.events]
  );

  return (
    <div className="space-y-6 pb-10">
      {/* Scan Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 bg-zinc-950 border border-zinc-800 rounded-2xl p-6">
        <div className="flex items-center gap-4">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-zinc-900 border border-zinc-800">
            <Activity className={cn(
              "h-6 w-6",
              ws.scanStatus === "running" ? "text-yellow-500 animate-pulse" :
                ws.scanStatus === "completed" ? "text-green-500" : "text-red-500"
            )} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-xl font-bold text-white uppercase tracking-tight">
                {ws.scanStatus === "running" ? "Scan in Progress" :
                  ws.scanStatus === "completed" ? "Scan Completed" : "Scan Stopped"}
              </h2>
              <Badge variant="outline" className={
                ws.scanStatus === "running" ? "border-yellow-500/50 text-yellow-500" :
                  ws.scanStatus === "completed" ? "border-green-500/50 text-green-500" :
                    "border-red-500/50 text-red-500"
              }>
                {ws.scanStatus.toUpperCase()}
              </Badge>
            </div>
            <div className="flex items-center gap-3 text-sm text-zinc-500 mt-1">
              <div className="flex items-center gap-1">
                <Globe className="h-3.5 w-3.5" />
                <span className="truncate max-w-[300px]">{targetUrl}</span>
              </div>
              <div className="flex items-center gap-1">
                {ws.connected ? <Wifi className="h-3 w-3 text-green-500" /> : <WifiOff className="h-3 w-3 text-red-500" />}
                <span className="text-[10px]">{ws.connected ? "Live" : "Disconnected"}</span>
              </div>
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
            <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">Agents</div>
            <div className="text-xl font-mono font-bold text-zinc-200">{agentsComplete}/5</div>
          </div>
          <div className="text-center">
            <div className="text-[10px] text-zinc-500 uppercase font-bold tracking-widest mb-1">Findings</div>
            <div className={cn("text-xl font-mono font-bold", ws.findings.length > 0 ? "text-red-500" : "text-zinc-200")}>
              {ws.findings.length}
            </div>
          </div>
          <Button
            variant={ws.scanStatus === "running" ? "destructive" : "outline"}
            onClick={ws.scanStatus === "running" ? handleStop : () => router.push("/dashboard")}
            className="ml-4"
            disabled={isStopping}
          >
            {ws.scanStatus === "running" ? (
              <><X className="h-4 w-4 mr-2" /> {isStopping ? "Stopping..." : "Stop"}</>
            ) : "Done"}
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="agents" className="w-full">
        <TabsList className="bg-zinc-900 border border-zinc-800 mb-6 p-1">
          <TabsTrigger value="agents" className="data-[state=active]:bg-zinc-800">
            <LayoutDashboard className="h-4 w-4 mr-2" /> Agent Panels
          </TabsTrigger>
          <TabsTrigger value="findings" className="data-[state=active]:bg-zinc-800">
            <List className="h-4 w-4 mr-2" /> Findings
            {ws.findings.length > 0 && (
              <span className="ml-2 bg-red-500 text-white text-[10px] px-1.5 py-0.5 rounded-full">
                {ws.findings.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="console" className="data-[state=active]:bg-zinc-800">
            <Terminal className="h-4 w-4 mr-2" /> Live Console
          </TabsTrigger>
        </TabsList>

        {/* Agent Panels Tab */}
        <TabsContent value="agents" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {agentsArray.map((agent) => (
              <AgentPanel key={agent.id} agent={agent} />
            ))}
          </div>

          {/* Findings summary below agent panels */}
          {ws.findings.length > 0 && (
            <div className="bg-zinc-950 border border-zinc-800 rounded-xl p-6">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-yellow-500" />
                Vulnerabilities Detected
              </h3>
              <div className="space-y-3">
                {ws.findings.map((f, i) => (
                  <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-zinc-900/50 border border-zinc-800">
                    <div>
                      <p className="font-medium text-sm text-zinc-200">{f.type || f.title}</p>
                      <p className="text-xs text-zinc-500 mt-0.5">{f.location || f.evidence?.slice(0, 80)}</p>
                    </div>
                    <SeverityBadge severity={(f.severity || "medium").toLowerCase() as any} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </TabsContent>

        {/* Findings Tab */}
        <TabsContent value="findings">
          <div className="space-y-4">
            {ws.findings.map((f, i) => (
              <div key={i} className="bg-zinc-950 border border-zinc-800 rounded-xl p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-bold text-zinc-200">{f.type || f.title}</h3>
                      <SeverityBadge severity={(f.severity || "medium").toLowerCase() as any} />
                    </div>
                    <p className="text-xs text-zinc-500 uppercase tracking-widest">Agent {f.agentId} • {f.role}</p>
                  </div>
                </div>
                <div className="space-y-2">
                  {f.location && (
                    <div className="flex gap-2 text-sm">
                      <span className="text-zinc-500 shrink-0">Location:</span>
                      <span className="text-zinc-300 font-mono text-xs">{f.location}</span>
                    </div>
                  )}
                  {f.payload && (
                    <div className="flex gap-2 text-sm">
                      <span className="text-zinc-500 shrink-0">Payload:</span>
                      <code className="text-red-400 font-mono text-xs bg-red-500/5 px-2 py-0.5 rounded">{f.payload}</code>
                    </div>
                  )}
                  {f.evidence && (
                    <div className="flex gap-2 text-sm">
                      <span className="text-zinc-500 shrink-0">Evidence:</span>
                      <span className="text-zinc-300 text-xs">{f.evidence}</span>
                    </div>
                  )}
                  {f.cwe && (
                    <div className="flex gap-2 text-sm">
                      <span className="text-zinc-500 shrink-0">CWE:</span>
                      <span className="text-zinc-300 text-xs font-mono">{f.cwe}</span>
                    </div>
                  )}
                </div>
              </div>
            ))}
            {ws.findings.length === 0 && (
              <div className="text-center py-20 bg-zinc-950 border border-zinc-800 rounded-xl">
                <Shield className="h-12 w-12 text-zinc-800 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-zinc-400">No findings yet</h3>
                <p className="text-sm text-zinc-500 mt-1">Agents are actively testing the application.</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Console Tab */}
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
                {consoleEvents.length} events
              </div>
            </div>
            <div
              ref={scrollRef}
              className="p-6 h-[500px] overflow-y-auto font-mono text-xs space-y-1.5"
            >
              {consoleEvents.map((event, i) => {
                const time = typeof event.timestamp === "number"
                  ? new Date(event.timestamp * 1000).toLocaleTimeString()
                  : new Date(event.timestamp).toLocaleTimeString();

                let typeColor = "text-blue-400";
                let message = "";
                switch (event.type) {
                  case "agent.started":
                    typeColor = "text-green-400";
                    message = `Agent started (${event.data?.role || event.role})`;
                    break;
                  case "agent.thinking":
                    typeColor = "text-yellow-400";
                    message = event.data?.status || "Thinking...";
                    break;
                  case "agent.thought":
                    typeColor = "text-zinc-500";
                    message = event.data?.thought?.slice(0, 150) || "";
                    break;
                  case "agent.decision":
                    typeColor = "text-cyan-400";
                    const d = event.data?.decision;
                    message = d ? `→ ${d.action} ${d.selector || ""} | ${d.reasoning}` : "Decision made";
                    break;
                  case "agent.action":
                    typeColor = "text-cyan-400";
                    message = `${event.data?.action}: ${event.data?.selector || ""} ${event.data?.value ? `= "${event.data.value.slice(0, 60)}"` : ""}`;
                    break;
                  case "agent.error":
                    typeColor = "text-red-400";
                    message = event.data?.message || event.data?.error || "Error";
                    break;
                  case "agent.complete":
                    typeColor = "text-green-400";
                    message = `Completed — ${event.data?.total_findings || 0} vulnerabilities found`;
                    break;
                  case "vulnerability.found":
                    typeColor = "text-red-500";
                    const v = event.data?.vulnerability || event.data;
                    message = `🚨 VULNERABILITY: ${v?.type || "Unknown"} [${v?.severity || "?"}]`;
                    break;
                  case "agent.iteration":
                    typeColor = "text-zinc-600";
                    message = `Iteration ${event.data?.iteration}/${event.data?.total}`;
                    break;
                  case "agent.log":
                    typeColor = "text-zinc-400";
                    message = event.data?.message || "";
                    break;
                  case "scan.complete":
                    typeColor = "text-green-500";
                    message = `✅ SCAN COMPLETE — ${event.data?.totalFindings || 0} total findings`;
                    break;
                  case "scan.stopped":
                    typeColor = "text-red-400";
                    message = "Scan stopped by user";
                    break;
                  default:
                    message = JSON.stringify(event.data).slice(0, 100);
                }

                return (
                  <div key={i} className="flex gap-3 group hover:bg-zinc-900/30 rounded px-1 py-0.5">
                    <span className="text-zinc-600 shrink-0">[{time}]</span>
                    <span className={cn("font-bold uppercase w-6 shrink-0 text-right", ROLE_COLORS[event.role] || "text-zinc-500")}>
                      {event.agentId || "—"}
                    </span>
                    <span className={cn("shrink-0 w-20 truncate", typeColor)}>{event.type.replace("agent.", "").replace("vulnerability.", "vuln.")}</span>
                    <span className="text-zinc-300 group-hover:text-white transition-colors truncate">{message}</span>
                  </div>
                );
              })}
              {ws.scanStatus === "running" && (
                <div className="flex gap-3 animate-pulse">
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

// ---------------------------------------------------------------------------
// Page wrapper with Suspense
// ---------------------------------------------------------------------------

export default function ScanPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="h-8 w-8 border-2 border-zinc-700 border-t-white rounded-full animate-spin mx-auto" />
          <p className="text-zinc-500">Initializing scan...</p>
        </div>
      </div>
    }>
      <ScanContent />
    </Suspense>
  );
}
