"use client";

import { useEffect, useState, useRef } from "react";
import { useParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { AgentSession, RunEvent, Finding, SecurityRun } from "@/lib/types";
import AgentLane from "@/components/AgentLane";
import {
  Shield, Activity, Bug, FileText, Clock, Globe, AlertTriangle,
  CheckCircle2, Loader2, ArrowLeft, Download, ChevronDown,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import Link from "next/link";

function SeverityRing({ criticals, highs, mediums, lows }: { criticals: number; highs: number; mediums: number; lows: number }) {
  const total = criticals + highs + mediums + lows;
  if (total === 0) return null;
  const radius = 36;
  const circumference = 2 * Math.PI * radius;
  const segments = [
    { count: criticals, color: "#ef4444" },
    { count: highs, color: "#f97316" },
    { count: mediums, color: "#eab308" },
    { count: lows, color: "#3b82f6" },
  ];
  let offset = 0;

  return (
    <div className="relative w-24 h-24 flex items-center justify-center">
      <svg className="w-24 h-24 -rotate-90" viewBox="0 0 80 80">
        <circle cx="40" cy="40" r={radius} fill="none" stroke="#1f2937" strokeWidth="6" />
        {segments.map((seg, i) => {
          const len = (seg.count / total) * circumference;
          const el = (
            <circle
              key={i}
              cx="40" cy="40" r={radius}
              fill="none" stroke={seg.color}
              strokeWidth="6" strokeLinecap="round"
              strokeDasharray={`${len} ${circumference - len}`}
              strokeDashoffset={-offset}
              className="transition-all duration-1000"
            />
          );
          offset += len;
          return el;
        })}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-black text-white">{total}</span>
        <span className="text-[9px] font-mono text-gray-500">VULNS</span>
      </div>
    </div>
  );
}

function RiskScore({ findings }: { findings: Finding[] }) {
  const weights = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 0.5 };
  const raw = findings.reduce((s, f) => s + (weights[f.severity] || 0), 0);
  const score = Math.min(10, raw / 3).toFixed(1);
  const num = parseFloat(score);
  const color = num >= 8 ? "text-red-500" : num >= 5 ? "text-orange-400" : num >= 3 ? "text-yellow-400" : "text-success-green";

  return (
    <div className="text-center">
      <div className={`text-3xl font-black ${color}`}>{score}</div>
      <div className="text-[9px] font-mono text-gray-500">RISK / 10</div>
    </div>
  );
}

export default function RunDetails() {
  const params = useParams();
  const runId = params.id as string;
  const eventsEndRef = useRef<HTMLDivElement>(null);

  const [run, setRun] = useState<SecurityRun | null>(null);
  const [sessions, setSessions] = useState<AgentSession[]>([]);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [eventFilter, setEventFilter] = useState<string | null>(null);

  useEffect(() => {
    if (!runId) return;

    const fetchData = async () => {
      const [runRes, sessRes, eventRes, findRes] = await Promise.all([
        supabase.from("security_runs").select("*").eq("id", runId).single(),
        supabase.from("agent_sessions").select("*").eq("run_id", runId),
        supabase.from("run_events").select("*").eq("run_id", runId).order("created_at", { ascending: true }).limit(200),
        supabase.from("findings").select("*").eq("run_id", runId),
      ]);
      if (runRes.data) setRun(runRes.data);
      if (sessRes.data) setSessions(sessRes.data);
      if (eventRes.data) setEvents(eventRes.data);
      if (findRes.data) setFindings(findRes.data);
    };
    fetchData();

    const channel = supabase
      .channel(`run:${runId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "security_runs", filter: `id=eq.${runId}` },
        (payload) => { if (payload.new) setRun(payload.new as SecurityRun); })
      .on("postgres_changes", { event: "*", schema: "public", table: "agent_sessions", filter: `run_id=eq.${runId}` },
        (payload) => {
          const ns = payload.new as AgentSession;
          setSessions((prev) => {
            const idx = prev.findIndex((s) => s.id === ns.id);
            if (idx === -1) return [...prev, ns];
            const u = [...prev]; u[idx] = ns; return u;
          });
        })
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "run_events", filter: `run_id=eq.${runId}` },
        (payload) => { setEvents((prev) => [...prev, payload.new as RunEvent].slice(-200)); })
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "findings", filter: `run_id=eq.${runId}` },
        (payload) => { setFindings((prev) => [...prev, payload.new as Finding]); })
      .subscribe();

    const interval = setInterval(fetchData, 3000);
    return () => { supabase.removeChannel(channel); clearInterval(interval); };
  }, [runId]);

  useEffect(() => {
    eventsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [events.length]);

  const criticals = findings.filter((f) => f.severity === "CRITICAL").length;
  const highs = findings.filter((f) => f.severity === "HIGH").length;
  const mediums = findings.filter((f) => f.severity === "MEDIUM").length;
  const lows = findings.filter((f) => f.severity === "LOW").length;
  const activeAgents = sessions.filter((s) => s.status === "RUNNING").length;
  const completedAgents = sessions.filter((s) => s.status === "COMPLETED").length;
  const isActive = run?.status === "RUNNING" || run?.status === "QUEUED";

  const elapsed = run?.started_at
    ? Math.floor((Date.now() - new Date(run.started_at).getTime()) / 1000)
    : 0;
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;

  const filteredEvents = eventFilter
    ? events.filter((e) => e.agent_type === eventFilter)
    : events;

  const agentTypes = [...new Set(events.map((e) => e.agent_type))];

  return (
    <div className="min-h-screen bg-black text-white">
      {/* Top Bar */}
      <div className="border-b border-gray-800/80 bg-gray-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-6 py-3 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/" className="text-gray-500 hover:text-white transition-colors">
              <ArrowLeft className="w-4 h-4" />
            </Link>
            <div className="flex items-center gap-3">
              <div className="p-1.5 rounded-lg bg-gradient-to-br from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/30">
                <Shield className="w-4 h-4 text-cyber-blue" />
              </div>
              <div>
                <h1 className="text-sm font-bold flex items-center gap-2">
                  SENTINEL
                  {isActive && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono rounded-full bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse" />
                      LIVE
                    </span>
                  )}
                  {run?.status === "COMPLETED" && (
                    <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[9px] font-mono rounded-full bg-success-green/10 border border-success-green/30 text-success-green">
                      <CheckCircle2 className="w-2.5 h-2.5" />
                      COMPLETE
                    </span>
                  )}
                </h1>
                <p className="text-[10px] font-mono text-gray-500">
                  <Globe className="w-2.5 h-2.5 inline mr-1" />
                  {run?.target_url || "..."} • {runId.slice(0, 8)}
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-6">
            <div className="flex items-center gap-1 text-xs font-mono text-gray-400">
              <Clock className="w-3 h-3" />
              {mins}:{secs.toString().padStart(2, "0")}
            </div>
            <div className="text-xs font-mono text-gray-400">
              {activeAgents > 0 && <span className="text-cyber-blue">{activeAgents} active</span>}
              {activeAgents > 0 && completedAgents > 0 && " • "}
              {completedAgents > 0 && <span className="text-success-green">{completedAgents} done</span>}
            </div>
            {run?.status === "COMPLETED" && (
              <Link
                href={`/runs/${runId}/report`}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyber-blue/20 to-cyan-500/10 border border-cyber-blue/30 text-cyan-300 hover:text-white hover:border-cyan-400 transition-all text-xs font-semibold"
              >
                <FileText className="w-3.5 h-3.5" />
                Full Report
              </Link>
            )}
          </div>
        </div>
      </div>

      <div className="max-w-[1600px] mx-auto p-6">
        {/* Stats Bar */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-8">
          <div className="col-span-2 lg:col-span-1 flex items-center justify-center bg-gray-950/50 border border-gray-800 rounded-xl p-4">
            <SeverityRing criticals={criticals} highs={highs} mediums={mediums} lows={lows} />
          </div>
          <div className="bg-gray-950/50 border border-gray-800 rounded-xl p-4 flex flex-col items-center justify-center">
            <RiskScore findings={findings} />
          </div>
          <div className="bg-gray-950/50 border border-gray-800 rounded-xl p-4 flex flex-col items-center justify-center">
            <div className="text-2xl font-black text-red-400">{criticals}</div>
            <div className="text-[9px] font-mono text-gray-500">CRITICAL</div>
          </div>
          <div className="bg-gray-950/50 border border-gray-800 rounded-xl p-4 flex flex-col items-center justify-center">
            <div className="text-2xl font-black text-orange-400">{highs}</div>
            <div className="text-[9px] font-mono text-gray-500">HIGH</div>
          </div>
          <div className="bg-gray-950/50 border border-gray-800 rounded-xl p-4 flex flex-col items-center justify-center">
            <div className="text-2xl font-black text-yellow-400">{mediums + lows}</div>
            <div className="text-[9px] font-mono text-gray-500">MEDIUM + LOW</div>
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Agents Grid */}
          <div className="xl:col-span-2 space-y-4">
            <h3 className="text-xs font-mono text-gray-500 uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-3 h-3" /> Agent Fleet — {sessions.length} deployed
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {sessions.map((session) => (
                <AgentLane
                  key={session.id}
                  session={session}
                  findings={findings.filter((f) => f.agent_type === session.agent_type)}
                />
              ))}
            </div>

            {/* Event Log */}
            <div className="mt-6">
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-xs font-mono text-gray-500 uppercase tracking-wider flex items-center gap-2">
                  <Bug className="w-3 h-3" /> Event Stream
                </h3>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setEventFilter(null)}
                    className={`px-2 py-1 text-[10px] rounded font-mono transition-colors ${!eventFilter ? "bg-gray-700 text-white" : "text-gray-500 hover:text-gray-300"}`}
                  >
                    ALL
                  </button>
                  {agentTypes.map((at) => (
                    <button
                      key={at}
                      onClick={() => setEventFilter(eventFilter === at ? null : at)}
                      className={`px-2 py-1 text-[10px] rounded font-mono transition-colors ${eventFilter === at ? "bg-gray-700 text-white" : "text-gray-500 hover:text-gray-300"}`}
                    >
                      {at.toUpperCase().slice(0, 6)}
                    </button>
                  ))}
                </div>
              </div>
              <div className="bg-gray-950/60 border border-gray-800 rounded-xl overflow-hidden">
                <div className="p-4 font-mono text-xs h-[320px] overflow-y-auto space-y-1.5 scroll-smooth">
                  {filteredEvents.map((e) => (
                    <div key={e.id}>
                      <div className="flex gap-2 leading-relaxed">
                        <span className="text-gray-600 shrink-0">
                          {new Date(e.created_at).toLocaleTimeString("en", { hour12: false })}
                        </span>
                        <span className={`shrink-0 font-bold ${
                          e.event_type === "ERROR" ? "text-red-500" :
                          e.event_type === "WARNING" ? "text-yellow-500" :
                          e.event_type === "SUCCESS" ? "text-green-400" :
                          e.event_type === "SCREENSHOT" ? "text-purple-400" :
                          "text-gray-500"
                        }`}>
                          [{e.agent_type}]
                        </span>
                        <span className={
                          e.event_type === "ERROR" ? "text-red-400" :
                          e.event_type === "SUCCESS" ? "text-green-300" :
                          "text-gray-400"
                        }>
                          {e.message}
                        </span>
                      </div>
                      {e.event_type === "SCREENSHOT" && (e.data as any)?.image && (
                        <div className="ml-20 my-2">
                          {/* eslint-disable-next-line @next/next/no-img-element */}
                          <img
                            src={(e.data as any).image}
                            alt="Screenshot"
                            className="rounded-lg border border-gray-700 max-w-xs hover:max-w-lg transition-all cursor-zoom-in"
                          />
                        </div>
                      )}
                    </div>
                  ))}
                  <div ref={eventsEndRef} />
                  {events.length === 0 && (
                    <div className="flex items-center justify-center h-full text-gray-600">
                      <Loader2 className="w-4 h-4 animate-spin mr-2" /> Waiting for events...
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Right: Live Findings Feed */}
          <div className="xl:col-span-1 space-y-4">
            <h3 className="text-xs font-mono text-gray-500 uppercase tracking-wider flex items-center gap-2">
              <AlertTriangle className="w-3 h-3" /> Live Findings — {findings.length} total
            </h3>
            <div className="space-y-3 max-h-[calc(100vh-240px)] overflow-y-auto pr-1">
              <AnimatePresence>
                {findings.slice().reverse().map((f) => (
                  <motion.div
                    key={f.id}
                    initial={{ opacity: 0, x: 20, scale: 0.95 }}
                    animate={{ opacity: 1, x: 0, scale: 1 }}
                    className={`p-3 rounded-xl border text-sm backdrop-blur-sm ${
                      f.severity === "CRITICAL" ? "bg-red-950/30 border-red-500/40" :
                      f.severity === "HIGH" ? "bg-orange-950/30 border-orange-500/40" :
                      f.severity === "MEDIUM" ? "bg-yellow-950/30 border-yellow-500/40" :
                      "bg-blue-950/20 border-blue-500/30"
                    }`}
                  >
                    <div className="flex justify-between items-start mb-1.5">
                      <span className={`font-bold text-xs ${
                        f.severity === "CRITICAL" ? "text-red-300" :
                        f.severity === "HIGH" ? "text-orange-300" :
                        f.severity === "MEDIUM" ? "text-yellow-300" :
                        "text-blue-300"
                      }`}>
                        {f.title}
                      </span>
                      <span className={`text-[9px] uppercase border px-1.5 py-0.5 rounded font-mono font-bold ${
                        f.severity === "CRITICAL" ? "border-red-500/50 text-red-400 bg-red-500/10" :
                        f.severity === "HIGH" ? "border-orange-500/50 text-orange-400 bg-orange-500/10" :
                        f.severity === "MEDIUM" ? "border-yellow-500/50 text-yellow-400 bg-yellow-500/10" :
                        "border-blue-500/50 text-blue-400 bg-blue-500/10"
                      }`}>
                        {f.severity}
                      </span>
                    </div>
                    <p className="text-gray-400 text-xs line-clamp-2 mb-2">{f.evidence}</p>
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] font-mono text-gray-600">{f.agent_type}</span>
                      <span className="text-[10px] font-mono text-gray-600">
                        {new Date(f.created_at).toLocaleTimeString("en", { hour12: false })}
                      </span>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {findings.length === 0 && (
                <div className="text-center text-gray-600 py-16">
                  <Loader2 className="w-6 h-6 animate-spin mx-auto mb-3 text-gray-700" />
                  <div className="text-sm font-mono">Agents scanning...</div>
                  <div className="text-xs text-gray-700 mt-1">Vulnerabilities will appear here</div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
