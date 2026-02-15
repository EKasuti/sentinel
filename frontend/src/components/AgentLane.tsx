"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AgentSession, Finding } from "@/lib/types";
import {
  ShieldAlert, CheckCircle, Terminal, Loader2, Eye, Key, Shield,
  Search, Globe, Radio, Bug, Zap, Cpu, Target, XCircle, ChevronDown,
} from "lucide-react";

interface AgentLaneProps {
  session: AgentSession;
  findings: Finding[];
}

const AGENT_CONFIG: Record<string, { icon: any; label: string; color: string }> = {
  spider:       { icon: Search,  label: "Spider / Recon",    color: "from-blue-500 to-blue-700" },
  exposure:     { icon: Eye,     label: "Secret Scanner",    color: "from-purple-500 to-purple-700" },
  headers_tls:  { icon: Shield,  label: "Headers & TLS",     color: "from-cyan-500 to-cyan-700" },
  cors:         { icon: Globe,   label: "CORS Scanner",      color: "from-emerald-500 to-emerald-700" },
  portscan:     { icon: Radio,   label: "Port Scanner",      color: "from-amber-500 to-amber-700" },
  auth_abuse:   { icon: Key,     label: "Auth Abuse",        color: "from-rose-500 to-rose-700" },
  sqli:         { icon: Bug,     label: "SQL Injection",     color: "from-red-500 to-red-700" },
  xss:          { icon: Zap,     label: "XSS Auditor",       color: "from-orange-500 to-orange-700" },
  llm_analysis: { icon: Cpu,     label: "LLM Analysis",      color: "from-indigo-500 to-indigo-700" },
  red_team:     { icon: Target,  label: "Red Team AI",       color: "from-pink-500 to-pink-700" },
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-400 border-red-500/40",
  HIGH:     "bg-orange-500/20 text-orange-400 border-orange-500/40",
  MEDIUM:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/40",
  LOW:      "bg-blue-500/20 text-blue-300 border-blue-500/40",
};

export default function AgentLane({ session, findings }: AgentLaneProps) {
  const [expanded, setExpanded] = useState(false);
  const config = AGENT_CONFIG[session.agent_type] || { icon: Terminal, label: session.agent_type, color: "from-gray-500 to-gray-700" };
  const Icon = config.icon;
  const isRunning = session.status === "RUNNING";
  const isCompleted = session.status === "COMPLETED";
  const isFailed = session.status === "FAILED";

  const critCount = findings.filter(f => f.severity === "CRITICAL").length;
  const highCount = findings.filter(f => f.severity === "HIGH").length;
  const medCount = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount = findings.filter(f => f.severity === "LOW").length;

  let borderColor = "border-gray-800";
  let glowStyle = {};
  if (isRunning) {
    borderColor = "border-cyber-blue/60";
    glowStyle = { boxShadow: "0 0 20px rgba(0,240,255,0.15), inset 0 1px 0 rgba(0,240,255,0.1)" };
  }
  if (isCompleted) {
    borderColor = findings.length > 0 ? "border-orange-500/40" : "border-success-green/40";
  }
  if (isFailed) borderColor = "border-danger-red/40";

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`relative rounded-xl bg-gray-950/60 border ${borderColor} backdrop-blur-sm transition-all duration-500 overflow-hidden`}
      style={glowStyle}
    >
      {/* Main Card */}
      <div className="p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg bg-gradient-to-br ${config.color} bg-opacity-20`}>
              <Icon className={`w-4 h-4 text-white ${isRunning ? "animate-pulse" : ""}`} />
            </div>
            <div>
              <span className="font-semibold text-sm text-white">{config.label}</span>
              <div className="text-[10px] font-mono text-gray-500 flex items-center gap-1.5 mt-0.5">
                {isRunning && <><Loader2 className="w-2.5 h-2.5 animate-spin text-cyber-blue" /><span className="text-cyber-blue">SCANNING</span></>}
                {isCompleted && <><CheckCircle className="w-2.5 h-2.5 text-success-green" /><span className="text-success-green">DONE</span></>}
                {isFailed && <><XCircle className="w-2.5 h-2.5 text-danger-red" /><span className="text-danger-red">FAILED</span></>}
                {!isRunning && !isCompleted && !isFailed && <span className="text-gray-600">QUEUED</span>}
              </div>
            </div>
          </div>

          {/* Severity badges */}
          <div className="flex items-center gap-1">
            {critCount > 0 && <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-red-500/20 text-red-400 border border-red-500/30">{critCount} CRIT</span>}
            {highCount > 0 && <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">{highCount} HIGH</span>}
            {medCount > 0 && <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">{medCount}</span>}
            {lowCount > 0 && <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">{lowCount}</span>}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-gray-800/50 h-1 rounded-full overflow-hidden">
          <motion.div
            className={`h-full rounded-full ${isCompleted ? (findings.length > 0 ? "bg-orange-500" : "bg-success-green") : "bg-gradient-to-r from-cyber-blue to-blue-400"}`}
            initial={{ width: 0 }}
            animate={{ width: `${session.progress}%` }}
            transition={{ ease: "easeOut", duration: 0.5 }}
          />
        </div>

        {/* Expand toggle */}
        {findings.length > 0 && (
          <button
            onClick={() => setExpanded(!expanded)}
            className="mt-2 flex items-center gap-1 text-[10px] font-mono text-gray-500 hover:text-gray-300 transition-colors w-full"
          >
            <ChevronDown className={`w-3 h-3 transition-transform ${expanded ? "rotate-180" : ""}`} />
            {findings.length} finding{findings.length !== 1 ? "s" : ""} — {expanded ? "HIDE" : "SHOW"}
          </button>
        )}
      </div>

      {/* Expanded findings list */}
      <AnimatePresence>
        {expanded && findings.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.3 }}
            className="border-t border-gray-800/50"
          >
            <div className="p-3 space-y-2 max-h-60 overflow-y-auto">
              {findings.map((f) => (
                <div
                  key={f.id}
                  className={`p-2 rounded-lg border text-xs ${SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.LOW}`}
                >
                  <div className="flex justify-between items-start gap-2">
                    <span className="font-semibold">{f.title}</span>
                    <span className="text-[9px] uppercase font-mono opacity-60 shrink-0">{f.severity}</span>
                  </div>
                  {f.evidence && (
                    <p className="mt-1 opacity-70 line-clamp-2 text-[11px]">{f.evidence}</p>
                  )}
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
