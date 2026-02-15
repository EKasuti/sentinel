"use client";

import { motion, AnimatePresence } from "framer-motion";
import { RunEvent, Finding } from "@/lib/types";
import { AGENT_META, AGENT_TYPE_MAP, SEVERITY_ORDER } from "./AgentStatusGrid";
import { X, Camera, AlertTriangle, CheckCircle, Activity, FileSearch, ChevronRight, Maximize2 } from "lucide-react";
import { useState } from "react";

interface AgentDetailModalProps {
    agentName: string | null;
    events: RunEvent[];
    findings: Finding[];
    status: string;
    onClose: () => void;
}

export default function AgentDetailModal({ agentName, events, findings, status, onClose }: AgentDetailModalProps) {
    const [expandedImage, setExpandedImage] = useState<string | null>(null);
    const [activeTab, setActiveTab] = useState<"summary" | "findings" | "screenshots" | "log">("summary");

    if (!agentName) return null;

    const meta = AGENT_META[agentName];
    const className = AGENT_TYPE_MAP[agentName] || agentName;
    const Icon = meta?.icon || Activity;

    const agentEvents = events.filter(e => e.agent_type === className);
    const agentFindings = findings.filter(f => f.agent_type === className);
    const screenshots = agentEvents.filter(e => e.event_type === 'SCREENSHOT');
    const infoEvents = agentEvents.filter(e => e.event_type === 'INFO');
    const warnings = agentEvents.filter(e => e.event_type === 'WARNING');
    const errors = agentEvents.filter(e => e.event_type === 'ERROR');
    const successes = agentEvents.filter(e => e.event_type === 'SUCCESS');

    // Build summary from events
    const buildSummary = () => {
        const summaryLines: string[] = [];
        for (const e of infoEvents) {
            const msg = e.message;
            if (msg.includes("Starting")) summaryLines.push(msg);
            else if (msg.includes("Discovered")) summaryLines.push(msg);
            else if (msg.includes("Navigat")) summaryLines.push(msg);
            else if (msg.includes("Found")) summaryLines.push(msg);
            else if (msg.includes("Testing")) summaryLines.push(msg);
            else if (msg.includes("Scanning")) summaryLines.push(msg);
            else if (msg.includes("THINK")) summaryLines.push(msg);
            else if (msg.includes("ACT")) summaryLines.push(msg);
            else if (msg.includes("Authentication")) summaryLines.push(msg);
            else if (msg.includes("Performing")) summaryLines.push(msg);
            else if (msg.includes("Login")) summaryLines.push(msg);
            else if (msg.includes("login")) summaryLines.push(msg);
            else if (msg.includes("Content")) summaryLines.push(msg);
            else if (msg.includes("LLM")) summaryLines.push(msg);
            else if (msg.includes("CONSOLE")) summaryLines.push(msg);
            else if (msg.includes("NETWORK")) summaryLines.push(msg);
        }
        return summaryLines.length > 0 ? summaryLines : infoEvents.map(e => e.message);
    };

    const summaryItems = buildSummary();

    const severityBadge = (severity: string) => {
        const colors: Record<string, string> = {
            CRITICAL: "bg-red-500/20 text-red-300 border-red-500/40",
            HIGH: "bg-orange-500/20 text-orange-300 border-orange-500/40",
            MEDIUM: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
            LOW: "bg-blue-500/20 text-blue-300 border-blue-500/40",
            INFO: "bg-gray-500/20 text-gray-300 border-gray-500/40",
        };
        return colors[severity] || colors.INFO;
    };

    const tabs = [
        { key: "summary" as const, label: "Summary", count: summaryItems.length },
        { key: "findings" as const, label: "Findings", count: agentFindings.length },
        { key: "screenshots" as const, label: "Screenshots", count: screenshots.length },
        { key: "log" as const, label: "Full Log", count: agentEvents.length },
    ];

    return (
        <AnimatePresence>
            {/* Backdrop */}
            <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md"
                onClick={onClose}
            />

            {/* Expanded Image */}
            {expandedImage && (
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="fixed inset-0 z-[60] bg-black/95 flex items-center justify-center p-8"
                    onClick={() => setExpandedImage(null)}
                >
                    <img
                        src={expandedImage}
                        alt="Expanded screenshot"
                        className="max-w-full max-h-full rounded-lg border border-gray-700 shadow-2xl"
                    />
                    <button className="absolute top-6 right-6 text-gray-400 hover:text-white transition-colors">
                        <X size={28} />
                    </button>
                </motion.div>
            )}

            {/* Modal Content */}
            <motion.div
                initial={{ opacity: 0, y: 30, scale: 0.97 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 30, scale: 0.97 }}
                transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                className="fixed inset-4 sm:inset-8 lg:inset-12 z-50 flex flex-col rounded-2xl overflow-hidden"
                onClick={(e) => e.stopPropagation()}
            >
                {/* Glass background */}
                <div className="absolute inset-0 bg-gradient-to-br from-gray-950 via-gray-900 to-gray-950 border border-white/5 rounded-2xl" />
                <div className="absolute inset-0 backdrop-blur-xl rounded-2xl" />

                {/* Header */}
                <div className="relative z-10 flex-shrink-0 px-8 pt-7 pb-5 border-b border-white/5">
                    <div className="flex justify-between items-start">
                        <div className="flex items-center gap-4">
                            <div
                                className="w-12 h-12 rounded-xl flex items-center justify-center shadow-lg"
                                style={{ background: `${meta?.color || '#888'}20`, border: `1.5px solid ${meta?.color || '#888'}40` }}
                            >
                                <Icon className="w-6 h-6" style={{ color: meta?.color || '#888' }} />
                            </div>
                            <div>
                                <h2 className="text-xl font-bold text-white tracking-tight">{meta?.label || agentName}</h2>
                                <div className="flex items-center gap-3 mt-1">
                                    <span className={`text-[10px] font-mono font-bold tracking-widest px-2 py-0.5 rounded-md border ${status === 'COMPLETED' ? 'bg-green-500/10 border-green-500/25 text-green-400' :
                                            status === 'RUNNING' ? 'bg-cyan-500/10 border-cyan-500/25 text-cyan-400' :
                                                status === 'FAILED' ? 'bg-red-500/10 border-red-500/25 text-red-400' :
                                                    'bg-gray-800/50 border-gray-700/30 text-gray-500'
                                        }`}>
                                        {status}
                                    </span>
                                    <span className="text-xs text-gray-500">{agentEvents.length} events · {screenshots.length} screenshots</span>
                                </div>
                            </div>
                        </div>
                        <button
                            onClick={onClose}
                            className="w-9 h-9 rounded-lg flex items-center justify-center text-gray-500 hover:text-white hover:bg-white/5 transition-all"
                        >
                            <X size={20} />
                        </button>
                    </div>

                    {/* Stats Row */}
                    <div className="grid grid-cols-4 gap-4 mt-6">
                        {[
                            { label: "Findings", value: agentFindings.length, color: agentFindings.length > 0 ? "text-orange-400" : "text-green-400" },
                            { label: "Warnings", value: warnings.length, color: warnings.length > 0 ? "text-yellow-400" : "text-gray-500" },
                            { label: "Errors", value: errors.length, color: errors.length > 0 ? "text-red-400" : "text-gray-500" },
                            { label: "Screenshots", value: screenshots.length, color: screenshots.length > 0 ? "text-purple-400" : "text-gray-500" },
                        ].map((stat) => (
                            <div key={stat.label} className="bg-white/[0.02] rounded-lg px-4 py-3 border border-white/[0.04]">
                                <div className={`text-2xl font-black ${stat.color}`}>{stat.value}</div>
                                <div className="text-[10px] text-gray-500 font-medium uppercase tracking-wider mt-0.5">{stat.label}</div>
                            </div>
                        ))}
                    </div>

                    {/* Tabs */}
                    <div className="flex gap-1 mt-5 bg-white/[0.02] rounded-lg p-1 border border-white/[0.04]">
                        {tabs.map((tab) => (
                            <button
                                key={tab.key}
                                onClick={() => setActiveTab(tab.key)}
                                className={`flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-md text-xs font-semibold tracking-wide transition-all ${activeTab === tab.key
                                        ? 'bg-white/[0.06] text-white shadow-sm'
                                        : 'text-gray-500 hover:text-gray-300 hover:bg-white/[0.02]'
                                    }`}
                            >
                                {tab.label}
                                {tab.count > 0 && (
                                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono ${activeTab === tab.key ? 'bg-white/10 text-white' : 'bg-white/5 text-gray-500'
                                        }`}>
                                        {tab.count}
                                    </span>
                                )}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Body */}
                <div className="relative z-10 flex-1 overflow-y-auto px-8 py-6">
                    <AnimatePresence mode="wait">
                        {activeTab === "summary" && (
                            <motion.div
                                key="summary"
                                initial={{ opacity: 0, y: 8 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -8 }}
                                className="space-y-3"
                            >
                                <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">Agent Activity Summary</h3>
                                {summaryItems.length === 0 ? (
                                    <div className="text-gray-600 italic py-8 text-center">No activity recorded yet.</div>
                                ) : (
                                    summaryItems.map((item, i) => (
                                        <motion.div
                                            key={i}
                                            initial={{ opacity: 0, x: -10 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            transition={{ delay: i * 0.03 }}
                                            className="flex items-start gap-3 group"
                                        >
                                            <div className="w-5 h-5 rounded-full flex-shrink-0 flex items-center justify-center bg-white/[0.03] border border-white/[0.06] mt-0.5">
                                                <ChevronRight className="w-3 h-3 text-gray-600 group-hover:text-gray-400 transition-colors" />
                                            </div>
                                            <p className="text-sm text-gray-400 leading-relaxed">{item}</p>
                                        </motion.div>
                                    ))
                                )}

                                {/* Quick findings preview */}
                                {agentFindings.length > 0 && (
                                    <div className="mt-8 pt-6 border-t border-white/5">
                                        <h4 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-4">
                                            Detected Issues ({agentFindings.length})
                                        </h4>
                                        <div className="space-y-2">
                                            {agentFindings.map((f) => (
                                                <div key={f.id} className="flex items-center gap-3 px-4 py-3 rounded-lg bg-white/[0.02] border border-white/[0.04] hover:bg-white/[0.04] transition-colors">
                                                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${severityBadge(f.severity)}`}>
                                                        {f.severity}
                                                    </span>
                                                    <span className="text-sm text-gray-300 font-medium">{f.title}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </motion.div>
                        )}

                        {activeTab === "findings" && (
                            <motion.div
                                key="findings"
                                initial={{ opacity: 0, y: 8 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -8 }}
                                className="space-y-4"
                            >
                                {agentFindings.length === 0 ? (
                                    <div className="text-center py-16">
                                        <CheckCircle className="w-10 h-10 text-green-500/40 mx-auto mb-3" />
                                        <div className="text-gray-500 text-sm">No vulnerabilities detected by this agent.</div>
                                    </div>
                                ) : (
                                    agentFindings
                                        .sort((a, b) => (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0))
                                        .map((f, i) => (
                                            <motion.div
                                                key={f.id}
                                                initial={{ opacity: 0, y: 10 }}
                                                animate={{ opacity: 1, y: 0 }}
                                                transition={{ delay: i * 0.06 }}
                                                className="rounded-xl border border-white/5 overflow-hidden bg-white/[0.015]"
                                            >
                                                <div className="px-5 py-4 border-b border-white/5">
                                                    <div className="flex items-start justify-between">
                                                        <div className="flex items-center gap-3">
                                                            <span className={`text-[10px] font-mono font-bold px-2.5 py-1 rounded-md border ${severityBadge(f.severity)}`}>
                                                                {f.severity}
                                                            </span>
                                                            <h4 className="text-base font-semibold text-white">{f.title}</h4>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div className="px-5 py-4 space-y-4">
                                                    <div>
                                                        <h5 className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                                                            <AlertTriangle className="w-3 h-3" /> Evidence
                                                        </h5>
                                                        <p className="text-sm text-gray-400 leading-relaxed whitespace-pre-wrap font-mono">{f.evidence}</p>
                                                    </div>
                                                    {f.recommendation && (
                                                        <div>
                                                            <h5 className="text-[10px] font-semibold text-green-500/70 uppercase tracking-widest mb-2">💡 Recommendation</h5>
                                                            <p className="text-sm text-gray-400 leading-relaxed">{f.recommendation}</p>
                                                        </div>
                                                    )}
                                                </div>
                                            </motion.div>
                                        ))
                                )}
                            </motion.div>
                        )}

                        {activeTab === "screenshots" && (
                            <motion.div
                                key="screenshots"
                                initial={{ opacity: 0, y: 8 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -8 }}
                            >
                                {screenshots.length === 0 ? (
                                    <div className="text-center py-16">
                                        <Camera className="w-10 h-10 text-gray-700 mx-auto mb-3" />
                                        <div className="text-gray-500 text-sm">No screenshots captured by this agent.</div>
                                    </div>
                                ) : (
                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                                        {screenshots.map((s, i) => (
                                            <motion.div
                                                key={i}
                                                initial={{ opacity: 0, scale: 0.95 }}
                                                animate={{ opacity: 1, scale: 1 }}
                                                transition={{ delay: i * 0.06 }}
                                                className="group cursor-pointer rounded-xl overflow-hidden border border-white/5 bg-white/[0.02] hover:border-white/10 transition-all"
                                                onClick={() => setExpandedImage((s.data as any)?.image)}
                                            >
                                                <div className="relative aspect-video">
                                                    {(s.data as any)?.image ? (
                                                        <img
                                                            src={(s.data as any).image}
                                                            alt={s.message}
                                                            className="w-full h-full object-cover"
                                                        />
                                                    ) : (
                                                        <div className="w-full h-full bg-gray-900 flex items-center justify-center">
                                                            <Camera className="w-8 h-8 text-gray-700" />
                                                        </div>
                                                    )}
                                                    <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                                        <Maximize2 className="w-6 h-6 text-white" />
                                                    </div>
                                                </div>
                                                <div className="px-3 py-2.5">
                                                    <div className="text-xs text-gray-400 truncate">{s.message}</div>
                                                    <div className="text-[10px] text-gray-600 font-mono mt-0.5">
                                                        {new Date(s.created_at).toLocaleTimeString()}
                                                    </div>
                                                </div>
                                            </motion.div>
                                        ))}
                                    </div>
                                )}
                            </motion.div>
                        )}

                        {activeTab === "log" && (
                            <motion.div
                                key="log"
                                initial={{ opacity: 0, y: 8 }}
                                animate={{ opacity: 1, y: 0 }}
                                exit={{ opacity: 0, y: -8 }}
                                className="font-mono text-xs space-y-1"
                            >
                                {agentEvents.length === 0 ? (
                                    <div className="text-center text-gray-600 py-16 italic">No events recorded.</div>
                                ) : (
                                    [...agentEvents].reverse().map((e, i) => (
                                        <div key={e.id} className="flex gap-3 py-1.5 hover:bg-white/[0.02] px-2 rounded-md transition-colors">
                                            <span className="text-gray-600 shrink-0 text-[10px]">
                                                {new Date(e.created_at).toLocaleTimeString()}
                                            </span>
                                            <span className={`text-[10px] font-bold w-16 shrink-0 text-right ${e.event_type === 'ERROR' ? 'text-red-400' :
                                                    e.event_type === 'WARNING' ? 'text-yellow-400' :
                                                        e.event_type === 'SUCCESS' ? 'text-green-400' :
                                                            e.event_type === 'SCREENSHOT' ? 'text-purple-400' :
                                                                'text-gray-500'
                                                }`}>
                                                {e.event_type}
                                            </span>
                                            <span className="text-gray-400 break-all">{e.message}</span>
                                        </div>
                                    ))
                                )}
                            </motion.div>
                        )}
                    </AnimatePresence>
                </div>
            </motion.div>
        </AnimatePresence>
    );
}
