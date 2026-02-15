"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AgentSession, Finding, RunEvent } from "@/lib/types";
import { ShieldAlert, CheckCircle, Terminal, Loader2, Eye, Key, Shield, Monitor, Maximize2, X, Radio } from "lucide-react";

interface AgentLaneProps {
    session: AgentSession;
    findings: Finding[];
    events: RunEvent[];
}

const AGENT_ICON_MAP: Record<string, any> = {
    exposure: Eye,
    headers_tls: Shield,
    auth_abuse: Key,
    llm_analysis: Terminal,
    sqli: ShieldAlert,
    xss: ShieldAlert,
    red_team: ShieldAlert,
};

export default function AgentLane({ session, findings, events }: AgentLaneProps) {
    const [lightboxImage, setLightboxImage] = useState<string | null>(null);
    const Icon = AGENT_ICON_MAP[session.agent_type] || Terminal;
    const isRunning = session.status === "RUNNING";
    const isCompleted = session.status === "COMPLETED";
    const isFailed = session.status === "FAILED";

    // Get screenshots for this agent
    const screenshots = events
        .filter(e => e.event_type === "SCREENSHOT" && (e.data as any)?.image)
        .reverse(); // Chronological order (events are newest-first)
    const latestScreenshot = screenshots[screenshots.length - 1];

    let statusColor = "border-gray-700";
    if (isRunning) statusColor = "border-cyber-blue shadow-[0_0_15px_rgba(0,240,255,0.3)]";
    if (isCompleted) statusColor = "border-success-green shadow-[0_0_10px_rgba(0,255,159,0.2)]";
    if (isFailed) statusColor = "border-danger-red";

    return (
        <>
            <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className={`relative p-4 rounded-lg bg-black/40 border ${statusColor} backdrop-blur-sm transition-all duration-300`}
            >
                {/* Header */}
                <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                        <Icon className={`w-5 h-5 ${isRunning ? 'animate-pulse text-cyber-blue' : 'text-gray-400'}`} />
                        <span className="font-mono text-sm uppercase tracking-wider text-gray-200">
                            {session.agent_type.replace('_', ' ')}
                        </span>
                    </div>
                    <div className="flex items-center gap-2">
                        {isRunning && (
                            <span className="flex items-center gap-1 text-[9px] font-mono text-cyber-blue bg-cyber-blue/10 px-1.5 py-0.5 rounded-full border border-cyber-blue/20">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse" />
                                LIVE
                            </span>
                        )}
                        {isRunning && <Loader2 className="w-4 h-4 animate-spin text-cyber-blue" />}
                        {isCompleted && <CheckCircle className="w-4 h-4 text-success-green" />}
                    </div>
                </div>

                {/* Progress Bar */}
                <div className="w-full bg-gray-800 h-1.5 rounded-full mt-2 mb-3 overflow-hidden">
                    <motion.div
                        className="h-full bg-gradient-to-r from-cyber-blue to-purple-500"
                        initial={{ width: 0 }}
                        animate={{ width: `${session.progress}%` }}
                        transition={{ ease: "linear" }}
                    />
                </div>

                {/* Browser Screenshot */}
                {latestScreenshot ? (
                    <motion.div
                        key={(latestScreenshot.data as any).image.slice(-20)}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="relative group cursor-pointer rounded-md overflow-hidden border border-gray-800 mb-3 hover:border-cyber-blue/40 transition-all"
                        onClick={() => setLightboxImage((latestScreenshot.data as any).image)}
                    >
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                            src={(latestScreenshot.data as any).image}
                            alt={latestScreenshot.message}
                            className="w-full h-40 object-cover object-top bg-black"
                        />
                        <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                        <div className="absolute bottom-0 left-0 right-0 p-2 flex justify-between items-end opacity-0 group-hover:opacity-100 transition-opacity">
                            <span className="text-[9px] font-mono text-gray-300 truncate">{latestScreenshot.message}</span>
                            <Maximize2 className="w-3 h-3 text-gray-400 flex-shrink-0" />
                        </div>
                        {screenshots.length > 1 && (
                            <div className="absolute top-1.5 right-1.5 text-[8px] font-mono text-gray-400 bg-black/70 px-1.5 py-0.5 rounded">
                                {screenshots.length} captures
                            </div>
                        )}
                    </motion.div>
                ) : (
                    <div className="rounded-md border border-gray-800/50 bg-gray-950/40 mb-3 flex items-center justify-center h-24 text-gray-700">
                        <div className="text-center">
                            <Monitor className="w-5 h-5 mx-auto mb-1 opacity-40" />
                            <span className="text-[9px] font-mono">
                                {isRunning ? "Waiting for screenshot..." : "No browser feed"}
                            </span>
                        </div>
                    </div>
                )}

                {/* Stats */}
                <div className="flex justify-between items-end text-xs font-mono text-gray-400">
                    <span>{session.status}</span>
                    <div className="flex items-center gap-1 text-danger-red">
                        {findings.length > 0 && (
                            <>
                                <ShieldAlert className="w-3 h-3" />
                                <span>{findings.length} ISSUES</span>
                            </>
                        )}
                    </div>
                </div>

                {/* Finding Dots */}
                {findings.length > 0 && (
                    <div className="flex gap-1 mt-2 flex-wrap">
                        {findings.map((f) => (
                            <motion.div
                                key={f.id}
                                initial={{ scale: 0 }}
                                animate={{ scale: 1 }}
                                className={`w-2 h-2 rounded-full ${f.severity === 'CRITICAL' ? 'bg-red-600 animate-ping' :
                                    f.severity === 'HIGH' ? 'bg-orange-500' : 'bg-yellow-400'
                                    }`}
                                title={f.title}
                            />
                        ))}
                    </div>
                )}
            </motion.div>

            {/* Lightbox */}
            <AnimatePresence>
                {lightboxImage && (
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 z-50 bg-black/90 backdrop-blur-sm flex items-center justify-center p-8"
                        onClick={() => setLightboxImage(null)}
                    >
                        <button
                            onClick={() => setLightboxImage(null)}
                            className="absolute top-6 right-6 text-gray-400 hover:text-white transition-colors"
                        >
                            <X className="w-6 h-6" />
                        </button>
                        <motion.img
                            initial={{ scale: 0.9 }}
                            animate={{ scale: 1 }}
                            exit={{ scale: 0.9 }}
                            src={lightboxImage}
                            alt="Agent screenshot fullscreen"
                            className="max-w-full max-h-full object-contain rounded-lg border border-gray-700"
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                        />
                    </motion.div>
                )}
            </AnimatePresence>
        </>
    );
}
