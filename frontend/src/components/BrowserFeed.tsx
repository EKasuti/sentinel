"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { RunEvent, AgentSession } from "@/lib/types";
import { Monitor, X, Maximize2, Radio } from "lucide-react";

interface BrowserFeedProps {
    events: RunEvent[];
    sessions: AgentSession[];
}

interface ScreenshotEntry {
    agentType: string;
    image: string;
    message: string;
    timestamp: string;
}

export default function BrowserFeed({ events, sessions }: BrowserFeedProps) {
    const [lightboxImage, setLightboxImage] = useState<string | null>(null);
    const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
    const scrollRef = useRef<HTMLDivElement>(null);

    // Extract latest screenshot per agent
    const screenshotsByAgent = new Map<string, ScreenshotEntry>();
    const allScreenshots: ScreenshotEntry[] = [];

    // Events are newest-first, so iterate in reverse to build chronological order
    const chronologicalEvents = [...events].reverse();
    for (const event of chronologicalEvents) {
        if (event.event_type === "SCREENSHOT" && (event.data as any)?.image) {
            const entry: ScreenshotEntry = {
                agentType: event.agent_type,
                image: (event.data as any).image,
                message: event.message,
                timestamp: event.created_at,
            };
            screenshotsByAgent.set(event.agent_type, entry);
            allScreenshots.push(entry);
        }
    }

    const latestScreenshots = Array.from(screenshotsByAgent.values());
    const hasRunningAgents = sessions.some(s => s.status === "RUNNING");

    // Filter screenshots by selected agent
    const displayScreenshots = selectedAgent
        ? allScreenshots.filter(s => s.agentType === selectedAgent)
        : allScreenshots;

    // The "hero" image: latest from selected agent, or overall latest
    const heroScreenshot = selectedAgent
        ? screenshotsByAgent.get(selectedAgent)
        : latestScreenshots[latestScreenshots.length - 1];

    // Auto-scroll timeline when new screenshots arrive
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollLeft = scrollRef.current.scrollWidth;
        }
    }, [allScreenshots.length]);

    if (allScreenshots.length === 0) {
        return (
            <div className="relative rounded-xl border border-gray-800 bg-gray-950/60 backdrop-blur-sm p-6 mb-8">
                <div className="flex items-center gap-2 mb-4">
                    <Monitor className="w-4 h-4 text-gray-500" />
                    <span className="text-sm font-mono text-gray-500 uppercase tracking-wider">Browser Feed</span>
                    {hasRunningAgents && (
                        <span className="flex items-center gap-1 ml-auto text-xs font-mono text-cyber-blue">
                            <Radio className="w-3 h-3 animate-pulse" />
                            WAITING FOR SCREENSHOTS
                        </span>
                    )}
                </div>
                <div className="flex items-center justify-center h-48 text-gray-600 font-mono text-sm">
                    <div className="text-center">
                        <Monitor className="w-10 h-10 mx-auto mb-3 opacity-30" />
                        <p>Agents are initializing...</p>
                        <p className="text-xs mt-1 text-gray-700">Screenshots will appear here as agents browse the target.</p>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <>
            <div className={`relative rounded-xl border bg-gray-950/60 backdrop-blur-sm p-4 mb-8 transition-all duration-500 ${hasRunningAgents
                ? "border-cyber-blue/40 shadow-[0_0_25px_rgba(0,240,255,0.08)]"
                : "border-gray-800"
                }`}>
                {/* Header */}
                <div className="flex items-center gap-2 mb-4">
                    <Monitor className="w-4 h-4 text-cyber-blue" />
                    <span className="text-sm font-mono text-gray-300 uppercase tracking-wider">Browser Feed</span>
                    {hasRunningAgents && (
                        <span className="flex items-center gap-1.5 ml-2 text-[10px] font-mono text-cyber-blue bg-cyber-blue/10 px-2 py-0.5 rounded-full border border-cyber-blue/20">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse" />
                            LIVE
                        </span>
                    )}
                    <span className="ml-auto text-[10px] font-mono text-gray-600">
                        {allScreenshots.length} captures
                    </span>
                </div>

                {/* Agent Filter Tabs */}
                <div className="flex gap-2 mb-4 flex-wrap">
                    <button
                        onClick={() => setSelectedAgent(null)}
                        className={`text-[10px] font-mono px-2.5 py-1 rounded-md border transition-all ${!selectedAgent
                            ? "border-cyber-blue/50 bg-cyber-blue/10 text-cyber-blue"
                            : "border-gray-800 text-gray-500 hover:text-gray-300 hover:border-gray-700"
                            }`}
                    >
                        ALL
                    </button>
                    {latestScreenshots.map(s => (
                        <button
                            key={s.agentType}
                            onClick={() => setSelectedAgent(s.agentType)}
                            className={`text-[10px] font-mono px-2.5 py-1 rounded-md border transition-all uppercase ${selectedAgent === s.agentType
                                ? "border-cyber-blue/50 bg-cyber-blue/10 text-cyber-blue"
                                : "border-gray-800 text-gray-500 hover:text-gray-300 hover:border-gray-700"
                                }`}
                        >
                            {s.agentType.replace("_", " ")}
                        </button>
                    ))}
                </div>

                {/* Hero Screenshot */}
                {heroScreenshot && (
                    <motion.div
                        key={heroScreenshot.image}
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.3 }}
                        className="relative group cursor-pointer rounded-lg overflow-hidden border border-gray-800 mb-4"
                        onClick={() => setLightboxImage(heroScreenshot.image)}
                    >
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                            src={heroScreenshot.image}
                            alt={heroScreenshot.message}
                            className="w-full max-h-[400px] object-contain bg-black"
                        />
                        <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                        <div className="absolute bottom-0 left-0 right-0 p-3 opacity-0 group-hover:opacity-100 transition-opacity">
                            <div className="flex justify-between items-end">
                                <div>
                                    <span className="text-[10px] font-mono text-cyber-blue uppercase bg-cyber-blue/10 px-1.5 py-0.5 rounded">
                                        {heroScreenshot.agentType.replace("_", " ")}
                                    </span>
                                    <p className="text-xs text-gray-300 mt-1">{heroScreenshot.message}</p>
                                </div>
                                <Maximize2 className="w-4 h-4 text-gray-400" />
                            </div>
                        </div>
                    </motion.div>
                )}

                {/* Screenshot Timeline Strip */}
                {displayScreenshots.length > 1 && (
                    <div
                        ref={scrollRef}
                        className="flex gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-gray-800 scrollbar-track-transparent"
                    >
                        {displayScreenshots.map((s, i) => (
                            <motion.div
                                key={`${s.agentType}-${s.timestamp}-${i}`}
                                initial={{ opacity: 0, scale: 0.9 }}
                                animate={{ opacity: 1, scale: 1 }}
                                className={`relative flex-shrink-0 w-32 h-20 rounded-md overflow-hidden border cursor-pointer transition-all hover:border-cyber-blue/50 ${heroScreenshot === s
                                    ? "border-cyber-blue/60 ring-1 ring-cyber-blue/20"
                                    : "border-gray-800"
                                    }`}
                                onClick={() => setLightboxImage(s.image)}
                            >
                                {/* eslint-disable-next-line @next/next/no-img-element */}
                                <img
                                    src={s.image}
                                    alt={s.message}
                                    className="w-full h-full object-cover"
                                />
                                <div className="absolute bottom-0 left-0 right-0 bg-black/70 px-1 py-0.5">
                                    <span className="text-[8px] font-mono text-gray-400 uppercase">
                                        {s.agentType.replace("_", " ")}
                                    </span>
                                </div>
                            </motion.div>
                        ))}
                    </div>
                )}
            </div>

            {/* Lightbox Overlay */}
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
                            className="absolute top-6 right-6 text-gray-400 hover:text-white transition-colors z-50"
                        >
                            <X className="w-6 h-6" />
                        </button>
                        <motion.img
                            initial={{ scale: 0.9 }}
                            animate={{ scale: 1 }}
                            exit={{ scale: 0.9 }}
                            src={lightboxImage}
                            alt="Screenshot fullscreen"
                            className="max-w-full max-h-full object-contain rounded-lg border border-gray-700"
                            onClick={(e: React.MouseEvent) => e.stopPropagation()}
                        />
                    </motion.div>
                )}
            </AnimatePresence>
        </>
    );
}
