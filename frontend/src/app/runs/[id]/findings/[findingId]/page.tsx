"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { Finding } from "@/lib/types";
import { Shield, ArrowLeft, AlertTriangle, Film, Camera, Maximize2, X } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function FindingDetails() {
    const params = useParams();
    const router = useRouter();
    const runId = params.id as string;
    const findingId = params.findingId as string;

    const [finding, setFinding] = useState<Finding | null>(null);
    const [selectedScreenshot, setSelectedScreenshot] = useState<string | null>(null);

    useEffect(() => {
        const fetchFinding = async () => {
            const { data } = await supabase
                .from('findings')
                .select('*')
                .eq('id', findingId)
                .single();
            if (data) setFinding(data);
        };
        fetchFinding();
    }, [findingId]);

    if (!finding) return <div className="p-10 text-white font-mono">Loading finding...</div>;

    const severityColor =
        finding.severity === 'CRITICAL' ? 'text-red-500 border-red-500' :
            finding.severity === 'HIGH' ? 'text-orange-500 border-orange-500' :
                finding.severity === 'MEDIUM' ? 'text-yellow-500 border-yellow-500' : 'text-blue-500 border-blue-500';

    return (
        <div className="min-h-screen bg-black text-white p-8 font-mono">
            {/* Image Modal for Evidence Trail */}
            <AnimatePresence>
                {selectedScreenshot && (
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/90 backdrop-blur-sm" onClick={() => setSelectedScreenshot(null)}>
                        <motion.img
                            initial={{ scale: 0.9, opacity: 0 }}
                            animate={{ scale: 1, opacity: 1 }}
                            exit={{ scale: 0.9, opacity: 0 }}
                            src={selectedScreenshot}
                            alt="Evidence Detail"
                            className="max-w-full max-h-screen rounded border border-cyber-blue shadow-2xl"
                        />
                        <button className="absolute top-4 right-4 text-white hover:text-cyber-blue" onClick={() => setSelectedScreenshot(null)}>
                            <X size={32} />
                        </button>
                    </div>
                )}
            </AnimatePresence>

            <header className="mb-8 border-b border-gray-800 pb-4">
                <button
                    onClick={() => router.back()}
                    className="text-gray-400 hover:text-white flex items-center gap-2 mb-4"
                >
                    <ArrowLeft size={16} /> Back to Run
                </button>
                <div className="flex justify-between items-start">
                    <div>
                        <div className="flex items-center gap-3 mb-2">
                            <h1 className="text-3xl font-bold">{finding.title}</h1>
                            {finding.screenshots && finding.screenshots.length > 0 && (
                                <span className="flex items-center gap-1 bg-red-900/40 border border-red-500/50 text-red-200 text-[10px] font-bold px-2 py-0.5 rounded tracking-wider animate-pulse">
                                    <Camera size={12} /> PROOF OF EXPLOITATION
                                </span>
                            )}
                        </div>
                        <div className="flex gap-4 items-center">
                            <span className={`border px-2 py-1 text-xs font-bold rounded ${severityColor}`}>
                                {finding.severity}
                            </span>
                            <span className="text-gray-500 text-sm">Agent: {finding.agent_type}</span>
                            <span className="text-gray-500 text-sm">ID: {finding.id}</span>
                        </div>
                    </div>
                    <Shield className="w-12 h-12 text-gray-800" />
                </div>
            </header>

            {/* Evidence Trail Filmstrip */}
            {finding.screenshots && finding.screenshots.length > 0 && (
                <motion.div
                    initial={{ x: 50, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    transition={{ duration: 0.5 }}
                    className="mb-8"
                >
                    <h3 className="text-cyber-blue text-sm font-bold tracking-widest mb-4 flex items-center gap-2 border-b border-gray-800 pb-2">
                        <Film size={16} /> AGENT EVIDENCE TRAIL
                    </h3>
                    <div className="flex gap-4 overflow-x-auto pb-4 scrollbar-thin scrollbar-thumb-gray-700">
                        {finding.screenshots.map((shot, idx) => (
                            <motion.div
                                key={idx}
                                initial={{ opacity: 0, x: 20 }}
                                animate={{ opacity: 1, x: 0 }}
                                transition={{ delay: idx * 0.08 }}
                                className="flex-shrink-0 w-64 group cursor-pointer"
                                onClick={() => setSelectedScreenshot(shot.url)}
                            >
                                <div className="relative aspect-video rounded border border-gray-700 overflow-hidden group-hover:border-cyber-blue/50 transition-colors">
                                    <img src={shot.url} alt={shot.caption} className="object-cover w-full h-full" />
                                    <div className="absolute inset-0 bg-black/50 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                                        <Maximize2 className="text-white" />
                                    </div>
                                    {/* Pulse Effect for High Severity Findings */}
                                    {(finding.severity === 'CRITICAL' || finding.severity === 'HIGH') && (
                                        <div className="absolute inset-0 border-2 border-red-500/0 group-hover:border-red-500/50 animate-pulse pointer-events-none" />
                                    )}
                                </div>
                                <div className="mt-2">
                                    <div className="text-xs text-cyber-blue font-mono">{new Date(shot.timestamp).toLocaleTimeString()}</div>
                                    <div className="text-xs text-gray-400 font-mono truncate">{shot.caption}</div>
                                </div>
                            </motion.div>
                        ))}
                    </div>
                </motion.div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-6"
                >
                    <div className="bg-gray-900/50 p-6 rounded border border-gray-800">
                        <h3 className="text-gray-400 text-sm uppercase mb-3 flex items-center gap-2">
                            <AlertTriangle size={16} /> Evidence & Reproduction
                        </h3>
                        <div className="text-gray-300 whitespace-pre-wrap leading-relaxed text-sm break-all">
                            {finding.evidence}
                        </div>
                    </div>

                    <div className="bg-gray-900/50 p-6 rounded border border-gray-800">
                        <h3 className="text-gray-400 text-sm uppercase mb-3 text-green-400">
                            Remediation
                        </h3>
                        <div className="text-gray-300 whitespace-pre-wrap leading-relaxed text-sm break-all">
                            {finding.recommendation}
                        </div>
                    </div>
                </motion.div>

                <div className="bg-gray-900/30 p-6 rounded border border-gray-800 h-fit">
                    <h3 className="text-gray-400 text-sm uppercase mb-4">Finding Metadata</h3>
                    <div className="space-y-2 text-sm">
                        <div className="flex justify-between border-b border-gray-800 pb-2">
                            <span className="text-gray-500">Detected At</span>
                            <span>{new Date(finding.created_at).toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between border-b border-gray-800 pb-2">
                            <span className="text-gray-500">Status</span>
                            <span>Open</span>
                        </div>
                        <div className="flex justify-between border-b border-gray-800 pb-2">
                            <span className="text-gray-500">Run ID</span>
                            <span className="text-xs">{runId}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
