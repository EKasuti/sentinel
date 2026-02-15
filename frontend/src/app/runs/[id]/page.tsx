"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { AgentSession, RunEvent, Finding, SecurityRun } from "@/lib/types";
import AgentLane from "@/components/AgentLane";
import { Shield, Activity, Bug } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

export default function RunDetails() {
    const params = useParams();
    const runId = params.id as string;

    const [run, setRun] = useState<SecurityRun | null>(null);
    const [sessions, setSessions] = useState<AgentSession[]>([]);
    const [events, setEvents] = useState<RunEvent[]>([]);
    const [findings, setFindings] = useState<Finding[]>([]);

    useEffect(() => {
        if (!runId) return;

        // Initial Fetch
        const fetchData = async () => {
            const runRes = await supabase.from('security_runs').select('*').eq('id', runId).single();
            if (runRes.data) setRun(runRes.data);

            const sessRes = await supabase.from('agent_sessions').select('*').eq('run_id', runId);
            if (sessRes.data) setSessions(sessRes.data);

            const eventRes = await supabase.from('run_events').select('*').eq('run_id', runId).order('created_at', { ascending: false }).limit(50);
            if (eventRes.data) setEvents(eventRes.data);

            const findRes = await supabase.from('findings').select('*').eq('run_id', runId);
            if (findRes.data) setFindings(findRes.data);
        };
        fetchData();

        // Realtime Subscription
        const channel = supabase
            .channel(`run:${runId}`)
            .on('postgres_changes', { event: '*', schema: 'public', table: 'security_runs', filter: `id=eq.${runId}` },
                (payload) => {
                    if (payload.new) setRun(payload.new as SecurityRun);
                }
            )
            .on('postgres_changes', { event: '*', schema: 'public', table: 'agent_sessions', filter: `run_id=eq.${runId}` },
                (payload) => {
                    const newSession = payload.new as AgentSession;
                    setSessions(prev => {
                        const idx = prev.findIndex(s => s.id === newSession.id);
                        if (idx === -1) return [...prev, newSession];
                        const update = [...prev];
                        update[idx] = newSession;
                        return update;
                    });
                }
            )
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'run_events', filter: `run_id=eq.${runId}` },
                (payload) => {
                    setEvents(prev => [payload.new as RunEvent, ...prev].slice(0, 50));
                }
            )
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'findings', filter: `run_id=eq.${runId}` },
                (payload) => {
                    setFindings(prev => [...prev, payload.new as Finding]);
                }
            )
            .subscribe((status) => {
                console.log(`Realtime Subscription Status: ${status} for channel run:${runId}`);
            });

        // Polling Fallback (every 2s)
        const interval = setInterval(fetchData, 2000);

        return () => {
            supabase.removeChannel(channel);
            clearInterval(interval);
        };
    }, [runId]);

    // Calculate Scores & Stats
    const totalFindings = findings.length;
    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;

    return (
        <div className="min-h-screen bg-black text-white p-8">
            {/* Header */}
            <header className="flex justify-between items-center mb-10 border-b border-gray-800 pb-6">
                <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                        <Shield className="text-cyber-blue" />
                        SENTINEL LIVE VIEW
                    </h2>
                    <p className="text-gray-500 font-mono text-sm mt-1">
                        TARGET: <span className="text-cyber-blue">{run?.target_url}</span> | RID: {runId.slice(0, 8)}
                    </p>
                </div>
                <div className="flex gap-6">
                    <div className="text-right">
                        <div className="text-3xl font-black text-white">{totalFindings}</div>
                        <div className="text-xs text-gray-400 font-mono">VULNERABILITIES</div>
                    </div>
                    <div className="text-right">
                        <div className="text-3xl font-black text-danger-red">{criticals}</div>
                        <div className="text-xs text-danger-red font-mono">CRITICAL</div>
                    </div>
                </div>
            </header>

            {/* Executive Summary */}
            {events.find(e => e.message === "EXECUTIVE SUMMARY GENERATED") && (
                <motion.div
                    initial={{ opacity: 0, y: -20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="mb-8 bg-gradient-to-r from-blue-900/20 to-purple-900/20 border border-blue-500/30 rounded-lg p-6"
                >
                    <h3 className="text-lg font-bold text-cyber-blue mb-4 flex items-center gap-2">
                        <Activity className="w-5 h-5" /> EXECUTIVE SECURITY SUMMARY
                    </h3>
                    <div className="text-gray-300 text-sm whitespace-pre-wrap leading-relaxed font-mono">
                        {(events.find(e => e.message === "EXECUTIVE SUMMARY GENERATED")?.data as any)?.summary}
                    </div>
                </motion.div>
            )}

            {/* Main Content Layout */}
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">

                {/* Left Column: Active Agents (Wide) */}
                <div className="lg:col-span-3 space-y-8">

                    {/* Active Agents Section */}
                    <div>
                        <h3 className="text-sm font-mono text-gray-400 mb-4 flex items-center gap-2 uppercase tracking-wider">
                            <Activity className="w-4 h-4 text-green-400" /> Active Operations
                        </h3>

                        {sessions.filter(s => ['QUEUED', 'RUNNING'].includes(s.status)).length === 0 ? (
                            <div className="bg-gray-900/30 border border-gray-800 rounded-lg p-8 text-center text-gray-500 font-mono text-sm">
                                No active agents. All tasks completed.
                            </div>
                        ) : (
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {sessions.filter(s => ['QUEUED', 'RUNNING'].includes(s.status)).map(session => (
                                    <AgentLane
                                        key={session.id}
                                        session={session}
                                        findings={findings.filter(f => f.agent_type === session.agent_type)}
                                    />
                                ))}
                            </div>
                        )}
                    </div>

                    {/* Console Output (Wide) */}
                    <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden flex flex-col h-[500px]">
                        <div className="bg-gray-900 px-4 py-2 border-b border-gray-800 flex justify-between items-center">
                            <h4 className="text-gray-500 font-mono text-xs uppercase tracking-wider">System Event Log</h4>
                            <div className="flex gap-2">
                                <span className="w-2 h-2 rounded-full bg-red-500/50"></span>
                                <span className="w-2 h-2 rounded-full bg-yellow-500/50"></span>
                                <span className="w-2 h-2 rounded-full bg-green-500/50"></span>
                            </div>
                        </div>
                        <div className="p-4 font-mono text-xs overflow-y-auto flex-1 space-y-2">
                            {events.length === 0 && <div className="text-gray-600 italic">Waiting for events...</div>}
                            {events.map(e => (
                                <div key={e.id} className="flex flex-col gap-1 border-b border-gray-800/30 pb-1 last:border-0">
                                    <div className="flex gap-3">
                                        <span className="text-gray-600 whitespace-nowrap">[{new Date(e.created_at).toLocaleTimeString()}]</span>
                                        <div className="flex-1 break-words">
                                            <span className="font-bold text-gray-400 mr-2">[{e.agent_type}]</span>
                                            <span className={`
                                                ${e.event_type === 'ERROR' ? 'text-red-400' : ''}
                                                ${e.event_type === 'WARNING' ? 'text-orange-400' : ''}
                                                ${e.event_type === 'SUCCESS' ? 'text-green-400' : ''}
                                                ${e.event_type === 'INFO' ? 'text-blue-300' : ''}
                                                ${e.event_type === 'SCREENSHOT' ? 'text-purple-400' : ''}
                                            `}>
                                                {e.message}
                                            </span>
                                        </div>
                                    </div>
                                    {e.event_type === 'SCREENSHOT' && (e.data as any)?.image && (
                                        <div className="ml-24 mt-2 mb-2">
                                            {/* eslint-disable-next-line @next/next/no-img-element */}
                                            <img
                                                src={(e.data as any).image}
                                                alt="Screenshot"
                                                className="rounded border border-gray-700 max-w-[300px] shadow-lg hover:scale-150 transition-transform origin-top-left z-10 relative cursor-zoom-in"
                                            />
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right Column: Sidebar (Findings & History) */}
                <div className="lg:col-span-1 space-y-8">

                    {/* Live Findings */}
                    <div className="bg-gray-900/30 border border-gray-800 rounded-lg p-4">
                        <h3 className="text-sm font-mono text-gray-400 mb-4 flex items-center justify-between uppercase tracking-wider border-b border-gray-800 pb-2">
                            <span className="flex items-center gap-2"><Bug className="w-4 h-4" /> Live Findings</span>
                            <span className="text-xs bg-gray-800 px-2 py-0.5 rounded-full">{findings.length}</span>
                        </h3>
                        <div className="space-y-3 max-h-[400px] overflow-y-auto pr-1">
                            <AnimatePresence>
                                {findings.slice().reverse().map(f => (
                                    <motion.div
                                        key={f.id}
                                        initial={{ opacity: 0, x: 20 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        onClick={() => window.location.href = `/runs/${runId}/findings/${f.id}`}
                                        className={`p-3 rounded border text-sm cursor-pointer transition-all hover:translate-x-1 ${f.severity === 'CRITICAL' ? 'bg-red-950/30 border-red-500/50 text-red-200' :
                                                f.severity === 'HIGH' ? 'bg-orange-950/30 border-orange-500/50 text-orange-200' :
                                                    f.severity === 'MEDIUM' ? 'bg-yellow-950/30 border-yellow-500/50 text-yellow-200' :
                                                        'bg-blue-950/30 border-blue-500/50 text-blue-200'
                                            }`}
                                    >
                                        <div className="flex justify-between items-start mb-1 gap-2">
                                            <span className="font-bold text-xs leading-tight">{f.title}</span>
                                            <span className="text-[9px] uppercase border px-1 rounded border-current opacity-70 whitespace-nowrap">{f.severity}</span>
                                        </div>
                                        <div className="text-[10px] text-gray-500 font-mono mt-2 flex justify-between items-center">
                                            <span>{f.agent_type}</span>
                                            <span className="opacity-50">&rarr;</span>
                                        </div>
                                    </motion.div>
                                ))}
                            </AnimatePresence>
                            {findings.length === 0 && (
                                <div className="text-center text-gray-600 py-8 text-xs italic">
                                    Scanning for vulnerabilities...
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Completed Agents History */}
                    <div className="bg-gray-900/30 border border-gray-800 rounded-lg p-4">
                        <h3 className="text-sm font-mono text-gray-400 mb-4 flex items-center gap-2 uppercase tracking-wider border-b border-gray-800 pb-2">
                            <Shield className="w-4 h-4" /> Completed Agents
                        </h3>
                        <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                            {sessions.filter(s => ['COMPLETED', 'FAILED'].includes(s.status)).length === 0 ? (
                                <div className="text-center text-gray-600 py-4 text-xs italic">
                                    No agents completed yet.
                                </div>
                            ) : (
                                sessions.filter(s => ['COMPLETED', 'FAILED'].includes(s.status)).map(session => (
                                    <div key={session.id} className="flex justify-between items-center p-2 rounded bg-gray-800/50 border border-gray-700/50 text-xs">
                                        <span className="font-mono text-gray-300">{session.agent_type}</span>
                                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${session.status === 'COMPLETED' ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'
                                            }`}>
                                            {session.status}
                                        </span>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
}
