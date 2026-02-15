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

            <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">

                {/* Left: Agent Lanes */}
                <div className="lg:col-span-3 space-y-6">
                    <h3 className="text-sm font-mono text-gray-400 mb-4 flex items-center gap-2">
                        <Activity className="w-4 h-4" /> ACTIVE AGENTS
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {sessions.map(session => (
                            <AgentLane
                                key={session.id}
                                session={session}
                                findings={findings.filter(f => f.agent_type === session.agent_type)}
                            />
                        ))}
                    </div>

                    {/* Console Output */}
                    <div className="mt-10 bg-gray-900/50 border border-gray-800 rounded-lg p-4 font-mono text-xs h-[300px] overflow-y-auto">
                        <h4 className="text-gray-500 mb-2 border-b border-gray-800 pb-2">SYSTEM EVENTS</h4>
                        <div className="space-y-1">
                            {events.map(e => (
                                <div key={e.id} className="flex flex-col gap-1 mb-2">
                                    <div className="flex gap-2">
                                        <span className="text-gray-600">[{new Date(e.created_at).toLocaleTimeString()}]</span>
                                        <span className={`
                                            ${e.event_type === 'ERROR' ? 'text-red-500' : ''}
                                            ${e.event_type === 'WARNING' ? 'text-yellow-500' : ''}
                                            ${e.event_type === 'SUCCESS' ? 'text-green-400' : ''}
                                            ${e.event_type === 'INFO' ? 'text-blue-300' : ''}
                                            ${e.event_type === 'SCREENSHOT' ? 'text-purple-400 font-bold' : ''}
                                        `}>
                                            {e.agent_type}: {e.message}
                                        </span>
                                    </div>
                                    {e.event_type === 'SCREENSHOT' && (e.data as any)?.image && (
                                        <div className="ml-24 mt-1">
                                            {/* eslint-disable-next-line @next/next/no-img-element */}
                                            <img
                                                src={(e.data as any).image}
                                                alt="Screenshot"
                                                className="rounded border border-gray-700 max-w-sm hover:scale-150 transition-transform origin-top-left z-10 relative"
                                            />
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>
                </div>

                {/* Right: Live Findings Feed */}
                <div className="lg:col-span-1 bg-gray-900/30 border-l border-gray-800 p-6 -my-8 pt-10">
                    <h3 className="text-sm font-mono text-gray-400 mb-6 flex items-center gap-2">
                        <Bug className="w-4 h-4" /> LIVE FINDINGS
                    </h3>

                    <div className="space-y-4">
                        <AnimatePresence>
                            {findings.slice().reverse().map(f => (
                                <motion.div
                                    key={f.id}
                                    initial={{ opacity: 0, x: 20 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    className={`p-3 rounded border text-sm ${f.severity === 'CRITICAL' ? 'bg-red-900/20 border-red-500 text-red-200' :
                                        f.severity === 'HIGH' ? 'bg-orange-900/20 border-orange-500 text-orange-200' :
                                            f.severity === 'MEDIUM' ? 'bg-yellow-900/20 border-yellow-500 text-yellow-200' :
                                                'bg-blue-900/10 border-blue-500/50 text-blue-200'
                                        }`}
                                >
                                    <div className="flex justify-between items-start mb-1">
                                        <span className="font-bold">{f.title}</span>
                                        <span className="text-[10px] uppercase border px-1 rounded border-current opacity-70">{f.severity}</span>
                                    </div>
                                    <p className="opacity-70 text-xs mb-2 line-clamp-2">{f.evidence}</p>
                                    <div className="text-[10px] text-gray-500 font-mono">{f.agent_type}</div>
                                </motion.div>
                            ))}
                        </AnimatePresence>
                        {findings.length === 0 && (
                            <div className="text-center text-gray-600 py-10 italic">
                                Scanners running...<br />Waiting for signatures.
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
