"use client";

import { useEffect, useState, useCallback } from "react";
import { useParams, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { AgentSession, RunEvent, Finding, SecurityRun } from "@/lib/types";
import AgentStatusGrid from "@/components/AgentStatusGrid";
import { AGENT_META, AGENT_TYPE_MAP } from "@/components/AgentStatusGrid";
import AgentDetailModal from "@/components/AgentDetailModal";
import { Activity, Bug, ChevronDown, Radar } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import RunHeader from "@/components/RunHeader";

export default function RunDetails() {
    const params = useParams();
    const router = useRouter();
    const runId = params.id as string;

    const [run, setRun] = useState<SecurityRun | null>(null);
    const [sessions, setSessions] = useState<AgentSession[]>([]);
    const [events, setEvents] = useState<RunEvent[]>([]);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [filterAgent, setFilterAgent] = useState<string>("ALL");
    const [dropdownOpen, setDropdownOpen] = useState(false);
    const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
    const [elapsed, setElapsed] = useState("00:00");
    const [cancelling, setCancelling] = useState(false);

    useEffect(() => {
        if (!runId) return;

        const fetchData = async () => {
            const runRes = await supabase.from('security_runs').select('*').eq('id', runId).single();
            if (runRes.data) setRun(runRes.data);

            const sessRes = await supabase.from('agent_sessions').select('*').eq('run_id', runId);
            if (sessRes.data) setSessions(sessRes.data);

            const eventRes = await supabase.from('run_events').select('*').eq('run_id', runId).order('created_at', { ascending: false }).limit(500);
            if (eventRes.data) setEvents(eventRes.data);

            const findRes = await supabase.from('findings').select('*').eq('run_id', runId);
            if (findRes.data) setFindings(findRes.data);
        };
        fetchData();

        const channel = supabase
            .channel(`run:${runId}`)
            .on('postgres_changes', { event: '*', schema: 'public', table: 'security_runs', filter: `id=eq.${runId}` },
                (payload) => { if (payload.new) setRun(payload.new as SecurityRun); }
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
                (payload) => { setEvents(prev => [payload.new as RunEvent, ...prev].slice(0, 500)); }
            )
            .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'findings', filter: `run_id=eq.${runId}` },
                (payload) => { setFindings(prev => [...prev, payload.new as Finding]); }
            )
            .subscribe();

        const interval = setInterval(fetchData, 3000);
        return () => { supabase.removeChannel(channel); clearInterval(interval); };
    }, [runId]);

    // Close dropdown when clicking outside
    useEffect(() => {
        const close = () => setDropdownOpen(false);
        if (dropdownOpen) {
            window.addEventListener('click', close);
            return () => window.removeEventListener('click', close);
        }
    }, [dropdownOpen]);

    // Elapsed time ticker
    useEffect(() => {
        const startStr = run?.started_at;
        if (!startStr) return;
        const startTime = new Date(startStr).getTime();
        const tick = () => {
            const endStr = run?.ended_at;
            const now = endStr ? new Date(endStr).getTime() : Date.now();
            const diff = Math.max(0, now - startTime);
            const h = Math.floor(diff / 3600000);
            const m = Math.floor((diff % 3600000) / 60000);
            const s = Math.floor((diff % 60000) / 1000);
            setElapsed(h > 0 ? `${h}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}` : `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`);
        };
        tick();
        const iv = setInterval(tick, 1000);
        return () => clearInterval(iv);
    }, [run?.started_at, run?.ended_at]);

    // Cancel handler
    const handleCancel = useCallback(async () => {
        if (cancelling) return;
        setCancelling(true);
        try {
            await fetch(`${process.env.NEXT_PUBLIC_API_URL}/runs/${runId}/cancel`, { method: 'POST' });
        } catch (err) {
            console.error('Failed to cancel:', err);
        } finally {
            setCancelling(false);
        }
    }, [runId, cancelling]);

    const totalFindings = findings.length;
    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;
    const mediums = findings.filter(f => f.severity === 'MEDIUM').length;
    const isRunning = run?.status === 'RUNNING';
    const isCompleted = run?.status === 'COMPLETED';
    const isCancelled = run?.status === 'CANCELLED';

    // Total requests sent (use events count as proxy)
    const totalRequests = events.length;

    // Security score: weighted deduction from 100
    const securityScore = Math.max(0, Math.min(100, 100 - (criticals * 25 + highs * 15 + mediums * 8 + findings.filter(f => f.severity === 'LOW').length * 3 + findings.filter(f => f.severity === 'INFO').length * 1)));
    const scoreColor = securityScore >= 80 ? 'text-green-400' : securityScore >= 50 ? 'text-yellow-400' : securityScore >= 25 ? 'text-orange-400' : 'text-red-400';
    const scoreBg = securityScore >= 80 ? 'bg-green-500/10 border-green-500/20' : securityScore >= 50 ? 'bg-yellow-500/10 border-yellow-500/20' : securityScore >= 25 ? 'bg-orange-500/10 border-orange-500/20' : 'bg-red-500/10 border-red-500/20';

    // Build dropdown options
    const agentOptions = Object.entries(AGENT_META).map(([key, meta]) => {
        const className = AGENT_TYPE_MAP[key] || key;
        const count = events.filter(e => e.agent_type === className).length;
        return { key, label: meta.label, icon: meta.icon, color: meta.color, count };
    });

    const selectedLabel = filterAgent === "ALL"
        ? "All Agents"
        : AGENT_META[filterAgent]?.label || filterAgent;

    const filteredEvents = events.filter(e => {
        if (filterAgent === "ALL") return true;
        const className = AGENT_TYPE_MAP[filterAgent] || filterAgent;
        return e.agent_type === className;
    });

    const getAgentStatus = (agentName: string) => {
        const session = sessions.find(s => s.agent_type === agentName);
        return session?.status || 'PENDING';
    };

    // Re-Run handler
    const handleReRun = useCallback(async () => {
        if (!run) return;

        try {
            // Get unique agents from current sessions
            const agents = Array.from(new Set(sessions.map(s => s.agent_type)));

            const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/runs/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: run.target_url,
                    agents: agents.length > 0 ? agents : undefined,
                    configuration: run.configuration
                })
            });

            if (res.ok) {
                const data = await res.json();
                router.push(`/runs/${data.run_id}`);
            }
        } catch (err) {
            console.error('Failed to re-run:', err);
        }
    }, [run, sessions, router]);

    return (
        <div className="min-h-screen bg-[#050508] text-white">
            {/* Background decoration */}
            <div className="fixed inset-0 pointer-events-none">
                <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/[0.02] rounded-full blur-[120px]" />
                <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/[0.02] rounded-full blur-[120px]" />
            </div>

            <RunHeader
                run={run}
                elapsed={elapsed}
                totalRequests={totalRequests}
                findings={findings}
                securityScore={securityScore}
                onReRun={handleReRun}
                onCancel={handleCancel}
                isCancelling={cancelling}
            />



            <div className="relative z-10 p-6 lg:p-8 max-w-[1600px] mx-auto">

                {/* Executive Summary */}
                {events.find(e => e.message === "EXECUTIVE SUMMARY GENERATED") && (
                    <motion.div
                        initial={{ opacity: 0, y: -20 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="mb-10 rounded-xl border border-blue-500/10 bg-gradient-to-r from-blue-500/[0.04] to-purple-500/[0.04] p-6 backdrop-blur-sm"
                    >
                        <h3 className="text-sm font-semibold text-cyan-400/90 mb-4 flex items-center gap-2 uppercase tracking-wider">
                            <Activity className="w-4 h-4" /> Executive Summary
                        </h3>
                        <div className="text-gray-400 text-sm whitespace-pre-wrap leading-relaxed font-mono">
                            {(events.find(e => e.message === "EXECUTIVE SUMMARY GENERATED")?.data as any)?.summary}
                        </div>
                    </motion.div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
                    {/* Left column */}
                    <div className="lg:col-span-3 space-y-8">
                        {/* Agent Grid */}
                        <div>
                            <h3 className="text-xs font-semibold text-gray-500 mb-5 flex items-center gap-2 uppercase tracking-widest">
                                <Activity className="w-3.5 h-3.5" /> Agents
                            </h3>
                            <AgentStatusGrid
                                sessions={sessions}
                                findings={findings}
                                events={events}
                                onAgentClick={(name) => setSelectedAgent(name)}
                            />
                        </div>

                        {/* Console Output with Dropdown */}
                        <div className="rounded-xl overflow-hidden border border-white/5 bg-white/[0.01]">
                            {/* Dropdown Header */}
                            <div className="flex items-center justify-between px-5 py-3.5 border-b border-white/5 bg-white/[0.015]">
                                <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-widest">
                                    Live Console
                                </span>

                                {/* Agent Filter Dropdown */}
                                <div className="relative" onClick={(e) => e.stopPropagation()}>
                                    <button
                                        onClick={() => setDropdownOpen(!dropdownOpen)}
                                        className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] text-sm text-gray-300 hover:bg-white/[0.06] hover:border-white/[0.08] transition-all"
                                    >
                                        {filterAgent !== "ALL" && AGENT_META[filterAgent] && (
                                            <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: AGENT_META[filterAgent].color }} />
                                        )}
                                        <span className="font-medium text-xs">{selectedLabel}</span>
                                        <span className="text-[10px] text-gray-600 font-mono ml-1">{filteredEvents.length}</span>
                                        <ChevronDown className={`w-3.5 h-3.5 text-gray-500 transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
                                    </button>

                                    <AnimatePresence>
                                        {dropdownOpen && (
                                            <motion.div
                                                initial={{ opacity: 0, y: -5, scale: 0.97 }}
                                                animate={{ opacity: 1, y: 0, scale: 1 }}
                                                exit={{ opacity: 0, y: -5, scale: 0.97 }}
                                                transition={{ duration: 0.15 }}
                                                className="absolute right-0 mt-1.5 w-60 rounded-xl overflow-hidden border border-white/[0.06] bg-gray-950/98 backdrop-blur-xl shadow-2xl z-50"
                                            >
                                                <div className="p-1.5">
                                                    <button
                                                        onClick={() => { setFilterAgent("ALL"); setDropdownOpen(false); }}
                                                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all ${filterAgent === "ALL" ? 'bg-white/[0.06] text-white' : 'text-gray-400 hover:bg-white/[0.03] hover:text-gray-200'
                                                            }`}
                                                    >
                                                        <Activity className="w-3.5 h-3.5 text-cyan-400" />
                                                        <span className="text-xs font-medium flex-1">All Agents</span>
                                                        <span className="text-[10px] text-gray-600 font-mono">{events.length}</span>
                                                    </button>

                                                    <div className="h-px bg-white/5 my-1" />

                                                    {agentOptions.map(({ key, label, icon: DropIcon, color, count }) => (
                                                        <button
                                                            key={key}
                                                            onClick={() => { setFilterAgent(key); setDropdownOpen(false); }}
                                                            className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all ${filterAgent === key ? 'bg-white/[0.06] text-white' : 'text-gray-400 hover:bg-white/[0.03] hover:text-gray-200'
                                                                }`}
                                                        >
                                                            <div className="w-3.5 h-3.5 rounded-full flex items-center justify-center" style={{ backgroundColor: `${color}20` }}>
                                                                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                                                            </div>
                                                            <span className="text-xs font-medium flex-1">{label}</span>
                                                            {count > 0 && (
                                                                <span className="text-[10px] text-gray-600 font-mono">{count}</span>
                                                            )}
                                                        </button>
                                                    ))}
                                                </div>
                                            </motion.div>
                                        )}
                                    </AnimatePresence>
                                </div>
                            </div>

                            {/* Log Content */}
                            <div className="p-4 font-mono text-xs h-[380px] overflow-y-auto">
                                <div className="space-y-0.5">
                                    {filteredEvents.map(e => (
                                        <div key={e.id} className="flex flex-col gap-1 mb-1.5">
                                            <div className="flex gap-2 py-0.5 hover:bg-white/[0.015] px-1 rounded transition-colors">
                                                <span className="text-gray-700 shrink-0 text-[10px]">
                                                    [{new Date(e.created_at).toLocaleTimeString()}]
                                                </span>
                                                <span className={`leading-relaxed text-[11px] ${e.event_type === 'ERROR' ? 'text-red-400' :
                                                    e.event_type === 'WARNING' ? 'text-yellow-400' :
                                                        e.event_type === 'SUCCESS' ? 'text-green-400' :
                                                            e.event_type === 'SCREENSHOT' ? 'text-purple-400' :
                                                                'text-gray-400'
                                                    }`}>
                                                    {filterAgent === "ALL" && (
                                                        <span className="text-gray-600 mr-1.5">
                                                            {(() => {
                                                                const entry = Object.entries(AGENT_TYPE_MAP).find(([, v]) => v === e.agent_type);
                                                                const snakeName = entry ? entry[0] : e.agent_type;
                                                                return AGENT_META[snakeName]?.label || e.agent_type;
                                                            })()}:
                                                        </span>
                                                    )}
                                                    {e.message}
                                                </span>
                                            </div>
                                            {e.event_type === 'SCREENSHOT' && (e.data as any)?.image && (
                                                <div className="ml-28 mt-1 mb-2">
                                                    <img
                                                        src={(e.data as any).image}
                                                        alt="Screenshot"
                                                        className="rounded-lg border border-white/5 max-w-xs hover:scale-110 transition-transform origin-top-left z-10 relative shadow-xl"
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                    {filteredEvents.length === 0 && (
                                        <div className="text-center text-gray-700 py-12 italic text-xs">
                                            No events yet.
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Right: Findings Feed */}
                    <div className="lg:col-span-1">
                        <div className="sticky top-8">
                            <h3 className="text-xs font-semibold text-gray-500 mb-5 flex items-center gap-2 uppercase tracking-widest">
                                <Bug className="w-3.5 h-3.5" /> Findings
                                {totalFindings > 0 && (
                                    <span className="ml-auto px-2 py-0.5 rounded-full bg-white/[0.04] text-[10px] font-mono text-gray-500">{totalFindings}</span>
                                )}
                            </h3>

                            <div className="space-y-3">
                                <AnimatePresence>
                                    {findings.slice().reverse().map(f => (
                                        <motion.div
                                            key={f.id}
                                            initial={{ opacity: 0, x: 20 }}
                                            animate={{ opacity: 1, x: 0 }}
                                            onClick={() => window.location.href = `/runs/${runId}/findings/${f.id}`}
                                            className={`group p-4 rounded-xl border text-sm cursor-pointer transition-all duration-200 hover:scale-[1.02] active:scale-[0.98] ${f.severity === 'CRITICAL' ? 'bg-red-500/[0.06] border-red-500/20 hover:border-red-500/40 hover:bg-red-500/[0.1]' :
                                                f.severity === 'HIGH' ? 'bg-orange-500/[0.06] border-orange-500/20 hover:border-orange-500/40 hover:bg-orange-500/[0.1]' :
                                                    f.severity === 'MEDIUM' ? 'bg-yellow-500/[0.04] border-yellow-500/15 hover:border-yellow-500/30 hover:bg-yellow-500/[0.08]' :
                                                        f.severity === 'LOW' ? 'bg-blue-500/[0.04] border-blue-500/15 hover:border-blue-500/30 hover:bg-blue-500/[0.08]' :
                                                            'bg-white/[0.02] border-white/5 hover:border-white/10 hover:bg-white/[0.04]'
                                                }`}
                                        >
                                            <div className="flex justify-between items-start mb-2">
                                                <span className="font-semibold text-white/90 text-[13px] leading-tight pr-2">{f.title}</span>
                                                <span className={`text-[9px] uppercase font-mono font-bold px-1.5 py-0.5 rounded border flex-shrink-0 ${f.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-300 border-red-500/30' :
                                                    f.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/30' :
                                                        f.severity === 'MEDIUM' ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' :
                                                            f.severity === 'LOW' ? 'bg-blue-500/20 text-blue-300 border-blue-500/30' :
                                                                'bg-gray-500/20 text-gray-300 border-gray-500/30'
                                                    }`}>{f.severity}</span>
                                            </div>
                                            <p className="text-gray-500 text-[11px] mb-2.5 line-clamp-2 leading-relaxed">{f.evidence}</p>
                                            <div className="text-[10px] text-gray-600 font-mono flex justify-between items-center">
                                                <span>{(() => {
                                                    const entry = Object.entries(AGENT_TYPE_MAP).find(([, v]) => v === f.agent_type);
                                                    const snakeName = entry ? entry[0] : f.agent_type;
                                                    return AGENT_META[snakeName]?.label || f.agent_type;
                                                })()}</span>
                                                <span className="text-gray-700 group-hover:text-gray-500 transition-colors">Details →</span>
                                            </div>
                                        </motion.div>
                                    ))}
                                </AnimatePresence>
                                {findings.length === 0 && (
                                    <div className="text-center text-gray-700 py-16 italic text-xs">
                                        {isRunning ? (
                                            <div className="space-y-2">
                                                <Radar className="w-8 h-8 mx-auto text-cyan-500/30 animate-pulse" />
                                                <span>Scanning for vulnerabilities...</span>
                                            </div>
                                        ) : (
                                            "No vulnerabilities detected."
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Agent Detail Modal */}
            <AnimatePresence>
                {selectedAgent && (
                    <AgentDetailModal
                        agentName={selectedAgent}
                        events={events}
                        findings={findings}
                        status={getAgentStatus(selectedAgent)}
                        onClose={() => setSelectedAgent(null)}
                    />
                )}
            </AnimatePresence>
        </div>
    );
}
