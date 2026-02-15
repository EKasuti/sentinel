import { motion } from "framer-motion";
import { AgentSession, Finding, RunEvent, RunStatus } from "@/lib/types";
import { Shield, AlertTriangle, CheckCircle, Clock, Loader2, Eye, Key, Terminal, ShieldAlert, Bug, Search, Bot } from "lucide-react";

// Map snake_case session names to class names used in DB findings/events
const AGENT_TYPE_MAP: Record<string, string> = {
    "headers_tls": "HeadersAgent",
    "exposure": "ExposureAgent",
    "auth_abuse": "AuthAbuseAgent",
    "xss": "XSSAgent",
    "llm_analysis": "LLMAnalysisAgent",
    "sqli": "SQLiAgent",
    "red_team": "RedTeamAgent",
};

const AGENT_META: Record<string, { label: string; icon: any; color: string; gradient: string }> = {
    "headers_tls": { label: "Headers / TLS", icon: Shield, color: "#00f0ff", gradient: "from-cyan-500/20 to-blue-600/20" },
    "exposure": { label: "Exposure", icon: Eye, color: "#bd00ff", gradient: "from-purple-500/20 to-pink-600/20" },
    "auth_abuse": { label: "Auth Abuse", icon: Key, color: "#ffd000", gradient: "from-yellow-500/20 to-amber-600/20" },
    "xss": { label: "XSS", icon: Bug, color: "#ff6b2b", gradient: "from-orange-500/20 to-red-600/20" },
    "llm_analysis": { label: "LLM Analysis", icon: Terminal, color: "#00ff9f", gradient: "from-emerald-500/20 to-green-600/20" },
    "sqli": { label: "SQL Injection", icon: Search, color: "#ff003c", gradient: "from-red-500/20 to-rose-600/20" },
    "red_team": { label: "Red Team", icon: Bot, color: "#f472b6", gradient: "from-pink-500/20 to-fuchsia-600/20" },
};

const AGENT_NAMES = Object.keys(AGENT_META);

const SEVERITY_ORDER: Record<string, number> = {
    'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0
};

interface AgentStatusGridProps {
    sessions: AgentSession[];
    findings: Finding[];
    events: RunEvent[];
    onAgentClick: (agentName: string) => void;
}

export default function AgentStatusGrid({ sessions, findings, events, onAgentClick }: AgentStatusGridProps) {
    const getAgentStatus = (agentName: string): RunStatus => {
        const session = sessions.find(s => s.agent_type === agentName);
        return session ? session.status : 'PENDING' as RunStatus;
    };

    const getAgentFindings = (agentName: string) => {
        const className = AGENT_TYPE_MAP[agentName] || agentName;
        return findings.filter(f => f.agent_type === className);
    };

    const getAgentEventCount = (agentName: string) => {
        const className = AGENT_TYPE_MAP[agentName] || agentName;
        return events.filter(e => e.agent_type === className).length;
    };

    const getAgentScreenshots = (agentName: string) => {
        const className = AGENT_TYPE_MAP[agentName] || agentName;
        return events.filter(e => e.agent_type === className && e.event_type === 'SCREENSHOT').length;
    };

    const getWorstSeverity = (agentFindings: Finding[]) => {
        if (agentFindings.length === 0) return null;
        return agentFindings.reduce((prev, current) =>
            (SEVERITY_ORDER[current.severity] || 0) > (SEVERITY_ORDER[prev.severity] || 0) ? current : prev
        ).severity;
    };

    const getSeverityBorderColor = (severity: string | null) => {
        if (!severity) return "border-gray-800/60";
        switch (severity) {
            case 'CRITICAL': return "border-red-500/60";
            case 'HIGH': return "border-orange-500/60";
            case 'MEDIUM': return "border-yellow-500/60";
            case 'LOW': return "border-blue-400/40";
            default: return "border-gray-700/60";
        }
    };

    return (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {AGENT_NAMES.map((agentName, index) => {
                const meta = AGENT_META[agentName];
                const Icon = meta.icon;
                const status = getAgentStatus(agentName);
                const agentFindings = getAgentFindings(agentName);
                const worstSeverity = getWorstSeverity(agentFindings);
                const isCompleted = status === 'COMPLETED';
                const isRunning = status === 'RUNNING';
                const isFailed = status === 'FAILED';
                const eventCount = getAgentEventCount(agentName);
                const screenshotCount = getAgentScreenshots(agentName);
                const hasFindings = agentFindings.length > 0;
                const borderColor = hasFindings ? getSeverityBorderColor(worstSeverity) :
                    isRunning ? "border-cyan-500/40" :
                        isCompleted ? "border-green-500/20" :
                            isFailed ? "border-red-500/30" : "border-gray-800/40";

                return (
                    <motion.div
                        key={agentName}
                        initial={{ opacity: 0, y: 15 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: index * 0.06, duration: 0.4 }}
                        onClick={() => onAgentClick(agentName)}
                        className={`relative group cursor-pointer rounded-xl overflow-hidden border ${borderColor} transition-all duration-300 hover:scale-[1.03] hover:shadow-lg active:scale-[0.98]`}
                    >
                        {/* Background gradient */}
                        <div className={`absolute inset-0 bg-gradient-to-br ${meta.gradient} opacity-40 group-hover:opacity-70 transition-opacity duration-300`} />
                        <div className="absolute inset-0 glass-dark" />

                        {/* Scanning animation for running state */}
                        {isRunning && (
                            <motion.div
                                className="absolute inset-0 bg-gradient-to-r from-transparent via-cyan-400/8 to-transparent"
                                initial={{ x: '-100%' }}
                                animate={{ x: '100%' }}
                                transition={{ repeat: Infinity, duration: 1.8, ease: "linear" }}
                            />
                        )}

                        {/* Content */}
                        <div className="relative z-10 p-5">
                            {/* Top row: Icon + Status */}
                            <div className="flex justify-between items-start mb-4">
                                <div className="flex items-center gap-3">
                                    <div
                                        className="w-9 h-9 rounded-lg flex items-center justify-center"
                                        style={{ background: `${meta.color}15`, border: `1px solid ${meta.color}30` }}
                                    >
                                        <Icon className="w-4.5 h-4.5" style={{ color: meta.color }} />
                                    </div>
                                    <div>
                                        <h4 className="font-semibold text-sm text-white/90 tracking-tight">
                                            {meta.label}
                                        </h4>
                                        <div className="text-[10px] text-gray-500 font-mono mt-0.5">
                                            {eventCount} events{screenshotCount > 0 ? ` · ${screenshotCount} 📸` : ''}
                                        </div>
                                    </div>
                                </div>
                                <StatusBadge status={status} />
                            </div>

                            {/* Findings count */}
                            <div className="flex items-end justify-between">
                                <div className="flex items-baseline gap-2">
                                    <span className={`text-3xl font-black tracking-tight ${hasFindings ? (
                                            worstSeverity === 'CRITICAL' ? 'text-red-400' :
                                                worstSeverity === 'HIGH' ? 'text-orange-400' :
                                                    worstSeverity === 'MEDIUM' ? 'text-yellow-400' :
                                                        'text-blue-400'
                                        ) : 'text-white/60'
                                        }`}>
                                        {agentFindings.length}
                                    </span>
                                    <span className="text-[11px] text-gray-500 font-medium uppercase tracking-wider">
                                        {agentFindings.length === 1 ? 'Finding' : 'Findings'}
                                    </span>
                                </div>

                                {/* Severity dots */}
                                {hasFindings && (
                                    <div className="flex gap-1.5">
                                        {agentFindings.map((f, i) => (
                                            <div
                                                key={i}
                                                className={`w-2 h-2 rounded-full ${f.severity === 'CRITICAL' ? 'bg-red-500 animate-pulse' :
                                                        f.severity === 'HIGH' ? 'bg-orange-500' :
                                                            f.severity === 'MEDIUM' ? 'bg-yellow-500' :
                                                                f.severity === 'LOW' ? 'bg-blue-400' :
                                                                    'bg-gray-500'
                                                    }`}
                                                title={f.title}
                                            />
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Click hint */}
                        <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-white/0 to-transparent group-hover:via-white/10 transition-all duration-300" />
                    </motion.div>
                );
            })}
        </div>
    );
}

// Export these for use in other components
export { AGENT_TYPE_MAP, AGENT_META, AGENT_NAMES, SEVERITY_ORDER };

function StatusBadge({ status }: { status: RunStatus | 'PENDING' }) {
    const configs: Record<string, { bg: string; text: string; icon: any; label: string }> = {
        COMPLETED: { bg: "bg-green-500/10 border-green-500/25", text: "text-green-400", icon: CheckCircle, label: "DONE" },
        RUNNING: { bg: "bg-cyan-500/10 border-cyan-500/25", text: "text-cyan-400", icon: Loader2, label: "RUNNING" },
        PENDING: { bg: "bg-gray-800/50 border-gray-700/30", text: "text-gray-500", icon: Clock, label: "PENDING" },
        FAILED: { bg: "bg-red-500/10 border-red-500/25", text: "text-red-400", icon: AlertTriangle, label: "FAILED" },
        QUEUED: { bg: "bg-amber-500/10 border-amber-500/25", text: "text-amber-400", icon: Clock, label: "QUEUED" },
    };

    const config = configs[status] || configs.PENDING;
    const BadgeIcon = config.icon;
    const isRunning = status === 'RUNNING';

    return (
        <div className={`flex items-center gap-1 px-2 py-0.5 rounded-md border ${config.bg} ${config.text}`}>
            <BadgeIcon className={`w-3 h-3 ${isRunning ? 'animate-spin' : ''}`} />
            <span className="text-[9px] font-mono font-bold tracking-widest">{config.label}</span>
        </div>
    );
}
