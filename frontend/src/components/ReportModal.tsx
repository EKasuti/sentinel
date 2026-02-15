"use client";

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Download, Copy, CheckCircle, Terminal, FileText, Shield, AlertTriangle, Activity, BarChart3, Zap } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { jsPDF } from 'jspdf';
import { supabase } from '@/lib/supabase';
import { Finding, AgentSession } from '@/lib/types';
import { AGENT_META, AGENT_TYPE_MAP } from './AgentStatusGrid';

interface ReportModalProps {
    isOpen: boolean;
    onClose: () => void;
    runId: string;
    targetUrl: string;
}

const loadingLines = [
    "Analyzing findings...",
    "Correlating attack vectors...",
    "Assessing business impact...",
    "Computing risk scores...",
    "Writing executive summary...",
];

const SEVERITY_COLORS: Record<string, { bg: string; border: string; text: string; fill: string }> = {
    CRITICAL: { bg: "bg-red-500/15", border: "border-red-500/30", text: "text-red-400", fill: "#ef4444" },
    HIGH: { bg: "bg-orange-500/15", border: "border-orange-500/30", text: "text-orange-400", fill: "#f97316" },
    MEDIUM: { bg: "bg-yellow-500/15", border: "border-yellow-500/30", text: "text-yellow-400", fill: "#eab308" },
    LOW: { bg: "bg-blue-500/15", border: "border-blue-500/30", text: "text-blue-400", fill: "#3b82f6" },
    INFO: { bg: "bg-gray-500/15", border: "border-gray-500/30", text: "text-gray-400", fill: "#6b7280" },
};

export default function ReportModal({ isOpen, onClose, runId, targetUrl }: ReportModalProps) {
    const [report, setReport] = useState("");
    const [isLoading, setIsLoading] = useState(true);
    const [loadingIndex, setLoadingIndex] = useState(0);
    const [copied, setCopied] = useState(false);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [sessions, setSessions] = useState<AgentSession[]>([]);
    const [activeView, setActiveView] = useState<"dashboard" | "report">("dashboard");

    // Fetch findings + sessions for charts
    useEffect(() => {
        if (!isOpen || !runId) return;
        const fetchData = async () => {
            const [findRes, sessRes] = await Promise.all([
                supabase.from('findings').select('*').eq('run_id', runId),
                supabase.from('agent_sessions').select('*').eq('run_id', runId),
            ]);
            if (findRes.data) setFindings(findRes.data);
            if (sessRes.data) setSessions(sessRes.data);
        };
        fetchData();
    }, [isOpen, runId]);

    // Loading text cycle
    useEffect(() => {
        if (!isOpen) return;
        const interval = setInterval(() => {
            setLoadingIndex(prev => (prev + 1) % loadingLines.length);
        }, 600);
        return () => clearInterval(interval);
    }, [isOpen]);

    // Fetch streamed report
    useEffect(() => {
        if (!isOpen || !runId) return;
        setReport("");
        setIsLoading(true);
        const abortController = new AbortController();

        const fetchReport = async () => {
            try {
                const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5001'}/reports/generate`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ run_id: runId }),
                    signal: abortController.signal
                });
                if (!response.body) throw new Error('No response body');
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let done = false;
                while (!done) {
                    const { value, done: doneReading } = await reader.read();
                    done = doneReading;
                    const chunkValue = decoder.decode(value, { stream: true });
                    setReport(prev => {
                        const next = prev + chunkValue;
                        if (next.length > 50) setIsLoading(false);
                        return next;
                    });
                }
                setIsLoading(false);
            } catch (error: any) {
                if (error.name !== 'AbortError') {
                    console.error('Error generating report:', error);
                    setReport(`# Error Generating Report\n\n${error.message}`);
                    setIsLoading(false);
                }
            }
        };
        fetchReport();
        return () => abortController.abort();
    }, [isOpen, runId]);

    const handleCopy = () => {
        navigator.clipboard.writeText(report);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const handleDownloadPDF = () => {
        const doc = new jsPDF();
        doc.setFont("helvetica", "bold");
        doc.setFontSize(18);
        doc.text("SENTINEL SECURITY REPORT", 10, 20);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(10);
        doc.text(`Target: ${targetUrl}`, 10, 28);
        doc.text(`Date: ${new Date().toLocaleDateString()}`, 10, 34);
        doc.text(`Findings: ${findings.length}`, 10, 40);

        const splitText = doc.splitTextToSize(report.replace(/#/g, ''), 180);
        let y = 50;
        splitText.forEach((line: string) => {
            if (y > 280) { doc.addPage(); y = 10; }
            doc.text(line, 10, y);
            y += 6;
        });
        doc.save(`sentinel_report_${runId.slice(0, 8)}.pdf`);
    };

    if (!isOpen) return null;

    // Compute chart data
    const severityCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach(f => { severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1; });
    const maxSevCount = Math.max(...Object.values(severityCounts), 1);

    // Risk score (simple weighted calc)
    const riskScore = Math.min(100, Math.round(
        (severityCounts.CRITICAL * 25 + severityCounts.HIGH * 15 + severityCounts.MEDIUM * 8 + severityCounts.LOW * 3 + severityCounts.INFO * 1)
    ));
    const riskColor = riskScore >= 70 ? "#ef4444" : riskScore >= 40 ? "#f97316" : riskScore >= 20 ? "#eab308" : "#22c55e";
    const riskLabel = riskScore >= 70 ? "Critical" : riskScore >= 40 ? "High" : riskScore >= 20 ? "Moderate" : "Low";

    // Agent findings
    const agentData = Object.entries(AGENT_META).map(([key, meta]) => {
        const className = AGENT_TYPE_MAP[key] || key;
        const agentFindings = findings.filter(f => f.agent_type === className);
        const session = sessions.find(s => s.agent_type === key);
        return { key, ...meta, findings: agentFindings.length, status: session?.status || 'PENDING' };
    }).sort((a, b) => b.findings - a.findings);

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-50 flex items-center justify-center">
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="fixed inset-0 bg-black/85 backdrop-blur-md"
                    onClick={onClose}
                />

                <motion.div
                    initial={{ scale: 0.96, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.96, opacity: 0, y: 20 }}
                    transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                    className="relative w-full max-w-5xl mx-4 h-[88vh] flex flex-col rounded-2xl overflow-hidden z-50"
                >
                    {/* Modal background */}
                    <div className="absolute inset-0 bg-gradient-to-b from-gray-950 via-[#0a0a12] to-gray-950 border border-white/5 rounded-2xl" />

                    {/* Header */}
                    <div className="relative z-10 flex-shrink-0 px-7 pt-6 pb-4 border-b border-white/5">
                        <div className="flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/20 flex items-center justify-center">
                                    <Shield className="w-5 h-5 text-cyan-400" />
                                </div>
                                <div>
                                    <h2 className="text-lg font-bold text-white tracking-tight">Security Report</h2>
                                    <p className="text-[11px] text-gray-500 font-mono">{targetUrl} · {new Date().toLocaleDateString()}</p>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {/* View Toggle */}
                                <div className="flex bg-white/[0.03] rounded-lg p-0.5 border border-white/[0.04]">
                                    <button
                                        onClick={() => setActiveView("dashboard")}
                                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all ${activeView === "dashboard" ? "bg-white/[0.07] text-white" : "text-gray-500 hover:text-gray-300"
                                            }`}
                                    >
                                        <BarChart3 className="w-3.5 h-3.5" />
                                        Dashboard
                                    </button>
                                    <button
                                        onClick={() => setActiveView("report")}
                                        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-[11px] font-semibold transition-all ${activeView === "report" ? "bg-white/[0.07] text-white" : "text-gray-500 hover:text-gray-300"
                                            }`}
                                    >
                                        <FileText className="w-3.5 h-3.5" />
                                        Full Report
                                    </button>
                                </div>
                                <button onClick={onClose} className="w-8 h-8 rounded-lg flex items-center justify-center text-gray-500 hover:text-white hover:bg-white/5 transition-all ml-2">
                                    <X size={18} />
                                </button>
                            </div>
                        </div>
                    </div>

                    {/* Content */}
                    <div className="relative z-10 flex-1 overflow-y-auto">
                        <AnimatePresence mode="wait">
                            {activeView === "dashboard" ? (
                                <motion.div
                                    key="dashboard"
                                    initial={{ opacity: 0, x: -10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: -10 }}
                                    className="p-7 space-y-6"
                                >
                                    {/* Top row: Risk Score + Severity Breakdown */}
                                    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
                                        {/* Risk Score Circle */}
                                        <div className="flex flex-col items-center justify-center py-6 px-5 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                                            <div className="relative w-32 h-32 mb-4">
                                                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                                                    <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="8" />
                                                    <motion.circle
                                                        cx="50" cy="50" r="42" fill="none" stroke={riskColor} strokeWidth="8"
                                                        strokeLinecap="round"
                                                        strokeDasharray={`${riskScore * 2.64} 264`}
                                                        initial={{ strokeDasharray: "0 264" }}
                                                        animate={{ strokeDasharray: `${riskScore * 2.64} 264` }}
                                                        transition={{ duration: 1.5, ease: "easeOut" }}
                                                    />
                                                </svg>
                                                <div className="absolute inset-0 flex flex-col items-center justify-center">
                                                    <motion.span
                                                        className="text-3xl font-black"
                                                        style={{ color: riskColor }}
                                                        initial={{ opacity: 0 }}
                                                        animate={{ opacity: 1 }}
                                                        transition={{ delay: 0.5 }}
                                                    >
                                                        {riskScore}
                                                    </motion.span>
                                                    <span className="text-[10px] text-gray-500 uppercase tracking-widest font-semibold mt-0.5">Risk</span>
                                                </div>
                                            </div>
                                            <span className="text-sm font-semibold" style={{ color: riskColor }}>{riskLabel} Risk</span>
                                            <span className="text-[10px] text-gray-600 mt-1">{findings.length} vulnerabilities detected</span>
                                        </div>

                                        {/* Severity Distribution */}
                                        <div className="col-span-2 py-5 px-6 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                                            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-5 flex items-center gap-2">
                                                <AlertTriangle className="w-3.5 h-3.5" /> Severity Distribution
                                            </h4>
                                            <div className="space-y-3">
                                                {Object.entries(SEVERITY_COLORS).map(([severity, colors]) => {
                                                    const count = severityCounts[severity] || 0;
                                                    const pct = maxSevCount > 0 ? (count / maxSevCount) * 100 : 0;
                                                    return (
                                                        <div key={severity} className="flex items-center gap-3">
                                                            <span className={`text-[10px] font-mono font-bold w-16 text-right ${colors.text}`}>
                                                                {severity}
                                                            </span>
                                                            <div className="flex-1 h-7 rounded-md bg-white/[0.02] overflow-hidden border border-white/[0.03] relative">
                                                                <motion.div
                                                                    className="h-full rounded-md"
                                                                    style={{ backgroundColor: `${colors.fill}25` }}
                                                                    initial={{ width: 0 }}
                                                                    animate={{ width: `${pct}%` }}
                                                                    transition={{ duration: 0.8, delay: 0.2, ease: "easeOut" }}
                                                                />
                                                                <div className="absolute inset-0 flex items-center px-3">
                                                                    <motion.div
                                                                        className="w-1.5 h-1.5 rounded-full mr-2"
                                                                        style={{ backgroundColor: colors.fill }}
                                                                        initial={{ scale: 0 }}
                                                                        animate={{ scale: 1 }}
                                                                        transition={{ delay: 0.5 }}
                                                                    />
                                                                </div>
                                                            </div>
                                                            <span className={`text-lg font-black w-8 text-center ${count > 0 ? colors.text : 'text-gray-700'}`}>
                                                                {count}
                                                            </span>
                                                        </div>
                                                    );
                                                })}
                                            </div>
                                        </div>
                                    </div>

                                    {/* Agent Coverage */}
                                    <div className="py-5 px-6 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                                        <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-5 flex items-center gap-2">
                                            <Activity className="w-3.5 h-3.5" /> Agent Coverage
                                        </h4>
                                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                                            {agentData.map((agent, i) => {
                                                const AgentIcon = agent.icon;
                                                return (
                                                    <motion.div
                                                        key={agent.key}
                                                        initial={{ opacity: 0, y: 8 }}
                                                        animate={{ opacity: 1, y: 0 }}
                                                        transition={{ delay: i * 0.05 }}
                                                        className="flex items-center gap-3 px-4 py-3 rounded-lg bg-white/[0.015] border border-white/[0.03] hover:bg-white/[0.03] transition-colors"
                                                    >
                                                        <div
                                                            className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
                                                            style={{ background: `${agent.color}15`, border: `1px solid ${agent.color}25` }}
                                                        >
                                                            <AgentIcon className="w-4 h-4" style={{ color: agent.color }} />
                                                        </div>
                                                        <div className="flex-1 min-w-0">
                                                            <div className="text-xs font-semibold text-gray-300 truncate">{agent.label}</div>
                                                            <div className="flex items-center gap-2 mt-0.5">
                                                                <span className={`text-[10px] font-mono ${agent.status === 'COMPLETED' ? 'text-green-500' :
                                                                        agent.status === 'RUNNING' ? 'text-cyan-400' :
                                                                            agent.status === 'FAILED' ? 'text-red-400' : 'text-gray-600'
                                                                    }`}>
                                                                    {agent.status === 'COMPLETED' ? '✓' : agent.status === 'RUNNING' ? '⟳' : agent.status === 'FAILED' ? '✗' : '○'}
                                                                </span>
                                                                {agent.findings > 0 && (
                                                                    <span className="text-[10px] font-bold text-orange-400">{agent.findings} found</span>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </motion.div>
                                                );
                                            })}
                                        </div>
                                    </div>

                                    {/* Key Findings Table */}
                                    {findings.length > 0 && (
                                        <div className="py-5 px-6 rounded-xl bg-white/[0.02] border border-white/[0.04]">
                                            <h4 className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-4 flex items-center gap-2">
                                                <Zap className="w-3.5 h-3.5" /> Key Findings
                                            </h4>
                                            <div className="overflow-hidden rounded-lg border border-white/[0.04]">
                                                <table className="w-full text-xs">
                                                    <thead>
                                                        <tr className="bg-white/[0.02] border-b border-white/[0.04]">
                                                            <th className="text-left py-2.5 px-4 text-gray-500 font-semibold uppercase tracking-wider text-[10px]">Severity</th>
                                                            <th className="text-left py-2.5 px-4 text-gray-500 font-semibold uppercase tracking-wider text-[10px]">Finding</th>
                                                            <th className="text-left py-2.5 px-4 text-gray-500 font-semibold uppercase tracking-wider text-[10px]">Agent</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {findings
                                                            .sort((a, b) => {
                                                                const order: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
                                                                return (order[b.severity] || 0) - (order[a.severity] || 0);
                                                            })
                                                            .map((f, i) => {
                                                                const sev = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.INFO;
                                                                const entry = Object.entries(AGENT_TYPE_MAP).find(([, v]) => v === f.agent_type);
                                                                const snakeName = entry ? entry[0] : f.agent_type;
                                                                const agentLabel = AGENT_META[snakeName]?.label || f.agent_type;
                                                                return (
                                                                    <tr key={f.id} className={`border-b border-white/[0.02] ${i % 2 === 0 ? '' : 'bg-white/[0.01]'}`}>
                                                                        <td className="py-2.5 px-4">
                                                                            <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${sev.bg} ${sev.border} ${sev.text}`}>
                                                                                {f.severity}
                                                                            </span>
                                                                        </td>
                                                                        <td className="py-2.5 px-4 text-gray-300 font-medium">{f.title}</td>
                                                                        <td className="py-2.5 px-4 text-gray-500">{agentLabel}</td>
                                                                    </tr>
                                                                );
                                                            })}
                                                    </tbody>
                                                </table>
                                            </div>
                                        </div>
                                    )}
                                </motion.div>
                            ) : (
                                <motion.div
                                    key="report"
                                    initial={{ opacity: 0, x: 10 }}
                                    animate={{ opacity: 1, x: 0 }}
                                    exit={{ opacity: 0, x: 10 }}
                                    className="p-7"
                                >
                                    {isLoading && report.length < 50 ? (
                                        <div className="h-full flex flex-col items-center justify-center gap-4 min-h-[300px]">
                                            <div className="relative">
                                                <Terminal size={40} className="text-cyan-400/40" />
                                                <motion.div
                                                    className="absolute inset-0 flex items-center justify-center"
                                                    animate={{ opacity: [0.3, 1, 0.3] }}
                                                    transition={{ repeat: Infinity, duration: 2 }}
                                                >
                                                    <Terminal size={40} className="text-cyan-400" />
                                                </motion.div>
                                            </div>
                                            <div className="text-sm font-medium text-gray-400 tracking-wide">
                                                {loadingLines[loadingIndex]}
                                                <motion.span
                                                    animate={{ opacity: [0, 1, 0] }}
                                                    transition={{ repeat: Infinity, duration: 0.8 }}
                                                    className="inline-block ml-0.5 text-cyan-400"
                                                >▊</motion.span>
                                            </div>
                                        </div>
                                    ) : (
                                        <div className="prose prose-invert max-w-none
                                            prose-headings:font-bold prose-headings:tracking-tight
                                            prose-h2:text-cyan-400 prose-h2:text-lg prose-h2:border-b prose-h2:border-white/5 prose-h2:pb-3 prose-h2:mb-4
                                            prose-h3:text-gray-200 prose-h3:text-base
                                            prose-p:text-gray-400 prose-p:text-sm prose-p:leading-relaxed
                                            prose-strong:text-white prose-strong:font-semibold
                                            prose-li:text-gray-400 prose-li:text-sm
                                            prose-table:text-xs
                                            prose-th:text-gray-400 prose-th:font-semibold prose-th:uppercase prose-th:tracking-wider prose-th:text-[10px] prose-th:py-2.5 prose-th:px-3 prose-th:bg-white/[0.02] prose-th:border-white/[0.04]
                                            prose-td:py-2 prose-td:px-3 prose-td:text-gray-400 prose-td:border-white/[0.04]
                                            prose-pre:bg-white/[0.02] prose-pre:border prose-pre:border-white/[0.04] prose-pre:rounded-xl prose-pre:text-xs
                                            prose-code:text-cyan-300 prose-code:font-normal
                                            prose-a:text-cyan-400 prose-a:no-underline hover:prose-a:underline
                                        ">
                                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                                {report}
                                            </ReactMarkdown>
                                        </div>
                                    )}
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    {/* Footer */}
                    <div className="relative z-10 flex-shrink-0 px-7 py-4 border-t border-white/5 bg-white/[0.01] flex justify-between items-center">
                        <div className="text-[10px] text-gray-600 font-mono">
                            {isLoading ? "Generating..." : `${report.length.toLocaleString()} chars · ${findings.length} findings`}
                        </div>
                        <div className="flex gap-2">
                            <button
                                onClick={handleCopy}
                                disabled={isLoading && report.length < 50}
                                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white/[0.04] border border-white/[0.06] text-gray-400 hover:text-white hover:bg-white/[0.06] transition-all text-[11px] font-semibold disabled:opacity-30"
                            >
                                {copied ? <CheckCircle size={13} className="text-green-400" /> : <Copy size={13} />}
                                {copied ? "Copied" : "Copy"}
                            </button>
                            <button
                                onClick={handleDownloadPDF}
                                disabled={isLoading && report.length < 50}
                                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/15 text-cyan-400 hover:bg-cyan-500/20 hover:border-cyan-500/25 transition-all text-[11px] font-semibold disabled:opacity-30"
                            >
                                <Download size={13} />
                                PDF
                            </button>
                        </div>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
}
