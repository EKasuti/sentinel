"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
    Shield,
    AlertTriangle,
    CheckCircle,
    ChevronDown,
    ChevronUp,
    ArrowLeft,
    Bot,
    Sparkles,
    Clock,
    Zap,
    Download,
    ExternalLink,
    Info,
    AlertCircle,
    BookOpen,
    Wrench,
} from "lucide-react";

// ---------- Types ----------
interface ReportFinding {
    id: string;
    severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
    title: string;
    evidence: string;
    recommendation: string;
    agent_type: string;
    created_at: string;
    what_is_wrong: string;
    why_it_matters: string;
    how_to_fix: string;
    references: string[];
    priority: string;
    effort: string;
}

interface ReportSession {
    agent_type: string;
    status: string;
    progress: number;
}

interface ReportData {
    run: {
        id: string;
        target_url: string;
        status: string;
        created_at: string;
        ended_at: string;
    };
    risk_score: number;
    risk_grade: string;
    findings: ReportFinding[];
    sessions: ReportSession[];
    summary: {
        total: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
}

// ---------- Config ----------
const SEVERITY_CONFIG = {
    CRITICAL: {
        color: "text-red-400",
        bg: "bg-red-500/10",
        border: "border-red-500/40",
        badge: "bg-red-500/20 text-red-400 border-red-500/30",
        glow: "shadow-[0_0_15px_rgba(239,68,68,0.15)]",
        label: "Critical",
        printColor: "#f87171",
    },
    HIGH: {
        color: "text-orange-400",
        bg: "bg-orange-500/10",
        border: "border-orange-500/40",
        badge: "bg-orange-500/20 text-orange-400 border-orange-500/30",
        glow: "shadow-[0_0_15px_rgba(249,115,22,0.15)]",
        label: "High",
        printColor: "#fb923c",
    },
    MEDIUM: {
        color: "text-yellow-400",
        bg: "bg-yellow-500/10",
        border: "border-yellow-500/40",
        badge: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
        glow: "shadow-[0_0_15px_rgba(234,179,8,0.15)]",
        label: "Medium",
        printColor: "#facc15",
    },
    LOW: {
        color: "text-blue-400",
        bg: "bg-blue-500/10",
        border: "border-blue-500/40",
        badge: "bg-blue-500/20 text-blue-400 border-blue-500/30",
        glow: "shadow-[0_0_15px_rgba(59,130,246,0.15)]",
        label: "Low",
        printColor: "#60a5fa",
    },
};

const GRADE_COLORS: Record<string, string> = {
    A: "text-emerald-400", B: "text-green-400", C: "text-yellow-400",
    D: "text-orange-400", F: "text-red-400",
};

const GRADE_BG: Record<string, string> = {
    A: "from-emerald-500/20 to-emerald-500/5", B: "from-green-500/20 to-green-500/5",
    C: "from-yellow-500/20 to-yellow-500/5", D: "from-orange-500/20 to-orange-500/5",
    F: "from-red-500/20 to-red-500/5",
};

const AGENT_LABELS: Record<string, string> = {
    spider: "🕷️ Spider / Recon", exposure: "🔍 Secret Scanner", headers_tls: "🔒 Headers & TLS",
    cors: "🌐 CORS Scanner", portscan: "📡 Port Scanner",
    auth_abuse: "🔑 Auth Abuse", llm_analysis: "🧠 LLM Analysis",
    sqli: "💉 SQL Injection", xss: "⚡ XSS", red_team: "🔴 Red Team AI",
};

function formatDate(dateStr: string) {
    if (!dateStr) return "—";
    return new Date(dateStr).toLocaleString();
}

// ---------- Components ----------

function RiskGauge({ score, grade }: { score: number; grade: string }) {
    const circumference = 2 * Math.PI * 60;
    const offset = circumference - (score / 100) * circumference;
    return (
        <div className="relative w-44 h-44 mx-auto">
            <svg className="w-44 h-44 -rotate-90" viewBox="0 0 140 140">
                <circle cx="70" cy="70" r="60" stroke="rgba(255,255,255,0.05)" strokeWidth="8" fill="none" />
                <motion.circle cx="70" cy="70" r="60" stroke="currentColor" strokeWidth="8" fill="none" strokeLinecap="round"
                    className={GRADE_COLORS[grade] || "text-gray-400"}
                    initial={{ strokeDashoffset: circumference }}
                    animate={{ strokeDashoffset: offset }}
                    transition={{ duration: 1.5, ease: "easeOut" }}
                    strokeDasharray={circumference}
                />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
                <motion.span className={`text-5xl font-black ${GRADE_COLORS[grade]}`}
                    initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ delay: 0.5, type: "spring" }}>
                    {grade}
                </motion.span>
                <span className="text-xs text-gray-500 font-mono mt-1">{score}/100</span>
            </div>
        </div>
    );
}

function CodeBlock({ code }: { code: string }) {
    // Parse code blocks from markdown-style formatting
    const parts = code.split(/(```[\s\S]*?```)/g);
    return (
        <div className="space-y-3">
            {parts.map((part, i) => {
                if (part.startsWith("```")) {
                    const lines = part.split("\n");
                    const lang = lines[0].replace("```", "").trim();
                    const codeContent = lines.slice(1, -1).join("\n");
                    return (
                        <div key={i} className="rounded-lg overflow-hidden">
                            {lang && (
                                <div className="bg-gray-800 text-gray-400 text-[10px] font-mono px-3 py-1 uppercase tracking-wider">
                                    {lang}
                                </div>
                            )}
                            <pre className="bg-gray-950 text-gray-200 text-sm p-4 overflow-x-auto font-mono leading-relaxed">
                                <code>{codeContent}</code>
                            </pre>
                        </div>
                    );
                }
                if (part.trim()) {
                    return (
                        <div key={i} className="text-sm text-gray-300 leading-relaxed whitespace-pre-wrap">
                            {part}
                        </div>
                    );
                }
                return null;
            })}
        </div>
    );
}

function FindingDetail({ finding, index }: { finding: ReportFinding; index: number }) {
    const [expanded, setExpanded] = useState(true);
    const config = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.LOW;
    const hasGemini = finding.what_is_wrong || finding.how_to_fix;

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.06 }}
            className={`rounded-xl border ${config.border} ${config.bg} ${config.glow} overflow-hidden print:shadow-none print:break-inside-avoid`}
            id={`finding-${finding.id}`}
        >
            {/* Header */}
            <button onClick={() => setExpanded(!expanded)}
                className="w-full flex items-center justify-between p-5 text-left hover:bg-white/[0.02] transition-colors print:hover:bg-transparent">
                <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="text-lg font-mono text-gray-500 w-8 shrink-0">#{index + 1}</span>
                    <span className={`shrink-0 text-[10px] font-bold uppercase tracking-wider px-2.5 py-1 rounded border ${config.badge}`}>
                        {finding.severity}
                    </span>
                    <span className="text-white font-semibold">{finding.title}</span>
                </div>
                <div className="flex items-center gap-3 shrink-0 ml-4 print:hidden">
                    <div className="flex items-center gap-2">
                        {finding.priority && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 flex items-center gap-1">
                                <Clock className="w-3 h-3" />{finding.priority}
                            </span>
                        )}
                        {finding.effort && (
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 flex items-center gap-1">
                                <Zap className="w-3 h-3" />{finding.effort}
                            </span>
                        )}
                    </div>
                    {expanded ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
                </div>
            </button>

            {/* Detail Sections */}
            <AnimatePresence initial={false}>
                {expanded && (
                    <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }} className="overflow-hidden">
                        <div className="px-5 pb-6 space-y-5 border-t border-white/5 pt-5">

                            {/* Agent + Meta */}
                            <div className="flex items-center gap-4 text-xs text-gray-500 font-mono">
                                <span>Discovered by: {AGENT_LABELS[finding.agent_type] || finding.agent_type}</span>
                                <span>•</span>
                                <span>{formatDate(finding.created_at)}</span>
                            </div>

                            {/* Evidence */}
                            <div>
                                <h4 className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wider flex items-center gap-1.5">
                                    <AlertCircle className="w-3.5 h-3.5" /> Evidence
                                </h4>
                                <div className="bg-black/40 rounded-lg p-4 font-mono text-sm text-gray-300 break-all leading-relaxed border border-white/5">
                                    {finding.evidence || "No evidence recorded"}
                                </div>
                            </div>

                            {/* Gemini Sections */}
                            {hasGemini && (
                                <div className="rounded-xl bg-gradient-to-br from-blue-500/[0.06] to-purple-500/[0.03] border border-blue-500/15 overflow-hidden">
                                    <div className="flex items-center gap-2 px-5 py-3 border-b border-blue-500/10 bg-blue-500/[0.03]">
                                        <div className="w-6 h-6 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center">
                                            <Sparkles className="w-3.5 h-3.5 text-white" />
                                        </div>
                                        <span className="text-sm font-bold text-blue-300">Gemini Security Analysis</span>
                                    </div>

                                    <div className="p-5 space-y-5">
                                        {/* What's Wrong */}
                                        {finding.what_is_wrong && (
                                            <div>
                                                <h5 className="text-xs font-bold text-red-300 mb-2 uppercase tracking-wider flex items-center gap-1.5">
                                                    <AlertTriangle className="w-3.5 h-3.5" /> What&apos;s Wrong
                                                </h5>
                                                <p className="text-sm text-gray-300 leading-relaxed">{finding.what_is_wrong}</p>
                                            </div>
                                        )}

                                        {/* Why It Matters */}
                                        {finding.why_it_matters && (
                                            <div>
                                                <h5 className="text-xs font-bold text-yellow-300 mb-2 uppercase tracking-wider flex items-center gap-1.5">
                                                    <Info className="w-3.5 h-3.5" /> Why It Matters
                                                </h5>
                                                <p className="text-sm text-gray-300 leading-relaxed">{finding.why_it_matters}</p>
                                            </div>
                                        )}

                                        {/* How to Fix */}
                                        {finding.how_to_fix && (
                                            <div>
                                                <h5 className="text-xs font-bold text-emerald-300 mb-3 uppercase tracking-wider flex items-center gap-1.5">
                                                    <Wrench className="w-3.5 h-3.5" /> How to Fix
                                                </h5>
                                                <CodeBlock code={finding.how_to_fix} />
                                            </div>
                                        )}

                                        {/* References */}
                                        {finding.references && finding.references.length > 0 && (
                                            <div>
                                                <h5 className="text-xs font-bold text-blue-300 mb-2 uppercase tracking-wider flex items-center gap-1.5">
                                                    <BookOpen className="w-3.5 h-3.5" /> References
                                                </h5>
                                                <ul className="space-y-1">
                                                    {finding.references.map((ref, i) => (
                                                        <li key={i}>
                                                            <a href={ref} target="_blank" rel="noopener noreferrer"
                                                                className="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1.5 transition-colors">
                                                                <ExternalLink className="w-3 h-3 shrink-0" />
                                                                <span className="truncate">{ref}</span>
                                                            </a>
                                                        </li>
                                                    ))}
                                                </ul>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}

                            {/* Fallback: basic recommendation if no Gemini */}
                            {!hasGemini && finding.recommendation && (
                                <div>
                                    <h4 className="text-xs font-bold text-gray-400 mb-2 uppercase tracking-wider">Recommendation</h4>
                                    <p className="text-sm text-gray-300">{finding.recommendation}</p>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </motion.div>
    );
}

// ---------- Page ----------
export default function ReportPage() {
    const params = useParams();
    const router = useRouter();
    const runId = params.id as string;

    const [report, setReport] = useState<ReportData | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");

    useEffect(() => {
        if (!runId) return;
        setLoading(true);
        fetch(`${process.env.NEXT_PUBLIC_API_URL}/runs/${runId}/report`)
            .then((r) => r.json())
            .then((data) => {
                if (data.error) setError(data.error);
                else setReport(data);
            })
            .catch((e) => setError(e.message))
            .finally(() => setLoading(false));
    }, [runId]);

    const handleDownloadPDF = () => {
        window.print();
    };

    if (loading) {
        return (
            <div className="min-h-screen bg-black flex items-center justify-center">
                <motion.div className="flex flex-col items-center gap-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                    <div className="w-14 h-14 rounded-full border-2 border-t-cyan-400 border-r-transparent border-b-purple-400 border-l-transparent animate-spin" />
                    <p className="text-gray-400 font-mono text-sm">
                        <Sparkles className="inline w-4 h-4 mr-1.5 text-blue-400" />
                        Gemini is analyzing vulnerabilities...
                    </p>
                    <p className="text-gray-600 text-xs">Generating detailed remediation with code examples</p>
                </motion.div>
            </div>
        );
    }

    if (error || !report) {
        return (
            <div className="min-h-screen bg-black flex items-center justify-center text-red-400">
                <p>Error: {error || "Failed to load report"}</p>
            </div>
        );
    }

    const { run, risk_score, risk_grade, findings, sessions, summary } = report;

    return (
        <>
            {/* Print Styles */}
            <style jsx global>{`
        @media print {
          body { background: white !important; color: black !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
          .print\\:hidden { display: none !important; }
          .print\\:break-inside-avoid { break-inside: avoid; }
          @page { margin: 1cm; size: A4; }
        }
      `}</style>

            <div className="min-h-screen bg-black text-white">
                {/* Top Bar */}
                <div className="border-b border-gray-800 bg-gray-950/50 backdrop-blur-xl sticky top-0 z-50 print:hidden">
                    <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
                        <button onClick={() => router.push(`/runs/${runId}`)}
                            className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors text-sm">
                            <ArrowLeft className="w-4 h-4" /> Back to Live View
                        </button>
                        <div className="flex items-center gap-4">
                            <button onClick={handleDownloadPDF}
                                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-white/5 border border-white/10 text-white hover:bg-white/10 transition-colors text-sm font-medium">
                                <Download className="w-4 h-4" /> Download PDF
                            </button>
                            <div className="flex items-center gap-2 text-gray-500 text-xs font-mono">
                                <Shield className="w-4 h-4 text-cyan-400" /> SENTINEL REPORT
                            </div>
                        </div>
                    </div>
                </div>

                <div className="max-w-6xl mx-auto px-6 py-10">
                    {/* ===== HEADER ===== */}
                    <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="text-center mb-14">
                        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono mb-6">
                            <Shield className="w-3.5 h-3.5" /> BLUE HAT SECURITY ASSESSMENT
                        </div>
                        <h1 className="text-4xl md:text-5xl font-black tracking-tight mb-4 bg-gradient-to-r from-white via-gray-200 to-gray-500 bg-clip-text text-transparent print:text-black">
                            Security Assessment Report
                        </h1>
                        <p className="text-gray-400 font-mono text-lg">
                            Target: <span className="text-cyan-400 print:text-blue-600">{run.target_url}</span>
                        </p>
                        <p className="text-gray-600 text-xs font-mono mt-2">
                            Assessment Date: {formatDate(run.created_at)} • Report ID: {run.id.slice(0, 8)}
                        </p>
                    </motion.div>

                    {/* ===== EXECUTIVE SUMMARY ===== */}
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.1 }}
                        className="mb-14 rounded-2xl bg-gray-900/30 border border-white/5 p-8 print:bg-gray-50 print:border-gray-200">
                        <h2 className="text-lg font-bold mb-6 flex items-center gap-2">
                            <BookOpen className="w-5 h-5 text-cyan-400" /> Executive Summary
                        </h2>
                        <p className="text-gray-300 leading-relaxed mb-6 print:text-gray-700">
                            An automated security assessment was performed on <strong className="text-white print:text-black">{run.target_url}</strong> using
                            Sentinel&apos;s multi-agent scanning platform. The assessment deployed{" "}
                            <strong className="text-white print:text-black">{sessions.length} autonomous agents</strong> to identify
                            vulnerabilities across multiple attack vectors including web application security, API security,
                            authentication, and infrastructure configuration.
                        </p>
                        <p className="text-gray-300 leading-relaxed print:text-gray-700">
                            The scan discovered <strong className={`${summary.critical > 0 ? "text-red-400" : summary.high > 0 ? "text-orange-400" : "text-emerald-400"} print:text-black`}>
                                {summary.total} vulnerabilit{summary.total === 1 ? "y" : "ies"}
                            </strong>
                            {summary.critical > 0 && <>, including <strong className="text-red-400 print:text-red-600">{summary.critical} critical</strong> issue{summary.critical > 1 ? "s" : ""} requiring immediate attention</>}
                            {summary.high > 0 && <>{summary.critical > 0 ? " and" : ", including"} <strong className="text-orange-400 print:text-orange-600">{summary.high} high-severity</strong> finding{summary.high > 1 ? "s" : ""}</>}
                            . Detailed remediation guidance is provided below for each finding.
                        </p>
                    </motion.div>

                    {/* ===== SCORE + SUMMARY ROW ===== */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-14">
                        {/* Risk Grade */}
                        <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.2 }}
                            className={`col-span-1 rounded-2xl bg-gradient-to-b ${GRADE_BG[risk_grade] || GRADE_BG.C} border border-white/5 p-6 text-center`}>
                            <h3 className="text-xs font-mono text-gray-400 mb-4 uppercase tracking-wider">Security Grade</h3>
                            <RiskGauge score={risk_score} grade={risk_grade} />
                            <p className="text-xs text-gray-500 mt-4 font-mono">
                                {risk_grade === "A" ? "Excellent security posture" :
                                    risk_grade === "B" ? "Good, minor issues to address" :
                                        risk_grade === "C" ? "Fair, several improvements needed" :
                                            risk_grade === "D" ? "Poor, significant vulnerabilities" :
                                                "Critical — immediate action required"}
                            </p>
                        </motion.div>

                        {/* Severity Breakdown */}
                        <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.3 }}
                            className="col-span-1 rounded-2xl bg-gray-900/50 border border-white/5 p-6">
                            <h3 className="text-xs font-mono text-gray-400 mb-5 uppercase tracking-wider">Severity Breakdown</h3>
                            <div className="space-y-3">
                                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                                    const count = summary[sev.toLowerCase() as keyof typeof summary] as number;
                                    const config = SEVERITY_CONFIG[sev];
                                    return (
                                        <div key={sev} className="flex items-center gap-3">
                                            <span className={`w-20 text-[10px] font-bold uppercase tracking-wider text-center px-2 py-0.5 rounded border ${config.badge}`}>
                                                {sev}
                                            </span>
                                            <div className="flex-1 h-2.5 rounded-full bg-white/5 overflow-hidden">
                                                <motion.div className={`h-full rounded-full ${config.color.replace("text-", "bg-")}`}
                                                    initial={{ width: 0 }}
                                                    animate={{ width: summary.total ? `${(count / summary.total) * 100}%` : "0%" }}
                                                    transition={{ delay: 0.5, duration: 0.8 }} />
                                            </div>
                                            <span className="text-sm font-mono text-gray-300 w-6 text-right">{count}</span>
                                        </div>
                                    );
                                })}
                            </div>
                            <div className="mt-5 pt-4 border-t border-white/5 text-center">
                                <span className="text-3xl font-black text-white">{summary.total}</span>
                                <span className="text-xs text-gray-500 ml-2 font-mono">TOTAL FINDINGS</span>
                            </div>
                        </motion.div>

                        {/* Agent Coverage */}
                        <motion.div initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.4 }}
                            className="col-span-1 rounded-2xl bg-gray-900/50 border border-white/5 p-6">
                            <h3 className="text-xs font-mono text-gray-400 mb-5 uppercase tracking-wider">Agent Coverage</h3>
                            <div className="space-y-2.5">
                                {sessions.map((s) => (
                                    <div key={s.agent_type} className="flex items-center justify-between">
                                        <span className="text-sm text-gray-300">{AGENT_LABELS[s.agent_type] || s.agent_type}</span>
                                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border ${s.status === "COMPLETED" ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" :
                                                s.status === "FAILED" ? "text-red-400 border-red-500/30 bg-red-500/10" :
                                                    "text-gray-400 border-gray-600 bg-gray-800"
                                            }`}>
                                            {s.status === "COMPLETED" ? (
                                                <span className="flex items-center gap-1"><CheckCircle className="w-3 h-3" /> Complete</span>
                                            ) : s.status === "FAILED" ? (
                                                <span className="flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Failed</span>
                                            ) : s.status}
                                        </span>
                                    </div>
                                ))}
                            </div>
                        </motion.div>
                    </div>

                    {/* ===== TABLE OF CONTENTS ===== */}
                    {findings.length > 0 && (
                        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
                            className="mb-14 rounded-2xl bg-gray-900/30 border border-white/5 p-6 print:bg-gray-50 print:border-gray-200">
                            <h2 className="text-sm font-bold mb-4 flex items-center gap-2 text-gray-400 uppercase tracking-wider">
                                Table of Contents
                            </h2>
                            <ol className="space-y-2">
                                {findings.map((f, i) => {
                                    const config = SEVERITY_CONFIG[f.severity];
                                    return (
                                        <li key={f.id}>
                                            <a href={`#finding-${f.id}`}
                                                className="flex items-center gap-3 text-sm hover:text-white transition-colors group">
                                                <span className="text-gray-600 font-mono w-6">#{i + 1}</span>
                                                <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${config.badge} shrink-0`}>
                                                    {f.severity}
                                                </span>
                                                <span className="text-gray-300 group-hover:text-white transition-colors">{f.title}</span>
                                            </a>
                                        </li>
                                    );
                                })}
                            </ol>
                        </motion.div>
                    )}

                    {/* ===== DETAILED FINDINGS ===== */}
                    <div className="mb-14">
                        <h2 className="text-xl font-bold mb-8 flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5 text-yellow-400" />
                            Detailed Vulnerability Findings
                        </h2>
                        <div className="space-y-4">
                            {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((sev) => {
                                const group = findings.filter(f => f.severity === sev);
                                if (group.length === 0) return null;
                                return group.map((f, i) => (
                                    <FindingDetail key={f.id} finding={f} index={findings.indexOf(f)} />
                                ));
                            })}
                        </div>
                        {findings.length === 0 && (
                            <div className="text-center py-16 text-gray-600">
                                <CheckCircle className="w-12 h-12 mx-auto mb-3 text-emerald-500/40" />
                                <p className="text-lg font-semibold text-gray-400">No vulnerabilities found</p>
                                <p className="text-sm mt-1">The scan completed without detecting any issues.</p>
                            </div>
                        )}
                    </div>

                    {/* ===== METHODOLOGY ===== */}
                    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.8 }}
                        className="mb-14 rounded-2xl bg-gray-900/30 border border-white/5 p-8 print:bg-gray-50 print:border-gray-200">
                        <h2 className="text-lg font-bold mb-4 flex items-center gap-2">
                            <BookOpen className="w-5 h-5 text-cyan-400" /> Methodology
                        </h2>
                        <div className="text-sm text-gray-400 space-y-3 leading-relaxed print:text-gray-600">
                            <p>This assessment was performed using Sentinel&apos;s autonomous multi-agent architecture. Each agent specializes in a specific attack vector:</p>
                            <ul className="list-disc list-inside space-y-1 ml-2">
                                <li><strong className="text-gray-300 print:text-gray-700">Spider / Recon</strong> — Full-site crawler mapping URLs, forms, APIs, tech stack, and sensitive paths</li>
                                <li><strong className="text-gray-300 print:text-gray-700">Secret Scanner</strong> — Deep 8-phase scan for leaked API keys, tokens, and credentials in JS bundles, source maps, cookies, and meta tags</li>
                                <li><strong className="text-gray-300 print:text-gray-700">Headers &amp; TLS</strong> — 12+ security header checks, deep CSP analysis, HSTS validation, TLS version/cipher/certificate audit</li>
                                <li><strong className="text-gray-300 print:text-gray-700">CORS Scanner</strong> — Tests 12 origin types across multiple paths for CORS misconfigurations including origin reflection and subdomain hijack</li>
                                <li><strong className="text-gray-300 print:text-gray-700">Port Scanner</strong> — Network port discovery and service fingerprinting across 45+ ports</li>
                                <li><strong className="text-gray-300 print:text-gray-700">SQL Injection</strong> — Automated SQLi payload fuzzing on form inputs with error-based detection</li>
                                <li><strong className="text-gray-300 print:text-gray-700">XSS Scanner</strong> — Cross-site scripting detection with reflected payload analysis</li>
                                <li><strong className="text-gray-300 print:text-gray-700">Auth Abuse</strong> — Authentication flow testing and session management review</li>
                                <li><strong className="text-gray-300 print:text-gray-700">LLM Analysis</strong> — AI-powered security code review and configuration analysis</li>
                                <li><strong className="text-gray-300 print:text-gray-700">Red Team AI</strong> — Browser-automated pentesting with LLM-guided decision making (Gemini 2.0 Flash)</li>
                            </ul>
                            <p className="mt-4">Remediation guidance is generated by <strong className="text-blue-300 print:text-blue-600">Google Gemini 2.0 Flash</strong>, providing detailed, code-level fix instructions tailored to each finding.</p>
                        </div>
                    </motion.div>

                    {/* ===== FOOTER ===== */}
                    <motion.footer initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1 }}
                        className="border-t border-gray-800 pt-8 pb-16 text-center">
                        <div className="flex items-center justify-center gap-3 mb-3">
                            <Shield className="w-5 h-5 text-cyan-400" />
                            <span className="text-sm font-bold text-gray-300">SENTINEL</span>
                        </div>
                        <p className="text-xs text-gray-500 max-w-lg mx-auto leading-relaxed">
                            This authorized security assessment was performed under the blue hat methodology.
                            All findings are reported to help the site owner strengthen their security posture.
                            No data was exfiltrated or modified during this assessment.
                        </p>
                        <div className="flex items-center justify-center gap-6 mt-5 text-xs font-mono text-gray-600">
                            <span className="flex items-center gap-1.5">
                                <Bot className="w-3.5 h-3.5" /> 10 Autonomous Security Agents
                            </span>
                            <span className="text-gray-800">•</span>
                            <span className="flex items-center gap-1.5">
                                <Sparkles className="w-3.5 h-3.5 text-blue-400" /> Powered by Google Gemini 2.0 Flash
                            </span>
                        </div>
                    </motion.footer>
                </div>
            </div>
        </>
    );
}
