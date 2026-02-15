import Link from "next/link";
import { Shield, Bug, Play, Globe, RotateCw, XCircle, ArrowLeft } from "lucide-react";

interface RunHeaderProps {
    run: any;
    elapsed: string;
    totalRequests: number;
    findings: any[];
    securityScore: number;
    onReRun: () => void;
    onCancel: () => void;
    isCancelling: boolean;
}

export default function RunHeader({
    run,
    elapsed,
    totalRequests,
    findings,
    securityScore,
    onReRun,
    onCancel,
    isCancelling
}: RunHeaderProps) {
    const isRunning = run?.status === 'RUNNING';
    const criticals = findings.filter(f => f.severity === 'CRITICAL').length;
    const highs = findings.filter(f => f.severity === 'HIGH').length;
    const mediums = findings.filter(f => f.severity === 'MEDIUM').length;

    // Calculate color based on score
    const getScoreColor = (score: number) => {
        if (score >= 80) return '#4ade80'; // green-400
        if (score >= 50) return '#facc15'; // yellow-400
        if (score >= 25) return '#fb923c'; // orange-400
        return '#f87171'; // red-400
    };

    const scoreColor = getScoreColor(securityScore);
    const radius = 18;
    const circumference = 2 * Math.PI * radius;
    const strokeDashoffset = circumference - (securityScore / 100) * circumference;

    return (
        <nav className="sticky top-0 z-40 border-b border-white/[0.08] bg-[#050508]/80 backdrop-blur-xl">
            <div className="max-w-[1600px] mx-auto px-6 h-20 flex items-center justify-between">
                {/* Left: Branding & Target */}
                <div className="flex items-center gap-6">
                    <Link href="/" className="flex items-center gap-3 group">
                        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-white/10 flex items-center justify-center group-hover:scale-105 transition-transform duration-300">
                            <Shield className="w-4 h-4 text-indigo-400" />
                        </div>
                        <div className="flex flex-col">
                            <span className="text-sm font-bold tracking-tight text-white/90">SENTINEL</span>
                            <span className="text-[10px] text-gray-500 font-mono tracking-wider">AUTONOMOUS BLUE TEAM</span>
                        </div>
                    </Link>

                    <div className="h-8 w-px bg-white/[0.08]" />

                    <div className="flex flex-col gap-0.5">
                        <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Target</span>
                        <div className="flex items-center gap-2">
                            <span className="text-sm text-gray-200 font-mono">{run?.target_url || '...'}</span>
                            {isRunning && (
                                <span className="relative flex h-2 w-2">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                </span>
                            )}
                        </div>
                    </div>
                </div>

                {/* Right: Metrics & Actions */}
                <div className="flex items-center gap-8">
                    {/* Metrics Group */}
                    <div className="flex items-center gap-8 mr-4">
                        {/* Elapsed */}
                        <div className="flex flex-col items-start gap-1">
                            <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Elapsed</span>
                            <span className="text-xl font-mono text-white/90 font-medium tracking-tight">{elapsed}</span>
                        </div>

                        {/* Requests */}
                        <div className="flex flex-col items-start gap-1">
                            <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Requests</span>
                            <span className="text-xl font-mono text-white/90 font-medium tracking-tight">{totalRequests}</span>
                        </div>

                        {/* Findings */}
                        <div className="flex flex-col items-start gap-1">
                            <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Findings</span>
                            <div className="flex items-center gap-2">
                                <Bug className="w-4 h-4 text-amber-500" />
                                <span className="text-xl font-mono text-white/90 font-medium tracking-tight">{findings.length}</span>
                            </div>
                        </div>

                        {/* Circle Score */}
                        <div className="flex items-center gap-3 pl-4 border-l border-white/[0.08]">
                            <div className="relative w-12 h-12 flex items-center justify-center">
                                {/* Background Circle */}
                                <svg className="transform -rotate-90 w-12 h-12">
                                    <circle
                                        cx="24"
                                        cy="24"
                                        r={radius}
                                        stroke="currentColor"
                                        strokeWidth="3"
                                        fill="transparent"
                                        className="text-white/[0.05]"
                                    />
                                    <circle
                                        cx="24"
                                        cy="24"
                                        r={radius}
                                        stroke={scoreColor}
                                        strokeWidth="3"
                                        fill="transparent"
                                        strokeDasharray={circumference}
                                        strokeDashoffset={strokeDashoffset}
                                        strokeLinecap="round"
                                        className="transition-all duration-1000 ease-out"
                                    />
                                </svg>
                                <span className={`absolute text-sm font-bold ${securityScore >= 80 ? 'text-emerald-400' :
                                        securityScore >= 50 ? 'text-yellow-400' :
                                            securityScore >= 25 ? 'text-orange-400' : 'text-red-400'
                                    }`}>
                                    {securityScore}
                                </span>
                            </div>
                            <div className="flex flex-col">
                                <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Score</span>
                                <span className="text-xs text-gray-400">Security Index</span>
                            </div>
                        </div>
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-3 pl-4 border-l border-white/[0.08]">
                        <Link
                            href="/"
                            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.08] transition-all group"
                        >
                            <Globe className="w-4 h-4 text-gray-400 group-hover:text-white transition-colors" />
                            <span className="text-sm font-medium text-gray-300 group-hover:text-white">New Target</span>
                        </Link>

                        {isRunning ? (
                            <button
                                onClick={onCancel}
                                disabled={isCancelling}
                                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 text-red-400 transition-all"
                            >
                                <XCircle className="w-4 h-4" />
                                <span className="text-sm font-medium">{isCancelling ? 'Stopping...' : 'Stop Run'}</span>
                            </button>
                        ) : (
                            <button
                                onClick={onReRun}
                                className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-white text-black hover:bg-gray-200 transition-all font-semibold"
                            >
                                <RotateCw className="w-4 h-4" />
                                <span className="text-sm">Re-Run</span>
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </nav>
    );
}
