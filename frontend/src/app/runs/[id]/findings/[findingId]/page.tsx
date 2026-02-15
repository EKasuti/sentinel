"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { Finding } from "@/lib/types";
import { Shield, ArrowLeft, AlertTriangle } from "lucide-react";
import { motion } from "framer-motion";

export default function FindingDetails() {
    const params = useParams();
    const router = useRouter();
    const runId = params.id as string;
    const findingId = params.findingId as string;

    const [finding, setFinding] = useState<Finding | null>(null);

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
            <header className="mb-8 border-b border-gray-800 pb-4">
                <button
                    onClick={() => router.back()}
                    className="text-gray-400 hover:text-white flex items-center gap-2 mb-4"
                >
                    <ArrowLeft size={16} /> Back to Run
                </button>
                <div className="flex justify-between items-start">
                    <div>
                        <h1 className="text-3xl font-bold mb-2">{finding.title}</h1>
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
