"use client";

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { Shield, Play, Loader2, RefreshCw } from "lucide-react";
import { supabase } from "@/lib/supabase";
import { SecurityRun } from "@/lib/types";

export default function Home() {
  const [url, setUrl] = useState("");
  const [isStarting, setIsStarting] = useState(false);
  const [runs, setRuns] = useState<SecurityRun[]>([]);
  const router = useRouter();

  useEffect(() => {
    fetchRuns();
  }, []);

  const fetchRuns = async () => {
    const { data } = await supabase.from('security_runs').select('*').order('created_at', { ascending: false }).limit(10);
    if (data) setRuns(data);
  };

  const startRun = async () => {
    if (!url) return;
    setIsStarting(true);

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const res = await fetch(`${apiUrl}/runs/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_url: url,
          agents: ["exposure", "headers_tls", "auth_abuse", "llm_analysis", "sqli", "xss", "red_team", "broken_links", "cloud_leak", "omniscience", "source_sorcerer", "shadow_hunter"]
        })
      });

      const data = await res.json();
      if (data.run_id) {
        router.push(`/runs/${data.run_id}`);
      }
    } catch (e) {
      console.error(e);
      alert("Failed to start run. Is backend running?");
      setIsStarting(false);
    }
  };

  return (
    <main className="flex min-h-screen flex-col items-center p-24 bg-dots-pattern">
      <div className="relative z-10 w-full max-w-2xl text-center mb-20">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
        >
          <div className="flex justify-center mb-6">
            <div className="p-4 rounded-full bg-cyber-blue/10 border border-cyber-blue shadow-[0_0_30px_rgba(0,240,255,0.2)]">
              <Shield className="w-16 h-16 text-cyber-blue" />
            </div>
          </div>
          <h1 className="text-6xl font-black tracking-tighter mb-4 bg-gradient-to-r from-white via-gray-200 to-gray-500 bg-clip-text text-transparent">
            SHIELD
          </h1>
          <p className="text-gray-400 mb-12 text-lg font-mono">
            AUTONOMOUS BLUE TEAM ORCHESTRATOR
          </p>

          <div className="flex gap-2 mb-8">
            <input
              type="text"
              placeholder="https://target-app.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className="flex-1 bg-gray-900 border border-gray-800 rounded-lg px-6 py-4 text-white focus:outline-none focus:border-cyber-blue focus:ring-1 focus:ring-cyber-blue transition-all font-mono"
            />
            <button
              onClick={startRun}
              disabled={isStarting}
              className="bg-white text-black font-bold px-8 py-4 rounded-lg hover:bg-gray-200 transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              {isStarting ? <Loader2 className="animate-spin" /> : <Play className="w-5 h-5" />}
              SCAN TARGET
            </button>
          </div>

          <div className="flex flex-wrap justify-center gap-4 text-xs font-mono text-gray-500 max-w-xl mx-auto">
            <span>• OMNISCIENCE VISION</span>
            <span>• SOURCE SORCERER JS AUDIT</span>
            <span>• SHADOW ASSET DISCOVERY</span>
            <span>• RED TEAM AUTONOMY</span>
            <span>• LOGIC ANALYSIS</span>
            <span>• CLOUD LEAK HUNTER</span>
          </div>
        </motion.div>
      </div>

      {/* History Table */}
      <div className="w-full max-w-4xl z-10">
        <div className="flex justify-between items-center mb-4 border-b border-gray-800 pb-2">
          <h2 className="text-xl font-bold font-mono text-gray-300">RECENT OPERATIONS</h2>
          <button onClick={fetchRuns} className="text-gray-500 hover:text-white transition-colors">
            <RefreshCw size={16} />
          </button>
        </div>
        <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-sm font-mono">
            <thead className="bg-gray-800/50 text-gray-400">
              <tr>
                <th className="p-4">TARGET</th>
                <th className="p-4">STATUS</th>
                <th className="p-4">DATE</th>
                <th className="p-4 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {runs.map(run => (
                <tr key={run.id} className="hover:bg-gray-800/20 transition-colors">
                  <td className="p-4 text-white">{run.target_url}</td>
                  <td className="p-4">
                    <span className={`px-2 py-1 rounded text-xs ${run.status === 'COMPLETED' ? 'bg-green-900/40 text-green-400' :
                        run.status === 'RUNNING' ? 'bg-blue-900/40 text-blue-400 animate-pulse' :
                          run.status === 'FAILED' ? 'bg-red-900/40 text-red-400' :
                            'bg-gray-800 text-gray-400'
                      }`}>
                      {run.status}
                    </span>
                  </td>
                  <td className="p-4 text-gray-500">{new Date(run.created_at).toLocaleDateString()}</td>
                  <td className="p-4 text-right">
                    <button
                      onClick={() => router.push(`/runs/${run.id}`)}
                      className="text-cyber-blue hover:underline"
                    >
                      VIEW REPORT &rarr;
                    </button>
                  </td>
                </tr>
              ))}
              {runs.length === 0 && (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-gray-500">No operations found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Background Decor */}
      <div className="fixed inset-0 pointer-events-none bg-[url('/grid.svg')] opacity-20" />
    </main>
  );
}
