"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { useRouter } from "next/navigation";
import { Shield, Play, Loader2 } from "lucide-react";

export default function Home() {
  const [url, setUrl] = useState("");
  const [isStarting, setIsStarting] = useState(false);
  const router = useRouter();

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
          agents: ["exposure", "headers_tls", "auth_abuse", "llm_analysis", "sqli", "xss", "red_team"]
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
    <main className="flex min-h-screen flex-col items-center justify-center p-24 bg-dots-pattern">
      <div className="relative z-10 w-full max-w-2xl text-center">
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
            SENTINEL
          </h1>
          <p className="text-gray-400 mb-12 text-lg font-mono">
            AUTONOMOUS BLUE TEAM ORCHESTRATOR
          </p>

          <div className="flex gap-2">
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

          <div className="mt-8 flex justify-center gap-4 text-xs font-mono text-gray-500">
            <span>• OPENAI LOGIC ANALYSIS</span>
            <span>• SQL INJECTION FUZZING</span>
            <span>• PLAYWRIGHT AUTOMATION</span>
          </div>
        </motion.div>
      </div>

      {/* Background Decor */}
      <div className="fixed inset-0 pointer-events-none bg-[url('/grid.svg')] opacity-20" />
    </main>
  );
}
