"use client";

import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useRouter } from "next/navigation";
import {
  Shield,
  Play,
  Loader2,
  Zap,
  Target,
  Globe,
  Lock,
  Bug,
  Cpu,
  Search,
  Radio,
  Radar,
  ChevronRight,
  Eye,
  Key,
} from "lucide-react";

// Animated background particle field
function ParticleField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    const particles: {
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      opacity: number;
      color: string;
    }[] = [];
    const colors = ["#00f0ff", "#bd00ff", "#00ff9f", "#ff003c"];

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener("resize", resize);

    for (let i = 0; i < 80; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.5,
        vy: (Math.random() - 0.5) * 0.5,
        size: Math.random() * 2 + 0.5,
        opacity: Math.random() * 0.5 + 0.1,
        color: colors[Math.floor(Math.random() * colors.length)],
      });
    }

    const animate = () => {
      ctx.fillStyle = "rgba(0, 0, 0, 0.05)";
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      particles.forEach((p, i) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.opacity;
        ctx.fill();

        particles.forEach((p2, j) => {
          if (i >= j) return;
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = p.color;
            ctx.globalAlpha = (1 - dist / 120) * 0.15;
            ctx.lineWidth = 0.5;
            ctx.stroke();
          }
        });
      });

      ctx.globalAlpha = 1;
      animationId = requestAnimationFrame(animate);
    };

    animate();
    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", resize);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-0"
      style={{ background: "transparent" }}
    />
  );
}

function RadarScan() {
  return (
    <div className="relative w-40 h-40">
      <div className="absolute inset-0 rounded-full border border-cyber-blue/20" />
      <div className="absolute inset-4 rounded-full border border-cyber-blue/15" />
      <div className="absolute inset-8 rounded-full border border-cyber-blue/10" />
      <div className="absolute inset-12 rounded-full border border-cyber-blue/5" />
      <motion.div
        className="absolute inset-0 rounded-full"
        style={{
          background:
            "conic-gradient(from 0deg, transparent 0deg, rgba(0, 240, 255, 0.3) 30deg, transparent 60deg)",
        }}
        animate={{ rotate: 360 }}
        transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
      />
      <div className="absolute inset-0 flex items-center justify-center">
        <Radar className="w-6 h-6 text-cyber-blue" />
      </div>
      <motion.div
        className="absolute w-1.5 h-1.5 rounded-full bg-danger-red"
        style={{ top: "25%", left: "60%" }}
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 2, repeat: Infinity, delay: 0.5 }}
      />
      <motion.div
        className="absolute w-1.5 h-1.5 rounded-full bg-yellow-400"
        style={{ top: "65%", left: "30%" }}
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 2, repeat: Infinity, delay: 1.2 }}
      />
      <motion.div
        className="absolute w-1.5 h-1.5 rounded-full bg-cyber-blue"
        style={{ top: "45%", left: "75%" }}
        animate={{ opacity: [0, 1, 0] }}
        transition={{ duration: 2, repeat: Infinity, delay: 0.8 }}
      />
    </div>
  );
}

function AgentCard({
  icon: Icon,
  name,
  description,
  color,
  delay,
}: {
  icon: React.ElementType;
  name: string;
  description: string;
  color: string;
  delay: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.5 }}
      className="group relative p-4 rounded-xl bg-gray-900/40 border border-gray-800/50 hover:border-gray-700 transition-all duration-300 backdrop-blur-sm"
    >
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-lg bg-gradient-to-br ${color} bg-opacity-10 shrink-0`}>
          <Icon className="w-4 h-4 text-white" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white mb-1">{name}</h3>
          <p className="text-xs text-gray-500 leading-relaxed">{description}</p>
        </div>
      </div>
    </motion.div>
  );
}

function TerminalDemo() {
  const [lines, setLines] = useState<string[]>([]);
  const terminalLines = [
    "$ sentinel scan https://target-app.com",
    "[SPIDER] Crawling attack surface...",
    "[SPIDER] Found 47 URLs, 12 forms, 8 API endpoints",
    "[HEADERS] Missing CSP, HSTS misconfigured",
    "[EXPOSURE] CRITICAL: Supabase anon key in JS bundle",
    "[CORS] Origin reflection + credentials on /api",
    "[SQLI] Testing login form with 17 payloads...",
    "[SQLI] Auth bypass: ' OR 1=1-- on /login",
    "[RED_TEAM] RLS disabled on 'users' table",
    "[RED_TEAM] 3 tables publicly readable",
    "--- SCAN COMPLETE: 14 vulns (4 CRITICAL) ---",
  ];

  useEffect(() => {
    let idx = 0;
    let isMounted = true;
    let resetting = false;
    const interval = setInterval(() => {
      if (!isMounted || resetting) return;
      if (idx < terminalLines.length) {
        const line = terminalLines[idx];
        idx++;
        setLines((prev) => [...prev, line]);
      } else {
        resetting = true;
        setTimeout(() => {
          if (isMounted) {
            setLines([]);
            idx = 0;
            resetting = false;
          }
        }, 3000);
      }
    }, 800);
    return () => { isMounted = false; clearInterval(interval); };
  }, []);

  return (
    <div className="w-full max-w-lg bg-gray-950/80 border border-gray-800 rounded-xl overflow-hidden backdrop-blur-sm">
      <div className="flex items-center gap-2 px-4 py-2.5 bg-gray-900/80 border-b border-gray-800">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/70" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/70" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/70" />
        </div>
        <span className="text-[10px] font-mono text-gray-500 ml-2">sentinel — live scan</span>
      </div>
      <div className="p-4 font-mono text-xs h-[280px] overflow-hidden">
        <AnimatePresence mode="sync">
          {lines.map((line, i) => (
            <motion.div
              key={`${i}-${line}`}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className={`mb-1.5 ${
                line.includes("CRITICAL") ? "text-red-400" :
                line.includes("COMPLETE") ? "text-success-green font-bold" :
                line.includes("$") ? "text-success-green" :
                line.includes("Missing") ? "text-yellow-400" :
                "text-gray-400"
              }`}
            >
              {line}
            </motion.div>
          ))}
        </AnimatePresence>
        <motion.span
          animate={{ opacity: [1, 0] }}
          transition={{ duration: 0.8, repeat: Infinity }}
          className="text-cyber-blue"
        >
          ▌
        </motion.span>
      </div>
    </div>
  );
}

function StatCounter({ value, label, delay }: { value: string; label: string; delay: number }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className="text-center"
    >
      <div className="text-2xl font-black text-white">{value}</div>
      <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">{label}</div>
    </motion.div>
  );
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [isStarting, setIsStarting] = useState(false);
  const [selectedAgents, setSelectedAgents] = useState<string[]>([
    "spider", "exposure", "headers_tls", "cors", "portscan",
    "auth_abuse", "sqli", "xss", "llm_analysis", "red_team",
  ]);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const router = useRouter();

  const agentOptions = [
    { id: "spider", name: "Spider / Recon", icon: Search },
    { id: "exposure", name: "Secret Scanner", icon: Eye },
    { id: "headers_tls", name: "Headers & TLS", icon: Lock },
    { id: "cors", name: "CORS Scanner", icon: Globe },
    { id: "portscan", name: "Port Scanner", icon: Radio },
    { id: "auth_abuse", name: "Auth Abuse", icon: Key },
    { id: "sqli", name: "SQL Injection", icon: Bug },
    { id: "xss", name: "XSS Auditor", icon: Zap },
    { id: "llm_analysis", name: "LLM Analysis", icon: Cpu },
    { id: "red_team", name: "Red Team AI", icon: Target },
  ];

  const toggleAgent = (id: string) => {
    setSelectedAgents((prev) =>
      prev.includes(id) ? prev.filter((a) => a !== id) : [...prev, id]
    );
  };

  const startRun = async () => {
    if (!url) return;
    setIsStarting(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const res = await fetch(`${apiUrl}/runs/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: url, agents: selectedAgents }),
      });
      const data = await res.json();
      if (data.run_id) router.push(`/runs/${data.run_id}`);
    } catch (e) {
      console.error(e);
      alert("Failed to start run. Is backend running?");
      setIsStarting(false);
    }
  };

  return (
    <main className="relative min-h-screen bg-black overflow-hidden">
      <ParticleField />

      <div className="fixed inset-0 pointer-events-none opacity-[0.03] z-0">
        <div
          className="w-full h-full"
          style={{
            backgroundImage: `linear-gradient(rgba(0,240,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(0,240,255,0.5) 1px, transparent 1px)`,
            backgroundSize: "60px 60px",
          }}
        />
      </div>

      <div className="relative z-10 flex flex-col lg:flex-row items-center justify-center min-h-screen gap-12 px-6 py-16 max-w-7xl mx-auto">
        {/* Left: Hero */}
        <div className="flex-1 max-w-xl">
          <motion.div initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.8 }}>
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyber-blue/10 border border-cyber-blue/30 text-cyber-blue text-xs font-mono mb-6"
            >
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-blue animate-pulse" />
              TREEHACKS 2026
            </motion.div>

            <div className="flex items-center gap-4 mb-6">
              <div className="p-3 rounded-2xl bg-gradient-to-br from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/30 shadow-[0_0_30px_rgba(0,240,255,0.15)]">
                <Shield className="w-10 h-10 text-cyber-blue" />
              </div>
              <div>
                <h1 className="text-5xl font-black tracking-tighter bg-gradient-to-r from-white via-gray-200 to-gray-400 bg-clip-text text-transparent">
                  SENTINEL
                </h1>
                <p className="text-xs font-mono text-gray-500 tracking-widest">
                  AUTONOMOUS SECURITY INTELLIGENCE
                </p>
              </div>
            </div>

            <p className="text-gray-400 text-lg leading-relaxed mb-8 max-w-md">
              Deploy <span className="text-white font-semibold">10 AI agents</span> to
              autonomously discover vulnerabilities in any web application.
              Spider crawls, fuzz inputs, probe APIs, and chain exploits —{" "}
              <span className="text-cyber-blue">all in real-time</span>.
            </p>

            <div className="space-y-3">
              <div className="flex gap-2">
                <div className="relative flex-1">
                  <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                  <input
                    type="text"
                    placeholder="https://target-app.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && startRun()}
                    className="w-full bg-gray-900/80 border border-gray-700 rounded-xl pl-11 pr-4 py-4 text-white focus:outline-none focus:border-cyber-blue focus:ring-1 focus:ring-cyber-blue/50 transition-all font-mono text-sm backdrop-blur-sm"
                  />
                </div>
                <motion.button
                  onClick={startRun}
                  disabled={isStarting || !url}
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  className="bg-gradient-to-r from-cyber-blue to-blue-500 text-black font-bold px-8 py-4 rounded-xl hover:shadow-[0_0_30px_rgba(0,240,255,0.3)] transition-all disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2 shrink-0"
                >
                  {isStarting ? (
                    <Loader2 className="w-5 h-5 animate-spin" />
                  ) : (
                    <Play className="w-5 h-5" />
                  )}
                  {isStarting ? "LAUNCHING..." : "SCAN"}
                </motion.button>
              </div>

              <button
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center gap-1 text-xs font-mono text-gray-500 hover:text-gray-300 transition-colors"
              >
                <ChevronRight className={`w-3 h-3 transition-transform ${showAdvanced ? "rotate-90" : ""}`} />
                {selectedAgents.length}/{agentOptions.length} AGENTS SELECTED — {showAdvanced ? "HIDE" : "CONFIGURE"}
              </button>

              <AnimatePresence>
                {showAdvanced && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="grid grid-cols-2 gap-2 pt-2">
                      {agentOptions.map((agent) => {
                        const isSelected = selectedAgents.includes(agent.id);
                        return (
                          <button
                            key={agent.id}
                            onClick={() => toggleAgent(agent.id)}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-left text-xs transition-all border ${
                              isSelected
                                ? "bg-gray-800/80 border-cyan-500/30 text-white"
                                : "bg-gray-900/40 border-gray-800 text-gray-500 hover:text-gray-300"
                            }`}
                          >
                            <div className={`w-3 h-3 rounded border flex items-center justify-center ${isSelected ? "bg-cyber-blue/30 border-cyber-blue" : "border-gray-600"}`}>
                              {isSelected && <div className="w-1.5 h-1.5 rounded-sm bg-cyber-blue" />}
                            </div>
                            <agent.icon className="w-3 h-3 shrink-0" />
                            <span className="font-medium">{agent.name}</span>
                          </button>
                        );
                      })}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            <div className="flex gap-8 mt-10 pt-8 border-t border-gray-800/50">
              <StatCounter value="10" label="AI Agents" delay={0.3} />
              <StatCounter value="200+" label="Checks" delay={0.5} />
              <StatCounter value="< 2m" label="Scan Time" delay={0.7} />
              <StatCounter value="∞" label="Attack Vectors" delay={0.9} />
            </div>
          </motion.div>
        </div>

        {/* Right: Demo */}
        <div className="flex-1 max-w-lg flex flex-col items-center gap-8">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.3, duration: 0.8 }}
          >
            <TerminalDemo />
          </motion.div>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.8 }}>
            <RadarScan />
          </motion.div>
        </div>
      </div>

      {/* Agent showcase */}
      <div className="relative z-10 max-w-6xl mx-auto px-6 pb-20">
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 1 }}>
          <h2 className="text-center text-sm font-mono text-gray-500 mb-8 uppercase tracking-widest">
            Multi-Agent Security Intelligence
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <AgentCard icon={Search} name="Spider" description="Crawls & maps every URL, form, and API endpoint" color="from-blue-600/20 to-blue-800/10" delay={1.1} />
            <AgentCard icon={Eye} name="Secrets" description="Scans JS bundles for leaked keys, tokens & credentials" color="from-purple-600/20 to-purple-800/10" delay={1.2} />
            <AgentCard icon={Lock} name="Headers" description="Tests 12+ security headers, CSP, TLS certs & ciphers" color="from-cyan-600/20 to-cyan-800/10" delay={1.3} />
            <AgentCard icon={Bug} name="Injection" description="SQLi & XSS fuzzing with 20+ payload variants" color="from-red-600/20 to-red-800/10" delay={1.4} />
            <AgentCard icon={Target} name="Red Team" description="LLM-driven autonomous pentesting agent" color="from-orange-600/20 to-orange-800/10" delay={1.5} />
          </div>
        </motion.div>
      </div>

      <div className="relative z-10 border-t border-gray-800/50 py-6">
        <div className="text-center text-xs font-mono text-gray-600">
          Built with Gemini 2.0 Flash + Playwright + Supabase Realtime
        </div>
      </div>
    </main>
  );
}
