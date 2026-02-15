"use client";

import {
  Globe, Lock, Search, ShieldCheck, ChevronRight, Zap, User, Key,
  Cookie, ArrowRight, Database, Code, ShieldAlert, FileWarning
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { AgentCard } from "@/components/AgentCard";
import { startScan } from "@/apis/scans";

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [authMethod, setAuthMethod] = useState("none");
  const [isLaunching, setIsLaunching] = useState(false);
  const router = useRouter();

  const handleLaunchScan = async () => {
    setIsLaunching(true);
    try {
      const res = await startScan(targetUrl);
      router.push(`/dashboard/scan?scanId=${res.scan_id}&url=${encodeURIComponent(targetUrl)}`);
    } catch (e) {
      console.error("Failed to start scan:", e);
      setIsLaunching(false);
    }
  };

  const authOptions = [
    { id: "none", label: "None", icon: Globe },
    { id: "basic", label: "Basic Auth", icon: User },
    { id: "bearer", label: "Bearer Token", icon: Key },
    { id: "apikey", label: "API Key", icon: Lock },
    { id: "cookie", label: "Cookie", icon: Cookie },
  ];

  return (
    <div className="space-y-10 pb-20">
      {/* Title */}
      <div className="space-y-2">
        <h2 className="text-4xl font-bold tracking-tight text-white">Configure Security Scan</h2>
        <p className="text-zinc-400 max-w-2xl text-base leading-relaxed">
          Sentinel deploys 5 specialized AI agents powered by Claude to autonomously test your
          application&apos;s security posture in real-time.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          {/* Target URL */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-6">
            <div className="mb-2 flex items-center gap-2">
              <Globe className="h-5 w-5 text-zinc-400" />
              <h3 className="text-base font-semibold text-zinc-200">Target URL</h3>
            </div>
            <p className="mb-4 text-sm text-zinc-400">
              The web application to scan — ensure you have authorization
            </p>
            <Input
              type="url"
              placeholder="https://your-app.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="bg-black/50 border-zinc-800 h-12 text-base text-white placeholder:text-zinc-700 focus-visible:ring-zinc-700"
            />
          </div>

          {/* Agent Fleet */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-zinc-500 tracking-wider uppercase">Agent Fleet (5 Agents)</h3>
              <span className="text-xs text-zinc-500">All agents deploy simultaneously</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <AgentCard
                icon={Database}
                title="SQL Injection"
                description="Tests input fields for SQLi, auth bypass, error-based injection"
              />
              <AgentCard
                icon={Code}
                title="XSS"
                description="Tests for reflected & stored cross-site scripting"
              />
              <AgentCard
                icon={ShieldAlert}
                title="Auth Bypass"
                description="Tests login, session management, privilege escalation"
              />
              <AgentCard
                icon={Search}
                title="IDOR"
                description="Tests for insecure direct object reference vulnerabilities"
              />
              <AgentCard
                icon={FileWarning}
                title="CSRF"
                description="Checks for missing anti-forgery tokens and protections"
              />
            </div>
          </div>

          {/* Authentication */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden">
            <div
              className="p-6 cursor-pointer hover:bg-zinc-900/30 transition-colors flex items-center justify-between"
              onClick={() => setShowAuth(!showAuth)}
            >
              <div className="flex items-center gap-2">
                <Lock className="h-5 w-5 text-zinc-400" />
                <h3 className="text-base font-semibold text-zinc-200">Authentication (Optional)</h3>
              </div>
              <ChevronRight className={cn("h-5 w-5 text-zinc-500 transition-transform duration-300", showAuth && "rotate-90")} />
            </div>

            {showAuth && (
              <div className="px-6 pb-6 pt-2 border-t border-zinc-800/50 animate-in fade-in slide-in-from-top-2">
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
                  {authOptions.map((option) => {
                    const Icon = option.icon;
                    const isSelected = authMethod === option.id;
                    return (
                      <button
                        key={option.id}
                        onClick={() => setAuthMethod(option.id)}
                        className={cn(
                          "flex flex-col items-center justify-center gap-2 p-3 rounded-lg border transition-all",
                          isSelected
                            ? "bg-zinc-800 border-zinc-600 text-white"
                            : "bg-transparent border-zinc-800 text-zinc-400 hover:bg-zinc-900"
                        )}
                      >
                        <Icon className="h-4 w-4" />
                        <span className="text-[10px] font-medium uppercase tracking-tight">{option.label}</span>
                      </button>
                    );
                  })}
                </div>
                {authMethod !== "none" && (
                  <div className="space-y-4 pt-4 border-t border-zinc-800/50">
                    {authMethod === "basic" && (
                      <div className="grid grid-cols-2 gap-4">
                        <Input className="bg-black/50 border-zinc-800" placeholder="Username" />
                        <Input className="bg-black/50 border-zinc-800" type="password" placeholder="Password" />
                      </div>
                    )}
                    {(authMethod === "bearer" || authMethod === "cookie") && (
                      <Input className="bg-black/50 border-zinc-800" placeholder={authMethod === "bearer" ? "Bearer Token" : "Cookie String"} />
                    )}
                    {authMethod === "apikey" && (
                      <div className="grid grid-cols-2 gap-4">
                        <Input className="bg-black/50 border-zinc-800" placeholder="Header Name (e.g. X-API-Key)" />
                        <Input className="bg-black/50 border-zinc-800" placeholder="Value" />
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Launch Panel */}
        <div className="space-y-6">
          <Card className="bg-white p-6 border-none shadow-2xl shadow-white/5">
            <h3 className="text-black font-bold text-xl mb-2">Ready to scan?</h3>
            <p className="text-zinc-600 text-sm mb-4 leading-relaxed">
              5 AI agents will deploy simultaneously, each powered by Claude for intelligent,
              context-aware security testing.
            </p>
            <div className="space-y-3 mb-6">
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span>Claude-powered intelligent testing</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span>Live browser screenshots</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span>Real-time vulnerability detection</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-zinc-500">
                <div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                <span>10 iterations per agent</span>
              </div>
            </div>
            <Button
              onClick={handleLaunchScan}
              disabled={!targetUrl || !/^https?:\/\/.+\..+/.test(targetUrl) || isLaunching}
              className="w-full bg-black hover:bg-zinc-800 text-white py-6 text-lg font-bold rounded-xl transition-all active:scale-[0.98] disabled:opacity-50"
            >
              {isLaunching ? (
                <span className="flex items-center gap-2">
                  <div className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Deploying Agents...
                </span>
              ) : (
                <>
                  <Zap className="mr-2 h-5 w-5 fill-white" />
                  Launch Scan
                </>
              )}
            </Button>
          </Card>
        </div>
      </div>
    </div>
  );
}
