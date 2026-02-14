"use client";

import { Globe, Lock, Search, ShieldCheck, ChevronRight, Zap, User, Key, Cookie, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";
import { AgentCard } from "@/components/AgentCard";

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [authMethod, setAuthMethod] = useState("none");
  const [selectedAgents, setSelectedAgents] = useState<string[]>(["exposure", "headers"]);
  const router = useRouter();

  const handleLaunchScan = () => {
    router.push(`/dashboard/scan?url=${encodeURIComponent(targetUrl)}&agents=${selectedAgents.join(",")}`);
  };

  const toggleAgent = (id: string) => {
    setSelectedAgents(prev =>
      prev.includes(id) ? prev.filter(a => a !== id) : [...prev, id]
    );
  };

  const authOptions = [
    { id: "none", label: "None", icon: Globe },
    { id: "basic", label: "Basic Auth", icon: User },
    { id: "bearer", label: "Bearer Token", icon: Key },
    { id: "apikey", label: "API Key", icon: Lock },
    { id: "cookie", label: "Cookie", icon: Cookie },
  ];

  const recentScans = [
    { id: "1", url: "https://api.example.com", status: "COMPLETED", findings: 12, date: "2h ago" },
    { id: "2", url: "https://staging.myapp.io", status: "COMPLETED", findings: 3, date: "5h ago" },
  ];

  return (
    <div className="space-y-10 pb-20">
      {/* Title and Description */}
      <div className="space-y-2">
        <h2 className="text-4xl font-bold tracking-tight text-white">Configure Security Scan</h2>
        <p className="text-zinc-400 max-w-2xl text-base leading-relaxed">
          Sentinel deploys parallel AI agents to analyze your application&apos;s security posture.
          Provide a target URL and choose your agents to begin.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-6">
          {/* Target URL Section */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-6">
            <div className="mb-2 flex items-center gap-2">
              <Globe className="h-5 w-5 text-zinc-400" />
              <h3 className="text-base font-semibold text-zinc-200">Target URL</h3>
            </div>
            <p className="mb-4 text-sm text-zinc-400">
              The application endpoint to scan
            </p>
            <Input
              type="url"
              placeholder="https://api.example.com"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="bg-black/50 border-zinc-800 h-12 text-base text-white placeholder:text-zinc-700 focus-visible:ring-zinc-700"
            />
          </div>

          {/* Agents Section */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-zinc-500 tracking-wider uppercase">Select Agents to Deploy</h3>
              <span className="text-xs text-zinc-500">{selectedAgents.length} agents selected</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <AgentCard
                icon={Search}
                title="Exposure Mapper"
                description="Attack surface & endpoints discovery"
                selected={selectedAgents.includes("exposure")}
                onClick={() => toggleAgent("exposure")}
              />
              <AgentCard
                icon={ShieldCheck}
                title="Headers & TLS"
                description="Security headers & SSL configuration"
                selected={selectedAgents.includes("headers")}
                onClick={() => toggleAgent("headers")}
              />
              <AgentCard
                icon={Lock}
                title="Auth & Abuse"
                description="Auth mechanisms & rate limits"
                selected={selectedAgents.includes("auth")}
                onClick={() => toggleAgent("auth")}
              />
            </div>
          </div>

          {/* Authentication Section */}
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

        <div className="space-y-6">
          {/* Launch Card */}
          <Card className="bg-white p-6 border-none shadow-2xl shadow-white/5">
            <h3 className="text-black font-bold text-xl mb-2">Ready to scan?</h3>
            <p className="text-zinc-600 text-sm mb-6 leading-relaxed">
              Ensure you have authorization to scan the target. Sentinel will start probing immediately.
            </p>
            <Button
              onClick={handleLaunchScan}
              disabled={!targetUrl || !/^https?:\/\/.+\..+/.test(targetUrl) || selectedAgents.length === 0}
              className="w-full bg-black hover:bg-zinc-800 text-white py-6 text-lg font-bold rounded-xl transition-all active:scale-[0.98] disabled:opacity-50"
            >
              <Zap className="mr-2 h-5 w-5 fill-white" />
              Launch Scan
            </Button>
          </Card>

          {/* Recent Activity */}
          <div className="space-y-4">
            <h3 className="text-xs font-semibold text-zinc-500 tracking-wider uppercase">Recent Scans</h3>
            <div className="space-y-3">
              {recentScans.map(scan => (
                <div key={scan.id} className="p-3 rounded-lg border border-zinc-800 bg-zinc-950/50 flex items-center justify-between group cursor-pointer hover:border-zinc-700 transition-colors">
                  <div className="overflow-hidden">
                    <p className="text-sm font-medium text-zinc-200 truncate">{scan.url.replace('https://', '')}</p>
                    <p className="text-[10px] text-zinc-500">{scan.date} • {scan.findings} findings</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 group-hover:translate-x-1 transition-all" />
                </div>
              ))}
              <Button
                variant="link"
                onClick={() => router.push('/dashboard/history')}
                className="text-zinc-500 hover:text-zinc-300 text-xs p-0 h-auto"
              >
                View full history
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
