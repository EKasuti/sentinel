"use client";

import { Shield, Globe, Lock, Search, ShieldCheck, ChevronRight, Zap, User, Key, Cookie } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { cn } from "@/lib/utils";

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState("");
  const [showAuth, setShowAuth] = useState(false);
  const [authMethod, setAuthMethod] = useState("none");
  const router = useRouter();

  const handleLaunchScan = () => {
    router.push(`/dashboard/scan?url=${encodeURIComponent(targetUrl)}`);
  };

  const authOptions = [

    { id: "none", label: "None", icon: Globe },
    { id: "basic", label: "Basic Auth", icon: User },
    { id: "bearer", label: "Bearer Token", icon: Key },
    { id: "apikey", label: "API Key", icon: Lock },
    { id: "cookie", label: "Cookie", icon: Cookie },
  ];

  return (
    <div className="min-h-screen bg-black text-white relative">
      {/* Header */}
      <header className="border-b border-zinc-900 px-8 py-4 bg-black/50 backdrop-blur-sm fixed top-0 w-full z-10">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800">
            <Shield className="h-5 w-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold tracking-tight">SENTINEL</h1>
            <p className="text-xs text-zinc-400 font-medium">Multi-Agent Security Scanner</p>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto max-w-4xl p-4 py-22">
        {/* Title and Description */}
        <div className="mb-6 text-center space-y-2">
          <h2 className="text-4xl font-bold tracking-tight">Configure Security Scan</h2>
          <p className="text-zinc-400 max-w-2xl mx-auto text-base leading-relaxed">
            Enter the target URL and optional authentication credentials. Sentinel
            will deploy three parallel agents to analyze your application's security
            posture.
          </p>
        </div>

        <div className="space-y-4">
          {/* Target URL Section */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 p-6">
            <div className="mb-2 flex items-center gap-2">
              <Globe className="h-5 w-5 text-zinc-400" />
              <h3 className="text-base font-semibold">Target URL</h3>
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
            <p className="mt-3 text-xs text-zinc-500 font-medium">
              Must be a valid HTTP or HTTPS URL. The scan will probe this endpoint and its subpaths.
            </p>
          </div>

          {/* Authentication Section */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-950/50 overflow-hidden transition-all duration-300">
            <div
              className="p-6 cursor-pointer hover:bg-zinc-900/30 transition-colors flex items-center justify-between"
              onClick={() => setShowAuth(!showAuth)}
            >
              <div className="flex items-center gap-2">
                <Lock className="h-5 w-5 text-zinc-400" />
                <div>
                  <h3 className="text-base font-semibold">Authentication</h3>
                  {!showAuth && (
                    <p className="text-sm text-zinc-400 mt-1">
                      Provide credentials for authenticated scanning (optional)
                    </p>
                  )}
                </div>
              </div>
              <ChevronRight className={cn("h-5 w-5 text-zinc-500 transition-transform duration-300", showAuth && "rotate-90")} />
            </div>

            {showAuth && (
              <div className="px-6 pb-6 pt-2 border-t border-zinc-800/50">
                <p className="text-sm text-zinc-400 mb-6">
                  Provide credentials for authenticated scanning (optional)
                </p>

                <div className="space-y-4">
                  <p className="text-xs font-semibold text-zinc-500 tracking-wider uppercase">Authentication Method</p>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                    {authOptions.map((option) => {
                      const Icon = option.icon;
                      const isSelected = authMethod === option.id;
                      return (
                        <button
                          key={option.id}
                          onClick={() => setAuthMethod(option.id)}
                          className={cn(
                            "flex flex-col items-center justify-center gap-3 p-4 rounded-lg border transition-all duration-200",
                            isSelected
                              ? "bg-zinc-800 border-zinc-600 text-white"
                              : "bg-transparent border-zinc-800 text-zinc-400 hover:bg-zinc-900 hover:border-zinc-700"
                          )}
                        >
                          <Icon className={cn("h-5 w-5", isSelected ? "text-white" : "text-zinc-500")} />
                          <span className="text-xs font-medium">{option.label}</span>
                        </button>
                      );
                    })}
                  </div>

                  {/* Dynamic Inputs based on selection */}
                  {authMethod !== "none" && (
                    <div className="mt-6 pt-6 border-t border-zinc-800/50 animate-in fade-in slide-in-from-top-2">
                      {authMethod === "basic" && (
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <label className="text-xs text-zinc-400">Username</label>
                            <Input className="bg-black/50 border-zinc-800" placeholder="admin" />
                          </div>
                          <div className="space-y-2">
                            <label className="text-xs text-zinc-400">Password</label>
                            <Input className="bg-black/50 border-zinc-800" type="password" placeholder="••••••" />
                          </div>
                        </div>
                      )}
                      {authMethod === "bearer" && (
                        <div className="space-y-2">
                          <label className="text-xs text-zinc-400">Token</label>
                          <Input className="bg-black/50 border-zinc-800" placeholder="ey..." />
                        </div>
                      )}
                      {authMethod === "apikey" && (
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <label className="text-xs text-zinc-400">Key Name</label>
                            <Input className="bg-black/50 border-zinc-800" placeholder="X-API-Key" />
                          </div>
                          <div className="space-y-2">
                            <label className="text-xs text-zinc-400">Value</label>
                            <Input className="bg-black/50 border-zinc-800" placeholder="secret_key" />
                          </div>
                        </div>
                      )}
                      {authMethod === "cookie" && (
                        <div className="space-y-2">
                          <label className="text-xs text-zinc-400">Cookie String</label>
                          <Input className="bg-black/50 border-zinc-800" placeholder="session=..." />
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Agents to Deploy */}
          <div className="pt-4">
            <h3 className="mb-4 text-xs font-semibold text-zinc-500 tracking-wider uppercase">• Agents to Deploy</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <Card className="bg-zinc-950/50 border-zinc-800 p-4 hover:bg-zinc-900/50 transition-colors cursor-default group">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800 group-hover:border-zinc-700 transition-colors">
                    <Search className="h-5 w-5 text-zinc-400" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm mb-1 text-zinc-200">Exposure Mapper</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">Attack surface & endpoints discovery</p>
                  </div>
                </div>
              </Card>

              <Card className="bg-zinc-950/50 border-zinc-800 p-4 hover:bg-zinc-900/50 transition-colors cursor-default group">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800 group-hover:border-zinc-700 transition-colors">
                    <ShieldCheck className="h-5 w-5 text-zinc-400" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm mb-1 text-zinc-200">Headers & TLS</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">Security headers & SSL configuration</p>
                  </div>
                </div>
              </Card>

              <Card className="bg-zinc-950/50 border-zinc-800 p-4 hover:bg-zinc-900/50 transition-colors cursor-default group">
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800 group-hover:border-zinc-700 transition-colors">
                    <Lock className="h-5 w-5 text-zinc-400" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-sm mb-1 text-zinc-200">Auth & Abuse</h4>
                    <p className="text-xs text-zinc-500 leading-relaxed">Auth mechanisms & rate limits</p>
                  </div>
                </div>
              </Card>
            </div>
          </div>

          {/* Launch Button */}
          <div className="flex flex-col items-center gap-4 w-full">
            <Button
              onClick={handleLaunchScan}
              disabled={!targetUrl || !/^https?:\/\/.+\..+/.test(targetUrl)}
              className="w-full md:w-auto px-8 bg-zinc-100 hover:bg-white text-black py-7 text-lg font-bold rounded-2xl transition-all hover:scale-[1.01] active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
            >
              <Zap className="mr-2 h-5 w-5 fill-black" />
              Launch Security Scan
            </Button>
          </div>
        </div>
      </main>
    </div>
  );
}