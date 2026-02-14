"use client";

import { Shield, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useRouter } from "next/navigation";

export default function Home() {
  const router = useRouter();

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center">
      <div className="text-center space-y-8 px-4">
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <div className="flex h-20 w-20 items-center justify-center rounded-2xl bg-zinc-900 border-2 border-zinc-800">
            <Shield className="h-10 w-10" />
          </div>
        </div>

        {/* Welcome Text */}
        <div>
          <h1 className="text-5xl font-bold mb-4">SENTINEL</h1>
          <p className="text-xl text-zinc-400">Multi-Agent Security Scanner</p>
          <p className="text-zinc-500 mt-4 max-w-md mx-auto">
            Deploy parallel AI agents to analyze your application's security posture
          </p>
        </div>

        {/* Navigate Button */}
        <Button
          onClick={() => router.push("/dashboard")}
          size="lg"
          className="bg-zinc-800 hover:bg-zinc-700 text-white px-8 py-6 text-lg"
        >
          Navigate to Dashboard
          <ArrowRight className="ml-2 h-5 w-5" />
        </Button>
      </div>
    </div>
  );
}
