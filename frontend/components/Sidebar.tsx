"use client";

import { Shield, LayoutDashboard, History, Settings, LogOut, Search } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";

const menuItems = [
  { icon: LayoutDashboard, label: "Dashboard", href: "/dashboard" },
  { icon: History, label: "History", href: "/dashboard/history" },
  { icon: Search, label: "Scanners", href: "/dashboard/scanners" },
  { icon: Settings, label: "Settings", href: "/dashboard/settings" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <div className="w-64 h-screen bg-black border-r border-zinc-900 flex flex-col fixed left-0 top-0">
      <div className="p-6">
        <Link href="/dashboard" className="flex items-center gap-3 group">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-zinc-900 border border-zinc-800 group-hover:border-zinc-700 transition-colors">
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">SENTINEL</h1>
            <p className="text-[10px] text-zinc-500 font-bold uppercase tracking-widest">Security OS</p>
          </div>
        </Link>
      </div>

      <nav className="flex-1 px-4 py-4 space-y-2">
        {menuItems.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/dashboard" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group",
                isActive
                  ? "bg-white text-black"
                  : "text-zinc-500 hover:text-white hover:bg-zinc-900"
              )}
            >
              <item.icon className={cn("h-4 w-4", isActive ? "text-black" : "text-zinc-500 group-hover:text-white")} />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="p-4 mt-auto">
        <div className="bg-zinc-950 border border-zinc-900 rounded-xl p-4 mb-4">
          <div className="flex items-center gap-3 mb-3">
            <div className="h-2 w-2 rounded-full bg-green-500" />
            <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">System Status</span>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between text-[10px]">
              <span className="text-zinc-500">API Gateway</span>
              <span className="text-zinc-300">Operational</span>
            </div>
            <div className="flex justify-between text-[10px]">
              <span className="text-zinc-500">Agents Online</span>
              <span className="text-zinc-300">24/24</span>
            </div>
          </div>
        </div>

        <button className="flex items-center gap-3 px-3 py-2.5 w-full rounded-lg text-sm font-medium text-zinc-500 hover:text-red-400 hover:bg-red-500/5 transition-all">
          <LogOut className="h-4 w-4" />
          Logout
        </button>
      </div>
    </div>
  );
}
