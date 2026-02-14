import { Sidebar } from "@/components/Sidebar";
import { Bell, User } from "lucide-react";

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-black text-white">
      <Sidebar />
      <div className="pl-64 flex flex-col min-h-screen">
        {/* Top Navbar */}
        <header className="h-16 border-b border-zinc-900 bg-black/50 backdrop-blur-md sticky top-0 z-30 flex items-center justify-between px-8">
          <div className="flex items-center gap-4 text-sm text-zinc-500">
            <span>Network</span>
            <span className="h-1 w-1 rounded-full bg-zinc-800" />
            <span className="text-zinc-300">Mainnet-Alpha</span>
          </div>

          <div className="flex items-center gap-4">
            <button className="h-9 w-9 flex items-center justify-center rounded-lg border border-zinc-800 hover:bg-zinc-900 transition-colors relative">
              <Bell className="h-4 w-4 text-zinc-400" />
              <span className="absolute top-2 right-2 h-1.5 w-1.5 bg-red-500 rounded-full" />
            </button>
            <div className="h-9 px-3 flex items-center gap-2 rounded-lg border border-zinc-800 bg-zinc-950">
              <div className="h-5 w-5 rounded-full bg-zinc-800 flex items-center justify-center">
                <User className="h-3 w-3 text-zinc-400" />
              </div>
              <span className="text-xs font-medium text-zinc-300">admin@sentinel.io</span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-8 max-w-7xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  );
}
