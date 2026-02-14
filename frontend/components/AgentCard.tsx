import { Card } from "@/components/ui/card";
import { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface AgentCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  selected?: boolean;
  onClick?: () => void;
  status?: "queued" | "running" | "completed" | "failed";
}

export function AgentCard({
  icon: Icon,
  title,
  description,
  selected,
  onClick,
  status
}: AgentCardProps) {
  return (
    <Card
      className={cn(
        "bg-zinc-950/50 border-zinc-800 p-4 transition-all cursor-pointer group",
        selected && "border-zinc-500 bg-zinc-900/50",
        !onClick && "cursor-default"
      )}
      onClick={onClick}
    >
      <div className="flex items-start gap-4">
        <div className={cn(
          "flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-zinc-900 border border-zinc-800 transition-colors",
          selected ? "border-zinc-600 bg-zinc-800" : "group-hover:border-zinc-700"
        )}>
          <Icon className={cn("h-5 w-5", selected ? "text-white" : "text-zinc-400")} />
        </div>
        <div className="flex-1">
          <div className="flex items-center justify-between mb-1">
            <h4 className="font-semibold text-sm text-zinc-200">{title}</h4>
            {status && (
              <div className={cn(
                "h-2 w-2 rounded-full",
                status === "running" && "bg-yellow-500 animate-pulse",
                status === "completed" && "bg-green-500",
                status === "failed" && "bg-red-500",
                status === "queued" && "bg-zinc-600"
              )} />
            )}
          </div>
          <p className="text-xs text-zinc-500 leading-relaxed">{description}</p>
        </div>
      </div>
    </Card>
  );
}
