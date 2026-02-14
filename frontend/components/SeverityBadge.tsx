import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: "low" | "medium" | "high" | "critical";
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  const variants = {
    low: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    critical: "bg-red-500/10 text-red-500 border-red-500/20",
  };

  return (
    <Badge className={cn("capitalize font-semibold", variants[severity], className)}>
      {severity}
    </Badge>
  );
}
