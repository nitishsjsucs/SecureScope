import { cn } from "@/lib/utils";
import { Sparkles } from "lucide-react";

interface SeverityBadgeProps {
  score: number | null | undefined;
  showScore?: boolean;
  size?: "sm" | "md" | "lg";
  isAiScored?: boolean;
  className?: string;
}

function getSeverityInfo(score: number | null | undefined) {
  if (score === null || score === undefined) {
    return {
      label: "N/A",
      color: "text-[#4B5563]",
      bgColor: "bg-[#E5E7EB]",
    };
  }
  if (score >= 9.0) {
    return {
      label: "Critical",
      color: "text-white",
      bgColor: "bg-[#EF4444]", // Red 500 - lighter
    };
  }
  if (score >= 7.0) {
    return {
      label: "High",
      color: "text-white",
      bgColor: "bg-[#F97316]", // Orange 500 - lighter
    };
  }
  if (score >= 4.0) {
    return {
      label: "Medium",
      color: "text-[#1F2937]",
      bgColor: "bg-[#fdd665]", // Yellow 200 - soft, clean yellow
    };
  }
  if (score >= 0.1) {
    return {
      label: "Low",
      color: "text-white",
      bgColor: "bg-[#10B981]", // Emerald 500 - lighter
    };
  }
  return {
    label: "None",
    color: "text-[#4B5563]",
    bgColor: "bg-[#E5E7EB]",
  };
}

// AI-scored specific styling with gradient background
function getAiSeverityInfo(score: number | null | undefined) {
  if (score === null || score === undefined) {
    return {
      label: "N/A",
      color: "text-[#4B5563]",
      bgColor: "bg-gradient-to-r from-[#E5E7EB] to-[#D1D5DB]",
    };
  }
  if (score >= 9.0) {
    return {
      label: "Critical",
      color: "text-white",
      bgColor: "bg-gradient-to-r from-[#EF4444] to-[#DC2626]",
    };
  }
  if (score >= 7.0) {
    return {
      label: "High",
      color: "text-white",
      bgColor: "bg-gradient-to-r from-[#F97316] to-[#EA580C]",
    };
  }
  if (score >= 4.0) {
    return {
      label: "Medium",
      color: "text-[#1F2937]",
      bgColor: "bg-gradient-to-r from-[#fdd665] to-[#FBBF24]",
    };
  }
  if (score >= 0.1) {
    return {
      label: "Low",
      color: "text-white",
      bgColor: "bg-gradient-to-r from-[#10B981] to-[#059669]",
    };
  }
  return {
    label: "None",
    color: "text-[#4B5563]",
    bgColor: "bg-gradient-to-r from-[#E5E7EB] to-[#D1D5DB]",
  };
}

export function SeverityBadge({
  score,
  showScore = true,
  size = "md",
  isAiScored = false,
  className,
}: SeverityBadgeProps) {
  const severity = isAiScored ? getAiSeverityInfo(score) : getSeverityInfo(score);

  const sizeClasses = {
    sm: "text-xs px-2 py-0.5",
    md: "text-sm px-2.5 py-1",
    lg: "text-base px-3 py-1.5",
  };

  const iconSizes = {
    sm: "h-2.5 w-2.5",
    md: "h-3 w-3",
    lg: "h-3.5 w-3.5",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full font-medium",
        severity.bgColor,
        severity.color,
        sizeClasses[size],
        isAiScored && "ring-1 ring-inset ring-white/20",
        className
      )}
      title={isAiScored ? "AI-estimated score by SexySecure agents" : undefined}
    >
      {isAiScored && (
        <Sparkles className={cn(iconSizes[size], "flex-shrink-0")} />
      )}
      {showScore && score != null ? (
        <>
          <span className="font-semibold">{score.toFixed(1)}</span>
          <span className="opacity-90 text-[0.85em]">{severity.label}</span>
        </>
      ) : (
        severity.label
      )}
    </span>
  );
}
