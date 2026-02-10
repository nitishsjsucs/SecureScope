import { cn } from "@/lib/utils";
import { Flame, TrendingUp, Thermometer, Snowflake, MessageCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type ChatterLevel = "cold" | "warm" | "trending" | "hot" | "viral";

interface ChatterConfig {
  level: ChatterLevel;
  label: string;
  icon: React.ElementType;
  color: string;
  bgColor: string;
  barColor: string;
  borderColor: string;
  glowColor?: string;
}

function getChatterConfig(score: number): ChatterConfig {
  if (score >= 80) {
    return {
      level: "viral",
      label: "Viral",
      icon: Flame,
      color: "text-[#EB5B3C]",
      bgColor: "bg-[#FEF0ED]",
      barColor: "bg-gradient-to-r from-orange-500 to-[#EB5B3C]",
      borderColor: "border-[#EB5B3C]/20",
      glowColor: "shadow-[#EB5B3C]/20",
    };
  }
  if (score >= 60) {
    return {
      level: "hot",
      label: "Hot",
      icon: Flame,
      color: "text-orange-500",
      bgColor: "bg-orange-50",
      barColor: "bg-gradient-to-r from-amber-400 to-orange-500",
      borderColor: "border-orange-200",
      glowColor: "shadow-orange-500/20",
    };
  }
  if (score >= 40) {
    return {
      level: "trending",
      label: "Trending",
      icon: TrendingUp,
      color: "text-[#047857]",
      bgColor: "bg-[#ECFDF5]",
      barColor: "bg-gradient-to-r from-[#059669] to-[#047857]",
      borderColor: "border-[#059669]/20",
    };
  }
  if (score >= 20) {
    return {
      level: "warm",
      label: "Warm",
      icon: Thermometer,
      color: "text-[#059669]",
      bgColor: "bg-[#ECFDF5]",
      barColor: "bg-[#059669]",
      borderColor: "border-[#059669]/20",
    };
  }
  return {
    level: "cold",
    label: "Cold",
    icon: Snowflake,
    color: "text-[#4B5563]",
    bgColor: "bg-[#F9FAFB]",
    barColor: "bg-[#6B7280]",
    borderColor: "border-[#D1D5DB]",
  };
}

interface ChatterScoreProps {
  score: number | null | undefined;
  size?: "sm" | "md" | "lg";
  showBar?: boolean;
  showLabel?: boolean;
  className?: string;
}

export function ChatterScore({
  score,
  size = "md",
  showBar = true,
  showLabel = true,
  className,
}: ChatterScoreProps) {
  if (score === null || score === undefined) {
    return null;
  }

  const config = getChatterConfig(score);
  const Icon = config.icon;

  const sizeConfig = {
    sm: {
      icon: "h-3 w-3",
      text: "text-xs",
      barHeight: "h-1",
      barWidth: "w-16",
      gap: "gap-1",
      padding: "px-1.5 py-0.5",
    },
    md: {
      icon: "h-4 w-4",
      text: "text-sm",
      barHeight: "h-1.5",
      barWidth: "w-24",
      gap: "gap-1.5",
      padding: "px-2 py-1",
    },
    lg: {
      icon: "h-5 w-5",
      text: "text-base",
      barHeight: "h-2",
      barWidth: "w-32",
      gap: "gap-2",
      padding: "px-3 py-1.5",
    },
  };

  const sizing = sizeConfig[size];

  return (
    <div
      className={cn(
        "inline-flex items-center rounded-lg border",
        sizing.gap,
        sizing.padding,
        config.bgColor,
        config.borderColor,
        config.glowColor && `shadow-md ${config.glowColor}`,
        className
      )}
      title={`Chatter Score: ${score}/100 - ${config.label}`}
    >
      <Icon className={cn(sizing.icon, config.color)} />
      
      <span className={cn("font-semibold", sizing.text, config.color)}>
        {score}
      </span>

      {showBar && (
        <div
          className={cn(
            "rounded-full bg-[#D1D5DB] overflow-hidden",
            sizing.barHeight,
            sizing.barWidth
          )}
        >
          <div
            className={cn("h-full rounded-full transition-all", config.barColor)}
            style={{ width: `${score}%` }}
          />
        </div>
      )}

      {showLabel && (
        <span className={cn(sizing.text, config.color, "font-medium")}>
          {config.label}
        </span>
      )}
    </div>
  );
}

// Compact inline version for table cells
export function ChatterScoreInline({
  score,
  threshold = 40,
  className,
}: {
  score: number | null | undefined;
  threshold?: number;
  className?: string;
}) {
  // Only show if score is above threshold
  if (score === null || score === undefined || score < threshold) {
    return null;
  }

  const config = getChatterConfig(score);
  const Icon = config.icon;

  return (
    <span
      title={`Chatter Score: ${score}/100 (${config.label})`}
      className={cn("inline-flex items-center", className)}
    >
      <Icon
        className={cn(
          "h-3.5 w-3.5",
          config.color,
          score >= 80 && "animate-pulse"
        )}
      />
    </span>
  );
}

// Large display version for CVE detail page header - matches metric card style
interface ChatterScoreDisplayProps {
  score: number | null | undefined;
  className?: string;
}

export function ChatterScoreDisplay({
  score,
  className,
}: ChatterScoreDisplayProps) {
  if (score === null || score === undefined) {
    return null;
  }

  const config = getChatterConfig(score);
  const Icon = config.icon;

  return (
    <Card className={cn("border-[#D1D5DB]", className)}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-[#4B5563]">
          Chatter Score
        </CardTitle>
        <div className={cn("p-1.5 rounded-lg", config.bgColor, config.color)}>
          <MessageCircle className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className={cn("text-3xl font-bold", config.color)}>
            {score}
          </span>
          <span className="text-sm text-[#6B7280]">/100</span>
          <span
            className={cn(
              "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium",
              config.bgColor,
              config.color
            )}
          >
            <Icon className="h-3 w-3" />
            {config.label}
          </span>
        </div>
        <p className="mt-2 text-xs text-[#6B7280]">
          Social media & forum traction
        </p>
      </CardContent>
    </Card>
  );
}

export { getChatterConfig };
