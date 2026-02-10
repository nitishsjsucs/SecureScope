import { cn } from "@/lib/utils";
import { ShieldCheck } from "lucide-react";

interface SexySecureBadgeProps {
  verified: boolean;
  verifiedAt?: string | null;
  verifiedBy?: string | null;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  className?: string;
}

export function SexySecureBadge({
  verified,
  verifiedAt,
  verifiedBy,
  size = "md",
  showLabel = false,
  className,
}: SexySecureBadgeProps) {
  if (!verified) return null;

  const sizeConfig = {
    sm: {
      icon: "h-3.5 w-3.5",
      container: "p-0.5",
      text: "text-xs",
      gap: "gap-1",
    },
    md: {
      icon: "h-4 w-4",
      container: "p-1",
      text: "text-sm",
      gap: "gap-1.5",
    },
    lg: {
      icon: "h-5 w-5",
      container: "p-1.5",
      text: "text-base",
      gap: "gap-2",
    },
  };

  const config = sizeConfig[size];

  // Build tooltip text
  const tooltipParts = ["Verified by SexySecure"];
  if (verifiedAt) {
    tooltipParts.push(`on ${new Date(verifiedAt).toLocaleDateString()}`);
  }
  if (verifiedBy) {
    tooltipParts.push(`by ${verifiedBy}`);
  }
  const tooltip = tooltipParts.join(" ");

  return (
    <span
      title={tooltip}
      className={cn(
        "inline-flex items-center",
        config.gap,
        className
      )}
    >
      <span
        className={cn(
          "inline-flex items-center justify-center rounded-md",
          "bg-gradient-to-br from-[#059669] to-[#047857]",
          "shadow-sm shadow-[#059669]/30",
          config.container
        )}
      >
        <ShieldCheck
          className={cn(config.icon, "text-white drop-shadow-sm")}
          strokeWidth={2.5}
        />
      </span>
      {showLabel && (
        <span
          className={cn(
            "font-semibold text-[#047857]",
            config.text
          )}
        >
          Verified
        </span>
      )}
    </span>
  );
}

// Inline version for use in tight spaces (like table cells)
export function SexySecureBadgeInline({
  verified,
  className,
}: {
  verified: boolean;
  className?: string;
}) {
  if (!verified) return null;

  return (
    <span
      title="Verified by SexySecure"
      className={cn(
        "inline-flex items-center justify-center",
        "w-4 h-4 rounded",
        "bg-gradient-to-br from-[#059669] to-[#047857]",
        "shadow-sm shadow-[#059669]/25",
        className
      )}
    >
      <ShieldCheck className="h-3 w-3 text-white" strokeWidth={2.5} />
    </span>
  );
}
