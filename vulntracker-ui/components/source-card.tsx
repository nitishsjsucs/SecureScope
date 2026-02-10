import { cn, formatDate } from "@/lib/utils";
import type { SourceType, SourceInfo } from "@/lib/types";
import {
  Database,
  Shield,
  AlertTriangle,
  Flame,
  Blocks,
  Github,
  Skull,
  ExternalLink,
  Search,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

// Source configuration with branding
const SOURCE_CONFIG: Record<
  SourceType,
  {
    name: string;
    shortName: string;
    icon: React.ElementType;
    bgGradient: string;
    iconBg: string;
    textColor: string;
    borderColor: string;
    description: string;
  }
> = {
  nvd: {
    name: "National Vulnerability Database",
    shortName: "NVD",
    icon: Database,
    bgGradient: "from-blue-50 to-blue-100/50",
    iconBg: "bg-blue-600",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "NIST's comprehensive vulnerability database",
  },
  mitre: {
    name: "MITRE CVE",
    shortName: "MITRE",
    icon: Shield,
    bgGradient: "from-[#FEF0ED] to-red-50",
    iconBg: "bg-[#EB5B3C]",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "CVE Numbering Authority",
  },
  cisa_kev: {
    name: "CISA KEV",
    shortName: "CISA",
    icon: AlertTriangle,
    bgGradient: "from-amber-50 to-orange-50",
    iconBg: "bg-gradient-to-br from-amber-500 to-orange-500",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "Known Exploited Vulnerabilities Catalog",
  },
  firecrawl: {
    name: "Firecrawl",
    shortName: "Firecrawl",
    icon: Flame,
    bgGradient: "from-orange-50 to-amber-50",
    iconBg: "bg-gradient-to-br from-orange-500 to-amber-500",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "Web intelligence & scraping",
  },
  openwall: {
    name: "Openwall",
    shortName: "Openwall",
    icon: Blocks,
    bgGradient: "from-[#F9FAFB] to-slate-100",
    iconBg: "bg-[#1F2937]",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "Security mailing lists",
  },
  github_advisory: {
    name: "GitHub Security Advisory",
    shortName: "GitHub",
    icon: Github,
    bgGradient: "from-[#F9FAFB] to-slate-100",
    iconBg: "bg-gray-900",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "GitHub Security Advisories",
  },
  exploitdb: {
    name: "Exploit Database",
    shortName: "ExploitDB",
    icon: Skull,
    bgGradient: "from-[#FEF0ED] to-red-50",
    iconBg: "bg-[#EB5B3C]",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "Archive of public exploits",
  },
  vulnrichment: {
    name: "CISA Vulnrichment",
    shortName: "Vulnrich",
    icon: Shield,
    bgGradient: "from-blue-50 to-indigo-50",
    iconBg: "bg-indigo-600",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "CISA KEV/SSVC enrichment data",
  },
  redhat: {
    name: "Red Hat Security",
    shortName: "Red Hat",
    icon: Shield,
    bgGradient: "from-red-50 to-rose-50",
    iconBg: "bg-red-600",
    textColor: "text-[#1F2937]",
    borderColor: "border-[#D1D5DB]",
    description: "Red Hat Security Advisories",
  },
};

interface SourceCardProps {
  source: SourceInfo;
  className?: string;
}

export function SourceCard({ source, className }: SourceCardProps) {
  const config = SOURCE_CONFIG[source.source];
  const Icon = config.icon;

  return (
    <div
      className={cn(
        "group relative flex flex-col rounded-xl border p-3 transition-all",
        "hover:shadow-md hover:scale-[1.02] hover:border-[#059669]/30",
        `bg-gradient-to-br ${config.bgGradient}`,
        config.borderColor,
        className
      )}
    >
      {/* Icon */}
      <div className="flex items-start justify-between mb-2">
        <div
          className={cn(
            "flex items-center justify-center w-8 h-8 rounded-lg shadow-sm",
            config.iconBg
          )}
        >
          <Icon className="h-4 w-4 text-white" />
        </div>
        {source.url && (
          <a
            href={source.url}
            target="_blank"
            rel="noopener noreferrer"
            className="opacity-0 group-hover:opacity-100 transition-opacity"
          >
            <ExternalLink className="h-4 w-4 text-[#4B5563] hover:text-[#059669]" />
          </a>
        )}
      </div>

      {/* Name */}
      <h4 className={cn("font-semibold text-sm", config.textColor)}>
        {config.shortName}
      </h4>

      {/* First seen date */}
      <p className="text-xs text-[#4B5563] mt-0.5">
        First seen: {formatDate(source.first_seen)}
      </p>
    </div>
  );
}

// Compact inline version for tight spaces
export function SourceBadge({
  sourceType,
  className,
}: {
  sourceType: SourceType;
  className?: string;
}) {
  const config = SOURCE_CONFIG[sourceType];
  const Icon = config.icon;

  return (
    <span
      title={config.name}
      className={cn(
        "inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs font-medium",
        `bg-gradient-to-br ${config.bgGradient}`,
        config.textColor,
        `border ${config.borderColor}`,
        className
      )}
    >
      <Icon className="h-3 w-3" />
      {config.shortName}
    </span>
  );
}

// Section component for the CVE detail page
interface SourcesSectionProps {
  sources?: SourceInfo[];
  className?: string;
}

export function SourcesSection({ sources, className }: SourcesSectionProps) {
  const hasSources = sources && sources.length > 0;

  return (
    <Card className={cn("border-[#D1D5DB]", className)}>
      <CardHeader>
        <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
          <Search className="h-5 w-5 text-[#4B5563]" />
          Published Sources
        </CardTitle>
      </CardHeader>
      <CardContent>
        {hasSources ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {sources.map((source) => (
              <SourceCard key={source.source} source={source} />
            ))}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-8 text-center">
            <div className="w-12 h-12 rounded-full bg-[#F9FAFB] flex items-center justify-center mb-3">
              <Search className="h-6 w-6 text-[#6B7280]" />
            </div>
            <p className="text-sm text-[#4B5563]">
              No source tracking data available yet
            </p>
            <p className="text-xs text-[#6B7280] mt-1">
              Sources will appear here as this CVE is published across security feeds
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// Export the config for use elsewhere
export { SOURCE_CONFIG };
