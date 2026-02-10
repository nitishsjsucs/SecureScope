import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { CveMetrics, SeverityLevel, ParsedVendor } from "./types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Severity calculation from CVSS score
export function getSeverityFromScore(score: number | null | undefined): {
  level: SeverityLevel;
  label: string;
  color: string;
  bgColor: string;
  borderColor: string;
} {
  if (score === null || score === undefined) {
    return {
      level: "none",
      label: "N/A",
      color: "text-slate-600",
      bgColor: "bg-slate-100",
      borderColor: "border-slate-200",
    };
  }
  if (score >= 9.0) {
    return {
      level: "critical",
      label: "Critical",
      color: "text-red-700",
      bgColor: "bg-red-50",
      borderColor: "border-red-200",
    };
  }
  if (score >= 7.0) {
    return {
      level: "high",
      label: "High",
      color: "text-orange-700",
      bgColor: "bg-orange-50",
      borderColor: "border-orange-200",
    };
  }
  if (score >= 4.0) {
    return {
      level: "medium",
      label: "Medium",
      color: "text-yellow-700",
      bgColor: "bg-yellow-50",
      borderColor: "border-yellow-200",
    };
  }
  if (score >= 0.1) {
    return {
      level: "low",
      label: "Low",
      color: "text-green-700",
      bgColor: "bg-green-50",
      borderColor: "border-green-200",
    };
  }
  return {
    level: "none",
    label: "None",
    color: "text-slate-600",
    bgColor: "bg-slate-100",
    borderColor: "border-slate-200",
  };
}

// Extract best CVSS score from metrics (prefer newer versions)
// Returns isAiScored flag to indicate if the score came from AI
export function getBestCvssScore(metrics: CveMetrics | null | undefined): {
  score: number | null;
  version: string | null;
  vector: string | null;
  isAiScored: boolean;
} {
  if (!metrics) {
    return { score: null, version: null, vector: null, isAiScored: false };
  }

  // Prefer newer CVSS versions (official scores first)
  if (metrics.cvssV4_0?.data?.score !== undefined) {
    return {
      score: metrics.cvssV4_0.data.score,
      version: "4.0",
      vector: metrics.cvssV4_0.data.vector || null,
      isAiScored: false,
    };
  }
  if (metrics.cvssV3_1?.data?.score !== undefined) {
    return {
      score: metrics.cvssV3_1.data.score,
      version: "3.1",
      vector: metrics.cvssV3_1.data.vector || null,
      isAiScored: false,
    };
  }
  if (metrics.cvssV3_0?.data?.score !== undefined) {
    return {
      score: metrics.cvssV3_0.data.score,
      version: "3.0",
      vector: metrics.cvssV3_0.data.vector || null,
      isAiScored: false,
    };
  }
  if (metrics.cvssV2_0?.data?.score !== undefined) {
    return {
      score: metrics.cvssV2_0.data.score,
      version: "2.0",
      vector: metrics.cvssV2_0.data.vector || null,
      isAiScored: false,
    };
  }

  // Fall back to AI score if no official score exists
  if (metrics.ai_score?.score !== undefined) {
    return {
      score: metrics.ai_score.score,
      version: metrics.ai_score.version || "AI",
      vector: metrics.ai_score.vector || null,
      isAiScored: true,
    };
  }

  return { score: null, version: null, vector: null, isAiScored: false };
}

// Parse vendor string (handles "vendor$PRODUCT$product" format)
export function parseVendorString(vendor: string): ParsedVendor {
  const PRODUCT_SEPARATOR = "$PRODUCT$";
  const parts = vendor.split(PRODUCT_SEPARATOR);
  return {
    vendor: parts[0],
    product: parts[1] || undefined,
  };
}

// Humanize vendor/product names (replace underscores, capitalize)
export function humanize(name: string): string {
  return name
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

// Format date for display - compact format (omit year if current year)
export function formatDate(dateString: string | null | undefined): string {
  if (!dateString) return "Unknown";
  const date = new Date(dateString);
  const now = new Date();
  const sameYear = date.getFullYear() === now.getFullYear();

  return date.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

// Format date with time
export function formatDateTime(dateString: string | null | undefined): string {
  if (!dateString) return "Unknown";
  return new Date(dateString).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// Format EPSS score as percentage
export function formatEpssScore(score: number): string {
  return `${(score * 100).toFixed(2)}%`;
}

// Format EPSS percentile
export function formatEpssPercentile(percentile: number): string {
  return `${(percentile * 100).toFixed(0)}th`;
}

// Truncate text with ellipsis
export function truncateText(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text;
  return text.slice(0, maxLength).trim() + "...";
}

// Get unique vendors from vendor array (extracts just vendor names, not products)
export function getUniqueVendors(vendors: string[]): string[] {
  const uniqueVendors = new Set<string>();
  for (const v of vendors) {
    const parsed = parseVendorString(v);
    uniqueVendors.add(parsed.vendor);
  }
  return Array.from(uniqueVendors);
}
