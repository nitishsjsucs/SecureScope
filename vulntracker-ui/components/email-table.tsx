"use client";

import { cn, formatDate } from "@/lib/utils";
import type { MonitoredEmail, EmailCategory } from "@/lib/types";
import { 
  Mail, 
  AlertTriangle, 
  Shield, 
  Newspaper, 
  Tag,
  HelpCircle,
  Star,
  Paperclip,
  Package
} from "lucide-react";

interface EmailTableProps {
  emails: MonitoredEmail[];
  selectedId: string | null;
  onSelect: (email: MonitoredEmail) => void;
  className?: string;
}

// Category config with colors and icons
const categoryConfig: Record<EmailCategory, { label: string; color: string; bgColor: string; icon: React.ReactNode }> = {
  cve_update: {
    label: "CVE Update",
    color: "text-[#DC2626]",
    bgColor: "bg-[#FEF2F2]",
    icon: <AlertTriangle className="h-3 w-3" />,
  },
  cve_detected: {
    label: "CVE Detected",
    color: "text-[#EA580C]",
    bgColor: "bg-[#FFF7ED]",
    icon: <AlertTriangle className="h-3 w-3" />,
  },
  security_advisory: {
    label: "Advisory",
    color: "text-[#7C3AED]",
    bgColor: "bg-[#F5F3FF]",
    icon: <Shield className="h-3 w-3" />,
  },
  threat_intel: {
    label: "Threat Intel",
    color: "text-[#DB2777]",
    bgColor: "bg-[#FDF2F8]",
    icon: <Shield className="h-3 w-3" />,
  },
  package_update: {
    label: "Package Update",
    color: "text-[#2563EB]",
    bgColor: "bg-[#EFF6FF]",
    icon: <Package className="h-3 w-3" />,
  },
  newsletter: {
    label: "Newsletter",
    color: "text-[#059669]",
    bgColor: "bg-[#ECFDF5]",
    icon: <Newspaper className="h-3 w-3" />,
  },
  promotional: {
    label: "Promotional",
    color: "text-[#6B7280]",
    bgColor: "bg-[#F3F4F6]",
    icon: <Tag className="h-3 w-3" />,
  },
  spam: {
    label: "Spam",
    color: "text-[#9CA3AF]",
    bgColor: "bg-[#F9FAFB]",
    icon: <Mail className="h-3 w-3" />,
  },
  other: {
    label: "Other",
    color: "text-[#6B7280]",
    bgColor: "bg-[#F3F4F6]",
    icon: <HelpCircle className="h-3 w-3" />,
  },
};

function getCategoryBadge(category: EmailCategory) {
  const config = categoryConfig[category] || categoryConfig.other;
  return (
    <span className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium",
      config.bgColor,
      config.color
    )}>
      {config.icon}
      {config.label}
    </span>
  );
}

function getFromName(from: string): string {
  // Extract name from "Name <email>" or just return email
  const match = from.match(/^(.+?)\s*<.+>$/);
  if (match) {
    return match[1].replace(/"/g, "").trim();
  }
  // Return part before @ for plain emails
  return from.split("@")[0];
}

export function EmailTable({ emails, selectedId, onSelect, className }: EmailTableProps) {
  if (emails.length === 0) {
    return (
      <div className={cn("bg-white rounded-xl border border-[#D1D5DB] overflow-hidden", className)}>
        <div className="flex flex-col items-center justify-center py-16 px-4">
          <Mail className="h-12 w-12 text-[#D1D5DB] mb-4" />
          <p className="text-[#6B7280] text-center">
            No emails yet. Click refresh to fetch new emails.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={cn("bg-white rounded-xl border border-[#D1D5DB] overflow-hidden", className)}>
      <div className="divide-y divide-[#E5E7EB]">
        {emails.map((email) => (
          <EmailRow
            key={email._id}
            email={email}
            isSelected={email._id === selectedId}
            onSelect={() => onSelect(email)}
          />
        ))}
      </div>
    </div>
  );
}

interface EmailRowProps {
  email: MonitoredEmail;
  isSelected: boolean;
  onSelect: () => void;
}

function EmailRow({ email, isSelected, onSelect }: EmailRowProps) {
  const category = email.analysis?.category || "other";
  const hasAttachments = email.attachments && email.attachments.length > 0;
  const hasCves = email.analysis?.cve_ids && email.analysis.cve_ids.length > 0;
  
  // Determine severity accent
  const getSeverityAccent = () => {
    if (!email.analysis) return "border-l-[#D1D5DB]";
    if (category === "cve_detected" || category === "cve_update") {
      if (email.analysis.severity_mentioned === "critical") return "border-l-[#DC2626]";
      if (email.analysis.severity_mentioned === "high") return "border-l-[#EA580C]";
      return "border-l-[#FBBF24]";
    }
    if (category === "security_advisory" || category === "threat_intel") {
      return "border-l-[#7C3AED]";
    }
    if (category === "package_update") {
      return "border-l-[#2563EB]";
    }
    if (category === "spam" || category === "promotional") {
      return "border-l-[#D1D5DB]";
    }
    return "border-l-[#059669]";
  };

  return (
    <button
      onClick={onSelect}
      className={cn(
        "w-full text-left px-4 py-3 transition-colors border-l-4",
        getSeverityAccent(),
        isSelected 
          ? "bg-[#ECFDF5]" 
          : email.read 
            ? "bg-white hover:bg-[#F9FAFB]" 
            : "bg-[#FAFAFA] hover:bg-[#F3F4F6]"
      )}
    >
      <div className="flex items-start gap-3">
        {/* Unread indicator + star */}
        <div className="flex flex-col items-center gap-1 pt-0.5">
          <div className={cn(
            "w-2 h-2 rounded-full flex-shrink-0",
            !email.read ? "bg-[#3B82F6]" : "bg-transparent"
          )} />
          {email.starred && (
            <Star className="h-3 w-3 text-[#FBBF24] fill-[#FBBF24]" />
          )}
        </div>

        {/* Content */}
        <div className="flex-1 min-w-0">
          {/* Top row: From + Date */}
          <div className="flex items-center justify-between gap-2 mb-1">
            <span className={cn(
              "text-sm truncate",
              !email.read ? "font-semibold text-[#1F2937]" : "font-medium text-[#4B5563]"
            )}>
              {getFromName(email.from)}
            </span>
            <span className="text-xs text-[#9CA3AF] flex-shrink-0">
              {formatDate(email.timestamp)}
            </span>
          </div>

          {/* Subject */}
          <p className={cn(
            "text-sm truncate mb-1",
            !email.read ? "text-[#1F2937]" : "text-[#4B5563]"
          )}>
            {email.subject || "(no subject)"}
          </p>

          {/* Preview */}
          <p className="text-xs text-[#6B7280] line-clamp-1 mb-2">
            {email.analysis?.summary || email.preview || ""}
          </p>

          {/* Bottom row: Category + CVEs + attachments */}
          <div className="flex items-center gap-2 flex-wrap">
            {getCategoryBadge(category)}
            
            {hasCves && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-[#FEF2F2] text-[#DC2626]">
                <AlertTriangle className="h-3 w-3" />
                {email.analysis!.cve_ids.length} CVE{email.analysis!.cve_ids.length > 1 ? "s" : ""}
              </span>
            )}

            {hasAttachments && (
              <span className="inline-flex items-center text-[#6B7280]">
                <Paperclip className="h-3 w-3" />
              </span>
            )}

            {email.analysis?.action_required && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-[#FEF3C7] text-[#D97706]">
                Action Required
              </span>
            )}
          </div>
        </div>
      </div>
    </button>
  );
}

// Loading skeleton
export function EmailTableSkeleton({ rows = 8 }: { rows?: number }) {
  return (
    <div className="bg-white rounded-xl border border-[#D1D5DB] overflow-hidden">
      <div className="divide-y divide-[#E5E7EB]">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="px-4 py-3 border-l-4 border-l-[#E5E7EB]">
            <div className="flex items-start gap-3">
              <div className="w-2 h-2 rounded-full bg-[#E5E7EB] animate-pulse" />
              <div className="flex-1">
                <div className="flex justify-between mb-1">
                  <div className="h-4 w-32 bg-[#E5E7EB] rounded animate-pulse" />
                  <div className="h-3 w-16 bg-[#E5E7EB] rounded animate-pulse" />
                </div>
                <div className="h-4 w-3/4 bg-[#E5E7EB] rounded animate-pulse mb-1" />
                <div className="h-3 w-full bg-[#E5E7EB] rounded animate-pulse mb-2" />
                <div className="flex gap-2">
                  <div className="h-5 w-20 bg-[#E5E7EB] rounded animate-pulse" />
                  <div className="h-5 w-16 bg-[#E5E7EB] rounded animate-pulse" />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
