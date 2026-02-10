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
  StarOff,
  Paperclip,
  ExternalLink,
  User,
  Calendar,
  ChevronRight,
  X,
  Package
} from "lucide-react";
import Link from "next/link";

interface EmailPreviewProps {
  email: MonitoredEmail | null;
  onClose?: () => void;
  onToggleStar?: (email: MonitoredEmail) => void;
  className?: string;
}

// Category config with colors and icons
const categoryConfig: Record<EmailCategory, { label: string; color: string; bgColor: string; icon: React.ReactNode }> = {
  cve_update: {
    label: "CVE Update",
    color: "text-[#DC2626]",
    bgColor: "bg-[#FEF2F2]",
    icon: <AlertTriangle className="h-4 w-4" />,
  },
  cve_detected: {
    label: "CVE Detected",
    color: "text-[#EA580C]",
    bgColor: "bg-[#FFF7ED]",
    icon: <AlertTriangle className="h-4 w-4" />,
  },
  security_advisory: {
    label: "Security Advisory",
    color: "text-[#7C3AED]",
    bgColor: "bg-[#F5F3FF]",
    icon: <Shield className="h-4 w-4" />,
  },
  threat_intel: {
    label: "Threat Intelligence",
    color: "text-[#DB2777]",
    bgColor: "bg-[#FDF2F8]",
    icon: <Shield className="h-4 w-4" />,
  },
  package_update: {
    label: "Package Update",
    color: "text-[#2563EB]",
    bgColor: "bg-[#EFF6FF]",
    icon: <Package className="h-4 w-4" />,
  },
  newsletter: {
    label: "Newsletter",
    color: "text-[#059669]",
    bgColor: "bg-[#ECFDF5]",
    icon: <Newspaper className="h-4 w-4" />,
  },
  promotional: {
    label: "Promotional",
    color: "text-[#6B7280]",
    bgColor: "bg-[#F3F4F6]",
    icon: <Tag className="h-4 w-4" />,
  },
  spam: {
    label: "Spam",
    color: "text-[#9CA3AF]",
    bgColor: "bg-[#F9FAFB]",
    icon: <Mail className="h-4 w-4" />,
  },
  other: {
    label: "Uncategorized",
    color: "text-[#6B7280]",
    bgColor: "bg-[#F3F4F6]",
    icon: <HelpCircle className="h-4 w-4" />,
  },
};

function getSeverityBadge(severity: string | null) {
  if (!severity) return null;
  
  const config: Record<string, { bg: string; text: string }> = {
    critical: { bg: "bg-[#DC2626]", text: "text-white" },
    high: { bg: "bg-[#EA580C]", text: "text-white" },
    medium: { bg: "bg-[#FBBF24]", text: "text-[#1F2937]" },
    low: { bg: "bg-[#059669]", text: "text-white" },
  };
  
  const style = config[severity] || config.low;
  
  return (
    <span className={cn(
      "inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase",
      style.bg,
      style.text
    )}>
      {severity}
    </span>
  );
}

export function EmailPreview({ email, onClose, onToggleStar, className }: EmailPreviewProps) {
  if (!email) {
    return (
      <div className={cn(
        "bg-white rounded-xl border border-[#D1D5DB] overflow-hidden flex flex-col items-center justify-center",
        className
      )}>
        <Mail className="h-16 w-16 text-[#D1D5DB] mb-4" />
        <p className="text-[#6B7280] text-center">
          Select an email to view details
        </p>
      </div>
    );
  }

  const category = email.analysis?.category || "other";
  const categoryInfo = categoryConfig[category];
  const analysis = email.analysis;

  return (
    <div className={cn(
      "bg-white rounded-xl border border-[#D1D5DB] overflow-hidden flex flex-col",
      className
    )}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-[#E5E7EB] flex-shrink-0">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            {/* Category badge */}
            <div className="flex items-center gap-2 mb-2">
              <span className={cn(
                "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-sm font-medium",
                categoryInfo.bgColor,
                categoryInfo.color
              )}>
                {categoryInfo.icon}
                {categoryInfo.label}
              </span>
              {analysis?.severity_mentioned && getSeverityBadge(analysis.severity_mentioned)}
              {analysis?.action_required && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-[#FEF3C7] text-[#D97706]">
                  Action Required
                </span>
              )}
            </div>

            {/* Subject */}
            <h2 className="text-lg font-semibold text-[#1F2937] mb-2">
              {email.subject || "(no subject)"}
            </h2>

            {/* From/Date */}
            <div className="flex items-center gap-4 text-sm text-[#6B7280]">
              <div className="flex items-center gap-1.5">
                <User className="h-4 w-4" />
                <span className="truncate max-w-[300px]">{email.from}</span>
              </div>
              <div className="flex items-center gap-1.5">
                <Calendar className="h-4 w-4" />
                <span>{formatDate(email.timestamp)}</span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 flex-shrink-0">
            {onToggleStar && (
              <button
                onClick={() => onToggleStar(email)}
                className="p-2 rounded-lg hover:bg-[#F9FAFB] transition-colors"
                title={email.starred ? "Unstar" : "Star"}
              >
                {email.starred ? (
                  <Star className="h-5 w-5 text-[#FBBF24] fill-[#FBBF24]" />
                ) : (
                  <StarOff className="h-5 w-5 text-[#9CA3AF]" />
                )}
              </button>
            )}
            {onClose && (
              <button
                onClick={onClose}
                className="p-2 rounded-lg hover:bg-[#F9FAFB] transition-colors lg:hidden"
              >
                <X className="h-5 w-5 text-[#6B7280]" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Analysis Section */}
      {analysis && (
        <div className="px-6 py-4 border-b border-[#E5E7EB] bg-[#F9FAFB] flex-shrink-0">
          {/* Summary */}
          <p className="text-sm text-[#4B5563] mb-4">
            {analysis.summary}
          </p>

          {/* CVE IDs */}
          {analysis.cve_ids.length > 0 && (
            <div className="mb-4">
              <h4 className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide mb-2">
                CVEs Mentioned
              </h4>
              <div className="flex flex-wrap gap-2">
                {analysis.cve_ids.map((cveId) => (
                  <Link
                    key={cveId}
                    href={`/cve/${cveId}`}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-sm font-medium bg-[#FEF2F2] text-[#DC2626] hover:bg-[#FEE2E2] transition-colors"
                  >
                    {cveId}
                    <ChevronRight className="h-3 w-3" />
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Key Points */}
          {analysis.key_points.length > 0 && (
            <div className="mb-4">
              <h4 className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide mb-2">
                Key Points
              </h4>
              <ul className="space-y-1">
                {analysis.key_points.map((point, i) => (
                  <li key={i} className="text-sm text-[#4B5563] flex items-start gap-2">
                    <span className="text-[#059669] mt-1">•</span>
                    {point}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Vendors & Products */}
          {(analysis.vendors.length > 0 || analysis.products.length > 0) && (
            <div className="flex flex-wrap gap-4">
              {analysis.vendors.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide mb-1">
                    Vendors
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {analysis.vendors.slice(0, 5).map((vendor) => (
                      <span
                        key={vendor}
                        className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#E5E7EB] text-[#374151]"
                      >
                        {vendor}
                      </span>
                    ))}
                    {analysis.vendors.length > 5 && (
                      <span className="text-xs text-[#6B7280]">
                        +{analysis.vendors.length - 5} more
                      </span>
                    )}
                  </div>
                </div>
              )}
              {analysis.products.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide mb-1">
                    Products
                  </h4>
                  <div className="flex flex-wrap gap-1">
                    {analysis.products.slice(0, 5).map((product) => (
                      <span
                        key={product}
                        className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-[#DBEAFE] text-[#1D4ED8]"
                      >
                        {product}
                      </span>
                    ))}
                    {analysis.products.length > 5 && (
                      <span className="text-xs text-[#6B7280]">
                        +{analysis.products.length - 5} more
                      </span>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Confidence */}
          <div className="mt-3 pt-3 border-t border-[#E5E7EB]">
            <div className="flex items-center gap-2">
              <span className="text-xs text-[#9CA3AF]">
                Analysis confidence: {Math.round(analysis.confidence * 100)}%
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Attachments */}
      {email.attachments && email.attachments.length > 0 && (
        <div className="px-6 py-3 border-b border-[#E5E7EB] flex-shrink-0">
          <h4 className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide mb-2">
            Attachments ({email.attachments.length})
          </h4>
          <div className="flex flex-wrap gap-2">
            {email.attachments.map((attachment) => (
              <span
                key={attachment.attachment_id}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-sm bg-[#F3F4F6] text-[#4B5563]"
              >
                <Paperclip className="h-3 w-3" />
                {attachment.filename || "Unnamed"}
                <span className="text-xs text-[#9CA3AF]">
                  ({Math.round(attachment.size / 1024)}KB)
                </span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Email Body */}
      <div className="flex-1 overflow-y-auto px-6 py-4">
        <div className="prose prose-sm max-w-none text-[#4B5563]">
          {email.text ? (
            <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed">
              {email.text}
            </pre>
          ) : email.html ? (
            <div 
              dangerouslySetInnerHTML={{ __html: email.html }} 
              className="email-html-content"
            />
          ) : (
            <p className="text-[#9CA3AF] italic">No content available</p>
          )}
        </div>
      </div>
    </div>
  );
}

// Skeleton for loading state
export function EmailPreviewSkeleton({ className }: { className?: string }) {
  return (
    <div className={cn(
      "bg-white rounded-xl border border-[#D1D5DB] overflow-hidden flex flex-col",
      className
    )}>
      {/* Header skeleton */}
      <div className="px-6 py-4 border-b border-[#E5E7EB]">
        <div className="flex items-center gap-2 mb-2">
          <div className="h-7 w-24 bg-[#E5E7EB] rounded-lg animate-pulse" />
          <div className="h-5 w-16 bg-[#E5E7EB] rounded animate-pulse" />
        </div>
        <div className="h-6 w-3/4 bg-[#E5E7EB] rounded animate-pulse mb-2" />
        <div className="flex gap-4">
          <div className="h-4 w-48 bg-[#E5E7EB] rounded animate-pulse" />
          <div className="h-4 w-24 bg-[#E5E7EB] rounded animate-pulse" />
        </div>
      </div>

      {/* Analysis skeleton */}
      <div className="px-6 py-4 border-b border-[#E5E7EB] bg-[#F9FAFB]">
        <div className="h-4 w-full bg-[#E5E7EB] rounded animate-pulse mb-2" />
        <div className="h-4 w-2/3 bg-[#E5E7EB] rounded animate-pulse mb-4" />
        <div className="flex gap-2 mb-4">
          <div className="h-7 w-28 bg-[#E5E7EB] rounded-lg animate-pulse" />
          <div className="h-7 w-28 bg-[#E5E7EB] rounded-lg animate-pulse" />
        </div>
        <div className="space-y-2">
          <div className="h-4 w-full bg-[#E5E7EB] rounded animate-pulse" />
          <div className="h-4 w-5/6 bg-[#E5E7EB] rounded animate-pulse" />
        </div>
      </div>

      {/* Body skeleton */}
      <div className="flex-1 px-6 py-4">
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div 
              key={i} 
              className="h-4 bg-[#E5E7EB] rounded animate-pulse"
              style={{ width: `${70 + Math.random() * 30}%` }}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
