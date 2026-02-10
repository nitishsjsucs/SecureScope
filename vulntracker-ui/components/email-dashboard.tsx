"use client";

import { useState, useCallback, useEffect } from "react";
import { EmailTable, EmailTableSkeleton } from "./email-table";
import { EmailPreview, EmailPreviewSkeleton } from "./email-preview";
import type { MonitoredEmail, EmailCategory } from "@/lib/types";
import { 
  RefreshCw, 
  Filter,
  Loader2,
  CheckCircle,
  AlertCircle,
  Mail,
  Inbox
} from "lucide-react";
import { cn } from "@/lib/utils";

interface EmailDashboardProps {
  initialEmails: MonitoredEmail[];
  initialTotal: number;
}

const categoryFilters: { value: string; label: string }[] = [
  { value: "all", label: "All" },
  { value: "cve_update", label: "CVE Updates" },
  { value: "cve_detected", label: "CVE Detected" },
  { value: "security_advisory", label: "Advisories" },
  { value: "threat_intel", label: "Threat Intel" },
  { value: "package_update", label: "Package Updates" },
  { value: "newsletter", label: "Newsletters" },
  { value: "promotional", label: "Promotional" },
  { value: "spam", label: "Spam" },
  { value: "other", label: "Other" },
];

export function EmailDashboard({ initialEmails, initialTotal }: EmailDashboardProps) {
  const [emails, setEmails] = useState<MonitoredEmail[]>(initialEmails);
  const [total, setTotal] = useState(initialTotal);
  const [selectedEmail, setSelectedEmail] = useState<MonitoredEmail | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshResult, setRefreshResult] = useState<{ type: "success" | "error"; message: string } | null>(null);
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [isLoading, setIsLoading] = useState(false);

  // Fetch emails with filter
  const fetchEmails = useCallback(async (category: string) => {
    setIsLoading(true);
    try {
      const params = new URLSearchParams();
      if (category && category !== "all") {
        params.set("category", category);
      }
      
      const response = await fetch(`/api/emails?${params.toString()}`);
      if (response.ok) {
        const data = await response.json();
        setEmails(data.emails);
        setTotal(data.total);
      }
    } catch (error) {
      console.error("Error fetching emails:", error);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Handle category filter change
  const handleCategoryChange = (category: string) => {
    setCategoryFilter(category);
    setSelectedEmail(null);
    fetchEmails(category);
  };

  // Handle refresh - fetch new emails from AgentMail
  const handleRefresh = async () => {
    setIsRefreshing(true);
    setRefreshResult(null);
    
    try {
      const response = await fetch("/api/emails/refresh", {
        method: "POST",
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setRefreshResult({
          type: "success",
          message: data.imported > 0 
            ? `Imported ${data.imported} new email${data.imported > 1 ? "s" : ""}`
            : "No new emails found",
        });
        
        // Refresh the list if new emails were imported
        if (data.imported > 0) {
          fetchEmails(categoryFilter);
        }
      } else {
        setRefreshResult({
          type: "error",
          message: data.error || "Failed to refresh emails",
        });
      }
    } catch (error) {
      setRefreshResult({
        type: "error",
        message: "Network error while refreshing",
      });
    } finally {
      setIsRefreshing(false);
      
      // Clear result after 5 seconds
      setTimeout(() => {
        setRefreshResult(null);
      }, 5000);
    }
  };

  // Handle email selection
  const handleSelectEmail = async (email: MonitoredEmail) => {
    setSelectedEmail(email);
    
    // Mark as read if not already
    if (!email.read) {
      try {
        const response = await fetch(`/api/emails/${email._id}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ read: true }),
        });
        
        if (response.ok) {
          // Update local state
          setEmails((prev) =>
            prev.map((e) =>
              e._id === email._id ? { ...e, read: true } : e
            )
          );
          setSelectedEmail({ ...email, read: true });
        }
      } catch (error) {
        console.error("Error marking email as read:", error);
      }
    }
  };

  // Handle star toggle
  const handleToggleStar = async (email: MonitoredEmail) => {
    const newStarred = !email.starred;
    
    try {
      const response = await fetch(`/api/emails/${email._id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ starred: newStarred }),
      });
      
      if (response.ok) {
        // Update local state
        setEmails((prev) =>
          prev.map((e) =>
            e._id === email._id ? { ...e, starred: newStarred } : e
          )
        );
        if (selectedEmail?._id === email._id) {
          setSelectedEmail({ ...email, starred: newStarred });
        }
      }
    } catch (error) {
      console.error("Error toggling star:", error);
    }
  };

  // Calculate unread count
  const unreadCount = emails.filter((e) => !e.read).length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-[#1F2937]">Email Monitor</h1>
          <p className="text-sm text-[#6B7280] mt-1">
            {total} email{total !== 1 ? "s" : ""} tracked
            {unreadCount > 0 && (
              <span className="ml-2 text-[#3B82F6]">
                ({unreadCount} unread)
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Refresh result toast */}
          {refreshResult && (
            <div className={cn(
              "flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all",
              refreshResult.type === "success" 
                ? "bg-[#ECFDF5] text-[#059669]"
                : "bg-[#FEF2F2] text-[#DC2626]"
            )}>
              {refreshResult.type === "success" ? (
                <CheckCircle className="h-4 w-4" />
              ) : (
                <AlertCircle className="h-4 w-4" />
              )}
              {refreshResult.message}
            </div>
          )}

          {/* Category Filter */}
          <div className="relative">
            <select
              value={categoryFilter}
              onChange={(e) => handleCategoryChange(e.target.value)}
              className="appearance-none bg-white border border-[#D1D5DB] rounded-lg px-3 py-2 pr-8 text-sm text-[#374151] focus:outline-none focus:ring-2 focus:ring-[#059669] focus:border-transparent"
            >
              {categoryFilters.map((filter) => (
                <option key={filter.value} value={filter.value}>
                  {filter.label}
                </option>
              ))}
            </select>
            <Filter className="absolute right-2 top-1/2 -translate-y-1/2 h-4 w-4 text-[#6B7280] pointer-events-none" />
          </div>

          {/* Refresh Button */}
          <button
            onClick={handleRefresh}
            disabled={isRefreshing}
            className={cn(
              "flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors",
              isRefreshing
                ? "bg-[#F3F4F6] text-[#9CA3AF] cursor-not-allowed"
                : "bg-[#059669] text-white hover:bg-[#047857]"
            )}
          >
            {isRefreshing ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Checking...
              </>
            ) : (
              <>
                <RefreshCw className="h-4 w-4" />
                Refresh
              </>
            )}
          </button>
        </div>
      </div>

      {/* Split Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-[400px_1fr] gap-4 h-[calc(100vh-220px)]">
        {/* Email List (Left) */}
        <div className="overflow-y-auto">
          {isLoading ? (
            <EmailTableSkeleton rows={8} />
          ) : (
            <EmailTable
              emails={emails}
              selectedId={selectedEmail?._id || null}
              onSelect={handleSelectEmail}
            />
          )}
        </div>

        {/* Email Preview (Right) */}
        <div className="hidden lg:block overflow-hidden">
          <EmailPreview
            email={selectedEmail}
            onToggleStar={handleToggleStar}
            className="h-full"
          />
        </div>

        {/* Mobile Preview Modal */}
        {selectedEmail && (
          <div className="fixed inset-0 z-50 lg:hidden bg-black/50">
            <div className="absolute inset-4 bg-white rounded-xl overflow-hidden">
              <EmailPreview
                email={selectedEmail}
                onClose={() => setSelectedEmail(null)}
                onToggleStar={handleToggleStar}
                className="h-full"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
