"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Shield, Search, Bell, X, ExternalLink, Package, Building2, AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { useState, useRef, useEffect, useCallback } from "react";

const navLinks = [
  { href: "/", label: "Explore" },
  { href: "/products", label: "Products" },
  { href: "/emails", label: "News" },
  { href: "/reports", label: "Reports" },
  { href: "/chat", label: "Chat" },
];

// Mock notifications data
const notifications = [
  {
    id: 1,
    type: "critical",
    title: "CVE-2026-1234",
    message: "Critical vulnerability in OpenSSL affects your product",
    time: "2 min ago",
    read: false,
  },
  {
    id: 2,
    type: "high",
    title: "CVE-2026-5678",
    message: "High severity issue found in express.js",
    time: "1 hour ago",
    read: false,
  },
  {
    id: 3,
    type: "medium",
    title: "New CVEs published",
    message: "12 new CVEs added matching your watchlist",
    time: "3 hours ago",
    read: true,
  },
  {
    id: 4,
    type: "info",
    title: "Analysis complete",
    message: "opencve/opencve analysis finished",
    time: "1 day ago",
    read: true,
  },
];

function getNotificationDot(type: string) {
  switch (type) {
    case "critical":
      return "bg-[#EF4444]";
    case "high":
      return "bg-[#F97316]";
    case "medium":
      return "bg-[#FEF08A] border border-[#D1D5DB]";
    default:
      return "bg-[#10B981]";
  }
}

interface SearchResult {
  type: "cve" | "product" | "vendor";
  id: string;
  title: string;
  subtitle: string;
  score?: number;
  severity?: string;
  url: string;
}

function getSeverityColor(severity?: string) {
  switch (severity) {
    case "Critical":
      return "bg-[#EF4444] text-white";
    case "High":
      return "bg-[#F97316] text-white";
    case "Medium":
      return "bg-[#FEF08A] text-[#1F2937]";
    case "Low":
      return "bg-[#10B981] text-white";
    default:
      return "bg-[#E5E7EB] text-[#4B5563]";
  }
}

function getTypeIcon(type: "cve" | "product" | "vendor") {
  switch (type) {
    case "cve":
      return <AlertTriangle className="h-4 w-4" />;
    case "product":
      return <Package className="h-4 w-4" />;
    case "vendor":
      return <Building2 className="h-4 w-4" />;
  }
}

function getTypeLabel(type: "cve" | "product" | "vendor") {
  switch (type) {
    case "cve":
      return "CVE";
    case "product":
      return "Product";
    case "vendor":
      return "Vendor";
  }
}

export function NavHeader() {
  const pathname = usePathname();
  const router = useRouter();
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [showResults, setShowResults] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const notificationsRef = useRef<HTMLDivElement>(null);

  // Debounced search
  const searchTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const performSearch = useCallback(async (query: string) => {
    if (query.length < 2) {
      setSearchResults([]);
      setShowResults(false);
      return;
    }

    setIsSearching(true);
    try {
      const response = await fetch(`/api/search?q=${encodeURIComponent(query)}`);
      if (response.ok) {
        const data = await response.json();
        setSearchResults(data.results || []);
        setShowResults(true);
        setSelectedIndex(-1);
      }
    } catch (error) {
      console.error("Search error:", error);
    } finally {
      setIsSearching(false);
    }
  }, []);

  // Handle search input change with debounce
  const handleSearchChange = (value: string) => {
    setSearchQuery(value);
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    if (value.length < 2) {
      setSearchResults([]);
      setShowResults(false);
      return;
    }

    searchTimeoutRef.current = setTimeout(() => {
      performSearch(value);
    }, 300);
  };

  // Navigate to selected result
  const navigateToResult = (result: SearchResult) => {
    setSearchOpen(false);
    setSearchQuery("");
    setSearchResults([]);
    setShowResults(false);
    router.push(result.url);
  };

  // Focus input when search opens
  useEffect(() => {
    if (searchOpen && searchInputRef.current) {
      searchInputRef.current.focus();
    }
  }, [searchOpen]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (
        notificationsRef.current &&
        !notificationsRef.current.contains(event.target as Node)
      ) {
        setNotificationsOpen(false);
      }
      if (
        searchContainerRef.current &&
        !searchContainerRef.current.contains(event.target as Node)
      ) {
        setShowResults(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  // Keyboard navigation
  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setSearchOpen(false);
        setShowResults(false);
        setNotificationsOpen(false);
        return;
      }

      if (!showResults || searchResults.length === 0) return;

      if (event.key === "ArrowDown") {
        event.preventDefault();
        setSelectedIndex((prev) =>
          prev < searchResults.length - 1 ? prev + 1 : prev
        );
      } else if (event.key === "ArrowUp") {
        event.preventDefault();
        setSelectedIndex((prev) => (prev > 0 ? prev - 1 : -1));
      } else if (event.key === "Enter" && selectedIndex >= 0) {
        event.preventDefault();
        navigateToResult(searchResults[selectedIndex]);
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [showResults, searchResults, selectedIndex]);

  // Cleanup timeout on unmount
  useEffect(() => {
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current);
      }
    };
  }, []);

  const unreadCount = notifications.filter((n) => !n.read).length;

  // Group results by type
  const groupedResults = searchResults.reduce(
    (acc, result) => {
      acc[result.type].push(result);
      return acc;
    },
    { cve: [], product: [], vendor: [] } as Record<string, SearchResult[]>
  );

  // Flatten for keyboard navigation
  const flatResults = [...groupedResults.cve, ...groupedResults.product, ...groupedResults.vendor];

  return (
    <header className="sticky top-0 z-50 w-full bg-white/80 backdrop-blur-xl border-b border-[#D1D5DB]">
      <div className="container mx-auto flex h-16 max-w-7xl items-center justify-between px-4">
        {/* Left: Logo + Nav */}
        <div className="flex items-center">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 mr-8 group">
            <div className="relative">
              {/* Logo mark - stylized shield with gradient */}
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-[#059669] via-[#10B981] to-[#047857] flex items-center justify-center shadow-sm group-hover:shadow-md transition-shadow">
                <Shield className="h-5 w-5 text-white" strokeWidth={2} />
              </div>
              {/* Subtle glow effect */}
              <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-[#059669] to-[#047857] opacity-0 group-hover:opacity-20 blur-md transition-opacity" />
            </div>
            <span className="font-display font-semibold text-xl tracking-tight text-[#1F2937]">
              SexySecure
            </span>
          </Link>

          {/* Navigation */}
          <nav className="flex items-center gap-1">
            {navLinks.map((link) => {
              const isActive =
                link.href === "/"
                  ? pathname === "/" || pathname.startsWith("/cve")
                  : pathname.startsWith(link.href);

              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    "px-4 py-2 text-sm font-medium transition-colors rounded-lg",
                    isActive
                      ? "text-[#1F2937] bg-[#F9FAFB]"
                      : "text-[#4B5563] hover:text-[#1F2937] hover:bg-[#F9FAFB]"
                  )}
                >
                  {link.label}
                  {isActive && (
                    <span className="block h-0.5 bg-[#059669] mt-1 -mb-1 rounded-full" />
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right: Actions */}
        <div className="flex items-center gap-2">
          {/* Expanding Search */}
          <div className="relative" ref={searchContainerRef}>
            <div
              className={cn(
                "flex items-center overflow-hidden transition-all duration-300 ease-out",
                searchOpen ? "w-80" : "w-10"
              )}
            >
              {searchOpen ? (
                <div className="flex items-center w-full bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] pr-1">
                  {isSearching ? (
                    <Loader2 className="h-4 w-4 text-[#6B7280] ml-3 flex-shrink-0 animate-spin" />
                  ) : (
                    <Search className="h-4 w-4 text-[#6B7280] ml-3 flex-shrink-0" />
                  )}
                  <input
                    ref={searchInputRef}
                    type="text"
                    value={searchQuery}
                    onChange={(e) => handleSearchChange(e.target.value)}
                    placeholder="Search CVEs, products, vendors..."
                    className="w-full px-2 py-2 text-sm bg-transparent outline-none text-[#1F2937] placeholder:text-[#6B7280]"
                    onFocus={() => {
                      if (searchResults.length > 0) {
                        setShowResults(true);
                      }
                    }}
                  />
                  <button
                    onClick={() => {
                      setSearchOpen(false);
                      setSearchQuery("");
                      setSearchResults([]);
                      setShowResults(false);
                    }}
                    className="p-1.5 rounded-md text-[#6B7280] hover:text-[#1F2937] hover:bg-[#E5E7EB] transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setSearchOpen(true)}
                  className="p-2.5 rounded-lg text-[#4B5563] hover:text-[#1F2937] hover:bg-[#F9FAFB] transition-colors"
                >
                  <Search className="h-5 w-5" />
                </button>
              )}
            </div>

            {/* Search Results Dropdown */}
            {showResults && searchResults.length > 0 && (
              <div className="absolute right-0 top-full mt-2 w-96 bg-white rounded-xl shadow-lg border border-[#D1D5DB] overflow-hidden z-50">
                {/* CVE Results */}
                {groupedResults.cve.length > 0 && (
                  <div>
                    <div className="px-3 py-2 bg-[#F9FAFB] border-b border-[#E5E7EB]">
                      <span className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide">
                        CVEs
                      </span>
                    </div>
                    {groupedResults.cve.map((result) => {
                      const flatIndex = flatResults.indexOf(result);
                      return (
                        <button
                          key={result.id}
                          onClick={() => navigateToResult(result)}
                          className={cn(
                            "w-full px-3 py-2.5 flex items-start gap-3 hover:bg-[#F9FAFB] transition-colors text-left border-b border-[#F3F4F6] last:border-0",
                            flatIndex === selectedIndex && "bg-[#F3F4F6]"
                          )}
                        >
                          <div className="w-8 h-8 rounded-lg bg-[#FEF2F2] flex items-center justify-center flex-shrink-0 mt-0.5">
                            <AlertTriangle className="h-4 w-4 text-[#EF4444]" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm text-[#1F2937]">
                                {result.title}
                              </span>
                              {result.severity && (
                                <span
                                  className={cn(
                                    "text-xs px-1.5 py-0.5 rounded font-medium",
                                    getSeverityColor(result.severity)
                                  )}
                                >
                                  {result.severity}
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-[#6B7280] mt-0.5 line-clamp-1">
                              {result.subtitle}
                            </p>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}

                {/* Product Results */}
                {groupedResults.product.length > 0 && (
                  <div>
                    <div className="px-3 py-2 bg-[#F9FAFB] border-b border-[#E5E7EB]">
                      <span className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide">
                        Products
                      </span>
                    </div>
                    {groupedResults.product.map((result) => {
                      const flatIndex = flatResults.indexOf(result);
                      return (
                        <button
                          key={result.id}
                          onClick={() => navigateToResult(result)}
                          className={cn(
                            "w-full px-3 py-2.5 flex items-start gap-3 hover:bg-[#F9FAFB] transition-colors text-left border-b border-[#F3F4F6] last:border-0",
                            flatIndex === selectedIndex && "bg-[#F3F4F6]"
                          )}
                        >
                          <div className="w-8 h-8 rounded-lg bg-[#ECFDF5] flex items-center justify-center flex-shrink-0 mt-0.5">
                            <Package className="h-4 w-4 text-[#059669]" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <span className="font-medium text-sm text-[#1F2937]">
                              {result.title}
                            </span>
                            <p className="text-xs text-[#6B7280] mt-0.5">
                              {result.subtitle}
                            </p>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}

                {/* Vendor Results */}
                {groupedResults.vendor.length > 0 && (
                  <div>
                    <div className="px-3 py-2 bg-[#F9FAFB] border-b border-[#E5E7EB]">
                      <span className="text-xs font-semibold text-[#6B7280] uppercase tracking-wide">
                        Vendors
                      </span>
                    </div>
                    {groupedResults.vendor.map((result) => {
                      const flatIndex = flatResults.indexOf(result);
                      return (
                        <button
                          key={result.id}
                          onClick={() => navigateToResult(result)}
                          className={cn(
                            "w-full px-3 py-2.5 flex items-start gap-3 hover:bg-[#F9FAFB] transition-colors text-left border-b border-[#F3F4F6] last:border-0",
                            flatIndex === selectedIndex && "bg-[#F3F4F6]"
                          )}
                        >
                          <div className="w-8 h-8 rounded-lg bg-[#EFF6FF] flex items-center justify-center flex-shrink-0 mt-0.5">
                            <Building2 className="h-4 w-4 text-[#3B82F6]" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <span className="font-medium text-sm text-[#1F2937]">
                              {result.title}
                            </span>
                            <p className="text-xs text-[#6B7280] mt-0.5">
                              {result.subtitle}
                            </p>
                          </div>
                        </button>
                      );
                    })}
                  </div>
                )}

                {/* Footer */}
                <div className="px-3 py-2 bg-[#F9FAFB] border-t border-[#E5E7EB]">
                  <span className="text-xs text-[#6B7280]">
                    Press <kbd className="px-1.5 py-0.5 bg-white border border-[#D1D5DB] rounded text-[10px] font-mono">↵</kbd> to select, <kbd className="px-1.5 py-0.5 bg-white border border-[#D1D5DB] rounded text-[10px] font-mono">↑↓</kbd> to navigate
                  </span>
                </div>
              </div>
            )}

            {/* No Results */}
            {showResults && searchResults.length === 0 && searchQuery.length >= 2 && !isSearching && (
              <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl shadow-lg border border-[#D1D5DB] overflow-hidden z-50">
                <div className="px-4 py-6 text-center">
                  <Search className="h-8 w-8 text-[#D1D5DB] mx-auto mb-2" />
                  <p className="text-sm text-[#6B7280]">
                    No results for &quot;{searchQuery}&quot;
                  </p>
                </div>
              </div>
            )}
          </div>

          {/* Notifications */}
          <div className="relative" ref={notificationsRef}>
            <button
              onClick={() => setNotificationsOpen(!notificationsOpen)}
              className={cn(
                "p-2.5 rounded-lg text-[#4B5563] hover:text-[#1F2937] hover:bg-[#F9FAFB] transition-colors relative",
                notificationsOpen && "bg-[#F9FAFB] text-[#1F2937]"
              )}
            >
              <Bell className="h-5 w-5" />
              {unreadCount > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-[#EF4444] rounded-full" />
              )}
            </button>

            {/* Notifications Dropdown */}
            {notificationsOpen && (
              <div className="absolute right-0 top-full mt-2 w-80 bg-white rounded-xl shadow-lg border border-[#D1D5DB] overflow-hidden z-50">
                {/* Header */}
                <div className="px-4 py-3 border-b border-[#E5E7EB] flex items-center justify-between">
                  <h3 className="font-semibold text-[#1F2937]">Notifications</h3>
                  {unreadCount > 0 && (
                    <span className="text-xs text-[#6B7280] bg-[#F3F4F6] px-2 py-0.5 rounded-full">
                      {unreadCount} new
                    </span>
                  )}
                </div>

                {/* Notification List */}
                <div className="max-h-80 overflow-y-auto">
                  {notifications.map((notification) => (
                    <div
                      key={notification.id}
                      className={cn(
                        "px-4 py-3 border-b border-[#F3F4F6] hover:bg-[#F9FAFB] cursor-pointer transition-colors",
                        !notification.read && "bg-[#FAFAFA]"
                      )}
                    >
                      <div className="flex gap-3">
                        <div
                          className={cn(
                            "w-2 h-2 rounded-full mt-2 flex-shrink-0",
                            getNotificationDot(notification.type)
                          )}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span
                              className={cn(
                                "text-sm font-medium",
                                notification.read
                                  ? "text-[#4B5563]"
                                  : "text-[#1F2937]"
                              )}
                            >
                              {notification.title}
                            </span>
                          </div>
                          <p className="text-xs text-[#6B7280] mt-0.5 line-clamp-2">
                            {notification.message}
                          </p>
                          <span className="text-xs text-[#9CA3AF] mt-1 block">
                            {notification.time}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>

                {/* Footer */}
                <div className="px-4 py-2.5 border-t border-[#E5E7EB] bg-[#FAFAFA]">
                  <Link
                    href="/notifications"
                    className="text-sm text-[#059669] hover:text-[#047857] font-medium flex items-center justify-center gap-1"
                    onClick={() => setNotificationsOpen(false)}
                  >
                    View all notifications
                    <ExternalLink className="h-3.5 w-3.5" />
                  </Link>
                </div>
              </div>
            )}
          </div>

          {/* User Avatar */}
          <button className="ml-2 w-9 h-9 rounded-full bg-[#F9FAFB] flex items-center justify-center text-[#4B5563] hover:bg-[#D1D5DB] transition-colors">
            <span className="text-sm font-medium">A</span>
          </button>
        </div>
      </div>
    </header>
  );
}
