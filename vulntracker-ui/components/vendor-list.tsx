"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { VendorCard } from "@/components/vendor-card";
import { getVendors } from "@/lib/api";
import type { Vendor, PaginatedResponse } from "@/lib/types";
import { Loader2 } from "lucide-react";

interface VendorListProps {
  initialData: PaginatedResponse<Vendor>;
}

export function VendorList({ initialData }: VendorListProps) {
  const [vendors, setVendors] = useState<Vendor[]>(initialData.results);
  const [nextPage, setNextPage] = useState<number | null>(
    initialData.next ? 2 : null
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadMore = async () => {
    if (!nextPage || loading) return;

    setLoading(true);
    setError(null);

    try {
      const data = await getVendors(nextPage);
      setVendors((prev) => [...prev, ...data.results]);
      setNextPage(data.next ? nextPage + 1 : null);
    } catch (err) {
      setError("Failed to load more vendors. Please try again.");
      console.error("Error loading vendors:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Vendor Cards */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {vendors.map((vendor) => (
          <VendorCard key={vendor.id} vendor={vendor} />
        ))}
      </div>

      {/* Error message */}
      {error && (
        <div className="text-center py-4">
          <p className="text-red-600 text-sm">{error}</p>
        </div>
      )}

      {/* Load More Button */}
      {nextPage && (
        <div className="flex justify-center pt-4">
          <Button
            variant="outline"
            onClick={loadMore}
            disabled={loading}
            className="min-w-[140px]"
          >
            {loading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Loading...
              </>
            ) : (
              "Load More"
            )}
          </Button>
        </div>
      )}

      {/* End of list indicator */}
      {!nextPage && vendors.length > 0 && (
        <p className="text-center text-sm text-slate-500 py-4">
          Showing all {vendors.length} vendors
        </p>
      )}
    </div>
  );
}

// Loading skeleton for vendor list
export function VendorListSkeleton({ count = 9 }: { count?: number }) {
  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="border rounded-lg p-4">
          <div className="flex items-center gap-3">
            <Skeleton className="h-10 w-10 rounded-lg" />
            <div className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-3 w-24" />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
