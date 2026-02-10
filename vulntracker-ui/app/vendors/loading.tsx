import { VendorListSkeleton } from "@/components/vendor-list";

export default function Loading() {
  return (
    <div className="space-y-6">
      {/* Page Header skeleton */}
      <div>
        <div className="h-8 w-32 bg-slate-200 rounded animate-pulse" />
        <div className="h-5 w-64 bg-slate-200 rounded animate-pulse mt-2" />
      </div>

      {/* Count skeleton */}
      <div className="h-4 w-32 bg-slate-200 rounded animate-pulse" />

      {/* Vendor List skeleton */}
      <VendorListSkeleton count={9} />
    </div>
  );
}
