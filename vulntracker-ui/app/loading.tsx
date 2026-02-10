import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { CveTableSkeleton } from "@/components/cve-table";

export default function Loading() {
  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-semibold text-slate-900">CVE Database</h1>
        <p className="text-slate-600 mt-1">
          Browse the latest Common Vulnerabilities and Exposures
        </p>
      </div>

      {/* Controls Bar Skeleton */}
      <div className="flex items-center justify-between">
        <Skeleton className="h-5 w-64" />
        <Skeleton className="h-10 w-[200px]" />
      </div>

      {/* Table Skeleton */}
      <Card>
        <CardContent className="p-0">
          <CveTableSkeleton rows={20} />
        </CardContent>
      </Card>

      {/* Pagination Skeleton */}
      <div className="flex items-center justify-between pt-2">
        <Skeleton className="h-5 w-64 hidden sm:block" />
        <div className="flex gap-1 mx-auto sm:mx-0">
          {Array.from({ length: 7 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-8" />
          ))}
        </div>
      </div>
    </div>
  );
}
