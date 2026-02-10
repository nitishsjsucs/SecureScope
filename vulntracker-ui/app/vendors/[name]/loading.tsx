import { Skeleton } from "@/components/ui/skeleton";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { CveListSkeleton } from "@/components/cve-list";

export default function Loading() {
  return (
    <div className="space-y-8">
      {/* Back link skeleton */}
      <Skeleton className="h-5 w-32" />

      {/* Header skeleton */}
      <div className="space-y-4">
        <div className="flex items-center gap-4">
          <Skeleton className="h-14 w-14 rounded-xl" />
          <div className="space-y-2">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-5 w-32" />
          </div>
        </div>
        <Skeleton className="h-5 w-40" />
      </div>

      {/* Products skeleton */}
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32" />
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {[1, 2, 3, 4, 5].map((i) => (
              <Skeleton key={i} className="h-6 w-20" />
            ))}
          </div>
        </CardContent>
      </Card>

      {/* CVEs skeleton */}
      <div>
        <Skeleton className="h-6 w-40 mb-4" />
        <CveListSkeleton count={5} />
      </div>
    </div>
  );
}
