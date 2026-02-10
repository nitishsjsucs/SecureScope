import { getCves, type CveSortOption } from "@/lib/api";
import { CveDashboard } from "@/components/cve-dashboard";
import { GreetingBanner } from "@/components/greeting-banner";
import { AlertCircle } from "lucide-react";

export const dynamic = "force-dynamic";

interface HomePageProps {
  searchParams: Promise<{ page?: string; sort?: string }>;
}

export default async function HomePage({ searchParams }: HomePageProps) {
  const params = await searchParams;
  const page = Math.max(1, parseInt(params.page || "1", 10) || 1);
  const sort = (params.sort as CveSortOption) || "-created_at";

  try {
    const initialData = await getCves(page, sort);

    return (
      <div className="space-y-6">
        {/* Greeting Banner */}
        <GreetingBanner />

        {/* Dashboard */}
        <CveDashboard
          initialData={initialData}
          initialPage={page}
          initialSort={sort}
        />
      </div>
    );
  } catch (error) {
    console.error("Error fetching CVEs:", error);

    return (
      <div className="flex flex-col items-center justify-center py-16 space-y-4">
        <AlertCircle className="h-12 w-12 text-red-500" />
        <h2 className="text-xl font-semibold text-slate-900">
          Failed to load CVEs
        </h2>
        <p className="text-slate-600 text-center max-w-md">
          Unable to connect to the database. Please check your MongoDB connection
          and try again.
        </p>
      </div>
    );
  }
}
