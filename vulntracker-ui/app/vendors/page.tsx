import { getVendors } from "@/lib/api";
import { VendorList } from "@/components/vendor-list";
import { AlertCircle } from "lucide-react";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Vendors - VulnTracker",
  description: "Browse vendors with known vulnerabilities",
};

export default async function VendorsPage() {
  try {
    const initialData = await getVendors(1);

    return (
      <div className="space-y-6">
        {/* Page Header */}
        <div>
          <h1 className="text-2xl font-semibold text-slate-900">Vendors</h1>
          <p className="text-slate-600 mt-1">
            Browse vendors with known vulnerabilities
          </p>
        </div>

        {/* Total count */}
        <div className="text-sm text-slate-500">
          {initialData.count.toLocaleString()} vendors found
        </div>

        {/* Vendor List */}
        <VendorList initialData={initialData} />
      </div>
    );
  } catch (error) {
    console.error("Error fetching vendors:", error);

    return (
      <div className="flex flex-col items-center justify-center py-16 space-y-4">
        <AlertCircle className="h-12 w-12 text-red-500" />
        <h2 className="text-xl font-semibold text-slate-900">
          Failed to load vendors
        </h2>
        <p className="text-slate-600 text-center max-w-md">
          Unable to connect to the database. Please check your MongoDB connection
          and try again.
        </p>
      </div>
    );
  }
}
