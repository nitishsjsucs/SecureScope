import Link from "next/link";
import { Plus, Package, AlertCircle } from "lucide-react";
import { ProductDashboard } from "@/components/product-dashboard";
import type { UserProduct, PaginatedResponse } from "@/lib/types";

export const dynamic = "force-dynamic";

interface ProductsPageProps {
  searchParams: Promise<{ page?: string }>;
}

async function getProducts(page: number): Promise<PaginatedResponse<UserProduct>> {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";
  const res = await fetch(`${baseUrl}/api/products?page=${page}`, {
    cache: "no-store",
  });

  if (!res.ok) {
    return { results: [], count: 0, next: null, previous: null };
  }

  return res.json();
}

export default async function ProductsPage({ searchParams }: ProductsPageProps) {
  const params = await searchParams;
  const page = Math.max(1, parseInt(params.page || "1", 10) || 1);

  try {
    const initialData = await getProducts(page);

    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-[#1F2937]">Products</h1>
            <p className="text-[#4B5563] text-sm mt-0.5">
              Track vulnerabilities across your GitHub repositories
            </p>
          </div>
          <Link
            href="/products/new"
            className="inline-flex items-center gap-2 px-4 py-2.5 bg-[#059669] hover:bg-[#047857] text-white font-medium rounded-lg transition-colors"
          >
            <Plus className="h-4 w-4" />
            Add Product
          </Link>
        </div>

        {/* Dashboard or Empty State */}
        {initialData.count > 0 ? (
          <ProductDashboard initialData={initialData} initialPage={page} />
        ) : (
          <EmptyState />
        )}
      </div>
    );
  } catch (error) {
    console.error("Error fetching products:", error);

    return (
      <div className="flex flex-col items-center justify-center py-16 space-y-4">
        <AlertCircle className="h-12 w-12 text-red-500" />
        <h2 className="text-xl font-semibold text-slate-900">
          Failed to load products
        </h2>
        <p className="text-slate-600 text-center max-w-md">
          Unable to connect to the database. Please try again.
        </p>
      </div>
    );
  }
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-16 h-16 rounded-2xl bg-[#ECFDF5] flex items-center justify-center mb-4">
        <Package className="h-8 w-8 text-[#059669]" />
      </div>
      <h3 className="text-lg font-semibold text-[#1F2937] mb-2">No products yet</h3>
      <p className="text-[#4B5563] mb-6 max-w-sm text-sm">
        Add your first GitHub repository to start tracking dependencies and vulnerabilities.
      </p>
      <Link
        href="/products/new"
        className="inline-flex items-center gap-2 px-4 py-2.5 bg-[#059669] hover:bg-[#047857] text-white font-medium rounded-lg transition-colors"
      >
        <Plus className="h-4 w-4" />
        Add Your First Product
      </Link>
    </div>
  );
}
