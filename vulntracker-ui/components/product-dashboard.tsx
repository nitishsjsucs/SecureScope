"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { ProductTable, ProductTableSkeleton } from "@/components/product-table";
import { Pagination, PageInfo } from "@/components/pagination";
import type { UserProduct, PaginatedResponse } from "@/lib/types";

interface ProductDashboardProps {
  initialData: PaginatedResponse<UserProduct>;
  initialPage: number;
}

const PAGE_SIZE = 20;

export function ProductDashboard({
  initialData,
  initialPage,
}: ProductDashboardProps) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const [data, setData] = useState(initialData);
  const [currentPage, setCurrentPage] = useState(initialPage);
  const [isLoading, setIsLoading] = useState(false);

  const totalPages = Math.ceil(data.count / PAGE_SIZE);

  // Fetch products for a specific page
  const fetchProducts = async (page: number) => {
    setIsLoading(true);

    try {
      const res = await fetch(`/api/products?page=${page}`);
      if (res.ok) {
        const newData = await res.json();
        setData(newData);
        setCurrentPage(page);

        // Update URL without full page reload
        const params = new URLSearchParams();
        if (page > 1) params.set("page", page.toString());

        const newUrl = params.toString() ? `?${params.toString()}` : "/products";
        startTransition(() => {
          router.push(newUrl, { scroll: false });
        });
      }
    } catch (error) {
      console.error("Error fetching products:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePageChange = (page: number) => {
    fetchProducts(page);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  return (
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex items-center justify-between">
        <PageInfo
          currentPage={currentPage}
          totalPages={totalPages}
          totalItems={data.count}
          pageSize={PAGE_SIZE}
        />
      </div>

      {/* Table */}
      {isLoading ? (
        <ProductTableSkeleton rows={PAGE_SIZE} />
      ) : (
        <ProductTable products={data.results} />
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2">
          <PageInfo
            currentPage={currentPage}
            totalPages={totalPages}
            totalItems={data.count}
            pageSize={PAGE_SIZE}
            className="hidden sm:block"
          />
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
            className="mx-auto sm:mx-0"
          />
        </div>
      )}
    </div>
  );
}
