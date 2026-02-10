"use client";

import Link from "next/link";
import { cn, formatDate } from "@/lib/utils";
import type { UserProduct } from "@/lib/types";
import {
  Github,
  RefreshCw,
  AlertTriangle,
  Shield,
  ChevronRight,
  Package,
} from "lucide-react";

interface ProductTableProps {
  products: UserProduct[];
  className?: string;
}

export function ProductTable({ products, className }: ProductTableProps) {
  return (
    <div
      className={cn(
        "bg-white rounded-xl border border-[#D1D5DB] overflow-hidden",
        className
      )}
    >
      {/* Table Header */}
      <div className="grid grid-cols-[2fr_120px_100px_140px_120px_100px_40px] gap-4 px-6 py-3 bg-[#F9FAFB] border-b border-[#D1D5DB] text-xs font-semibold text-[#4B5563] uppercase tracking-wider">
        <div>Product</div>
        <div className="text-center">Status</div>
        <div className="text-center">Dependencies</div>
        <div className="text-center">CVEs</div>
        <div>Ecosystems</div>
        <div className="text-right">Updated</div>
        <div></div>
      </div>

      {/* Table Body */}
      <div className="divide-y divide-[#E5E7EB]">
        {products.map((product) => (
          <ProductTableRow key={product._id} product={product} />
        ))}
      </div>
    </div>
  );
}

interface ProductTableRowProps {
  product: UserProduct;
}

function ProductTableRow({ product }: ProductTableRowProps) {
  const totalCves =
    product.critical_cves +
    product.high_cves +
    product.medium_cves +
    product.low_cves;
  const isAnalyzing = product.status === "analyzing";
  const hasError = product.status === "error";

  const directDeps =
    product.dependencies?.filter((d) => d.depth === 0).length || 0;
  const transitiveDeps =
    product.dependencies?.filter((d) => d.depth > 0).length || 0;

  // Get ecosystems
  const ecosystems =
    product.dependencies?.reduce(
      (acc, dep) => {
        acc[dep.type] = (acc[dep.type] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>
    ) || {};

  const topEcosystems = Object.entries(ecosystems)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 2);

  // Determine severity accent based on CVE counts
  const getSeverityAccent = () => {
    if (isAnalyzing) return "border-l-blue-400";
    if (hasError) return "border-l-red-400";
    if (product.critical_cves > 0) return "border-l-[#DC2626]";
    if (product.high_cves > 0) return "border-l-[#EA580C]";
    if (product.medium_cves > 0) return "border-l-[#FBBF24]";
    if (product.low_cves > 0) return "border-l-[#059669]";
    return "border-l-[#059669]"; // Clean - green
  };

  return (
    <Link href={`/products/${product._id}`} className="block">
      <div
        className={cn(
          "grid grid-cols-[2fr_120px_100px_140px_120px_100px_40px] gap-4 px-6 py-4 items-center transition-colors cursor-pointer group border-l-4",
          getSeverityAccent(),
          "hover:bg-[#F9FAFB]"
        )}
      >
        {/* Product Name & Repo */}
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-[#F9FAFB] flex items-center justify-center flex-shrink-0 group-hover:bg-[#ECFDF5] transition-colors">
            <Package className="h-4 w-4 text-[#6B7280] group-hover:text-[#059669] transition-colors" />
          </div>
          <div className="min-w-0">
            <span className="font-semibold text-[#1F2937] group-hover:text-[#059669] transition-colors block truncate">
              {product.name}
            </span>
            <span className="text-xs text-[#6B7280] flex items-center gap-1 truncate">
              <Github className="h-3 w-3 flex-shrink-0" />
              {product.github_owner}/{product.github_repo}
            </span>
          </div>
        </div>

        {/* Status */}
        <div className="flex justify-center">
          {isAnalyzing ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-blue-50 text-blue-700">
              <RefreshCw className="h-3 w-3 animate-spin" />
              Analyzing
            </span>
          ) : hasError ? (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-red-50 text-red-700">
              <AlertTriangle className="h-3 w-3" />
              Error
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-emerald-50 text-emerald-700">
              <Shield className="h-3 w-3" />
              Ready
            </span>
          )}
        </div>

        {/* Dependencies */}
        <div className="text-center">
          {isAnalyzing ? (
            <span className="text-sm text-[#6B7280]">-</span>
          ) : (
            <div>
              <span className="font-semibold text-[#1F2937]">
                {product.total_dependencies}
              </span>
              <span className="text-xs text-[#6B7280] block">
                {directDeps}d / {transitiveDeps}t
              </span>
            </div>
          )}
        </div>

        {/* CVEs */}
        <div className="flex justify-center">
          {isAnalyzing || hasError ? (
            <span className="text-sm text-[#6B7280]">-</span>
          ) : totalCves === 0 ? (
            <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-600">
              <Shield className="h-3.5 w-3.5" />
              Clean
            </span>
          ) : (
            <div className="flex items-center gap-1">
              {product.critical_cves > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-[#DC2626] text-white">
                  {product.critical_cves}C
                </span>
              )}
              {product.high_cves > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-orange-500 text-white">
                  {product.high_cves}H
                </span>
              )}
              {product.medium_cves > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-amber-500 text-white">
                  {product.medium_cves}M
                </span>
              )}
              {product.low_cves > 0 && (
                <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-emerald-500 text-white">
                  {product.low_cves}L
                </span>
              )}
            </div>
          )}
        </div>

        {/* Ecosystems */}
        <div className="flex items-center gap-1 flex-wrap">
          {isAnalyzing || hasError ? (
            <span className="text-xs text-[#6B7280]">-</span>
          ) : topEcosystems.length > 0 ? (
            topEcosystems.map(([eco, count]) => (
              <span
                key={eco}
                className="px-1.5 py-0.5 text-[10px] rounded bg-[#F3F4F6] text-[#4B5563]"
              >
                {eco}
              </span>
            ))
          ) : (
            <span className="text-xs text-[#6B7280]">-</span>
          )}
        </div>

        {/* Updated Date */}
        <div className="text-right">
          <span className="text-sm text-[#4B5563]">
            {formatDate(product.updated_at)}
          </span>
        </div>

        {/* Arrow */}
        <div className="flex justify-end">
          <ChevronRight className="h-4 w-4 text-[#9CA3AF] group-hover:text-[#059669] transition-colors" />
        </div>
      </div>
    </Link>
  );
}

// Loading skeleton for table
export function ProductTableSkeleton({ rows = 10 }: { rows?: number }) {
  return (
    <div className="bg-white rounded-xl border border-[#D1D5DB] overflow-hidden">
      {/* Table Header */}
      <div className="grid grid-cols-[2fr_120px_100px_140px_120px_100px_40px] gap-4 px-6 py-3 bg-[#F9FAFB] border-b border-[#D1D5DB] text-xs font-semibold text-[#4B5563] uppercase tracking-wider">
        <div>Product</div>
        <div className="text-center">Status</div>
        <div className="text-center">Dependencies</div>
        <div className="text-center">CVEs</div>
        <div>Ecosystems</div>
        <div className="text-right">Updated</div>
        <div></div>
      </div>

      {/* Skeleton Rows */}
      <div className="divide-y divide-[#E5E7EB]">
        {Array.from({ length: rows }).map((_, i) => (
          <div
            key={i}
            className="grid grid-cols-[2fr_120px_100px_140px_120px_100px_40px] gap-4 px-6 py-4 items-center border-l-4 border-l-[#E5E7EB]"
          >
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 bg-[#E5E7EB] rounded-lg animate-pulse" />
              <div className="space-y-1.5">
                <div className="h-4 w-32 bg-[#E5E7EB] rounded animate-pulse" />
                <div className="h-3 w-24 bg-[#E5E7EB] rounded animate-pulse" />
              </div>
            </div>
            <div className="flex justify-center">
              <div className="h-6 w-20 bg-[#E5E7EB] rounded-full animate-pulse" />
            </div>
            <div className="flex justify-center">
              <div className="h-4 w-12 bg-[#E5E7EB] rounded animate-pulse" />
            </div>
            <div className="flex justify-center gap-1">
              <div className="h-5 w-8 bg-[#E5E7EB] rounded animate-pulse" />
              <div className="h-5 w-8 bg-[#E5E7EB] rounded animate-pulse" />
            </div>
            <div className="flex gap-1">
              <div className="h-5 w-10 bg-[#E5E7EB] rounded animate-pulse" />
            </div>
            <div className="flex justify-end">
              <div className="h-4 w-16 bg-[#E5E7EB] rounded animate-pulse" />
            </div>
            <div />
          </div>
        ))}
      </div>
    </div>
  );
}
