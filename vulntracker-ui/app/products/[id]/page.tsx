import { notFound } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Github,
  Package,
  RefreshCw,
  AlertTriangle,
  ExternalLink,
  Clock,
  Check,
  Shield,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { UserProduct } from "@/lib/types";

interface PageProps {
  params: Promise<{ id: string }>;
}

async function getProduct(id: string): Promise<UserProduct | null> {
  const baseUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";
  const res = await fetch(`${baseUrl}/api/products/${id}`, {
    cache: "no-store",
  });

  if (!res.ok) {
    return null;
  }

  return res.json();
}

export default async function ProductDetailPage({ params }: PageProps) {
  const { id } = await params;
  const product = await getProduct(id);

  if (!product) {
    notFound();
  }

  const totalCves =
    product.critical_cves +
    product.high_cves +
    product.medium_cves +
    product.low_cves;
  const isAnalyzing = product.status === "analyzing";
  const hasError = product.status === "error";

  // Count direct vs transitive dependencies
  const directDeps = product.dependencies.filter(d => d.depth === 0).length;
  const transitiveDeps = product.dependencies.filter(d => d.depth > 0).length;

  // Group dependencies by type
  const groupedDeps = product.dependencies.reduce((acc, dep) => {
    if (!acc[dep.type]) acc[dep.type] = [];
    acc[dep.type].push(dep);
    return acc;
  }, {} as Record<string, typeof product.dependencies>);

  const typeLabels: Record<string, string> = {
    npm: "Node.js (npm)",
    pip: "Python (pip)",
    go: "Go Modules",
    cargo: "Rust (Cargo)",
    gem: "Ruby (Gem)",
    maven: "Java (Maven)",
    gradle: "Java (Gradle)",
    composer: "PHP (Composer)",
    nuget: "C# (NuGet)",
    other: "Other",
  };

  return (
    <div className="space-y-8">
      {/* Back link */}
      <Link
        href="/products"
        className="inline-flex items-center gap-2 text-[#4B5563] hover:text-[#1F2937] transition-colors"
      >
        <ArrowLeft className="h-4 w-4" />
        Back to Products
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl bg-[#F9FAFB] flex items-center justify-center">
            <Package className="h-7 w-7 text-[#1F2937]" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-[#1F2937]">
              {product.name}
            </h1>
            <a
              href={product.github_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-[#4B5563] hover:text-[#059669] transition-colors text-sm"
            >
              <Github className="h-4 w-4" />
              {product.github_owner}/{product.github_repo}
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>

        {/* Status Badge */}
        {isAnalyzing ? (
          <Badge className="bg-[#ECFDF5] text-[#047857] border-0">
            <RefreshCw className="h-3 w-3 mr-1 animate-spin" />
            Analyzing...
          </Badge>
        ) : hasError ? (
          <Badge className="bg-[#FEF0ED] text-[#EB5B3C] border-0">
            <AlertTriangle className="h-3 w-3 mr-1" />
            Error
          </Badge>
        ) : (
          <Badge className="bg-[#ECFDF5] text-[#047857] border-0">
            <Check className="h-3 w-3 mr-1" />
            Analyzed
          </Badge>
        )}
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard
          label="Total Dependencies"
          value={product.total_dependencies}
          color="default"
        />
        <StatCard
          label="Direct"
          value={directDeps}
          color="blue"
        />
        <StatCard
          label="Transitive"
          value={transitiveDeps}
          color="gray"
        />
        <StatCard
          label="Critical CVEs"
          value={product.critical_cves}
          color={product.critical_cves > 0 ? "red" : "default"}
        />
        <StatCard
          label="High CVEs"
          value={product.high_cves}
          color={product.high_cves > 0 ? "orange" : "default"}
        />
      </div>

      {/* CVE Summary */}
      {totalCves > 0 && (
        <Card className="border-[#EB5B3C]/20 bg-[#FEF0ED]/30">
          <CardContent className="p-5">
            <div className="flex items-center gap-3 mb-3">
              <Shield className="h-5 w-5 text-[#EB5B3C]" />
              <h3 className="font-semibold text-[#1F2937]">
                Vulnerability Summary
              </h3>
            </div>
            <div className="flex flex-wrap gap-3">
              {product.critical_cves > 0 && (
                <span className="px-3 py-1.5 text-sm font-medium rounded-lg bg-[#FEF0ED] text-[#EB5B3C]">
                  {product.critical_cves} Critical
                </span>
              )}
              {product.high_cves > 0 && (
                <span className="px-3 py-1.5 text-sm font-medium rounded-lg bg-orange-50 text-orange-600">
                  {product.high_cves} High
                </span>
              )}
              {product.medium_cves > 0 && (
                <span className="px-3 py-1.5 text-sm font-medium rounded-lg bg-amber-50 text-amber-600">
                  {product.medium_cves} Medium
                </span>
              )}
              {product.low_cves > 0 && (
                <span className="px-3 py-1.5 text-sm font-medium rounded-lg bg-[#ECFDF5] text-[#047857]">
                  {product.low_cves} Low
                </span>
              )}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Dependencies */}
      <Card className="border-[#D1D5DB]">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
            <Package className="h-5 w-5 text-[#4B5563]" />
            Dependencies ({product.total_dependencies})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {Object.entries(groupedDeps).map(([type, deps]) => (
            <div key={type}>
              <h4 className="text-sm font-medium text-[#4B5563] mb-3">
                {typeLabels[type] || type} ({deps.length})
              </h4>
              <div className="grid gap-2">
                {deps.map((dep, index) => (
                  <div
                    key={`${dep.name}-${index}`}
                    className={`flex items-center justify-between p-3 rounded-lg ${
                      dep.depth === 0 
                        ? 'bg-[#F9FAFB]' 
                        : dep.depth === 1 
                          ? 'bg-[#FAFAFA] ml-4 border-l-2 border-[#D1D5DB]' 
                          : 'bg-[#FDFDFD] ml-8 border-l-2 border-[#F0F0F0]'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <Package className={`h-4 w-4 ${dep.depth === 0 ? 'text-[#4B5563]' : 'text-[#6B7280]'}`} />
                      <div>
                        <span className={`font-medium ${dep.depth === 0 ? 'text-[#1F2937]' : 'text-[#4B5563]'}`}>
                          {dep.name}
                        </span>
                        {dep.version && (
                          <span className="text-[#6B7280] ml-2 text-sm">
                            v{dep.version}
                          </span>
                        )}
                        {dep.parent && (
                          <span className="text-[#6B7280] ml-2 text-xs">
                            via {dep.parent}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {dep.depth === 0 ? (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-50 text-blue-600">
                          Direct
                        </span>
                      ) : (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-500">
                          L{dep.depth}
                        </span>
                      )}
                      {dep.cve_count && dep.cve_count > 0 && (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-[#FEF0ED] text-[#EB5B3C]">
                          {dep.cve_count} CVEs
                        </span>
                      )}
                      {dep.tracked ? (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-[#ECFDF5] text-[#047857]">
                          <Check className="h-3 w-3 inline mr-0.5" />
                          Tracking
                        </span>
                      ) : (
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-white border border-[#D1D5DB] text-[#6B7280]">
                          Not tracked
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          {product.dependencies.length === 0 && (
            <div className="text-center py-8">
              <Package className="h-12 w-12 text-[#6B7280] mx-auto mb-3" />
              <p className="text-[#4B5563]">No dependencies detected yet</p>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Last analyzed */}
      {product.last_analyzed && (
        <p className="text-sm text-[#6B7280] flex items-center gap-1.5">
          <Clock className="h-4 w-4" />
          Last analyzed: {new Date(product.last_analyzed).toLocaleString()}
        </p>
      )}
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: "default" | "green" | "red" | "orange" | "blue" | "gray";
}) {
  const colorClasses = {
    default: "text-[#1F2937]",
    green: "text-[#059669]",
    red: "text-[#EB5B3C]",
    orange: "text-orange-500",
    blue: "text-blue-600",
    gray: "text-gray-500",
  };

  return (
    <Card className="border-[#D1D5DB]">
      <CardContent className="p-4">
        <p className="text-sm text-[#4B5563] mb-1">{label}</p>
        <p className={`text-2xl font-bold ${colorClasses[color]}`}>{value}</p>
      </CardContent>
    </Card>
  );
}
