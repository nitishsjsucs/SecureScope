import { notFound } from "next/navigation";
import Link from "next/link";
import { getVendor, getVendorCves, getVendorProducts } from "@/lib/api";
import { VendorCveList } from "@/components/vendor-cve-list";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { humanize, formatDate } from "@/lib/utils";
import {
  Building2,
  Package,
  AlertTriangle,
  Calendar,
  ArrowLeft,
} from "lucide-react";

interface PageProps {
  params: Promise<{ name: string }>;
}

export async function generateMetadata({ params }: PageProps) {
  const { name } = await params;
  const decodedName = decodeURIComponent(name);
  return {
    title: `${humanize(decodedName)} - VulnTracker`,
    description: `CVEs affecting ${humanize(decodedName)}`,
  };
}

export default async function VendorDetailPage({ params }: PageProps) {
  const { name } = await params;
  const decodedName = decodeURIComponent(name);

  try {
    // Fetch vendor info, CVEs, and products in parallel
    const [vendor, cvesData, productsData] = await Promise.all([
      getVendor(decodedName),
      getVendorCves(decodedName, 1),
      getVendorProducts(decodedName, 1),
    ]);

    return (
      <div className="space-y-8">
        {/* Back link */}
        <Link
          href="/vendors"
          className="inline-flex items-center text-sm text-slate-500 hover:text-slate-700 transition-colors"
        >
          <ArrowLeft className="h-4 w-4 mr-1" />
          Back to Vendors
        </Link>

        {/* Header */}
        <div className="space-y-4">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-slate-100">
              <Building2 className="h-8 w-8 text-slate-600" />
            </div>
            <div>
              <h1 className="text-2xl font-semibold text-slate-900">
                {humanize(vendor.name)}
              </h1>
              <p className="text-slate-500 text-sm">
                {cvesData.count.toLocaleString()} vulnerabilities
              </p>
            </div>
          </div>

          {/* Date info */}
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <Calendar className="h-4 w-4" />
            <span>Updated {formatDate(vendor.updated_at)}</span>
          </div>
        </div>

        <Separator />

        {/* Products */}
        {productsData.count > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Package className="h-5 w-5 text-slate-600" />
                Products ({productsData.count})
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {productsData.results.map((product) => (
                  <Badge
                    key={product.id}
                    variant="secondary"
                    className="font-normal"
                  >
                    {humanize(product.name)}
                  </Badge>
                ))}
                {productsData.count > productsData.results.length && (
                  <Badge variant="outline" className="text-slate-500">
                    +{productsData.count - productsData.results.length} more
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* CVEs */}
        <section>
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="h-5 w-5 text-slate-600" />
            <h2 className="text-lg font-semibold text-slate-900">
              Vulnerabilities ({cvesData.count.toLocaleString()})
            </h2>
          </div>
          <VendorCveList vendorName={decodedName} initialData={cvesData} />
        </section>
      </div>
    );
  } catch (error) {
    console.error("Error fetching vendor:", error);
    notFound();
  }
}
