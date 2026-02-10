import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { humanize, formatDate } from "@/lib/utils";
import type { Vendor } from "@/lib/types";
import { Building2, ChevronRight } from "lucide-react";

interface VendorCardProps {
  vendor: Vendor;
}

export function VendorCard({ vendor }: VendorCardProps) {
  return (
    <Link href={`/vendors/${encodeURIComponent(vendor.name)}`}>
      <Card className="transition-all hover:shadow-md hover:border-slate-300 cursor-pointer">
        <CardContent className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-100">
                <Building2 className="h-5 w-5 text-slate-600" />
              </div>
              <div>
                <h3 className="font-medium text-slate-900">
                  {humanize(vendor.name)}
                </h3>
                <p className="text-xs text-slate-500">
                  Updated {formatDate(vendor.updated_at)}
                </p>
              </div>
            </div>
            <ChevronRight className="h-5 w-5 text-slate-400" />
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
