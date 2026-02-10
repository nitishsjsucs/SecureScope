import Link from "next/link";
import { cn, humanize, parseVendorString } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";

interface VendorChipProps {
  vendor: string;
  showProduct?: boolean;
  clickable?: boolean;
  className?: string;
}

export function VendorChip({
  vendor,
  showProduct = false,
  clickable = true,
  className,
}: VendorChipProps) {
  const parsed = parseVendorString(vendor);
  const displayName = showProduct && parsed.product
    ? `${humanize(parsed.vendor)} / ${humanize(parsed.product)}`
    : humanize(parsed.vendor);

  const badge = (
    <Badge
      variant="secondary"
      className={cn(
        "font-normal text-slate-600 bg-slate-100 hover:bg-slate-200 transition-colors",
        clickable && "cursor-pointer",
        className
      )}
    >
      {displayName}
    </Badge>
  );

  if (clickable) {
    return (
      <Link href={`/vendors/${encodeURIComponent(parsed.vendor)}`}>
        {badge}
      </Link>
    );
  }

  return badge;
}

interface VendorChipListProps {
  vendors: string[];
  maxDisplay?: number;
  showProducts?: boolean;
  className?: string;
}

export function VendorChipList({
  vendors,
  maxDisplay = 3,
  showProducts = false,
  className,
}: VendorChipListProps) {
  // Get unique vendors (not products)
  const uniqueVendors = Array.from(
    new Set(vendors.map((v) => parseVendorString(v).vendor))
  );

  const displayVendors = uniqueVendors.slice(0, maxDisplay);
  const remaining = uniqueVendors.length - maxDisplay;

  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {displayVendors.map((vendor) => (
        <VendorChip
          key={vendor}
          vendor={vendor}
          showProduct={showProducts}
        />
      ))}
      {remaining > 0 && (
        <Badge variant="outline" className="text-slate-500 font-normal">
          +{remaining} more
        </Badge>
      )}
    </div>
  );
}
