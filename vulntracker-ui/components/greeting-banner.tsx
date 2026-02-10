import { unstable_cache } from "next/cache";
import { getCvesCollection, getProductsCollection } from "@/lib/mongodb";
import { GreetingMessage } from "./greeting-message";

export interface DashboardStats {
  total_cves: number;
  total_products: number;
  tracked_dependencies: number;
  cves_affecting_products: number;
  critical_affecting: number;
  high_affecting: number;
  medium_affecting: number;
  low_affecting: number;
}

// Cache stats for 60 seconds
const getCachedStats = unstable_cache(
  async (): Promise<DashboardStats> => {
    const [cvesCollection, productsCollection] = await Promise.all([
      getCvesCollection(),
      getProductsCollection(),
    ]);

    const [totalCves, totalProducts, productStats] = await Promise.all([
      cvesCollection.countDocuments({}),
      productsCollection.countDocuments({}),
      productsCollection
        .aggregate([
          {
            $group: {
              _id: null,
              total_critical: { $sum: "$critical_cves" },
              total_high: { $sum: "$high_cves" },
              total_medium: { $sum: "$medium_cves" },
              total_low: { $sum: "$low_cves" },
              tracked_deps: { $sum: "$tracked_dependencies" },
            },
          },
        ])
        .toArray(),
    ]);

    const stats = productStats[0] || {
      total_critical: 0,
      total_high: 0,
      total_medium: 0,
      total_low: 0,
      tracked_deps: 0,
    };

    const affectingProducts =
      stats.total_critical + stats.total_high + stats.total_medium + stats.total_low;

    return {
      total_cves: totalCves,
      total_products: totalProducts,
      tracked_dependencies: stats.tracked_deps,
      cves_affecting_products: affectingProducts,
      critical_affecting: stats.total_critical,
      high_affecting: stats.total_high,
      medium_affecting: stats.total_medium,
      low_affecting: stats.total_low,
    };
  },
  ["dashboard-stats-banner"],
  { revalidate: 60, tags: ["stats"] }
);

export async function GreetingBanner() {
  let stats: DashboardStats | null = null;
  
  try {
    stats = await getCachedStats();
  } catch (error) {
    console.error("Failed to fetch stats:", error);
  }

  return <GreetingMessage stats={stats} />;
}
