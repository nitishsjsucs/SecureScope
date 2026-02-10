import { NextResponse } from "next/server";
import { unstable_cache } from "next/cache";
import { getCvesCollection, getProductsCollection } from "@/lib/mongodb";

const CACHE_TTL = 60; // 1 minute

// Cache the stats (called frequently for greeting)
const getCachedStats = unstable_cache(
  async () => {
    const [cvesCollection, productsCollection] = await Promise.all([
      getCvesCollection(),
      getProductsCollection(),
    ]);

    // Run all queries in parallel
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
  ["dashboard-stats"],
  { revalidate: CACHE_TTL, tags: ["stats"] }
);

export async function GET() {
  try {
    const stats = await getCachedStats();
    return NextResponse.json(stats);
  } catch (error) {
    console.error("Error fetching stats:", error);
    return NextResponse.json(
      { error: "Failed to fetch stats" },
      { status: 500 }
    );
  }
}
