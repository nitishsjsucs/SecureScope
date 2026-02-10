import { NextRequest, NextResponse } from "next/server";
import { unstable_cache } from "next/cache";
import { getCvesCollection } from "@/lib/mongodb";

const PRODUCT_SEPARATOR = "$PRODUCT$";
const CACHE_TTL = 300; // 5 minutes

interface RouteParams {
  params: Promise<{ name: string }>;
}

// Factory function to create cached vendor detail fetcher
function createCachedVendorFetcher(vendorName: string) {
  return unstable_cache(
    async () => {
      const collection = await getCvesCollection();

      // Find CVEs containing this vendor
      const pipeline = [
        {
          $match: {
            vendors: { $regex: `^${vendorName}($|\\${PRODUCT_SEPARATOR})` }
          }
        },
        {
          $facet: {
            // Count total CVEs
            cveCount: [{ $count: "count" }],
            // Get unique products for this vendor
            products: [
              { $unwind: "$vendors" },
              {
                $match: {
                  vendors: { $regex: `^${vendorName}\\${PRODUCT_SEPARATOR}` }
                }
              },
              {
                $project: {
                  product: {
                    $arrayElemAt: [{ $split: ["$vendors", PRODUCT_SEPARATOR] }, 1]
                  }
                }
              },
              {
                $group: {
                  _id: "$product"
                }
              },
              { $sort: { _id: 1 } }
            ]
          }
        }
      ];

      const [result] = await collection.aggregate(pipeline).toArray();
      const cveCount = result.cveCount[0]?.count || 0;
      const products = result.products.map((p: { _id: string }) => p._id);

      return { cveCount, products };
    },
    [`vendor-detail-${vendorName}`],
    { revalidate: CACHE_TTL, tags: ["vendors", `vendor-${vendorName}`] }
  );
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { name } = await params;
    const vendorName = decodeURIComponent(name);
    
    // Get cached vendor data
    const getCachedVendorDetail = createCachedVendorFetcher(vendorName);
    const { cveCount, products } = await getCachedVendorDetail();

    if (cveCount === 0) {
      return NextResponse.json(
        { error: "Vendor not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      id: vendorName,
      name: vendorName,
      cve_count: cveCount,
      products: products,
      created_at: null,
      updated_at: null,
    });
  } catch (error) {
    console.error("Error fetching vendor:", error);
    return NextResponse.json(
      { error: "Failed to fetch vendor" },
      { status: 500 }
    );
  }
}
