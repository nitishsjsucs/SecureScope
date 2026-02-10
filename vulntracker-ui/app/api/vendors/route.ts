import { NextRequest, NextResponse } from "next/server";
import { unstable_cache } from "next/cache";
import { getCvesCollection } from "@/lib/mongodb";

const PAGE_SIZE = 20;
const PRODUCT_SEPARATOR = "$PRODUCT$";
const CACHE_TTL = 300; // 5 minutes

// Cached vendor aggregation - this is the expensive operation
const getCachedVendorData = unstable_cache(
  async () => {
    const collection = await getCvesCollection();

    // Aggregate to get unique vendors with counts
    const pipeline = [
      // Unwind vendors array
      { $unwind: "$vendors" },
      // Extract vendor name (before $PRODUCT$ separator)
      {
        $project: {
          vendor: {
            $cond: {
              if: { $regexMatch: { input: "$vendors", regex: `\\${PRODUCT_SEPARATOR}` } },
              then: { $arrayElemAt: [{ $split: ["$vendors", PRODUCT_SEPARATOR] }, 0] },
              else: "$vendors"
            }
          }
        }
      },
      // Group by vendor name
      {
        $group: {
          _id: "$vendor",
          cve_count: { $sum: 1 }
        }
      },
      // Sort by name
      { $sort: { _id: 1 } },
    ];

    const vendors = await collection.aggregate(pipeline).toArray();
    return vendors as { _id: string; cve_count: number }[];
  },
  ["vendors-list"],
  { revalidate: CACHE_TTL, tags: ["vendors"] }
);

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));

    // Get cached vendor data
    const allVendors = await getCachedVendorData();
    const count = allVendors.length;

    // Paginate in memory (fast since data is cached)
    const start = (page - 1) * PAGE_SIZE;
    const paginatedVendors = allVendors.slice(start, start + PAGE_SIZE);

    // Transform to expected format
    const results = paginatedVendors.map((v) => ({
      id: v._id,
      name: v._id,
      cve_count: v.cve_count,
      created_at: null,
      updated_at: null,
    }));

    // Build pagination URLs
    const baseUrl = "/api/vendors";
    const totalPages = Math.ceil(count / PAGE_SIZE);

    return NextResponse.json({
      count,
      next: page < totalPages ? `${baseUrl}?page=${page + 1}` : null,
      previous: page > 1 ? `${baseUrl}?page=${page - 1}` : null,
      results,
    });
  } catch (error) {
    console.error("Error fetching vendors:", error);
    return NextResponse.json(
      { error: "Failed to fetch vendors" },
      { status: 500 }
    );
  }
}
