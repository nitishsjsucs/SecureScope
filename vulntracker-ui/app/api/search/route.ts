import { NextRequest, NextResponse } from "next/server";
import { unstable_cache } from "next/cache";
import { getDatabase } from "@/lib/mongodb";

export interface SearchResult {
  type: "cve" | "product" | "vendor";
  id: string;
  title: string;
  subtitle: string;
  score?: number;
  severity?: string;
  url: string;
}

export interface SearchResponse {
  query: string;
  results: SearchResult[];
  total: number;
}

const MAX_RESULTS_PER_TYPE = 5;
const SEARCH_CACHE_TTL = 60; // 1 minute for search results

// Create a cached search function for a specific query
function createCachedSearch(query: string, isCveId: boolean) {
  return unstable_cache(
    async () => {
      const db = await getDatabase();
      const results: SearchResult[] = [];

      // Run all searches in parallel for speed
      const [cveResults, productResults, vendorResults] = await Promise.all([
        searchCves(db, query, isCveId),
        searchProducts(db, query),
        searchVendors(db, query),
      ]);

      results.push(...cveResults, ...productResults, ...vendorResults);
      return results;
    },
    [`search-${query.toLowerCase()}`],
    { revalidate: SEARCH_CACHE_TTL, tags: ["search"] }
  );
}

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const query = searchParams.get("q")?.trim();

    if (!query || query.length < 2) {
      return NextResponse.json({
        query: query || "",
        results: [],
        total: 0,
      });
    }

    // Check if query looks like a CVE ID
    const isCveId = /^cve-?\d{4}-?\d+$/i.test(query);

    // Get cached search results
    const getCachedResults = createCachedSearch(query, isCveId);
    const results = await getCachedResults();

    return NextResponse.json({
      query,
      results,
      total: results.length,
    });
  } catch (error) {
    console.error("Search error:", error);
    return NextResponse.json(
      { error: "Search failed", details: String(error) },
      { status: 500 }
    );
  }
}

async function searchCves(
  db: Awaited<ReturnType<typeof getDatabase>>,
  query: string,
  isCveId: boolean
): Promise<SearchResult[]> {
  const collection = db.collection("cves");

  try {
    // Try Atlas Search first
    const pipeline = [
      {
        $search: {
          index: "cves",
          compound: {
            should: [
              // Exact/prefix match on CVE ID (highest priority)
              {
                autocomplete: {
                  query: query,
                  path: "_id",
                  fuzzy: { maxEdits: 1 },
                },
              },
              // Search in description
              {
                text: {
                  query: query,
                  path: "description",
                  fuzzy: { maxEdits: 1 },
                },
              },
              // Search in title
              {
                text: {
                  query: query,
                  path: "title",
                  fuzzy: { maxEdits: 1 },
                },
              },
              // Search in vendors array
              {
                text: {
                  query: query,
                  path: "vendors",
                },
              },
            ],
            minimumShouldMatch: 1,
          },
        },
      },
      {
        $limit: MAX_RESULTS_PER_TYPE,
      },
      {
        $project: {
          _id: 1,
          title: 1,
          description: 1,
          vendors: 1,
          metrics: 1,
          score: { $meta: "searchScore" },
        },
      },
    ];

    const cves = await collection.aggregate(pipeline).toArray();

    return cves.map((cve) => {
      const cvssScore =
        cve.metrics?.cvssV3_1?.data?.score ||
        cve.metrics?.cvssV4_0?.data?.score ||
        cve.metrics?.cvssV3_0?.data?.score ||
        null;

      let severity = "N/A";
      if (cvssScore !== null) {
        if (cvssScore >= 9.0) severity = "Critical";
        else if (cvssScore >= 7.0) severity = "High";
        else if (cvssScore >= 4.0) severity = "Medium";
        else if (cvssScore >= 0.1) severity = "Low";
        else severity = "None";
      }

      // Build subtitle from description or vendors
      let subtitle = cve.description?.slice(0, 100) || "";
      if (subtitle.length === 100) subtitle += "...";
      if (!subtitle && cve.vendors?.length) {
        subtitle = `Affects: ${cve.vendors.slice(0, 3).join(", ")}`;
      }

      return {
        type: "cve" as const,
        id: cve._id,
        title: cve._id,
        subtitle,
        score: cvssScore,
        severity,
        url: `/cve/${cve._id}`,
      };
    });
  } catch (error) {
    // Fallback to regex search if Atlas Search index doesn't exist
    console.warn("Atlas Search failed, falling back to regex:", error);
    return fallbackCveSearch(collection, query, isCveId);
  }
}

async function fallbackCveSearch(
  collection: ReturnType<Awaited<ReturnType<typeof getDatabase>>["collection"]>,
  query: string,
  isCveId: boolean
): Promise<SearchResult[]> {
  const filter: Record<string, unknown> = {};

  if (isCveId) {
    // Normalize CVE ID format
    const normalizedId = query.toUpperCase().replace(/^CVE-?/, "CVE-");
    filter._id = { $regex: normalizedId, $options: "i" };
  } else {
    filter.$or = [
      { _id: { $regex: query, $options: "i" } },
      { description: { $regex: query, $options: "i" } },
      { title: { $regex: query, $options: "i" } },
      { vendors: { $regex: query, $options: "i" } },
    ];
  }

  const cves = await collection
    .find(filter)
    .limit(MAX_RESULTS_PER_TYPE)
    .toArray();

  return cves.map((cve) => {
    const cvssScore =
      cve.metrics?.cvssV3_1?.data?.score ||
      cve.metrics?.cvssV4_0?.data?.score ||
      cve.metrics?.cvssV3_0?.data?.score ||
      null;

    let severity = "N/A";
    if (cvssScore !== null) {
      if (cvssScore >= 9.0) severity = "Critical";
      else if (cvssScore >= 7.0) severity = "High";
      else if (cvssScore >= 4.0) severity = "Medium";
      else if (cvssScore >= 0.1) severity = "Low";
      else severity = "None";
    }

    let subtitle = cve.description?.slice(0, 100) || "";
    if (subtitle.length === 100) subtitle += "...";

    const cveId = String(cve._id);
    return {
      type: "cve" as const,
      id: cveId,
      title: cveId,
      subtitle,
      score: cvssScore,
      severity,
      url: `/cve/${cveId}`,
    };
  });
}

async function searchProducts(
  db: Awaited<ReturnType<typeof getDatabase>>,
  query: string
): Promise<SearchResult[]> {
  const collection = db.collection("products");

  try {
    // Try Atlas Search first
    const pipeline = [
      {
        $search: {
          index: "product_search",
          compound: {
            should: [
              {
                autocomplete: {
                  query: query,
                  path: "name",
                },
              },
              {
                text: {
                  query: query,
                  path: "github_repo",
                },
              },
              {
                text: {
                  query: query,
                  path: "github_owner",
                },
              },
              {
                text: {
                  query: query,
                  path: "description",
                  fuzzy: { maxEdits: 1 },
                },
              },
            ],
            minimumShouldMatch: 1,
          },
        },
      },
      {
        $limit: MAX_RESULTS_PER_TYPE,
      },
      {
        $project: {
          _id: 1,
          name: 1,
          github_owner: 1,
          github_repo: 1,
          description: 1,
          total_dependencies: 1,
          critical_cves: 1,
          high_cves: 1,
        },
      },
    ];

    const products = await collection.aggregate(pipeline).toArray();

    return products.map((product) => ({
      type: "product" as const,
      id: product._id.toString(),
      title: product.name,
      subtitle: `${product.github_owner}/${product.github_repo}`,
      score: (product.critical_cves || 0) + (product.high_cves || 0),
      url: `/products/${product._id}`,
    }));
  } catch (error) {
    // Fallback to regex search
    console.warn("Atlas Search for products failed, falling back to regex:", error);
    return fallbackProductSearch(collection, query);
  }
}

async function fallbackProductSearch(
  collection: ReturnType<Awaited<ReturnType<typeof getDatabase>>["collection"]>,
  query: string
): Promise<SearchResult[]> {
  const products = await collection
    .find({
      $or: [
        { name: { $regex: query, $options: "i" } },
        { github_repo: { $regex: query, $options: "i" } },
        { github_owner: { $regex: query, $options: "i" } },
        { description: { $regex: query, $options: "i" } },
      ],
    })
    .limit(MAX_RESULTS_PER_TYPE)
    .toArray();

  return products.map((product) => ({
    type: "product" as const,
    id: product._id.toString(),
    title: product.name,
    subtitle: `${product.github_owner}/${product.github_repo}`,
    score: (product.critical_cves || 0) + (product.high_cves || 0),
    url: `/products/${product._id}`,
  }));
}

async function searchVendors(
  db: Awaited<ReturnType<typeof getDatabase>>,
  query: string
): Promise<SearchResult[]> {
  // Vendors are stored as strings in CVE documents
  // We'll aggregate unique vendors that match the query
  const collection = db.collection("cves");

  try {
    // Use aggregation to find matching vendors
    const pipeline = [
      {
        $match: {
          vendors: { $regex: query, $options: "i" },
        },
      },
      { $unwind: "$vendors" },
      {
        $match: {
          vendors: { $regex: query, $options: "i" },
        },
      },
      {
        $group: {
          _id: "$vendors",
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: MAX_RESULTS_PER_TYPE },
    ];

    const vendors = await collection.aggregate(pipeline).toArray();

    return vendors.map((vendor) => {
      // Parse vendor$PRODUCT$product format
      const parts = vendor._id.split("$PRODUCT$");
      const vendorName = parts[0];
      const productName = parts[1];

      return {
        type: "vendor" as const,
        id: vendor._id,
        title: productName ? `${vendorName} - ${productName}` : vendorName,
        subtitle: `${vendor.count} CVE${vendor.count !== 1 ? "s" : ""}`,
        url: `/vendors/${encodeURIComponent(vendorName)}${productName ? `?product=${encodeURIComponent(productName)}` : ""}`,
      };
    });
  } catch (error) {
    console.error("Vendor search error:", error);
    return [];
  }
}
