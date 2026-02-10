import { NextRequest, NextResponse } from "next/server";
import { getCvesCollection } from "@/lib/mongodb";
import { Sort } from "mongodb";

const PAGE_SIZE = 20;
const PRODUCT_SEPARATOR = "$PRODUCT$";

// Sort options mapping
const SORT_OPTIONS: Record<string, Sort> = {
  "-updated_at": { updated_at: -1 },
  "updated_at": { updated_at: 1 },
  "-created_at": { created_at: -1 },
  "created_at": { created_at: 1 },
  "-cvss": { "metrics.cvssV3_1.data.score": -1, updated_at: -1 },
  "cvss": { "metrics.cvssV3_1.data.score": 1, updated_at: -1 },
};

interface RouteParams {
  params: Promise<{ name: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { name } = await params;
    const vendorName = decodeURIComponent(name);
    
    const searchParams = request.nextUrl.searchParams;
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const sortParam = searchParams.get("sort") || "-updated_at";

    const collection = await getCvesCollection();

    // Filter for CVEs containing this vendor (with or without product)
    const filter = {
      vendors: { $regex: `^${vendorName}($|\\${PRODUCT_SEPARATOR})` }
    };

    // Get total count
    const count = await collection.countDocuments(filter);

    if (count === 0) {
      return NextResponse.json(
        { error: "Vendor not found" },
        { status: 404 }
      );
    }

    // Get sort option
    const sort = SORT_OPTIONS[sortParam] || SORT_OPTIONS["-updated_at"];

    // Fetch CVEs
    const skip = (page - 1) * PAGE_SIZE;
    const cves = await collection
      .find(filter)
      .sort(sort)
      .skip(skip)
      .limit(PAGE_SIZE)
      .toArray();

    // Transform documents to match expected API format
    const results = cves.map((cve) => ({
      cve_id: cve._id,
      description: cve.description,
      title: cve.title,
      metrics: cve.metrics || {},
      vendors: cve.vendors || [],
      weaknesses: cve.weaknesses || [],
      created_at: cve.created_at?.toISOString() || null,
      updated_at: cve.updated_at?.toISOString() || null,
      sexysecure: cve.sexysecure || null,
    }));

    // Build pagination URLs
    const baseUrl = `/api/vendors/${encodeURIComponent(vendorName)}/cve`;
    const totalPages = Math.ceil(count / PAGE_SIZE);
    const buildUrl = (p: number) => {
      const params = new URLSearchParams();
      params.set("page", p.toString());
      if (sortParam !== "-updated_at") params.set("sort", sortParam);
      return `${baseUrl}?${params.toString()}`;
    };

    return NextResponse.json({
      count,
      next: page < totalPages ? buildUrl(page + 1) : null,
      previous: page > 1 ? buildUrl(page - 1) : null,
      results,
    });
  } catch (error) {
    console.error("Error fetching vendor CVEs:", error);
    return NextResponse.json(
      { error: "Failed to fetch vendor CVEs" },
      { status: 500 }
    );
  }
}
