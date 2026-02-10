import { NextRequest, NextResponse } from "next/server";
import { getProductsCollection } from "@/lib/mongodb";
import { ObjectId } from "mongodb";

const PAGE_SIZE = 20;

// GET /api/products - List all products
export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));

    const collection = await getProductsCollection();

    // Get total count
    const count = await collection.countDocuments({});

    // Fetch products
    const skip = (page - 1) * PAGE_SIZE;
    const products = await collection
      .find({})
      .sort({ updated_at: -1 })
      .skip(skip)
      .limit(PAGE_SIZE)
      .toArray();

    // Transform documents
    const results = products.map((product) => ({
      _id: product._id.toString(),
      name: product.name,
      description: product.description,
      github_url: product.github_url,
      github_owner: product.github_owner,
      github_repo: product.github_repo,
      default_branch: product.default_branch || "main",
      status: product.status,
      dependencies: product.dependencies || [],
      total_dependencies: product.total_dependencies || 0,
      tracked_dependencies: product.tracked_dependencies || 0,
      critical_cves: product.critical_cves || 0,
      high_cves: product.high_cves || 0,
      medium_cves: product.medium_cves || 0,
      low_cves: product.low_cves || 0,
      last_analyzed: product.last_analyzed?.toISOString() || null,
      created_at: product.created_at?.toISOString() || null,
      updated_at: product.updated_at?.toISOString() || null,
      error_message: product.error_message || null,
    }));

    const totalPages = Math.ceil(count / PAGE_SIZE);

    return NextResponse.json({
      count,
      next: page < totalPages ? `/api/products?page=${page + 1}` : null,
      previous: page > 1 ? `/api/products?page=${page - 1}` : null,
      results,
    });
  } catch (error) {
    console.error("Error fetching products:", error);
    return NextResponse.json(
      { error: "Failed to fetch products" },
      { status: 500 }
    );
  }
}

// POST /api/products - Create a new product from GitHub URL
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { github_url } = body;

    if (!github_url) {
      return NextResponse.json(
        { error: "github_url is required" },
        { status: 400 }
      );
    }

    // Parse GitHub URL
    const githubRegex = /^https?:\/\/github\.com\/([^\/]+)\/([^\/]+)\/?$/;
    const match = github_url.match(githubRegex);

    if (!match) {
      return NextResponse.json(
        { error: "Invalid GitHub URL format. Expected: https://github.com/owner/repo" },
        { status: 400 }
      );
    }

    const [, github_owner, github_repo] = match;
    const cleanRepo = github_repo.replace(/\.git$/, "");

    const collection = await getProductsCollection();

    // Check if product already exists
    const existing = await collection.findOne({
      github_owner: github_owner.toLowerCase(),
      github_repo: cleanRepo.toLowerCase(),
    });

    if (existing) {
      return NextResponse.json(
        { error: "Product already exists", product_id: existing._id.toString() },
        { status: 409 }
      );
    }

    // Create new product
    const now = new Date();
    const product = {
      name: cleanRepo,
      description: null,
      github_url: `https://github.com/${github_owner}/${cleanRepo}`,
      github_owner: github_owner.toLowerCase(),
      github_repo: cleanRepo.toLowerCase(),
      default_branch: "main",
      status: "analyzing",
      dependencies: [],
      total_dependencies: 0,
      tracked_dependencies: 0,
      critical_cves: 0,
      high_cves: 0,
      medium_cves: 0,
      low_cves: 0,
      last_analyzed: null,
      created_at: now,
      updated_at: now,
      error_message: null,
    };

    const result = await collection.insertOne(product);

    return NextResponse.json({
      _id: result.insertedId.toString(),
      ...product,
      created_at: now.toISOString(),
      updated_at: now.toISOString(),
    }, { status: 201 });
  } catch (error) {
    console.error("Error creating product:", error);
    return NextResponse.json(
      { error: "Failed to create product" },
      { status: 500 }
    );
  }
}
