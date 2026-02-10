import { NextRequest, NextResponse } from "next/server";
import { getProductsCollection } from "@/lib/mongodb";
import { ObjectId } from "mongodb";

interface RouteParams {
  params: Promise<{ id: string }>;
}

// GET /api/products/[id] - Get product details
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params;
    const collection = await getProductsCollection();

    let product;
    try {
      product = await collection.findOne({ _id: new ObjectId(id) });
    } catch {
      return NextResponse.json({ error: "Invalid product ID" }, { status: 400 });
    }

    if (!product) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    return NextResponse.json({
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
    });
  } catch (error) {
    console.error("Error fetching product:", error);
    return NextResponse.json(
      { error: "Failed to fetch product" },
      { status: 500 }
    );
  }
}

// PATCH /api/products/[id] - Update product (e.g., track dependencies)
export async function PATCH(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params;
    const body = await request.json();
    const collection = await getProductsCollection();

    let objectId;
    try {
      objectId = new ObjectId(id);
    } catch {
      return NextResponse.json({ error: "Invalid product ID" }, { status: 400 });
    }

    const updateData: Record<string, unknown> = {
      updated_at: new Date(),
    };

    // Allow updating specific fields
    if (body.name !== undefined) updateData.name = body.name;
    if (body.description !== undefined) updateData.description = body.description;
    if (body.dependencies !== undefined) {
      updateData.dependencies = body.dependencies;
      updateData.tracked_dependencies = body.dependencies.filter((d: { tracked: boolean }) => d.tracked).length;
    }

    const result = await collection.findOneAndUpdate(
      { _id: objectId },
      { $set: updateData },
      { returnDocument: "after" }
    );

    if (!result) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    return NextResponse.json({
      _id: result._id.toString(),
      name: result.name,
      description: result.description,
      github_url: result.github_url,
      github_owner: result.github_owner,
      github_repo: result.github_repo,
      default_branch: result.default_branch || "main",
      status: result.status,
      dependencies: result.dependencies || [],
      total_dependencies: result.total_dependencies || 0,
      tracked_dependencies: result.tracked_dependencies || 0,
      critical_cves: result.critical_cves || 0,
      high_cves: result.high_cves || 0,
      medium_cves: result.medium_cves || 0,
      low_cves: result.low_cves || 0,
      last_analyzed: result.last_analyzed?.toISOString() || null,
      created_at: result.created_at?.toISOString() || null,
      updated_at: result.updated_at?.toISOString() || null,
      error_message: result.error_message || null,
    });
  } catch (error) {
    console.error("Error updating product:", error);
    return NextResponse.json(
      { error: "Failed to update product" },
      { status: 500 }
    );
  }
}

// DELETE /api/products/[id] - Delete a product
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params;
    const collection = await getProductsCollection();

    let objectId;
    try {
      objectId = new ObjectId(id);
    } catch {
      return NextResponse.json({ error: "Invalid product ID" }, { status: 400 });
    }

    const result = await collection.deleteOne({ _id: objectId });

    if (result.deletedCount === 0) {
      return NextResponse.json({ error: "Product not found" }, { status: 404 });
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Error deleting product:", error);
    return NextResponse.json(
      { error: "Failed to delete product" },
      { status: 500 }
    );
  }
}
