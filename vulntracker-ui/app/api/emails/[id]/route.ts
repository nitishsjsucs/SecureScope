import { NextRequest, NextResponse } from "next/server";
import { getEmailsCollection } from "@/lib/mongodb";
import { ObjectId } from "mongodb";

// GET - Get single email by ID
export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const collection = await getEmailsCollection();
    
    let email;
    
    // Try ObjectId first, then message_id
    if (ObjectId.isValid(id)) {
      email = await collection.findOne({ _id: new ObjectId(id) });
    }
    
    if (!email) {
      email = await collection.findOne({ message_id: id });
    }

    if (!email) {
      return NextResponse.json(
        { error: "Email not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      ...email,
      _id: email._id.toString(),
    });
  } catch (error) {
    console.error("Error fetching email:", error);
    return NextResponse.json(
      { error: "Failed to fetch email" },
      { status: 500 }
    );
  }
}

// PATCH - Update email (mark read, starred, etc.)
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    const collection = await getEmailsCollection();

    const updateFields: Record<string, unknown> = {
      updated_at: new Date().toISOString(),
    };

    // Only allow updating specific fields
    if (typeof body.read === "boolean") {
      updateFields.read = body.read;
    }
    if (typeof body.starred === "boolean") {
      updateFields.starred = body.starred;
    }

    let filter;
    if (ObjectId.isValid(id)) {
      filter = { _id: new ObjectId(id) };
    } else {
      filter = { message_id: id };
    }

    const result = await collection.findOneAndUpdate(
      filter,
      { $set: updateFields },
      { returnDocument: "after" }
    );

    if (!result) {
      return NextResponse.json(
        { error: "Email not found" },
        { status: 404 }
      );
    }

    return NextResponse.json({
      ...result,
      _id: result._id.toString(),
    });
  } catch (error) {
    console.error("Error updating email:", error);
    return NextResponse.json(
      { error: "Failed to update email" },
      { status: 500 }
    );
  }
}
