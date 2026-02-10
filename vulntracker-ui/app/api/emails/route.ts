import { NextRequest, NextResponse } from "next/server";
import { getEmailsCollection } from "@/lib/mongodb";
import type { MonitoredEmail } from "@/lib/types";

const AGENTMAIL_API_URL = "https://api.agentmail.to/v0";
const AGENTMAIL_API_KEY = process.env.AGENTMAIL_API_KEY;

// GET - List emails from MongoDB
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get("page") || "1");
    const limit = parseInt(searchParams.get("limit") || "50");
    const category = searchParams.get("category");
    const unreadOnly = searchParams.get("unread") === "true";

    const collection = await getEmailsCollection();
    
    // Build query
    const query: Record<string, unknown> = {};
    if (category && category !== "all") {
      query["analysis.category"] = category;
    }
    if (unreadOnly) {
      query.read = false;
    }

    const skip = (page - 1) * limit;
    
    const [emails, total] = await Promise.all([
      collection
        .find(query)
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(limit)
        .toArray(),
      collection.countDocuments(query),
    ]);

    return NextResponse.json({
      emails: emails.map((e) => ({ ...e, _id: e._id.toString() })),
      total,
      page,
      limit,
      has_more: skip + emails.length < total,
    });
  } catch (error) {
    console.error("Error fetching emails:", error);
    return NextResponse.json(
      { error: "Failed to fetch emails" },
      { status: 500 }
    );
  }
}
