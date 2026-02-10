import { NextRequest, NextResponse } from "next/server";
import { getChatSessionsCollection } from "@/lib/mongodb";

// GET - List all chat sessions
export async function GET() {
  try {
    const collection = await getChatSessionsCollection();
    
    const sessions = await collection
      .find({})
      .project({
        _id: 1,
        title: 1,
        created_at: 1,
        updated_at: 1,
        // Include message count but not full messages
        messages: { $slice: 1 }, // Get first message for preview
      })
      .sort({ updated_at: -1 })
      .limit(50)
      .toArray();

    // Transform to include message count
    const sessionsWithCount = await collection
      .aggregate([
        { $sort: { updated_at: -1 } },
        { $limit: 50 },
        {
          $project: {
            _id: 1,
            title: 1,
            created_at: 1,
            updated_at: 1,
            message_count: { $size: "$messages" },
            preview: { $arrayElemAt: ["$messages.content", 0] },
          },
        },
      ])
      .toArray();

    return NextResponse.json({
      sessions: sessionsWithCount.map((s) => ({
        ...s,
        _id: s._id.toString(),
      })),
      total: sessionsWithCount.length,
    });
  } catch (error) {
    console.error("Error fetching sessions:", error);
    return NextResponse.json(
      { error: "Failed to fetch sessions" },
      { status: 500 }
    );
  }
}

// POST - Create a new empty session
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { title } = body;

    const collection = await getChatSessionsCollection();
    const now = new Date().toISOString();

    const newSession = {
      title: title || "New conversation",
      messages: [],
      created_at: now,
      updated_at: now,
    };

    const result = await collection.insertOne(newSession);

    return NextResponse.json({
      _id: result.insertedId.toString(),
      ...newSession,
    });
  } catch (error) {
    console.error("Error creating session:", error);
    return NextResponse.json(
      { error: "Failed to create session" },
      { status: 500 }
    );
  }
}
