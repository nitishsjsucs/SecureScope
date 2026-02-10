import { ChatInterface } from "@/components/chat-interface";
import { getChatSessionsCollection } from "@/lib/mongodb";
import type { ChatSession } from "@/lib/types";

async function getChatSessions(): Promise<ChatSession[]> {
  try {
    const collection = await getChatSessionsCollection();
    
    const sessions = await collection
      .aggregate([
        { $sort: { updated_at: -1 } },
        { $limit: 50 },
        {
          $project: {
            _id: 1,
            title: 1,
            created_at: 1,
            updated_at: 1,
            messages: { $slice: ["$messages", 0] }, // Don't load messages initially
          },
        },
      ])
      .toArray();

    return sessions.map((s) => ({
      _id: s._id.toString(),
      title: s.title as string || "Untitled",
      created_at: s.created_at as string || new Date().toISOString(),
      updated_at: s.updated_at as string || new Date().toISOString(),
      messages: [],
    }));
  } catch (error) {
    console.error("Error fetching chat sessions:", error);
    return [];
  }
}

export default async function ChatPage() {
  const sessions = await getChatSessions();

  return (
    <main className="container mx-auto max-w-7xl px-4 py-6">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-[#1F2937]">Chat</h1>
        <p className="text-sm text-[#6B7280] mt-1">
          Ask questions about CVEs and vulnerabilities in the database
        </p>
      </div>

      <ChatInterface initialSessions={sessions} />
    </main>
  );
}
