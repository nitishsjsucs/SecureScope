import { NextRequest, NextResponse } from "next/server";
import { getCvesCollection, getChatSessionsCollection } from "@/lib/mongodb";
import { ObjectId } from "mongodb";
import type { RAGSource, ChatMessage, SeverityLevel } from "@/lib/types";

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

// Extract CVE IDs from user message
function extractCveIds(text: string): string[] {
  const cvePattern = /CVE-\d{4}-\d{4,}/gi;
  const matches = text.match(cvePattern);
  return matches ? [...new Set(matches.map((m) => m.toUpperCase()))] : [];
}

// Extract year references from user message (e.g., "1999", "2024", "from 1999")
function extractYearFromQuery(text: string): number | null {
  // Look for 4-digit years in typical CVE year range (1999-2030)
  const yearPattern = /\b(199\d|20[0-2]\d|2030)\b/g;
  const matches = text.match(yearPattern);
  if (matches && matches.length > 0) {
    // Return the first year found (most likely the intended filter)
    return parseInt(matches[0], 10);
  }
  return null;
}

// Extract potential search terms from the query
function extractSearchTerms(text: string): string[] {
  // Remove common words and extract meaningful terms
  const stopWords = new Set([
    "what", "which", "how", "why", "when", "where", "who", "is", "are", "was", 
    "were", "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "as", "into", "through", "during", "before",
    "after", "above", "below", "between", "about", "against", "can", "could",
    "would", "should", "may", "might", "must", "shall", "will", "do", "does",
    "did", "have", "has", "had", "be", "been", "being", "this", "that", "these",
    "those", "i", "you", "he", "she", "it", "we", "they", "me", "him", "her",
    "us", "them", "my", "your", "his", "its", "our", "their", "any", "all",
    "both", "each", "few", "more", "most", "some", "such", "no", "nor", "not",
    "only", "own", "same", "so", "than", "too", "very", "just", "also", "now",
    "tell", "show", "find", "get", "give", "know", "think", "see", "come", "go",
    "make", "take", "use", "cve", "cves", "vulnerability", "vulnerabilities",
    "security", "issue", "issues", "problem", "problems", "affect", "affects",
    "affected", "affecting", "related", "regarding", "concerning"
  ]);

  const words = text.toLowerCase()
    .replace(/[^\w\s-]/g, " ")
    .split(/\s+/)
    .filter((word) => word.length > 2 && !stopWords.has(word));

  return [...new Set(words)];
}

// Get severity from CVSS metrics
function getSeverity(metrics: Record<string, unknown>): SeverityLevel {
  const versions = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"];
  for (const version of versions) {
    const metric = metrics[version] as { data?: { score?: number } } | undefined;
    if (metric?.data?.score !== undefined) {
      const score = metric.data.score;
      if (score >= 9.0) return "critical";
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      if (score > 0) return "low";
      return "none";
    }
  }
  return "none";
}

// Search CVEs using text search
// Note: CVE documents use _id as the CVE ID (e.g., "CVE-2024-1234") - stored as strings, not ObjectId
async function searchCves(query: string, limit: number = 10): Promise<RAGSource[]> {
  const collection = await getCvesCollection();
  
  // Extract specific CVE IDs, search terms, and year filter
  const cveIds = extractCveIds(query);
  const searchTerms = extractSearchTerms(query);
  const yearFilter = extractYearFromQuery(query);
  
  // Track if the query is specific (has year or specific terms) - affects fallback behavior
  const isSpecificQuery = yearFilter !== null || cveIds.length > 0;
  
  console.log("[searchCves] Query:", query);
  console.log("[searchCves] Extracted CVE IDs:", cveIds);
  console.log("[searchCves] Extracted search terms:", searchTerms);
  console.log("[searchCves] Year filter:", yearFilter);
  console.log("[searchCves] Is specific query:", isSpecificQuery);
  
  const sources: RAGSource[] = [];
  
  // First, fetch any specifically mentioned CVEs by _id (string IDs like "CVE-2024-1234")
  if (cveIds.length > 0) {
    console.log("[searchCves] Searching for specific CVE IDs...");
    const specificCves = await collection
      .find({ _id: { $in: cveIds } } as Record<string, unknown>)
      .limit(cveIds.length)
      .toArray();
    
    console.log("[searchCves] Found", specificCves.length, "specific CVEs");
    
    for (const cve of specificCves) {
      const cveId = String(cve._id);
      sources.push({
        type: "cve",
        id: cveId,
        title: cveId,
        snippet: cve.description?.substring(0, 300) || "No description available",
        relevance_score: 1.0,
        severity: getSeverity(cve.metrics || {}),
        url: `/cve/${cveId}`,
      });
    }
  }
  
  // If we have search terms, do a text-based search
  if (searchTerms.length > 0 && sources.length < limit) {
    const remainingLimit = limit - sources.length;
    const existingIds = new Set(sources.map((s) => s.id));
    
    // Build regex pattern for search terms
    const regexPattern = searchTerms.join("|");
    console.log("[searchCves] Regex pattern:", regexPattern);
    
    // Build the query conditions
    const queryConditions: Record<string, unknown> = {
      _id: { $nin: Array.from(existingIds) },
      $or: [
        { description: { $regex: regexPattern, $options: "i" } },
        { title: { $regex: regexPattern, $options: "i" } },
        { vendors: { $regex: regexPattern, $options: "i" } },
      ],
    };
    
    // If year is specified, filter CVE IDs by year (CVE-YYYY-XXXXX format)
    if (yearFilter) {
      queryConditions._id = {
        $nin: Array.from(existingIds),
        $regex: `^CVE-${yearFilter}-`,
        $options: "i",
      };
    }
    
    const searchResults = await collection
      .find(queryConditions as Record<string, unknown>)
      .sort({ updated_at: -1 })
      .limit(remainingLimit)
      .toArray();
    
    console.log("[searchCves] Text search found", searchResults.length, "results");
    
    for (const cve of searchResults) {
      const cveId = String(cve._id);
      sources.push({
        type: "cve",
        id: cveId,
        title: cveId,
        snippet: cve.description?.substring(0, 300) || "No description available",
        relevance_score: 0.7,
        severity: getSeverity(cve.metrics || {}),
        url: `/cve/${cveId}`,
      });
    }
  }
  
  // If year filter is specified but no text search terms, search just by year
  if (yearFilter && searchTerms.length === 0 && sources.length < limit) {
    console.log("[searchCves] Searching by year only:", yearFilter);
    const remainingLimit = limit - sources.length;
    const existingIds = new Set(sources.map((s) => s.id));
    
    const yearResults = await collection
      .find({
        _id: {
          $nin: Array.from(existingIds),
          $regex: `^CVE-${yearFilter}-`,
          $options: "i",
        },
      } as Record<string, unknown>)
      .sort({ updated_at: -1 })
      .limit(remainingLimit)
      .toArray();
    
    console.log("[searchCves] Year-only search found", yearResults.length, "results");
    
    for (const cve of yearResults) {
      const cveId = String(cve._id);
      sources.push({
        type: "cve",
        id: cveId,
        title: cveId,
        snippet: cve.description?.substring(0, 300) || "No description available",
        relevance_score: 0.6,
        severity: getSeverity(cve.metrics || {}),
        url: `/cve/${cveId}`,
      });
    }
  }
  
  // If still no results and query is NOT specific, get recent critical/high CVEs as fallback
  // Don't show fallback for specific queries (with year filter or specific CVE IDs) to avoid confusion
  if (sources.length === 0 && !isSpecificQuery) {
    console.log("[searchCves] No results, fetching fallback high-severity CVEs...");
    const recentCves = await collection
      .find({
        $or: [
          { "metrics.cvssV4_0.data.score": { $gte: 7.0 } },
          { "metrics.cvssV3_1.data.score": { $gte: 7.0 } },
          { "metrics.cvssV3_0.data.score": { $gte: 7.0 } },
        ],
      })
      .sort({ updated_at: -1 })
      .limit(5)
      .toArray();
    
    console.log("[searchCves] Fallback found", recentCves.length, "high-severity CVEs");
    
    for (const cve of recentCves) {
      const cveId = String(cve._id);
      sources.push({
        type: "cve",
        id: cveId,
        title: cveId,
        snippet: cve.description?.substring(0, 300) || "No description available",
        relevance_score: 0.3,
        severity: getSeverity(cve.metrics || {}),
        url: `/cve/${cveId}`,
      });
    }
  } else if (sources.length === 0 && isSpecificQuery) {
    console.log("[searchCves] No results for specific query, not showing fallback CVEs");
  }
  
  console.log("[searchCves] Total sources returned:", sources.length);
  return sources;
}

// Generate response using OpenAI
async function generateResponse(
  userMessage: string,
  sources: RAGSource[],
  conversationHistory: ChatMessage[]
): Promise<string> {
  if (!OPENAI_API_KEY) {
    throw new Error("OpenAI API key not configured");
  }

  // Build context from sources
  const contextParts = sources.map((source, i) => {
    const severityStr = source.severity ? ` [${source.severity.toUpperCase()}]` : "";
    return `[${i + 1}] ${source.title}${severityStr}\n${source.snippet}`;
  });
  
  const context = contextParts.length > 0
    ? `\n\nRelevant CVE data from the database:\n${contextParts.join("\n\n")}`
    : "\n\nNo specific CVE data found matching the query.";

  // Build conversation messages
  const messages = [
    {
      role: "system",
      content: `You are a security analyst assistant with access to a comprehensive CVE vulnerability database containing over 330,000 CVEs. Your role is to help security professionals understand vulnerabilities, assess risks, and make informed decisions.

Guidelines:
- Provide accurate, technical information based on the CVE data provided
- When referencing CVEs, always mention the CVE ID
- Explain severity levels and potential impact clearly
- If the provided data doesn't fully answer the question, acknowledge limitations
- Be concise but thorough
- If asked about something not in the provided context, say you don't have that specific information in the current search results
${context}`,
    },
    // Include recent conversation history (last 10 messages)
    ...conversationHistory.slice(-10).map((msg) => ({
      role: msg.role as "user" | "assistant",
      content: msg.content,
    })),
    {
      role: "user",
      content: userMessage,
    },
  ];

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o",
      messages,
      temperature: 0.7,
      max_tokens: 1000,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    console.error("OpenAI API error:", error);
    throw new Error("Failed to generate response");
  }

  const data = await response.json();
  return data.choices[0].message.content;
}

// POST - Send a message and get a response
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { message, sessionId } = body;

    if (!message || typeof message !== "string") {
      return NextResponse.json(
        { error: "Message is required" },
        { status: 400 }
      );
    }

    // Get or create session
    const sessionsCollection = await getChatSessionsCollection();
    let session;
    let conversationHistory: ChatMessage[] = [];

    if (sessionId) {
      session = await sessionsCollection.findOne({
        _id: new ObjectId(sessionId),
      });
      if (session) {
        conversationHistory = session.messages || [];
      }
    }

    // Search for relevant CVEs
    const sources = await searchCves(message, 10);

    // Generate response using OpenAI
    const responseContent = await generateResponse(
      message,
      sources,
      conversationHistory
    );

    // Create user message
    const userMessage: ChatMessage = {
      id: new ObjectId().toString(),
      role: "user",
      content: message,
      timestamp: new Date().toISOString(),
    };

    // Create assistant message
    const assistantMessage: ChatMessage = {
      id: new ObjectId().toString(),
      role: "assistant",
      content: responseContent,
      sources: sources.length > 0 ? sources : undefined,
      timestamp: new Date().toISOString(),
    };

    // Update or create session
    const now = new Date().toISOString();
    
    if (session) {
      // Update existing session - cast to unknown first to avoid strict typing issues with $each
      const updateDoc = {
        $push: {
          messages: { $each: [userMessage, assistantMessage] },
        },
        $set: { updated_at: now },
      };
      await sessionsCollection.updateOne(
        { _id: new ObjectId(sessionId) },
        updateDoc as unknown as Parameters<typeof sessionsCollection.updateOne>[1]
      );
    } else {
      // Create new session
      const title = message.length > 50 
        ? message.substring(0, 50) + "..." 
        : message;
      
      const newSession = {
        title,
        messages: [userMessage, assistantMessage],
        created_at: now,
        updated_at: now,
      };
      
      const result = await sessionsCollection.insertOne(newSession);
      session = { _id: result.insertedId, ...newSession };
    }

    return NextResponse.json({
      userMessage,
      assistantMessage,
      sessionId: session._id.toString(),
      sources,
    });
  } catch (error) {
    console.error("Chat error:", error);
    return NextResponse.json(
      { error: "Failed to process message" },
      { status: 500 }
    );
  }
}
