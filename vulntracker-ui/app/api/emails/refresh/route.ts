import { NextRequest, NextResponse } from "next/server";
import { getEmailsCollection } from "@/lib/mongodb";
import OpenAI from "openai";
import type { EmailCategory, EmailLLMAnalysis, MonitoredEmail, SeverityLevel } from "@/lib/types";

const AGENTMAIL_API_URL = "https://api.agentmail.to/v0";
const AGENTMAIL_API_KEY = process.env.AGENTMAIL_API_KEY;

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

interface AgentMailMessage {
  inbox_id: string;
  thread_id: string;
  message_id: string;
  labels: string[];
  timestamp: string;
  from: string;
  to: string[];
  cc?: string[];
  subject?: string;
  preview?: string;
  text?: string;
  html?: string;
  attachments?: Array<{
    attachment_id: string;
    filename?: string;
    size: number;
    content_type?: string;
  }>;
  created_at: string;
  updated_at: string;
}

interface AgentMailInbox {
  inbox_id: string;
  display_name?: string;
}

// Analyze email with OpenAI
async function analyzeEmail(email: { subject: string | null; text: string | null; from: string }): Promise<EmailLLMAnalysis> {
  const prompt = `Analyze this security mailing list email and categorize it.

FROM: ${email.from}
SUBJECT: ${email.subject || "(no subject)"}
BODY:
${(email.text || "").slice(0, 4000)}

Respond with a JSON object:
{
  "category": one of ["cve_update", "cve_detected", "security_advisory", "threat_intel", "newsletter", "promotional", "spam", "other"],
  "confidence": number between 0 and 1,
  "summary": "brief 1-2 sentence summary",
  "cve_ids": ["CVE-XXXX-XXXXX", ...] // any CVE IDs mentioned,
  "vendors": ["vendor1", ...] // vendors mentioned,
  "products": ["product1", ...] // products mentioned,
  "severity_mentioned": "critical" | "high" | "medium" | "low" | null,
  "action_required": true/false // whether immediate action is suggested,
  "key_points": ["point 1", "point 2", ...] // 2-4 key takeaways
}

Categories explained:
- cve_update: Official CVE updates from NVD, MITRE, or similar
- cve_detected: New vulnerability detected/announced
- security_advisory: Vendor security advisories
- threat_intel: Threat intelligence, malware reports, attack campaigns
- newsletter: Regular security newsletters/digests
- promotional: Marketing, product promotions
- spam: Spam or irrelevant
- other: Doesn't fit other categories`;

  try {
    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
      response_format: { type: "json_object" },
      temperature: 0.3,
    });

    const content = response.choices[0]?.message?.content;
    if (!content) {
      throw new Error("No response from OpenAI");
    }

    const analysis = JSON.parse(content);
    
    return {
      category: analysis.category as EmailCategory,
      confidence: analysis.confidence || 0.5,
      summary: analysis.summary || "",
      cve_ids: analysis.cve_ids || [],
      vendors: analysis.vendors || [],
      products: analysis.products || [],
      severity_mentioned: analysis.severity_mentioned as SeverityLevel | null,
      action_required: analysis.action_required || false,
      key_points: analysis.key_points || [],
      analyzed_at: new Date().toISOString(),
    };
  } catch (error) {
    console.error("OpenAI analysis error:", error);
    // Return a default analysis on error
    return {
      category: "other",
      confidence: 0,
      summary: "Analysis failed",
      cve_ids: [],
      vendors: [],
      products: [],
      severity_mentioned: null,
      action_required: false,
      key_points: [],
      analyzed_at: new Date().toISOString(),
    };
  }
}

// Fetch full message details from AgentMail
async function fetchMessageDetails(inboxId: string, messageId: string): Promise<AgentMailMessage | null> {
  try {
    const response = await fetch(
      `${AGENTMAIL_API_URL}/inboxes/${inboxId}/messages/${messageId}`,
      {
        headers: {
          Authorization: `Bearer ${AGENTMAIL_API_KEY}`,
        },
      }
    );

    if (!response.ok) {
      console.error(`Failed to fetch message ${messageId}:`, response.status);
      return null;
    }

    return response.json();
  } catch (error) {
    console.error(`Error fetching message ${messageId}:`, error);
    return null;
  }
}

// POST - Refresh emails from AgentMail
export async function POST(request: NextRequest) {
  if (!AGENTMAIL_API_KEY) {
    return NextResponse.json(
      { error: "AgentMail API key not configured" },
      { status: 500 }
    );
  }

  try {
    // First, get all inboxes
    const inboxesResponse = await fetch(`${AGENTMAIL_API_URL}/inboxes`, {
      headers: {
        Authorization: `Bearer ${AGENTMAIL_API_KEY}`,
      },
    });

    if (!inboxesResponse.ok) {
      const text = await inboxesResponse.text();
      console.error("AgentMail inboxes error:", inboxesResponse.status, text);
      return NextResponse.json(
        { error: "Failed to fetch inboxes from AgentMail" },
        { status: 500 }
      );
    }

    const inboxesData = await inboxesResponse.json();
    const inboxes: AgentMailInbox[] = inboxesData.inboxes || [];

    if (inboxes.length === 0) {
      return NextResponse.json({
        message: "No inboxes found",
        imported: 0,
        analyzed: 0,
      });
    }

    const collection = await getEmailsCollection();
    let totalImported = 0;
    let totalAnalyzed = 0;

    // Process each inbox
    for (const inbox of inboxes) {
      // Fetch recent messages from this inbox
      const messagesResponse = await fetch(
        `${AGENTMAIL_API_URL}/inboxes/${inbox.inbox_id}/messages?limit=50`,
        {
          headers: {
            Authorization: `Bearer ${AGENTMAIL_API_KEY}`,
          },
        }
      );

      if (!messagesResponse.ok) {
        console.error(`Failed to fetch messages for inbox ${inbox.inbox_id}`);
        continue;
      }

      const messagesData = await messagesResponse.json();
      const messages: AgentMailMessage[] = messagesData.messages || [];

      for (const msg of messages) {
        // Check if we already have this message
        const existing = await collection.findOne({ message_id: msg.message_id });
        if (existing) {
          continue; // Skip already imported messages
        }

        // Fetch full message details (includes text/html body)
        const fullMessage = await fetchMessageDetails(inbox.inbox_id, msg.message_id);
        if (!fullMessage) {
          continue;
        }

        // Analyze with OpenAI
        const analysis = await analyzeEmail({
          subject: fullMessage.subject || null,
          text: fullMessage.text || null,
          from: fullMessage.from,
        });

        // Create email document
        const emailDoc: Omit<MonitoredEmail, "_id"> = {
          message_id: fullMessage.message_id,
          inbox_id: fullMessage.inbox_id,
          thread_id: fullMessage.thread_id,
          from: fullMessage.from,
          to: fullMessage.to || [],
          cc: fullMessage.cc || null,
          subject: fullMessage.subject || null,
          preview: fullMessage.preview || null,
          text: fullMessage.text || null,
          html: fullMessage.html || null,
          attachments: (fullMessage.attachments || []).map((a) => ({
            attachment_id: a.attachment_id,
            filename: a.filename || null,
            size: a.size,
            content_type: a.content_type || null,
          })),
          labels: fullMessage.labels || [],
          timestamp: fullMessage.timestamp,
          analysis,
          read: false,
          starred: false,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        };

        await collection.insertOne(emailDoc);
        totalImported++;
        if (analysis.category !== "other" || analysis.confidence > 0) {
          totalAnalyzed++;
        }
      }
    }

    return NextResponse.json({
      message: `Successfully imported ${totalImported} new emails`,
      imported: totalImported,
      analyzed: totalAnalyzed,
      inboxes_checked: inboxes.length,
    });
  } catch (error) {
    console.error("Error refreshing emails:", error);
    return NextResponse.json(
      { error: "Failed to refresh emails" },
      { status: 500 }
    );
  }
}
