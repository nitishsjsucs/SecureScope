import { NextRequest, NextResponse } from "next/server";
import { getCvesCollection, getAiScoredCvesCollection } from "@/lib/mongodb";

interface RouteParams {
  params: Promise<{ id: string }>;
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params;
    const collection = await getCvesCollection();

    // We use CVE ID strings as _id, not ObjectId
    const cve = await collection.findOne({ _id: id as unknown as import("mongodb").ObjectId });

    if (!cve) {
      return NextResponse.json(
        { error: "CVE not found" },
        { status: 404 }
      );
    }

    const metrics = cve.metrics || {};
    
    // Check if CVE has official CVSS score
    const hasOfficialScore = metrics.cvssV4_0?.data?.score ||
                            metrics.cvssV3_1?.data?.score ||
                            metrics.cvssV3_0?.data?.score ||
                            metrics.cvssV2_0?.data?.score;
    
    // If no official score, check for AI score
    if (!hasOfficialScore) {
      const aiScoredCollection = await getAiScoredCvesCollection();
      const aiScore = await aiScoredCollection.findOne({ _id: id as unknown as import("mongodb").ObjectId });
      
      if (aiScore) {
        metrics.ai_score = {
          score: aiScore.ai_cvss_score as number,
          version: "4.0",
          vector: aiScore.ai_cvss_vector as string | undefined,
          confidence: aiScore.ai_confidence as number || 0.8,
          reasoning: aiScore.ai_severity as string | undefined,
          scored_at: aiScore.ai_scored_at as string,
          model: aiScore.ai_method as string | undefined,
        };
      }
    }

    // Transform document to match expected API format
    const result = {
      cve_id: cve._id,
      description: cve.description,
      title: cve.title,
      metrics,
      vendors: cve.vendors || [],
      weaknesses: cve.weaknesses || [],
      created_at: cve.created_at?.toISOString() || null,
      updated_at: cve.updated_at?.toISOString() || null,
      sexysecure: cve.sexysecure || null,
      sources: cve.sources || [],
      advisories: cve.advisories || [],
      chatter_score: cve.chatter_score ?? null,
    };

    return NextResponse.json(result);
  } catch (error) {
    console.error("Error fetching CVE:", error);
    return NextResponse.json(
      { error: "Failed to fetch CVE" },
      { status: 500 }
    );
  }
}
