import { NextRequest, NextResponse } from "next/server";
import { getCvesCollection, getAiScoredCvesCollection } from "@/lib/mongodb";
import { getBestCvssScore, getSeverityFromScore } from "@/lib/utils";

const MAX_RESULTS = 20;

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const query = searchParams.get("q")?.trim() || "";

    if (query.length < 2) {
      return NextResponse.json({ results: [] });
    }

    const collection = await getCvesCollection();

    // Build search filter - support CVE ID search and description search
    const isCveId = /^CVE-?\d{4}/i.test(query);
    
    let filter: Record<string, unknown>;
    if (isCveId) {
      // Search by CVE ID prefix
      const normalizedQuery = query.toUpperCase().replace(/^CVE-?/, "CVE-");
      filter = {
        _id: { $regex: `^${normalizedQuery}`, $options: "i" },
      };
    } else {
      // Search in description using text index or regex
      filter = {
        $or: [
          { description: { $regex: query, $options: "i" } },
          { _id: { $regex: query, $options: "i" } },
        ],
      };
    }

    // Fetch matching CVEs
    const cves = await collection
      .find(filter)
      .sort({ updated_at: -1 })
      .limit(MAX_RESULTS)
      .toArray();

    // Get AI scores for CVEs without official scores
    const cveIdsNeedingAiScores = cves
      .filter((cve) => {
        const metrics = cve.metrics || {};
        return !metrics.cvssV4_0?.data?.score &&
               !metrics.cvssV3_1?.data?.score &&
               !metrics.cvssV3_0?.data?.score &&
               !metrics.cvssV2_0?.data?.score;
      })
      .map((cve) => String(cve._id));

    let aiScoresMap: Map<string, Record<string, unknown>> = new Map();
    if (cveIdsNeedingAiScores.length > 0) {
      const aiScoredCollection = await getAiScoredCvesCollection();
      const aiScores = await aiScoredCollection
        .find({ _id: { $in: cveIdsNeedingAiScores } } as Record<string, unknown>)
        .toArray();
      aiScoresMap = new Map(aiScores.map((s) => [String(s._id), s]));
    }

    // Transform to search results format
    const results = cves.map((cve) => {
      const cveId = String(cve._id);
      const metrics = cve.metrics || {};

      // Add AI score if needed
      const hasOfficialScore = metrics.cvssV4_0?.data?.score ||
                              metrics.cvssV3_1?.data?.score ||
                              metrics.cvssV3_0?.data?.score ||
                              metrics.cvssV2_0?.data?.score;

      if (!hasOfficialScore && aiScoresMap.has(cveId)) {
        const aiScore = aiScoresMap.get(cveId)!;
        metrics.ai_score = {
          score: aiScore.ai_cvss_score as number,
          version: "4.0",
          vector: aiScore.ai_cvss_vector as string | undefined,
          confidence: aiScore.ai_confidence as number || 0.8,
          scored_at: aiScore.ai_scored_at as string,
          model: aiScore.ai_method as string | undefined,
        };
      }

      // Get best available score
      const { score, isAiScored } = getBestCvssScore(metrics);
      const { label: severity } = getSeverityFromScore(score);

      return {
        cve_id: cveId,
        description: cve.description 
          ? cve.description.slice(0, 200) + (cve.description.length > 200 ? "..." : "")
          : null,
        score,
        severity,
        isAiScored,
      };
    });

    return NextResponse.json({ results });
  } catch (error) {
    console.error("Error searching CVEs:", error);
    return NextResponse.json(
      { error: "Failed to search CVEs" },
      { status: 500 }
    );
  }
}
