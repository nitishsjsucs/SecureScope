import { NextRequest, NextResponse } from "next/server";
import { unstable_cache } from "next/cache";
import { getCvesCollection, getAiScoredCvesCollection } from "@/lib/mongodb";
import { Sort } from "mongodb";

const PAGE_SIZE = 20;
const COUNT_CACHE_TTL = 60; // 1 minute for count cache

// Sort options mapping
const SORT_OPTIONS: Record<string, Sort> = {
  "-updated_at": { updated_at: -1 },
  "updated_at": { updated_at: 1 },
  "-created_at": { created_at: -1 },
  "created_at": { created_at: 1 },
  "-cvss": { "metrics.cvssV3_1.data.score": -1, "metrics.cvssV4_0.data.score": -1, updated_at: -1 },
  "cvss": { "metrics.cvssV3_1.data.score": 1, updated_at: -1 },
};

// Cache the total count (expensive on large collections)
function createCachedCount(filterKey: string, filter: Record<string, unknown>) {
  return unstable_cache(
    async () => {
      const collection = await getCvesCollection();
      return collection.countDocuments(filter);
    },
    [`cve-count-${filterKey}`],
    { revalidate: COUNT_CACHE_TTL, tags: ["cves", "cve-count"] }
  );
}

export async function GET(request: NextRequest) {
  try {
    const searchParams = request.nextUrl.searchParams;
    const page = Math.max(1, parseInt(searchParams.get("page") || "1", 10));
    const sortParam = searchParams.get("sort") || "-created_at";
    const verified = searchParams.get("verified");
    const status = searchParams.get("status");

    const collection = await getCvesCollection();

    // Build query filter
    const filter: Record<string, unknown> = {};
    
    if (verified === "true") {
      filter["sexysecure.verified"] = true;
    } else if (verified === "false") {
      filter["sexysecure.verified"] = false;
    }
    
    if (status) {
      filter["sexysecure.status"] = status;
    }

    // Create a cache key based on filter params
    const filterKey = `v${verified || "all"}-s${status || "all"}`;

    // Get cached count (much faster for repeated requests)
    const getCachedCount = createCachedCount(filterKey, filter);
    const count = await getCachedCount();

    // Get sort option
    const sort = SORT_OPTIONS[sortParam] || SORT_OPTIONS["-created_at"];

    // Fetch CVEs (not cached - data should be fresh)
    const skip = (page - 1) * PAGE_SIZE;
    const cves = await collection
      .find(filter)
      .sort(sort)
      .skip(skip)
      .limit(PAGE_SIZE)
      .toArray();

    // Check if any CVEs are missing CVSS scores and need AI scores
    const cveIdsNeedingAiScores = cves
      .filter((cve) => {
        const metrics = cve.metrics || {};
        return !metrics.cvssV4_0?.data?.score &&
               !metrics.cvssV3_1?.data?.score &&
               !metrics.cvssV3_0?.data?.score &&
               !metrics.cvssV2_0?.data?.score;
      })
      .map((cve) => String(cve._id));

    // Fetch AI scores for CVEs that need them
    // Note: ai_scored_cves collection uses _id as the CVE ID (e.g., "CVE-2024-1234")
    let aiScoresMap: Map<string, Record<string, unknown>> = new Map();
    if (cveIdsNeedingAiScores.length > 0) {
      const aiScoredCollection = await getAiScoredCvesCollection();
      const aiScores = await aiScoredCollection
        .find({ _id: { $in: cveIdsNeedingAiScores } } as Record<string, unknown>)
        .toArray();
      
      aiScoresMap = new Map(aiScores.map((s) => [String(s._id), s]));
    }

    // Transform documents to match expected API format
    const results = cves.map((cve) => {
      const cveId = String(cve._id);
      const metrics = cve.metrics || {};
      
      // Check if we need to add AI score
      const hasOfficialScore = metrics.cvssV4_0?.data?.score ||
                              metrics.cvssV3_1?.data?.score ||
                              metrics.cvssV3_0?.data?.score ||
                              metrics.cvssV2_0?.data?.score;
      
      // If no official score, check for AI score
      // Field mapping from ai_scored_cves collection:
      // - ai_cvss_score -> score
      // - ai_cvss_vector -> vector  
      // - ai_confidence -> confidence
      // - ai_severity -> severity
      // - ai_scored_at -> scored_at
      // - ai_method -> model (repurposed)
      if (!hasOfficialScore && aiScoresMap.has(cveId)) {
        const aiScore = aiScoresMap.get(cveId)!;
        metrics.ai_score = {
          score: aiScore.ai_cvss_score as number,
          version: "4.0", // The vectors appear to be CVSS 4.0 format
          vector: aiScore.ai_cvss_vector as string | undefined,
          confidence: aiScore.ai_confidence as number || 0.8,
          reasoning: aiScore.ai_severity as string | undefined,
          scored_at: aiScore.ai_scored_at as string,
          model: aiScore.ai_method as string | undefined,
        };
      }
      
      return {
        cve_id: cveId,
        description: cve.description,
        title: cve.title,
        metrics,
        vendors: cve.vendors || [],
        weaknesses: cve.weaknesses || [],
        created_at: cve.created_at?.toISOString() || null,
        updated_at: cve.updated_at?.toISOString() || null,
        sexysecure: cve.sexysecure || null,
        sources: cve.sources || [],
        chatter_score: cve.chatter_score ?? null,
      };
    });

    // Build pagination URLs
    const baseUrl = "/api/cve";
    const totalPages = Math.ceil(count / PAGE_SIZE);
    const buildUrl = (p: number) => {
      const params = new URLSearchParams();
      params.set("page", p.toString());
      if (sortParam !== "-created_at") params.set("sort", sortParam);
      if (verified) params.set("verified", verified);
      if (status) params.set("status", status);
      return `${baseUrl}?${params.toString()}`;
    };

    return NextResponse.json({
      count,
      next: page < totalPages ? buildUrl(page + 1) : null,
      previous: page > 1 ? buildUrl(page - 1) : null,
      results,
    });
  } catch (error) {
    console.error("Error fetching CVEs:", error);
    return NextResponse.json(
      { error: "Failed to fetch CVEs" },
      { status: 500 }
    );
  }
}
