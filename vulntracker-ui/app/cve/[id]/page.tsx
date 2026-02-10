import { notFound } from "next/navigation";
import Link from "next/link";
import { getCve } from "@/lib/api";
import { MetricsPanel } from "@/components/metrics-panel";
import { SeverityBadge } from "@/components/severity-badge";
import { SexySecureBadge } from "@/components/sexysecure-badge";
import { SourcesSection } from "@/components/source-card";
import { VendorChip } from "@/components/vendor-chip";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import {
  getBestCvssScore,
  formatDate,
  formatDateTime,
  parseVendorString,
  humanize,
} from "@/lib/utils";
import {
  Calendar,
  Clock,
  ExternalLink,
  AlertTriangle,
  Building2,
  Package,
  ShieldAlert,
  FileText,
  Sparkles,
  Bot,
} from "lucide-react";

interface PageProps {
  params: Promise<{ id: string }>;
}

export async function generateMetadata({ params }: PageProps) {
  const { id } = await params;
  return {
    title: `${id} - VulnTracker`,
    description: `Details for vulnerability ${id}`,
  };
}

export default async function CveDetailPage({ params }: PageProps) {
  const { id } = await params;

  try {
    const cve = await getCve(id);
    const { score, version, isAiScored } = getBestCvssScore(cve.metrics);
    const isVerified = cve.sexysecure?.verified ?? false;
    const aiScoreData = cve.metrics?.ai_score;

    // Group vendors and products
    const vendorProducts = new Map<string, string[]>();
    for (const v of cve.vendors) {
      const parsed = parseVendorString(v);
      if (!vendorProducts.has(parsed.vendor)) {
        vendorProducts.set(parsed.vendor, []);
      }
      if (parsed.product) {
        vendorProducts.get(parsed.vendor)!.push(parsed.product);
      }
    }

    return (
      <div className="space-y-8">
        {/* Header */}
        <div className="space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <h1 className="text-3xl font-mono font-bold text-[#1F2937]">
                  {cve.cve_id}
                </h1>
                <SexySecureBadge
                  verified={isVerified}
                  verifiedAt={cve.sexysecure?.verified_at}
                  verifiedBy={cve.sexysecure?.verified_by}
                  size="lg"
                  showLabel={true}
                />
              </div>
              {cve.title && (
                <p className="text-lg text-[#4B5563]">{cve.title}</p>
              )}
            </div>
            <SeverityBadge score={score} size="lg" isAiScored={isAiScored} />
          </div>

          {/* AI Score Notice */}
          {isAiScored && aiScoreData && (
            <div className="flex items-start gap-3 p-4 rounded-xl bg-gradient-to-r from-[#F0FDF4] to-[#ECFDF5] border border-[#059669]/20">
              <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#059669] to-[#047857] flex items-center justify-center flex-shrink-0">
                <Sparkles className="h-5 w-5 text-white" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-semibold text-[#047857]">AI-Generated Score</span>
                  <Badge variant="outline" className="text-xs border-[#059669]/30 text-[#059669] bg-white">
                    {Math.round((aiScoreData.confidence || 0.8) * 100)}% confidence
                  </Badge>
                </div>
                <p className="text-sm text-[#4B5563] leading-relaxed">
                  This CVE doesn&apos;t have an official CVSS score yet. Our AI agents analyzed the vulnerability 
                  description and generated an estimated score of <span className="font-semibold text-[#1F2937]">{score?.toFixed(1)}</span> ({aiScoreData.reasoning || 'N/A'} severity).
                  {aiScoreData.model && (
                    <span className="text-[#6B7280]"> Scoring method: {aiScoreData.model.replace(/_/g, ' ')}.</span>
                  )}
                </p>
                <p className="text-xs text-[#6B7280] mt-1.5 flex items-center gap-1">
                  <Bot className="h-3 w-3" />
                  Scored by SexySecure AI on {aiScoreData.scored_at ? formatDate(aiScoreData.scored_at) : 'N/A'}
                </p>
              </div>
            </div>
          )}

          {/* Date info */}
          <div className="flex flex-wrap items-center gap-4 text-sm text-[#4B5563]">
            <span className="flex items-center gap-1.5">
              <Calendar className="h-4 w-4" />
              Published {formatDate(cve.created_at)}
            </span>
            <span className="flex items-center gap-1.5">
              <Clock className="h-4 w-4" />
              Updated {formatDateTime(cve.updated_at)}
            </span>
            {version && (
              <Badge 
                variant="outline" 
                className={
                  isAiScored 
                    ? "text-[#059669] border-[#059669]/30 bg-[#ECFDF5]" 
                    : "text-[#4B5563] border-[#D1D5DB]"
                }
              >
                {isAiScored && <Sparkles className="h-3 w-3 mr-1" />}
                {isAiScored ? "AI Estimated" : `CVSS ${version}`}
              </Badge>
            )}
          </div>
        </div>

        <Separator className="bg-[#D1D5DB]" />

        {/* Metrics Panel - includes Chatter Score as a card */}
        <section>
          <h2 className="text-lg font-semibold text-[#1F2937] mb-4">
            Metrics & Scores
          </h2>
          <MetricsPanel metrics={cve.metrics} chatterScore={cve.chatter_score} />
        </section>

        {/* Detection Sources */}
        <SourcesSection sources={cve.sources} />

        {/* Advisories */}
        {cve.advisories && cve.advisories.length > 0 && (
          <Card className="border-[#D1D5DB]">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
                <FileText className="h-5 w-5 text-[#4B5563]" />
                Security Advisories
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {cve.advisories.map((advisory) => (
                  <a
                    key={advisory.id}
                    href={advisory.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-between p-3 rounded-lg border border-[#D1D5DB] hover:border-[#059669]/30 hover:bg-[#F9FAFB] transition-all group"
                  >
                    <div className="flex items-center gap-3">
                      <Badge
                        variant="outline"
                        className={
                          advisory.source === "euvd"
                            ? "bg-blue-50 text-blue-700 border-blue-200"
                            : advisory.source === "ghsa"
                            ? "bg-gray-50 text-gray-700 border-gray-200"
                            : advisory.source === "debian"
                            ? "bg-red-50 text-red-700 border-red-200"
                            : "bg-orange-50 text-orange-700 border-orange-200"
                        }
                      >
                        {advisory.source.toUpperCase()}
                      </Badge>
                      <div>
                        <p className="font-mono text-sm text-[#1F2937]">
                          {advisory.id}
                        </p>
                        {advisory.title && (
                          <p className="text-xs text-[#6B7280] mt-0.5 max-w-md truncate">
                            {advisory.title}
                          </p>
                        )}
                      </div>
                    </div>
                    <ExternalLink className="h-4 w-4 text-[#6B7280] group-hover:text-[#059669] transition-colors" />
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Description */}
        {cve.description && (
          <Card className="border-[#D1D5DB]">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
                <AlertTriangle className="h-5 w-5 text-[#4B5563]" />
                Description
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-[#1F2937] leading-relaxed whitespace-pre-wrap">
                {cve.description}
              </p>
            </CardContent>
          </Card>
        )}

        {/* Affected Vendors & Products */}
        {vendorProducts.size > 0 && (
          <Card className="border-[#D1D5DB]">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
                <Building2 className="h-5 w-5 text-[#4B5563]" />
                Affected Vendors & Products
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Array.from(vendorProducts.entries()).map(
                  ([vendor, products]) => (
                    <div
                      key={vendor}
                      className="border-b border-[#D1D5DB] pb-4 last:border-0 last:pb-0"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <Building2 className="h-4 w-4 text-[#6B7280]" />
                        <Link
                          href={`/vendors/${encodeURIComponent(vendor)}`}
                          className="font-medium text-[#1F2937] hover:text-[#059669] transition-colors"
                        >
                          {humanize(vendor)}
                        </Link>
                      </div>
                      {products.length > 0 && (
                        <div className="ml-6 flex flex-wrap gap-2">
                          {products.map((product) => (
                            <Badge
                              key={product}
                              variant="secondary"
                              className="font-normal bg-[#F9FAFB] text-[#1F2937] border-[#D1D5DB]"
                            >
                              <Package className="h-3 w-3 mr-1" />
                              {humanize(product)}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  )
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Weaknesses */}
        {cve.weaknesses.length > 0 && (
          <Card className="border-[#D1D5DB]">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
                <ShieldAlert className="h-5 w-5 text-[#4B5563]" />
                Weaknesses (CWE)
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {cve.weaknesses.map((cwe) => (
                  <a
                    key={cwe}
                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1"
                  >
                    <Badge
                      variant="outline"
                      className="hover:bg-[#ECFDF5] hover:border-[#059669] hover:text-[#047857] transition-colors border-[#D1D5DB] text-[#1F2937]"
                    >
                      {cwe}
                      <ExternalLink className="h-3 w-3 ml-1" />
                    </Badge>
                  </a>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* External Links */}
        <Card className="border-[#D1D5DB]">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2 text-[#1F2937]">
              <ExternalLink className="h-5 w-5 text-[#4B5563]" />
              External References
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-[#059669] hover:text-[#047857] transition-colors"
              >
                NVD
                <ExternalLink className="h-3 w-3" />
              </a>
              <a
                href={`https://www.cve.org/CVERecord?id=${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-[#059669] hover:text-[#047857] transition-colors"
              >
                CVE.org
                <ExternalLink className="h-3 w-3" />
              </a>
              <a
                href={`https://vulners.com/cve/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-sm text-[#059669] hover:text-[#047857] transition-colors"
              >
                Vulners
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  } catch (error) {
    console.error("Error fetching CVE:", error);
    notFound();
  }
}
