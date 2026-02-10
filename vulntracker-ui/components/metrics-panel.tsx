import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/severity-badge";
import { ChatterScoreDisplay } from "@/components/chatter-score";
import {
  cn,
  formatEpssScore,
  formatEpssPercentile,
  formatDate,
  getSeverityFromScore,
} from "@/lib/utils";
import type { CveMetrics, CvssMetric } from "@/lib/types";
import {
  AlertTriangle,
  TrendingUp,
  Shield,
  Calendar,
} from "lucide-react";

interface MetricsPanelProps {
  metrics: CveMetrics;
  chatterScore?: number | null;
  className?: string;
}

// Helper to check if a CVSS metric has a valid score
function hasValidScore(metric: CvssMetric | undefined): metric is CvssMetric {
  return metric?.data?.score !== undefined && metric.data.score !== null;
}

export function MetricsPanel({ metrics, chatterScore, className }: MetricsPanelProps) {
  return (
    <div className={cn("grid gap-4 md:grid-cols-2 lg:grid-cols-4", className)}>
      {/* Chatter Score */}
      {chatterScore !== null && chatterScore !== undefined && (
        <ChatterScoreDisplay score={chatterScore} />
      )}

      {/* CVSS v4.0 */}
      {hasValidScore(metrics.cvssV4_0) && (
        <CvssCard
          title="CVSS v4.0"
          metric={metrics.cvssV4_0}
          icon={<Shield className="h-4 w-4" />}
        />
      )}

      {/* CVSS v3.1 */}
      {hasValidScore(metrics.cvssV3_1) && (
        <CvssCard
          title="CVSS v3.1"
          metric={metrics.cvssV3_1}
          icon={<Shield className="h-4 w-4" />}
        />
      )}

      {/* CVSS v3.0 (if no v3.1) */}
      {!hasValidScore(metrics.cvssV3_1) && hasValidScore(metrics.cvssV3_0) && (
        <CvssCard
          title="CVSS v3.0"
          metric={metrics.cvssV3_0}
          icon={<Shield className="h-4 w-4" />}
        />
      )}

      {/* CVSS v2.0 */}
      {hasValidScore(metrics.cvssV2_0) && (
        <CvssCard
          title="CVSS v2.0"
          metric={metrics.cvssV2_0}
          icon={<Shield className="h-4 w-4" />}
        />
      )}

      {/* EPSS */}
      {metrics.epss?.score !== undefined && metrics.epss?.percentile !== undefined && (
        <EpssCard epss={metrics.epss} />
      )}

      {/* KEV */}
      {metrics.kev && <KevCard kev={metrics.kev} />}
    </div>
  );
}

interface CvssCardProps {
  title: string;
  metric: CvssMetric;
  icon: React.ReactNode;
}

function CvssCard({ title, metric, icon }: CvssCardProps) {
  const severity = getSeverityFromScore(metric.data.score);

  return (
    <Card className="border-[#D1D5DB]">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-[#4B5563]">
          {title}
        </CardTitle>
        <div className={cn("p-1.5 rounded-lg", severity.bgColor, severity.color)}>
          {icon}
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className={cn("text-3xl font-bold", severity.color)}>
            {metric.data.score.toFixed(1)}
          </span>
          <SeverityBadge score={metric.data.score} showScore={false} size="sm" />
        </div>
        {metric.data.vector && (
          <p className="mt-2 text-xs text-[#6B7280] font-mono break-all">
            {metric.data.vector}
          </p>
        )}
      </CardContent>
    </Card>
  );
}

interface EpssCardProps {
  epss: NonNullable<CveMetrics["epss"]>;
}

function EpssCard({ epss }: EpssCardProps) {
  // EPSS score > 0.1 (10%) is considered high
  const isHigh = epss.score > 0.1;

  return (
    <Card className="border-[#D1D5DB]">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-[#4B5563]">
          EPSS Score
        </CardTitle>
        <div
          className={cn(
            "p-1.5 rounded-lg",
            isHigh ? "bg-orange-50 text-orange-500" : "bg-blue-50 text-blue-600"
          )}
        >
          <TrendingUp className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span
            className={cn(
              "text-3xl font-bold",
              isHigh ? "text-orange-500" : "text-blue-600"
            )}
          >
            {formatEpssScore(epss.score)}
          </span>
        </div>
        <p className="mt-1 text-sm text-[#4B5563]">
          {formatEpssPercentile(epss.percentile)} percentile
        </p>
        <p className="mt-1 text-xs text-[#6B7280]">
          Probability of exploitation in next 30 days
        </p>
      </CardContent>
    </Card>
  );
}

interface KevCardProps {
  kev: NonNullable<CveMetrics["kev"]>;
}

function KevCard({ kev }: KevCardProps) {
  return (
    <Card className="border-[#EB5B3C]/20 bg-[#FEF0ED]/50">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-[#EB5B3C]">
          Known Exploited
        </CardTitle>
        <div className="p-1.5 rounded-lg bg-[#FEF0ED] text-[#EB5B3C]">
          <AlertTriangle className="h-4 w-4" />
        </div>
      </CardHeader>
      <CardContent>
        <Badge variant="destructive" className="mb-2">
          CISA KEV
        </Badge>
        <div className="space-y-1 text-sm">
          {kev.dateAdded && (
            <p className="flex items-center gap-1 text-[#4B5563]">
              <Calendar className="h-3 w-3" />
              Added: {formatDate(kev.dateAdded)}
            </p>
          )}
          {kev.dueDate && (
            <p className="flex items-center gap-1 text-[#EB5B3C] font-medium">
              <Calendar className="h-3 w-3" />
              Due: {formatDate(kev.dueDate)}
            </p>
          )}
        </div>
        {kev.knownRansomwareCampaignUse === "Known" && (
          <Badge variant="destructive" className="mt-2">
            Ransomware
          </Badge>
        )}
      </CardContent>
    </Card>
  );
}
