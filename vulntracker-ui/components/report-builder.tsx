"use client";

import { useState, useCallback } from "react";
import { 
  FileText, 
  AlertTriangle, 
  Shield, 
  Users, 
  ClipboardList,
  Plus,
  X,
  Loader2,
  Download,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { CveSelector } from "./cve-selector";
import type { 
  IncidentReportData, 
  ReportClassification, 
  IncidentSeverity, 
  IncidentStatus,
  ReportCve,
} from "@/lib/types";

interface ReportBuilderProps {
  onPreview: (data: Partial<IncidentReportData>) => void;
  isGenerating: boolean;
  setIsGenerating: (value: boolean) => void;
}

const SEVERITY_OPTIONS: IncidentSeverity[] = ["Critical", "High", "Medium", "Low"];
const STATUS_OPTIONS: IncidentStatus[] = ["Open", "Investigating", "Contained", "Resolved"];
const CLASSIFICATION_OPTIONS: ReportClassification[] = ["CONFIDENTIAL", "INTERNAL", "PUBLIC"];

function ListInput({
  label,
  placeholder,
  items,
  onItemsChange,
  icon: Icon,
}: {
  label: string;
  placeholder: string;
  items: string[];
  onItemsChange: (items: string[]) => void;
  icon?: React.ComponentType<{ className?: string }>;
}) {
  const [inputValue, setInputValue] = useState("");

  const addItem = () => {
    const trimmed = inputValue.trim();
    if (trimmed && !items.includes(trimmed)) {
      onItemsChange([...items, trimmed]);
      setInputValue("");
    }
  };

  const removeItem = (index: number) => {
    onItemsChange(items.filter((_, i) => i !== index));
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      addItem();
    }
  };

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-[#1F2937]">
        {label}
      </label>
      <div className="flex gap-2">
        <div className="flex-1 flex items-center bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus-within:border-[#059669] focus-within:ring-2 focus-within:ring-[#059669]/20 transition-all">
          {Icon && <Icon className="h-4 w-4 text-[#6B7280] ml-3" />}
          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            className="w-full px-3 py-2 text-sm bg-transparent outline-none text-[#1F2937] placeholder:text-[#6B7280]"
          />
        </div>
        <button
          type="button"
          onClick={addItem}
          className="px-3 py-2 bg-[#059669] text-white rounded-lg hover:bg-[#047857] transition-colors"
        >
          <Plus className="h-4 w-4" />
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-2 mt-2">
          {items.map((item, index) => (
            <span
              key={index}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-[#F9FAFB] border border-[#D1D5DB] rounded-lg text-sm"
            >
              {item}
              <button
                type="button"
                onClick={() => removeItem(index)}
                className="p-0.5 rounded hover:bg-[#EF4444]/10 text-[#6B7280] hover:text-[#EF4444] transition-colors"
              >
                <X className="h-3 w-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

export function ReportBuilder({ onPreview, isGenerating, setIsGenerating }: ReportBuilderProps) {
  // Form state - simplified MVP fields
  const [classification, setClassification] = useState<ReportClassification>("CONFIDENTIAL");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDate, setIncidentDate] = useState(new Date().toISOString().split("T")[0]);
  const [incidentTime, setIncidentTime] = useState(new Date().toTimeString().slice(0, 5));
  const [detectionDate, setDetectionDate] = useState(new Date().toISOString().split("T")[0]);
  const [severity, setSeverity] = useState<IncidentSeverity>("Medium");
  const [status, setStatus] = useState<IncidentStatus>("Investigating");
  
  const [affectedSystems, setAffectedSystems] = useState<string[]>([]);
  const [businessImpact, setBusinessImpact] = useState("");
  
  const [selectedCves, setSelectedCves] = useState<ReportCve[]>([]);
  const [threatActor, setThreatActor] = useState("");
  const [attackVector, setAttackVector] = useState("");
  
  const [recommendations, setRecommendations] = useState<string[]>([]);
  
  const [preparedBy, setPreparedBy] = useState("");
  const [reviewedBy, setReviewedBy] = useState("");

  const [error, setError] = useState<string | null>(null);

  const generateReport = useCallback(async (download: boolean = false) => {
    if (!incidentTitle.trim()) {
      setError("Incident title is required");
      return;
    }

    setError(null);
    setIsGenerating(true);

    try {
      const reportData: Partial<IncidentReportData> = {
        classification,
        incident_title: incidentTitle,
        incident_date: incidentDate,
        incident_time: incidentTime,
        detection_date: detectionDate,
        severity,
        status,
        affected_systems: affectedSystems,
        business_impact: businessImpact,
        cves_exploited: selectedCves.map(c => c.cve_id),
        threat_actor: threatActor,
        attack_vector: attackVector,
        recommendations,
        prepared_by: preparedBy,
        reviewed_by: reviewedBy,
      };

      if (download) {
        // For download, we import pdf dynamically and generate blob
        const { pdf } = await import("@react-pdf/renderer");
        const { ReportPdfDocument } = await import("./report-pdf-template");
        
        const blob = await pdf(<ReportPdfDocument data={reportData} />).toBlob();
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement("a");
        a.href = url;
        a.download = `incident-report-${new Date().toISOString().split("T")[0]}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } else {
        // Preview mode - pass data to parent, PDF will be generated by preview component
        onPreview(reportData);
      }
    } catch (err) {
      console.error("Error generating report:", err);
      setError(err instanceof Error ? err.message : "Failed to generate report");
    } finally {
      setIsGenerating(false);
    }
  }, [
    classification, incidentTitle, incidentDate, incidentTime, detectionDate,
    severity, status, affectedSystems, businessImpact, selectedCves,
    threatActor, attackVector, recommendations, preparedBy, reviewedBy,
    onPreview, setIsGenerating
  ]);

  return (
    <div className="space-y-6">
      {/* Error Message */}
      {error && (
        <div className="p-3 bg-[#FEF2F2] border border-[#FECACA] rounded-lg flex items-center gap-2 text-[#DC2626]">
          <AlertTriangle className="h-4 w-4" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {/* Classification & Header */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <Shield className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Report Classification</h2>
        </div>
        
        <div className="grid grid-cols-3 gap-2">
          {CLASSIFICATION_OPTIONS.map((opt) => (
            <button
              key={opt}
              type="button"
              onClick={() => setClassification(opt)}
              className={cn(
                "px-3 py-2 rounded-lg border text-sm font-medium transition-colors",
                classification === opt
                  ? opt === "CONFIDENTIAL"
                    ? "bg-[#DC2626] text-white border-[#DC2626]"
                    : opt === "INTERNAL"
                    ? "bg-[#F59E0B] text-white border-[#F59E0B]"
                    : "bg-[#059669] text-white border-[#059669]"
                  : "bg-white text-[#4B5563] border-[#D1D5DB] hover:border-[#9CA3AF]"
              )}
            >
              {opt}
            </button>
          ))}
        </div>
      </section>

      {/* Incident Overview */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <FileText className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Incident Overview</h2>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-[#1F2937] mb-1">
              Incident Title <span className="text-[#DC2626]">*</span>
            </label>
            <input
              type="text"
              value={incidentTitle}
              onChange={(e) => setIncidentTitle(e.target.value)}
              placeholder="e.g., Ransomware Attack on Production Servers"
              className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-[#1F2937] mb-1">
                Incident Date
              </label>
              <input
                type="date"
                value={incidentDate}
                onChange={(e) => setIncidentDate(e.target.value)}
                className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#1F2937] mb-1">
                Incident Time
              </label>
              <input
                type="time"
                value={incidentTime}
                onChange={(e) => setIncidentTime(e.target.value)}
                className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
              />
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-[#1F2937] mb-1">
                Detection Date
              </label>
              <input
                type="date"
                value={detectionDate}
                onChange={(e) => setDetectionDate(e.target.value)}
                className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[#1F2937] mb-1">
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
              >
                {SEVERITY_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-[#1F2937] mb-1">
                Status
              </label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value as IncidentStatus)}
                className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
              >
                {STATUS_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>{opt}</option>
                ))}
              </select>
            </div>
          </div>
        </div>
      </section>

      {/* Affected Systems */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <Users className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Affected Systems & Impact</h2>
        </div>

        <ListInput
          label="Affected Systems"
          placeholder="e.g., prod-web-01.internal"
          items={affectedSystems}
          onItemsChange={setAffectedSystems}
        />

        <div>
          <label className="block text-sm font-medium text-[#1F2937] mb-1">
            Business Impact
          </label>
          <textarea
            value={businessImpact}
            onChange={(e) => setBusinessImpact(e.target.value)}
            placeholder="Describe the business impact of this incident..."
            rows={3}
            className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all resize-none"
          />
        </div>
      </section>

      {/* Threat Intelligence */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <AlertTriangle className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Threat Intelligence</h2>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-[#1F2937] mb-1">
              Threat Actor
            </label>
            <input
              type="text"
              value={threatActor}
              onChange={(e) => setThreatActor(e.target.value)}
              placeholder="e.g., APT29, Unknown"
              className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-[#1F2937] mb-1">
              Attack Vector
            </label>
            <input
              type="text"
              value={attackVector}
              onChange={(e) => setAttackVector(e.target.value)}
              placeholder="e.g., Phishing, RCE, Supply Chain"
              className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
            />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-[#1F2937] mb-1">
            CVEs Exploited
          </label>
          <CveSelector
            selectedCves={selectedCves}
            onCvesChange={setSelectedCves}
          />
        </div>
      </section>

      {/* Recommendations */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <ClipboardList className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Recommendations</h2>
        </div>

        <ListInput
          label="Security Recommendations"
          placeholder="e.g., Implement MFA for all privileged accounts"
          items={recommendations}
          onItemsChange={setRecommendations}
        />
      </section>

      {/* Metadata */}
      <section className="space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-[#E5E7EB]">
          <FileText className="h-5 w-5 text-[#059669]" />
          <h2 className="font-semibold text-[#1F2937]">Report Metadata</h2>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-[#1F2937] mb-1">
              Prepared By
            </label>
            <input
              type="text"
              value={preparedBy}
              onChange={(e) => setPreparedBy(e.target.value)}
              placeholder="Your name"
              className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-[#1F2937] mb-1">
              Reviewed By
            </label>
            <input
              type="text"
              value={reviewedBy}
              onChange={(e) => setReviewedBy(e.target.value)}
              placeholder="Reviewer name"
              className="w-full px-3 py-2 bg-[#F9FAFB] rounded-lg border border-[#D1D5DB] focus:border-[#059669] focus:ring-2 focus:ring-[#059669]/20 outline-none text-sm transition-all"
            />
          </div>
        </div>
      </section>

      {/* Actions */}
      <div className="flex gap-3 pt-4 border-t border-[#E5E7EB]">
        <button
          type="button"
          onClick={() => generateReport(false)}
          disabled={isGenerating}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-[#F9FAFB] border border-[#D1D5DB] text-[#1F2937] rounded-lg hover:bg-[#F3F4F6] disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
        >
          {isGenerating ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Eye className="h-4 w-4" />
          )}
          Preview Report
        </button>
        <button
          type="button"
          onClick={() => generateReport(true)}
          disabled={isGenerating}
          className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-[#059669] text-white rounded-lg hover:bg-[#047857] disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
        >
          {isGenerating ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Download className="h-4 w-4" />
          )}
          Download PDF
        </button>
      </div>
    </div>
  );
}
