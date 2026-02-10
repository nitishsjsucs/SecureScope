"use client";

import { useState } from "react";
import { ScrollText } from "lucide-react";
import { ReportBuilder } from "@/components/report-builder";
import { PdfPreview } from "@/components/pdf-preview";
import type { IncidentReportData } from "@/lib/types";

export default function ReportsPage() {
  const [reportData, setReportData] = useState<Partial<IncidentReportData> | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const handlePreview = (data: Partial<IncidentReportData>) => {
    setReportData({ ...data }); // Create new object to trigger re-render
  };

  return (
    <main className="container mx-auto max-w-7xl px-4 py-6">
      {/* Page Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#059669] to-[#047857] flex items-center justify-center">
            <ScrollText className="h-5 w-5 text-white" />
          </div>
          <div>
            <h1 className="font-display text-2xl font-semibold text-[#1F2937]">
              Incident Report Generator
            </h1>
            <p className="text-sm text-[#6B7280]">
              Create professional security incident reports with CVE data
            </p>
          </div>
        </div>
      </div>

      {/* Two-Column Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ minHeight: "calc(100vh - 200px)" }}>
        {/* Left: Form */}
        <div className="bg-white rounded-xl border border-[#D1D5DB] p-6 overflow-y-auto max-h-[calc(100vh-180px)]">
          <ReportBuilder
            onPreview={handlePreview}
            isGenerating={isGenerating}
            setIsGenerating={setIsGenerating}
          />
        </div>

        {/* Right: Preview */}
        <div className="h-[calc(100vh-180px)] sticky top-24">
          <PdfPreview
            reportData={reportData}
            isLoading={isGenerating}
          />
        </div>
      </div>
    </main>
  );
}
