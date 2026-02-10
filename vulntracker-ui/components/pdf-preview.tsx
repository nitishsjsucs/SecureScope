"use client";

import { useState, useEffect } from "react";
import { FileText, Maximize2, Download, RefreshCw, Loader2 } from "lucide-react";
import { pdf } from "@react-pdf/renderer";
import { ReportPdfDocument } from "./report-pdf-template";
import type { IncidentReportData } from "@/lib/types";

interface PdfPreviewProps {
  reportData: Partial<IncidentReportData> | null;
  isLoading?: boolean;
  onDownload?: () => void;
}

export function PdfPreview({ reportData, isLoading }: PdfPreviewProps) {
  const [pdfUrl, setPdfUrl] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generate PDF when reportData changes
  useEffect(() => {
    if (!reportData) {
      setPdfUrl(null);
      return;
    }

    let cancelled = false;

    async function generatePdf() {
      setIsGenerating(true);
      setError(null);

      try {
        const blob = await pdf(<ReportPdfDocument data={reportData!} />).toBlob();
        
        if (cancelled) return;
        
        // Revoke old URL
        if (pdfUrl) {
          URL.revokeObjectURL(pdfUrl);
        }
        
        const url = URL.createObjectURL(blob);
        setPdfUrl(url);
      } catch (err) {
        console.error("PDF generation error:", err);
        if (!cancelled) {
          setError("Failed to generate PDF preview");
        }
      } finally {
        if (!cancelled) {
          setIsGenerating(false);
        }
      }
    }

    generatePdf();

    return () => {
      cancelled = true;
    };
  }, [reportData]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (pdfUrl) {
        URL.revokeObjectURL(pdfUrl);
      }
    };
  }, []);

  const handleDownload = async () => {
    if (!reportData) return;

    try {
      const blob = await pdf(<ReportPdfDocument data={reportData} />).toBlob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident-report-${reportData.report_id || new Date().toISOString().split("T")[0]}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      console.error("Download error:", err);
    }
  };

  if (!reportData && !isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8 bg-[#F9FAFB] rounded-xl border-2 border-dashed border-[#D1D5DB]">
        <div className="w-16 h-16 rounded-2xl bg-[#E5E7EB] flex items-center justify-center mb-4">
          <FileText className="h-8 w-8 text-[#6B7280]" />
        </div>
        <h3 className="font-semibold text-[#1F2937] mb-2">No Preview Available</h3>
        <p className="text-sm text-[#6B7280] max-w-xs">
          Fill out the form and click &quot;Preview Report&quot; to see your incident report here.
        </p>
      </div>
    );
  }

  if (isLoading || isGenerating) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8 bg-[#F9FAFB] rounded-xl border border-[#D1D5DB]">
        <div className="relative w-16 h-16 mb-4">
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-[#059669] to-[#047857] animate-pulse" />
          <div className="absolute inset-0 flex items-center justify-center">
            <Loader2 className="h-8 w-8 text-white animate-spin" />
          </div>
        </div>
        <h3 className="font-semibold text-[#1F2937] mb-2">Generating Preview...</h3>
        <p className="text-sm text-[#6B7280]">
          This may take a moment
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center p-8 bg-[#FEF2F2] rounded-xl border border-[#FECACA]">
        <div className="w-16 h-16 rounded-2xl bg-[#FEE2E2] flex items-center justify-center mb-4">
          <FileText className="h-8 w-8 text-[#DC2626]" />
        </div>
        <h3 className="font-semibold text-[#DC2626] mb-2">Preview Error</h3>
        <p className="text-sm text-[#B91C1C]">{error}</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-white rounded-xl border border-[#D1D5DB] overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#F9FAFB] border-b border-[#E5E7EB]">
        <span className="text-sm font-medium text-[#1F2937]">Report Preview</span>
        <div className="flex items-center gap-1">
          <button
            onClick={handleDownload}
            className="p-1.5 rounded-lg text-[#6B7280] hover:text-[#1F2937] hover:bg-[#E5E7EB] transition-colors"
            title="Download PDF"
          >
            <Download className="h-4 w-4" />
          </button>
          {pdfUrl && (
            <a
              href={pdfUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="p-1.5 rounded-lg text-[#6B7280] hover:text-[#1F2937] hover:bg-[#E5E7EB] transition-colors"
              title="Open in new tab"
            >
              <Maximize2 className="h-4 w-4" />
            </a>
          )}
        </div>
      </div>

      {/* PDF Embed */}
      <div className="flex-1 bg-[#525659]">
        {pdfUrl && (
          <iframe
            src={pdfUrl}
            className="w-full h-full"
            title="Report Preview"
          />
        )}
      </div>
    </div>
  );
}
