import { NextRequest, NextResponse } from "next/server";
import { spawn } from "child_process";
import { writeFile, readFile, unlink, mkdir } from "fs/promises";
import { join } from "path";
import { randomUUID } from "crypto";
import { tmpdir } from "os";
import type { IncidentReportData } from "@/lib/types";

// Path to the Python incident report generator
const PYTHON_SCRIPT_DIR = "/Volumes/stuff/Projects/nvd/incident_report_generator";

// Generate a unique report ID
function generateReportId(): string {
  const date = new Date();
  const dateStr = date.toISOString().split("T")[0].replace(/-/g, "");
  const random = Math.floor(Math.random() * 10000).toString().padStart(4, "0");
  return `IR-${dateStr}-${random}`;
}

// Ensure temp directory exists
async function ensureTempDir(): Promise<string> {
  const tempDir = join(tmpdir(), "sexysecure-reports");
  try {
    await mkdir(tempDir, { recursive: true });
  } catch {
    // Directory might already exist
  }
  return tempDir;
}

export async function POST(request: NextRequest) {
  const uuid = randomUUID();
  let jsonPath = "";
  let pdfPath = "";

  try {
    const body = await request.json();
    const reportData: Partial<IncidentReportData> = body;

    // Auto-generate report ID if not provided
    if (!reportData.report_id) {
      reportData.report_id = generateReportId();
    }

    // Ensure report date is set
    if (!reportData.report_date) {
      reportData.report_date = new Date().toISOString().split("T")[0];
    }

    // Set defaults for required Python fields
    const fullReportData = {
      report_id: reportData.report_id,
      report_date: reportData.report_date,
      classification: reportData.classification || "CONFIDENTIAL",
      incident_title: reportData.incident_title || "",
      incident_date: reportData.incident_date || "",
      incident_time: reportData.incident_time || "",
      detection_date: reportData.detection_date || "",
      severity: reportData.severity || "Medium",
      status: reportData.status || "Investigating",
      affected_systems: reportData.affected_systems || [],
      affected_networks: reportData.affected_networks || [],
      business_impact: reportData.business_impact || "",
      threat_actor: reportData.threat_actor || "",
      attack_vector: reportData.attack_vector || "",
      cves_exploited: reportData.cves_exploited || [],
      mitre_techniques: reportData.mitre_techniques || [],
      malicious_ips: reportData.malicious_ips || [],
      malicious_domains: reportData.malicious_domains || [],
      malicious_urls: reportData.malicious_urls || [],
      file_hashes: reportData.file_hashes || [],
      timeline_events: reportData.timeline_events || [],
      containment_actions: reportData.containment_actions || [],
      eradication_actions: reportData.eradication_actions || [],
      recovery_actions: reportData.recovery_actions || [],
      recommendations: reportData.recommendations || [],
      prepared_by: reportData.prepared_by || "",
      reviewed_by: reportData.reviewed_by || "",
      approved_by: reportData.approved_by || "",
      distribution_list: reportData.distribution_list || [],
      source_files: reportData.source_files || [],
      pages_analyzed: reportData.pages_analyzed || 0,
    };

    // Create temp directory and file paths
    const tempDir = await ensureTempDir();
    jsonPath = join(tempDir, `report-${uuid}.json`);
    pdfPath = join(tempDir, `report-${uuid}.pdf`);

    // Write JSON data to temp file
    await writeFile(jsonPath, JSON.stringify(fullReportData, null, 2));

    // Run Python script to generate PDF
    const pdfGenerated = await new Promise<boolean>((resolve) => {
      const pythonProcess = spawn("python3", [
        "-m", "incident_report_generator.cli",
        "fill",
        "--input", jsonPath,
        "--output", pdfPath,
        "--classification", fullReportData.classification,
      ], {
        cwd: PYTHON_SCRIPT_DIR.replace("/incident_report_generator", ""),
        env: { ...process.env, PYTHONPATH: PYTHON_SCRIPT_DIR.replace("/incident_report_generator", "") },
      });

      let stderr = "";

      pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
      });

      pythonProcess.on("close", (code) => {
        if (code !== 0) {
          console.error("Python script error:", stderr);
          resolve(false);
        } else {
          resolve(true);
        }
      });

      pythonProcess.on("error", (err) => {
        console.error("Failed to start Python process:", err);
        resolve(false);
      });

      // Timeout after 30 seconds
      setTimeout(() => {
        pythonProcess.kill();
        resolve(false);
      }, 30000);
    });

    if (!pdfGenerated) {
      return NextResponse.json(
        { error: "Failed to generate PDF report" },
        { status: 500 }
      );
    }

    // Read the generated PDF
    const pdfBuffer = await readFile(pdfPath);

    // Cleanup temp files
    await Promise.all([
      unlink(jsonPath).catch(() => {}),
      unlink(pdfPath).catch(() => {}),
    ]);

    // Return PDF as response
    return new NextResponse(pdfBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `inline; filename="${fullReportData.report_id}.pdf"`,
        "Content-Length": pdfBuffer.length.toString(),
      },
    });
  } catch (error) {
    console.error("Error generating report:", error);

    // Cleanup on error
    await Promise.all([
      jsonPath ? unlink(jsonPath).catch(() => {}) : Promise.resolve(),
      pdfPath ? unlink(pdfPath).catch(() => {}) : Promise.resolve(),
    ]);

    return NextResponse.json(
      { error: "Failed to generate report" },
      { status: 500 }
    );
  }
}
