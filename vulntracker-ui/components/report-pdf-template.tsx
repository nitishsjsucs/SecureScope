"use client";

import { 
  Document, 
  Page, 
  Text, 
  View, 
  StyleSheet,
  Font,
} from "@react-pdf/renderer";
import type { 
  IncidentReportData, 
  ReportClassification,
} from "@/lib/types";

// Register fonts (using system defaults for now)
Font.register({
  family: "Helvetica",
  fonts: [
    { src: "Helvetica" },
    { src: "Helvetica-Bold", fontWeight: "bold" },
  ],
});

// Color palette matching Python template
const colors = {
  headerBg: "#1a365d",
  sectionBg: "#2c5282",
  criticalBg: "#c53030",
  highBg: "#dd6b20",
  mediumBg: "#d69e2e",
  lowBg: "#38a169",
  tableHeaderBg: "#e2e8f0",
  textDark: "#1a202c",
  textGray: "#4a5568",
  borderGray: "#cbd5e0",
  white: "#ffffff",
};

// Get classification banner color
function getClassificationColor(classification: ReportClassification): string {
  switch (classification) {
    case "CONFIDENTIAL":
      return colors.criticalBg;
    case "INTERNAL":
      return colors.highBg;
    case "PUBLIC":
      return colors.lowBg;
    default:
      return colors.criticalBg;
  }
}

// Get severity color
function getSeverityColor(severity: string): string {
  switch (severity) {
    case "Critical":
      return colors.criticalBg;
    case "High":
      return colors.highBg;
    case "Medium":
      return colors.mediumBg;
    case "Low":
      return colors.lowBg;
    default:
      return colors.tableHeaderBg;
  }
}

// Styles
const styles = StyleSheet.create({
  page: {
    padding: 40,
    fontSize: 10,
    fontFamily: "Helvetica",
    color: colors.textDark,
  },
  // Classification banner
  classificationBanner: {
    padding: 8,
    marginBottom: 20,
    textAlign: "center",
  },
  classificationText: {
    color: colors.white,
    fontSize: 12,
    fontWeight: "bold",
    letterSpacing: 2,
  },
  // Title
  title: {
    fontSize: 20,
    fontWeight: "bold",
    textAlign: "center",
    marginBottom: 20,
    color: colors.headerBg,
  },
  // Meta info row
  metaRow: {
    flexDirection: "row",
    marginBottom: 20,
    borderWidth: 1,
    borderColor: colors.borderGray,
  },
  metaCell: {
    flex: 1,
    padding: 8,
    borderRightWidth: 1,
    borderRightColor: colors.borderGray,
  },
  metaCellLast: {
    flex: 1,
    padding: 8,
  },
  metaLabel: {
    fontSize: 8,
    color: colors.textGray,
    marginBottom: 2,
  },
  metaValue: {
    fontSize: 10,
    fontWeight: "bold",
  },
  // Section header
  sectionHeader: {
    backgroundColor: colors.sectionBg,
    padding: 8,
    marginTop: 15,
    marginBottom: 10,
  },
  sectionHeaderText: {
    color: colors.white,
    fontSize: 11,
    fontWeight: "bold",
  },
  // Field group
  fieldGroup: {
    marginBottom: 8,
  },
  fieldLabel: {
    fontSize: 8,
    color: colors.textGray,
    marginBottom: 2,
  },
  fieldValue: {
    fontSize: 10,
    paddingBottom: 4,
  },
  // Table styles
  table: {
    borderWidth: 1,
    borderColor: colors.borderGray,
    marginBottom: 10,
  },
  tableRow: {
    flexDirection: "row",
    borderBottomWidth: 1,
    borderBottomColor: colors.borderGray,
  },
  tableRowLast: {
    flexDirection: "row",
  },
  tableHeader: {
    backgroundColor: colors.tableHeaderBg,
  },
  tableCell: {
    padding: 6,
    flex: 1,
    borderRightWidth: 1,
    borderRightColor: colors.borderGray,
  },
  tableCellLast: {
    padding: 6,
    flex: 1,
  },
  tableCellText: {
    fontSize: 9,
  },
  tableHeaderText: {
    fontSize: 9,
    fontWeight: "bold",
  },
  // Bullet list
  bulletList: {
    marginLeft: 10,
  },
  bulletItem: {
    flexDirection: "row",
    marginBottom: 3,
  },
  bullet: {
    width: 15,
    fontSize: 10,
  },
  bulletText: {
    flex: 1,
    fontSize: 10,
  },
  // CVE badge
  cveBadge: {
    flexDirection: "row",
    alignItems: "center",
    marginBottom: 4,
    marginRight: 8,
  },
  cveId: {
    fontSize: 9,
    fontWeight: "bold",
    marginRight: 4,
  },
  severityBadge: {
    paddingHorizontal: 4,
    paddingVertical: 2,
    borderRadius: 2,
  },
  severityText: {
    fontSize: 7,
    color: colors.white,
    fontWeight: "bold",
  },
  // Signature block
  signatureSection: {
    marginTop: 30,
    borderTopWidth: 1,
    borderTopColor: colors.borderGray,
    paddingTop: 15,
  },
  signatureRow: {
    flexDirection: "row",
    marginBottom: 20,
  },
  signatureBlock: {
    flex: 1,
    marginRight: 20,
  },
  signatureBlockLast: {
    flex: 1,
  },
  signatureLine: {
    borderBottomWidth: 1,
    borderBottomColor: colors.textDark,
    marginTop: 30,
    marginBottom: 4,
  },
  signatureLabel: {
    fontSize: 8,
    color: colors.textGray,
  },
  // Footer
  footer: {
    position: "absolute",
    bottom: 30,
    left: 40,
    right: 40,
    textAlign: "center",
    fontSize: 8,
    color: colors.textGray,
    borderTopWidth: 1,
    borderTopColor: colors.borderGray,
    paddingTop: 10,
  },
  // Flex row for inline items
  flexRow: {
    flexDirection: "row",
    flexWrap: "wrap",
  },
  // Two column layout
  twoColumn: {
    flexDirection: "row",
  },
  column: {
    flex: 1,
    paddingRight: 10,
  },
  columnLast: {
    flex: 1,
  },
});

interface ReportPdfProps {
  data: Partial<IncidentReportData>;
}

export function ReportPdfDocument({ data }: ReportPdfProps) {
  const reportDate = data.report_date || new Date().toISOString().split("T")[0];
  const reportId = data.report_id || `IR-${reportDate.replace(/-/g, "")}-0001`;

  return (
    <Document>
      <Page size="A4" style={styles.page}>
        {/* Classification Banner */}
        <View style={[styles.classificationBanner, { backgroundColor: getClassificationColor(data.classification || "CONFIDENTIAL") }]}>
          <Text style={styles.classificationText}>
            {data.classification || "CONFIDENTIAL"}
          </Text>
        </View>

        {/* Title */}
        <Text style={styles.title}>SECURITY INCIDENT REPORT</Text>

        {/* Meta Info Row */}
        <View style={styles.metaRow}>
          <View style={styles.metaCell}>
            <Text style={styles.metaLabel}>Report ID</Text>
            <Text style={styles.metaValue}>{reportId}</Text>
          </View>
          <View style={styles.metaCell}>
            <Text style={styles.metaLabel}>Report Date</Text>
            <Text style={styles.metaValue}>{reportDate}</Text>
          </View>
          <View style={styles.metaCell}>
            <Text style={styles.metaLabel}>Severity</Text>
            <Text style={[styles.metaValue, { color: getSeverityColor(data.severity || "Medium") }]}>
              {data.severity || "Medium"}
            </Text>
          </View>
          <View style={styles.metaCellLast}>
            <Text style={styles.metaLabel}>Status</Text>
            <Text style={styles.metaValue}>{data.status || "Investigating"}</Text>
          </View>
        </View>

        {/* Section 1: Incident Overview */}
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionHeaderText}>1. INCIDENT OVERVIEW</Text>
        </View>

        <View style={styles.fieldGroup}>
          <Text style={styles.fieldLabel}>Incident Title</Text>
          <Text style={styles.fieldValue}>{data.incident_title || "Untitled Incident"}</Text>
        </View>

        <View style={styles.twoColumn}>
          <View style={styles.column}>
            <View style={styles.fieldGroup}>
              <Text style={styles.fieldLabel}>Incident Date</Text>
              <Text style={styles.fieldValue}>{data.incident_date || "N/A"}</Text>
            </View>
          </View>
          <View style={styles.column}>
            <View style={styles.fieldGroup}>
              <Text style={styles.fieldLabel}>Incident Time</Text>
              <Text style={styles.fieldValue}>{data.incident_time || "N/A"}</Text>
            </View>
          </View>
          <View style={styles.columnLast}>
            <View style={styles.fieldGroup}>
              <Text style={styles.fieldLabel}>Detection Date</Text>
              <Text style={styles.fieldValue}>{data.detection_date || "N/A"}</Text>
            </View>
          </View>
        </View>

        {/* Section 2: Affected Systems */}
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionHeaderText}>2. AFFECTED SYSTEMS & IMPACT</Text>
        </View>

        <View style={styles.fieldGroup}>
          <Text style={styles.fieldLabel}>Affected Systems</Text>
          {(data.affected_systems && data.affected_systems.length > 0) ? (
            <View style={styles.bulletList}>
              {data.affected_systems.map((system, i) => (
                <View key={i} style={styles.bulletItem}>
                  <Text style={styles.bullet}>•</Text>
                  <Text style={styles.bulletText}>{system}</Text>
                </View>
              ))}
            </View>
          ) : (
            <Text style={styles.fieldValue}>No systems specified</Text>
          )}
        </View>

        <View style={styles.fieldGroup}>
          <Text style={styles.fieldLabel}>Business Impact</Text>
          <Text style={styles.fieldValue}>{data.business_impact || "Not specified"}</Text>
        </View>

        {/* Section 3: Threat Intelligence */}
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionHeaderText}>3. THREAT INTELLIGENCE</Text>
        </View>

        <View style={styles.twoColumn}>
          <View style={styles.column}>
            <View style={styles.fieldGroup}>
              <Text style={styles.fieldLabel}>Suspected Threat Actor</Text>
              <Text style={styles.fieldValue}>{data.threat_actor || "Unknown"}</Text>
            </View>
          </View>
          <View style={styles.columnLast}>
            <View style={styles.fieldGroup}>
              <Text style={styles.fieldLabel}>Attack Vector</Text>
              <Text style={styles.fieldValue}>{data.attack_vector || "Unknown"}</Text>
            </View>
          </View>
        </View>

        <View style={styles.fieldGroup}>
          <Text style={styles.fieldLabel}>CVEs Exploited</Text>
          {(data.cves_exploited && data.cves_exploited.length > 0) ? (
            <View style={styles.bulletList}>
              {data.cves_exploited.map((cve, i) => (
                <View key={i} style={styles.bulletItem}>
                  <Text style={styles.bullet}>•</Text>
                  <Text style={styles.bulletText}>{cve}</Text>
                </View>
              ))}
            </View>
          ) : (
            <Text style={styles.fieldValue}>No CVEs identified</Text>
          )}
        </View>

        {/* Section 4: Recommendations */}
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionHeaderText}>4. RECOMMENDATIONS</Text>
        </View>

        {(data.recommendations && data.recommendations.length > 0) ? (
          <View style={styles.bulletList}>
            {data.recommendations.map((rec, i) => (
              <View key={i} style={styles.bulletItem}>
                <Text style={styles.bullet}>{i + 1}.</Text>
                <Text style={styles.bulletText}>{rec}</Text>
              </View>
            ))}
          </View>
        ) : (
          <Text style={styles.fieldValue}>No recommendations specified</Text>
        )}

        {/* Signature Section */}
        <View style={styles.signatureSection}>
          <Text style={[styles.sectionHeaderText, { color: colors.headerBg, marginBottom: 15 }]}>
            APPROVAL & DISTRIBUTION
          </Text>
          <View style={styles.signatureRow}>
            <View style={styles.signatureBlock}>
              <Text style={styles.fieldValue}>{data.prepared_by || ""}</Text>
              <View style={styles.signatureLine} />
              <Text style={styles.signatureLabel}>Prepared By</Text>
            </View>
            <View style={styles.signatureBlock}>
              <Text style={styles.fieldValue}>{data.reviewed_by || ""}</Text>
              <View style={styles.signatureLine} />
              <Text style={styles.signatureLabel}>Reviewed By</Text>
            </View>
            <View style={styles.signatureBlockLast}>
              <Text style={styles.fieldValue}>{data.approved_by || ""}</Text>
              <View style={styles.signatureLine} />
              <Text style={styles.signatureLabel}>Approved By</Text>
            </View>
          </View>
        </View>

        {/* Footer */}
        <Text style={styles.footer}>
          Generated by SexySecure • {new Date().toLocaleString()} • This document contains sensitive information
        </Text>
      </Page>
    </Document>
  );
}
