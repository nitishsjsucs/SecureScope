// API Response wrapper for paginated endpoints
export interface PaginatedResponse<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

// SexySecure pipeline tracking
export type SexySecureStatus = "imported" | "reviewing" | "verified" | "published";
export type SexySecurePriority = "critical" | "high" | "medium" | "low" | null;

export interface SexySecureData {
  verified: boolean;
  verified_at: string | null;
  verified_by: string | null;
  status: SexySecureStatus;
  notes: string | null;
  tags: string[];
  priority: SexySecurePriority;
  reviewed_at: string | null;
  reviewed_by: string | null;
}

// CVE List Item (from /api/cve) - includes metrics and vendors for dashboard
export interface CveListItem {
  cve_id: string;
  description: string | null;
  created_at: string;
  updated_at: string;
  metrics: CveMetrics;
  vendors: string[]; // Format: "vendor" or "vendor$PRODUCT$product"
  sexysecure?: SexySecureData | null;
  sources?: SourceInfo[];      // Sources that detected/flagged this CVE
  chatter_score?: number | null; // 0-100 social media traction score
}

// CVE Detail (from /api/cve/{id})
export interface CveDetail {
  cve_id: string;
  title: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
  metrics: CveMetrics;
  weaknesses: string[];
  vendors: string[]; // Format: "vendor" or "vendor$PRODUCT$product"
  sexysecure?: SexySecureData | null;
  sources?: SourceInfo[];      // Sources that detected/flagged this CVE
  advisories?: Advisory[];     // Linked security advisories (EUVD, GHSA, etc.)
  chatter_score?: number | null; // 0-100 social media traction score
}

// Metrics structure
export interface CveMetrics {
  cvssV2_0?: CvssMetric;
  cvssV3_0?: CvssMetric;
  cvssV3_1?: CvssMetric;
  cvssV4_0?: CvssMetric;
  kev?: KevData;
  epss?: EpssData;
  ssvc?: SsvcData;
  ai_score?: AiScoreData;  // AI-generated CVSS score from our agent system
}

export interface CvssMetric {
  data: CvssData;
}

export interface CvssData {
  score: number;
  vector: string;
  severity?: string;
}

// AI-generated CVSS score from our agent system
export interface AiScoreData {
  score: number;
  version: string;           // CVSS version used (e.g., "3.1")
  vector?: string;           // Optional CVSS vector string
  confidence: number;        // 0-1 confidence score
  reasoning?: string;        // Brief explanation of the score
  scored_at: string;         // ISO timestamp when scored
  model?: string;            // AI model used for scoring
}

export interface EpssData {
  score: number;
  percentile: number;
}

export interface KevData {
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse?: string;
  notes?: string;
  product?: string;
  requiredAction?: string;
  shortDescription?: string;
  vendorProject?: string;
  vulnerabilityName?: string;
}

export interface SsvcData {
  automatable?: string;
  exploitation?: string;
  technical_impact?: string;
  timestamp?: string;
}

// Vendor (from /api/vendors)
export interface Vendor {
  id: string;
  name: string;
  cve_count?: number;
  products?: string[];
  created_at: string | null;
  updated_at: string | null;
}

// Product (from /api/vendors/{name}/products)
export interface Product {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

// Weakness (from /api/weaknesses)
export interface Weakness {
  cwe_id: string;
  created_at: string;
  updated_at: string;
}

// Severity levels
export type SeverityLevel = "critical" | "high" | "medium" | "low" | "none";

// Sources that flagged/detected the CVE
export type SourceType =
  | "nvd"             // NIST National Vulnerability Database
  | "mitre"           // MITRE CVE
  | "vulnrichment"    // CISA Vulnrichment (KEV/SSVC enrichment data)
  | "redhat"          // Red Hat Security
  | "cisa_kev"        // CISA Known Exploited Vulnerabilities
  | "firecrawl"       // Firecrawl web intelligence
  | "openwall"        // Openwall security mailing lists
  | "github_advisory" // GitHub Security Advisories
  | "exploitdb";      // Exploit Database

// Firecrawl web mention (snippet + URL from scraped content)
export interface FirecrawlMention {
  title: string;           // Article/page title
  url: string;             // Link to the source
  snippet: string;         // First ~200 chars of relevant content
  source_site: string;     // e.g., "BleepingComputer", "HackerNews"
  found_at: string;        // ISO date when Firecrawl found this
}

export interface SourceInfo {
  source: SourceType;
  first_seen: string;      // ISO date when this source first reported the CVE
  url?: string | null;     // Optional link to the source's page for this CVE
  mentions?: FirecrawlMention[];  // Only for firecrawl source type
}

// Security Advisory (EUVD, GHSA, Debian, Ubuntu)
export type AdvisorySource = "euvd" | "ghsa" | "debian" | "ubuntu";

export interface Advisory {
  id: string;              // e.g., "EUVD-2024-15804", "GHSA-xxxx-xxxx"
  source: AdvisorySource;
  title: string;
  url: string;
}

// Parsed vendor info
export interface ParsedVendor {
  vendor: string;
  product?: string;
}

// User Product (tracked from GitHub repos)
export type ProductStatus = "analyzing" | "ready" | "error";

export interface Dependency {
  name: string;
  version: string | null;
  type: "npm" | "pip" | "go" | "cargo" | "gem" | "maven" | "gradle" | "composer" | "nuget" | "other";
  file: string;           // package.json, requirements.txt, etc.
  tracked: boolean;       // Whether user wants to track CVEs for this
  cve_count?: number;     // Number of known CVEs affecting this dependency
  depth: number;          // 0 = direct dependency, 1+ = transitive (dependency of dependency)
  parent?: string;        // Name of parent dependency (for transitive deps)
}

export interface UserProduct {
  _id: string;
  name: string;
  description: string | null;
  github_url: string;
  github_owner: string;
  github_repo: string;
  default_branch: string;
  status: ProductStatus;
  dependencies: Dependency[];
  total_dependencies: number;
  tracked_dependencies: number;
  critical_cves: number;
  high_cves: number;
  medium_cves: number;
  low_cves: number;
  last_analyzed: string | null;
  created_at: string;
  updated_at: string;
  error_message?: string | null;
}

// Email monitoring types
export type EmailCategory =
  | "cve_update"        // CVE update from official sources (NVD, MITRE, etc.)
  | "cve_detected"      // New CVE detected affecting tracked products
  | "security_advisory" // Security advisory from vendors
  | "threat_intel"      // Threat intelligence reports
  | "package_update"    // Package/software update notifications (Fedora, etc.)
  | "newsletter"        // Security newsletters
  | "promotional"       // Marketing/promotional content
  | "spam"              // Spam/unwanted
  | "other";            // Uncategorized

export interface EmailAttachment {
  attachment_id: string;
  filename: string | null;
  size: number;
  content_type: string | null;
}

export interface EmailLLMAnalysis {
  category: EmailCategory;
  confidence: number;           // 0-1 confidence score
  summary: string;              // Brief summary of the email
  cve_ids: string[];            // Any CVE IDs mentioned
  vendors: string[];            // Vendors mentioned
  products: string[];           // Products mentioned
  severity_mentioned: SeverityLevel | null;  // If severity is mentioned
  action_required: boolean;     // Whether immediate action is suggested
  key_points: string[];         // Bullet points of key info
  analyzed_at: string;          // ISO timestamp
}

export interface MonitoredEmail {
  _id: string;
  message_id: string;           // AgentMail message ID
  inbox_id: string;             // AgentMail inbox ID
  thread_id: string;            // AgentMail thread ID
  from: string;
  to: string[];
  cc: string[] | null;
  subject: string | null;
  preview: string | null;       // Short preview text
  text: string | null;          // Plain text body
  html: string | null;          // HTML body
  attachments: EmailAttachment[];
  labels: string[];
  timestamp: string;            // When email was sent
  analysis: EmailLLMAnalysis | null;  // LLM analysis result
  read: boolean;
  starred: boolean;
  created_at: string;           // When we imported it
  updated_at: string;
}

// API response for emails
export interface EmailListResponse {
  emails: MonitoredEmail[];
  total: number;
  page: number;
  limit: number;
  has_more: boolean;
}

// Chat types for RAG interface
export type ChatRole = "user" | "assistant" | "system";

export interface RAGSource {
  type: "cve" | "product";
  id: string;                  // CVE ID or product name
  title: string;               // CVE ID or product display name
  snippet: string;             // Relevant excerpt from description
  relevance_score: number;     // 0-1 relevance score
  severity?: SeverityLevel;    // For CVEs
  url?: string;                // Link to the detail page
}

export interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  sources?: RAGSource[];       // CVEs/products referenced in response
  timestamp: string;
}

export interface ChatSession {
  _id: string;
  title: string;               // Auto-generated from first message
  messages: ChatMessage[];
  created_at: string;
  updated_at: string;
}

// API response for chat sessions
export interface ChatSessionListResponse {
  sessions: ChatSession[];
  total: number;
}

// Incident Report types (matching Python IncidentData dataclass)
export type ReportClassification = "CONFIDENTIAL" | "INTERNAL" | "PUBLIC";
export type IncidentSeverity = "Critical" | "High" | "Medium" | "Low";
export type IncidentStatus = "Open" | "Investigating" | "Contained" | "Resolved";

export interface TimelineEvent {
  timestamp: string;
  event: string;
  source: string;
}

// Selected CVE for report (minimal info needed)
export interface ReportCve {
  cve_id: string;
  severity: IncidentSeverity | null;
  score: number | null;
  description: string | null;
}

// Full incident report data structure (MVP subset)
export interface IncidentReportData {
  // Header
  report_id: string;
  report_date: string;
  classification: ReportClassification;

  // Incident Overview
  incident_title: string;
  incident_date: string;
  incident_time: string;
  detection_date: string;
  severity: IncidentSeverity;
  status: IncidentStatus;

  // Affected Systems
  affected_systems: string[];
  affected_networks: string[];
  business_impact: string;

  // Threat Intelligence
  threat_actor: string;
  attack_vector: string;
  cves_exploited: string[];
  mitre_techniques: string[];

  // IOCs (future expansion)
  malicious_ips: string[];
  malicious_domains: string[];
  malicious_urls: string[];
  file_hashes: string[];

  // Timeline
  timeline_events: TimelineEvent[];

  // Response Actions
  containment_actions: string[];
  eradication_actions: string[];
  recovery_actions: string[];

  // Recommendations
  recommendations: string[];

  // Metadata
  prepared_by: string;
  reviewed_by: string;
  approved_by: string;
  distribution_list: string[];

  // Source Analysis (auto-filled)
  source_files: string[];
  pages_analyzed: number;
}

// Default/empty report for form initialization
export const createEmptyReport = (): IncidentReportData => ({
  report_id: "",
  report_date: new Date().toISOString().split("T")[0],
  classification: "CONFIDENTIAL",
  incident_title: "",
  incident_date: new Date().toISOString().split("T")[0],
  incident_time: new Date().toTimeString().slice(0, 5),
  detection_date: new Date().toISOString().split("T")[0],
  severity: "Medium",
  status: "Investigating",
  affected_systems: [],
  affected_networks: [],
  business_impact: "",
  threat_actor: "",
  attack_vector: "",
  cves_exploited: [],
  mitre_techniques: [],
  malicious_ips: [],
  malicious_domains: [],
  malicious_urls: [],
  file_hashes: [],
  timeline_events: [],
  containment_actions: [],
  eradication_actions: [],
  recovery_actions: [],
  recommendations: [],
  prepared_by: "",
  reviewed_by: "",
  approved_by: "",
  distribution_list: [],
  source_files: [],
  pages_analyzed: 0,
});
