/**
 * Shared types between client and server
 * ATL – AI Threat Lens
 */

export interface DemoResponse {
  message: string;
}

export interface UrlScanRequest {
  url: string;
}

export interface MLResult {
  label: string;
  risk: number;
  is_spam: boolean;
  spam_conf: number;
}

export interface VirusTotalResult {
  success: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  total: number;
  file_type?: string;
  sha256?: string;
}

export interface GoogleSafeBrowsingResult {
  flagged: boolean;
  threat: string;
}

export interface AbuseIPDBResult {
  success: boolean;
  ip: string;
  score: number;
  reports: number;
  country: string;
}

export interface IPQualityScoreResult {
  success: boolean;
  risk_score: number;
  phishing: boolean;
  malware: boolean;
  spam: boolean;
  domain_age: string;
}

export interface URLScanResult {
  success: boolean;
  result: string;
  scan_id: string;
}

export type ThreatLevel = "SAFE" | "WARNING" | "DANGER" | "CRITICAL";
export type RiskLevel   = "safe" | "medium" | "high" | "critical";

// ── Composite danger score returned by the backend ──────────
export interface CompositeScore {
  overall:    number;          // 0–100 weighted average
  breakdown: {
    ml:       number | null;   // 0–100
    vt:       number | null;   // 0–100
    abuseipdb:number | null;   // 0–100 (abuseConfidenceScore)
    ipqs:     number | null;   // 0–100
    gsb:      number | null;   // 0 or 100
  };
}

export interface ScanResponse {
  mode:         "url" | "file";
  threat_label: ThreatLevel;
  risk_level:   RiskLevel;
  category:     string;
  filename?:    string;
  composite?:   CompositeScore;    // NEW
  ml?:          MLResult;
  virustotal:   VirusTotalResult;
  google_safebrowsing?: GoogleSafeBrowsingResult;
  abuseipdb?:   AbuseIPDBResult;
  ipqualityscore?: IPQualityScoreResult;
  urlscan?:     URLScanResult;
  error?:       string;
}
