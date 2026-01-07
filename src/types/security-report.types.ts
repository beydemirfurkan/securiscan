/**
 * Security Report types
 */

export enum Severity {
  CRITICAL = 'Kritik',
  HIGH = 'Yüksek',
  MEDIUM = 'Orta',
  LOW = 'Düşük',
  INFO = 'Bilgi'
}

export interface ExploitStep {
  description: string;
  scenario: string;
  impact: string;
}

export interface RiskItem {
  name: string;
  url?: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  location: string;
  remediation: string;
  cvssScore: number;
  exploitExample: string;
  exploitablePaths: ExploitStep[];
  relatedCves?: RiskItem[];
}

export interface TechStackItem {
  name: string;
  description: string;
  commonRisks: RiskItem[];
}

export interface ComplianceItem {
  standard: string;
  status: 'PASS' | 'FAIL' | 'WARNING';
  details: string;
}

export interface HeaderAnalysis {
  key: string;
  value: string;
  status: 'SECURE' | 'MISSING' | 'WARNING' | 'INFO';
  description: string;
}

export interface SSLInfo {
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  protocol: string;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface SubdomainInfo {
  name: string;
  ip: string;
  status: 'ACTIVE' | 'CLOUDFLARE' | 'HIDDEN';
}

export interface DarkWebLeak {
  source: string;
  date: string;
  type: string;
  severity: 'HIGH' | 'MEDIUM';
}

export interface ActionPlanItem {
  task: string;
  priority: 'URGENT' | 'HIGH' | 'MEDIUM';
  effort: 'LOW' | 'MEDIUM' | 'HIGH';
  estimatedTime: string;
  delayImpact: string;
}

export interface NetworkInfo {
  ip: string;
  location: string;
  isp: string;
  asn: string;
  organization: string;
  serverType: string;
  ports: number[];
}

// New types for enhanced scanning
export interface CVEInfo {
  id: string;
  cvssScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  publishedDate: string;
  nvdUrl: string;
  hasExploit: boolean;
}

export interface CVECorrelationResult {
  technology: string;
  version?: string;
  cves: CVEInfo[];
  totalCount: number;
}

export interface SecurityReport {
  targetUrl: string;
  scanTimestamp: string;
  overallScore: number;
  vulnerabilities: Vulnerability[];
  summary: string;
  techStackDetected: TechStackItem[];
  compliance: ComplianceItem[];
  networkInfo: NetworkInfo;
  headers: HeaderAnalysis[];
  ssl: SSLInfo;
  // Premium Features
  subdomains: SubdomainInfo[];
  darkWebLeaks: DarkWebLeak[];
  actionPlan: ActionPlanItem[];
  isPremium?: boolean; // Added for backend response
  // New fields for enhanced scanning
  httpMethods?: {
    allowed: string[];
    dangerous: string[];
  };
  robotsAnalysis?: {
    sensitivePaths: string[];
    hasSecurityTxt: boolean;
  };
  cveCorrelations?: CVECorrelationResult[];
}
