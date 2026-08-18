export interface User {
  id: string;
  email: string;
  role: 'USER' | 'ADMIN';
}

export interface AuthState {
  user: User | null;
  token: string | null;
}

export interface VerifiedVulnerability {
  finding_id: string;
  is_vulnerable: boolean;
  vulnerability: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: number;
  affected_lines: number[];
  explanation: string;
  attack_scenario: string;
  recommendation: string;
  fixed_code: string;
  static_evidence: string;
  original_code: string;
  retrieved_knowledge: Record<string, unknown>[];
}

export interface VulnerabilityReport {
  analysis_id: string;
  contract_name: string;
  timestamp: string;
  total_findings: number;
  is_vulnerable: boolean;
  severity_counts: Record<string, number>;
  findings: VerifiedVulnerability[];
  summary: string;
}

export interface AnalysisHistoryItem {
  id: string;
  contract_name: string;
  status: string;
  created_at: string;
  total_findings: number;
  is_vulnerable: boolean;
  severity_counts: Record<string, number>;
}

export interface AdminUser {
  id: string;
  email: string;
  role: string;
  created_at: string;
  scan_count: number;
}

export interface AdminAnalysis {
  id: string;
  user_email: string;
  contract_name: string;
  status: string;
  created_at: string;
  total_findings: number;
  is_vulnerable: boolean;
  severity_counts: Record<string, number>;
}

export interface AdminAnalytics {
  total_users: number;
  total_analyses: number;
  total_vulnerabilities: number;
  severity_distribution: Record<string, number>;
  category_distribution: Record<string, number>;
  vulnerable_contracts_ratio: number;
}
