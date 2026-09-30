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
  verification_status?: 'CONFIRMED' | 'REJECTED' | 'UNVERIFIED';
  vulnerability: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  confidence: number;
  static_confidence?: number;
  affected_lines: number[];
  evidence: { function: string; lines: number[] }[];
  explanation: string;
  attack_scenario: string;
  recommendation: string;
  fixed_code: string;
  static_evidence: string;
  original_code: string;
  retrieved_knowledge?: Record<string, unknown>[];
  rag_similarity_score?: number;
  rag_explanation?: string;
  contract?: string;
  function?: string;
  swc_id?: string;
  fix_verified?: boolean;
  fix_verification_reason?: string;
  fallback_used?: boolean;
  fallback_reason?: string;
  model_used?: string;
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
  security_score?: number;
  risk_level?: string;
  source_code?: string;
  // Phase 3: Blockchain Audit Registry fields
  audit_id?: string;
  tx_hash?: string;
  registry_address?: string;
  chain_id?: number;
  on_chain_status?: string;
  on_chain_timestamp?: string;
  source_hash?: string;
  report_hash?: string;
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
