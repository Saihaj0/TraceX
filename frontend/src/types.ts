// Types mirroring the TRACE-X API responses (kept in sync with backend/app/api).

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Support = 'insufficient' | 'low' | 'moderate' | 'strong';

export interface Investigation {
  id: string;
  name: string;
  case_id: string;
  description?: string | null;
  notes?: string | null;
  status: string;
  origin: string;
  is_demo: boolean;
  created_at?: string | null;
  updated_at?: string | null;
  analysis_config: Record<string, number | string>;
  metrics: {
    events: number;
    evidence_sources: number;
    rejected_records: number;
    findings: number;
    high_priority_findings: number;
    suspicion_chains: number;
    undated_events: number;
    low_confidence_timestamps: number;
  };
  processing: string;
  last_run?: {
    id: string;
    started_at?: string | null;
    duration_ms?: number | null;
    engine_version: string;
    rules_version: string;
    trigger: string;
    summary: Record<string, any>;
    status: string;
  } | null;
}

export interface EvidenceSource {
  id: string;
  filename: string;
  file_type: string;
  source_type: string;
  size_bytes: number;
  sha256: string;
  origin: string;
  imported_at: string | null;
  record_count: number;
  accepted_count: number;
  rejected_count: number;
  status: string;
  parser: { name: string; version: string };
  timezone_note: string | null;
  metadata: Record<string, any>;
  error_count: number;
  integrity_note: string;
}

export interface TimelineEvent {
  id: string;
  evidence_source_id?: string | null;
  timestamp: string | null;
  timestamp_raw: string | null;
  timestamp_precision: string;
  timestamp_confidence: string;
  timezone_note: string | null;
  event_type: string;
  source_type: string;
  source_file: string | null;
  source_record_id: string | null;
  host: string | null;
  user: string | null;
  process_id: number | null;
  process_name: string | null;
  file_path: string | null;
  device_id: string | null;
  description: string | null;
  raw_record_reference: string | null;
  parser_name: string;
  parser_version: string;
  integrity_hash: string | null;
  ingestion_status: string;
  origin: string;
  warnings: string[];
  order_uncertain: boolean;
  has_timestamp: boolean;
  flagged?: boolean;
}

export interface TimelineResponse {
  total: number;
  offset: number;
  limit: number;
  returned: number;
  undated_in_page: number;
  sort: string;
  events: TimelineEvent[];
  stats?: Record<string, any>;
  flagged_count?: number;
}

export interface EvidenceRow {
  event_id: string;
  timestamp?: string | null;
  event_type: string;
  description: string;
  source_file?: string | null;
  source_record_id?: string | null;
  raw_record_reference?: string | null;
  evidence_source_id?: string | null;
  source_type?: string;
  host?: string | null;
  user?: string | null;
  file_path?: string | null;
  parser?: string;
  integrity_hash?: string | null;
  origin?: string;
}

export interface FindingExplanation {
  why_triggered?: string;
  observed_evidence: string[];
  correlation: string[];
  hypothesis: string;
  does_not_establish: string[];
  missing_evidence: string[];
  contradicting_evidence: Array<Record<string, any>>;
  temporal_relationships: Array<Record<string, any>>;
  limitations: string[];
  alternative_explanations: Array<{ explanation: string; why_relevant?: string }>;
  recommended_next_checks: string[];
  evidence: EvidenceRow[];
  rule_metadata: Record<string, any>;
  related_findings: string[];
}

export interface Finding {
  id: string;
  investigation_id: string;
  analysis_run_id?: string | null;
  rule_id: string;
  rule_name: string;
  rule_version: string;
  title: string;
  severity: Severity;
  support: Support;
  heuristic_score: number | null;
  score_components: Array<{ name: string; value: number; weight: number }>;
  occurred_at: string | null;
  event_ids: string[];
  events: TimelineEvent[];
  explanation: FindingExplanation;
  created_at?: string | null;
  severity_note: string;
}

export interface ChainStep {
  position: number;
  key: string;
  label: string;
  matched: boolean;
  event_ids: string[];
  timestamp?: string | null;
  description?: string;
  relationships?: string[];
  evidence_ref?: string | null;
  source_file?: string | null;
  source_record_id?: string | null;
  is_anchor?: boolean;
  missing_reason?: string;
}

export interface SuspicionChain {
  id: string;
  investigation_id: string;
  pattern_id: string;
  pattern_name: string;
  title: string;
  event_ids: string[];
  steps: ChainStep[];
  relationship_types: string[];
  severity: Severity;
  support: Support;
  completeness: 'complete' | 'partial';
  missing_steps: Array<{ label: string; reason: string }>;
  alternative_explanations: Array<{ explanation: string; why_relevant?: string }>;
  triggered_rules: string[];
  status: string;
  created_at?: string | null;
  note: string;
  events?: TimelineEvent[];
}

export interface GraphNodeData {
  id: string;
  label: string;
  node_type: string;
  event_id?: string | null;
  flagged?: boolean;
  [key: string]: any;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  relation: string;
  explanation: string;
  evidence_refs: string[];
  rule_ref: string | null;
  inferred: boolean;
  confidence: string;
  weight: number;
  kind: 'observed' | 'inferred';
}

export interface GraphPayload {
  nodes: Array<{ data: GraphNodeData }>;
  edges: Array<{ data: GraphEdgeData }>;
  counts: {
    nodes: number;
    edges: number;
    by_node_type: Record<string, number>;
    by_relation: Record<string, number>;
  };
  legend: {
    node_types: string[];
    relations: Array<{ relation: string; kind: string; meaning: string }>;
  };
  inference_rules: Array<{ relation: string; rule: string; requires: string[] }>;
  empty_reason?: string | null;
}

export interface DashboardData {
  investigation_id?: string | null;
  processing_status: string;
  metrics: Record<string, any>;
  activity_timeline: Array<{ bucket: string; count: number }>;
  recent_investigations: Investigation[];
  recent_findings: Array<Record<string, any>>;
  recent_chains: Array<Record<string, any>>;
  last_analysis: Record<string, any> | null;
  graph_preview_nodes: Array<Record<string, any>>;
  disclaimer: string;
}

export interface RuleInfo {
  id: string;
  name: string;
  description: string;
  category: string;
  required_evidence: string[];
  required_evidence_note: string;
  detection_conditions: string[];
  exclusions: string[];
  severity: string;
  explanation_template: string;
  limitations: string[];
  version: string;
  ruleset_version: string;
  anchor_event_types: string[];
}

export interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  expected_rules: string[];
  expected_chains: string[];
  expected_absent: string[];
  alternatives: string[];
  notes: string;
  case_id: string;
  sources: Array<{ filename: string; file_type: string; source_type: string; records: number; rejected: number }>;
}

export interface Toast {
  id: number;
  kind: 'info' | 'success' | 'error' | 'warning';
  message: string;
}

// --- auth -----------------------------------------------------------------

export interface AuthUser {
  id: string;
  username: string;
  display_name: string | null;
  is_admin: boolean;
  created_at: string | null;
  last_login_at: string | null;
}

export interface AuthStatus {
  user_auth_required: boolean;
  user: AuthUser | null;
  auth_mode: 'user_session' | 'trusted_local';
  note: string;
}

// The session credential is delivered as an HttpOnly cookie — JavaScript
// never sees it, so the login response carries no token.
export interface AuthSession {
  expires_at: string;
  user: AuthUser;
  message?: string;
}

// --- admin ----------------------------------------------------------------

export interface AdminSession {
  id: string;
  created_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  user_agent: string | null;
  client_ip: string | null;
  status: 'live' | 'expired' | 'revoked';
  is_current: boolean;
}

export interface AdminUser {
  id: string;
  username: string;
  display_name: string | null;
  is_admin: boolean;
  is_active: boolean;
  created_at: string | null;
  last_login_at: string | null;
  active_sessions: number;
  total_sessions: number;
  sessions: AdminSession[];
}

export interface AdminUsersResponse {
  users: AdminUser[];
  count: number;
  note: string;
}