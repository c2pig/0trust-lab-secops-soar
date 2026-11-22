export type AppRoute =
  | 'home'
  | 'workforce-journey'
  | 'agentic-transaction'
  | 'data-byok'
  | 'resilience-tabletop'
  | 'secops-soar';

export interface ObservabilitySpan {
  id: string;
  traceparent: string;
  trace_id: string;
  span_id: string;
  parent_span_id: string;
  session_id: string;
  method: string;
  path: string;
  status: number;
  latency_ms: number;
  timestamp: string;
  otlp_export: 'configured' | 'in-lab-only';
  redacted_auth_header: string | null;
  redaction_applied: boolean;
  execution_origin: 'cloudflare-edge' | 'browser-webcrypto-fallback';
  response_summary: Record<string, unknown>;
}

export interface WorkforceJourneyScimRecord {
  schemas: string[];
  id: string;
  userName: string;
  displayName: string;
  department: string;
  active: boolean;
  status: 'ACTIVE' | 'REVOKED';
  roles: string[];
  active_jtis: string[];
  provisioned_at: string;
  revoked_at?: string;
  idp_adapter: string;
  entra_oid?: string;
  privileged_group_active?: boolean;
  graph_request_id?: string;
}

export interface WorkforceJourneyDecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}
