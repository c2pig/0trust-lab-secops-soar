export interface KVNamespace {
  get(key: string): Promise<string | null>;
  put(key: string, value: string, options?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<void>;
}

function sanitizeSessionId(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') return 'demo-visitor';
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return cleaned || 'demo-visitor';
}

export type AttackScenarioId =
  | 'CREDENTIAL_STUFFING'
  | 'IMPOSSIBLE_TRAVEL'
  | 'PUBLIC_BUCKET_CANARY';

export type SoarActionId =
  | 'WAF_BLOCK_ASN'
  | 'CAEP_UNIVERSAL_LOGOUT'
  | 'AGENT_KILL_SWITCH';

export interface SecopsEnv {
  STATE_KV?: KVNamespace;
  ENVIRONMENT?: string;
}

export interface IngestRequest {
  sessionId?: string;
  scenario?: AttackScenarioId;
  auto_remediate?: boolean;
}

export interface SecopsSessionKvRecord {
  session_id: string;
  incident_id: string;
  scenario: AttackScenarioId;
  sigma_rule_id: string;
  risk_score: number;
  incident_status: 'ACTIVE_INCIDENT' | 'CONTAINED';
  compromised_user_revoked: boolean;
  waf_blocked: boolean;
  kill_switch_active: boolean;
  executed_actions: SoarActionId[];
  mttd_ms: number;
  mttr_ms: number | null;
  updated_at: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const KV_TTL_SECONDS = 3600;
const MAX_EPHEMERAL_ENTRIES = 256;
const EPHEMERAL_TTL_MS = KV_TTL_SECONDS * 1000;
const VALID_SCENARIOS = new Set<AttackScenarioId>([
  'CREDENTIAL_STUFFING',
  'IMPOSSIBLE_TRAVEL',
  'PUBLIC_BUCKET_CANARY'
]);

const ephemeralSecopsStore = new Map<
  string,
  { record: SecopsSessionKvRecord; expiresAt: number }
>();

function setEphemeralSecops(key: string, record: SecopsSessionKvRecord): void {
  const now = Date.now();
  for (const [k, v] of ephemeralSecopsStore) {
    if (now > v.expiresAt) ephemeralSecopsStore.delete(k);
  }
  if (ephemeralSecopsStore.has(key)) ephemeralSecopsStore.delete(key);
  while (ephemeralSecopsStore.size >= MAX_EPHEMERAL_ENTRIES) {
    const oldest = ephemeralSecopsStore.keys().next().value;
    if (oldest === undefined) break;
    ephemeralSecopsStore.delete(oldest);
  }
  ephemeralSecopsStore.set(key, { record, expiresAt: now + EPHEMERAL_TTL_MS });
}

const SCENARIO_META: Record<
  AttackScenarioId,
  {
    sigma_rule_id: string;
    sigma_level: 'high' | 'critical';
    risk_score: number;
    recommended_action: SoarActionId;
    mttd_ms: number;
    auto_mttr_ms: number;
    source_ip: string;
    asn: string;
  }
> = {
  CREDENTIAL_STUFFING: {
    sigma_rule_id: 'SIGMA-AUTH-001',
    sigma_level: 'high',
    risk_score: 78,
    recommended_action: 'WAF_BLOCK_ASN',
    mttd_ms: 420,
    auto_mttr_ms: 890,
    source_ip: '185.220.101.42',
    asn: 'AS49870'
  },
  IMPOSSIBLE_TRAVEL: {
    sigma_rule_id: 'SIGMA-GEO-002',
    sigma_level: 'critical',
    risk_score: 94,
    recommended_action: 'CAEP_UNIVERSAL_LOGOUT',
    mttd_ms: 310,
    auto_mttr_ms: 640,
    source_ip: '198.51.100.77',
    asn: 'AS24940'
  },
  PUBLIC_BUCKET_CANARY: {
    sigma_rule_id: 'SIGMA-CLOUD-003',
    sigma_level: 'critical',
    risk_score: 98,
    recommended_action: 'AGENT_KILL_SWITCH',
    mttd_ms: 260,
    auto_mttr_ms: 520,
    source_ip: '192.0.2.199',
    asn: 'AS14061'
  }
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store'
    }
  });
}

export async function onRequestPost(context: {
  request: Request;
  env: SecopsEnv;
}): Promise<Response> {
  const rawText = await context.request.text();
  if (rawText.length > MAX_BODY_BYTES) {
    return jsonResponse(
      { error: 'PAYLOAD_TOO_LARGE', message: 'Request payload exceeds 64KB limit.' },
      413
    );
  }

  let body: IngestRequest = {};
  if (rawText.trim().length > 0) {
    try {
      body = JSON.parse(rawText) as IngestRequest;
    } catch {
      return jsonResponse(
        { error: 'INVALID_JSON', message: 'Request body must be valid JSON.' },
        400
      );
    }
  }

  if (!body.scenario || !VALID_SCENARIOS.has(body.scenario)) {
    return jsonResponse(
      {
        error: 'INVALID_SCENARIO',
        message:
          'scenario must be one of CREDENTIAL_STUFFING, IMPOSSIBLE_TRAVEL, or PUBLIC_BUCKET_CANARY.'
      },
      400
    );
  }

  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const kvKey = `lab6:soar:${sessionId}`;
  const meta = SCENARIO_META[body.scenario];
  const autoRemediate = Boolean(body.auto_remediate);
  const timestamp = new Date().toISOString();
  const incidentId = `INC-SOAR-${Date.now().toString(36).toUpperCase().slice(-6)}`;

  const executedActions: SoarActionId[] = autoRemediate ? [meta.recommended_action] : [];
  const compromisedUserRevoked = executedActions.includes('CAEP_UNIVERSAL_LOGOUT');
  const wafBlocked = executedActions.includes('WAF_BLOCK_ASN');
  const killSwitchActive = executedActions.includes('AGENT_KILL_SWITCH');

  const record: SecopsSessionKvRecord = {
    session_id: sessionId,
    incident_id: incidentId,
    scenario: body.scenario,
    sigma_rule_id: meta.sigma_rule_id,
    risk_score: meta.risk_score,
    incident_status: autoRemediate ? 'CONTAINED' : 'ACTIVE_INCIDENT',
    compromised_user_revoked: compromisedUserRevoked,
    waf_blocked: wafBlocked,
    kill_switch_active: killSwitchActive,
    executed_actions: executedActions,
    mttd_ms: meta.mttd_ms,
    mttr_ms: autoRemediate ? meta.auto_mttr_ms : null,
    updated_at: timestamp
  };

  if (context.env.STATE_KV) {
    await context.env.STATE_KV.put(kvKey, JSON.stringify(record), {
      expirationTtl: KV_TTL_SECONDS
    });
  } else {
    setEphemeralSecops(kvKey, record);
  }

  return jsonResponse({
    status: record.incident_status,
    incident_id: incidentId,
    scenario: body.scenario,
    sigma_rule_id: meta.sigma_rule_id,
    sigma_level: meta.sigma_level,
    risk_score: meta.risk_score,
    auto_remediate: autoRemediate,
    recommended_action: meta.recommended_action,
    executed_actions: executedActions,
    compromised_user_revoked: compromisedUserRevoked,
    waf_blocked: wafBlocked,
    kill_switch_active: killSwitchActive,
    mttd_ms: record.mttd_ms,
    mttr_ms: record.mttr_ms,
    source_ip: meta.source_ip,
    asn: meta.asn,
    storage: context.env.STATE_KV ? 'cloudflare-kv' : 'ephemeral-edge',
    kv_ttl_seconds: KV_TTL_SECONDS,
    timestamp
  });
}
