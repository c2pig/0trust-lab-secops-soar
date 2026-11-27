import type {
  AttackScenarioId,
  SecopsEnv,
  SecopsSessionKvRecord,
  SoarActionId
} from './ingest';

function sanitizeSessionId(raw: string | null | undefined): string {
  if (!raw || typeof raw !== 'string') return 'demo-visitor';
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  return cleaned || 'demo-visitor';
}

interface ContainRequest {
  sessionId?: string;
  action?: SoarActionId;
  incident_id?: string;
  scenario?: AttackScenarioId;
}

const MAX_BODY_BYTES = 64 * 1024;
const KV_TTL_SECONDS = 3600;
const MAX_EPHEMERAL_ENTRIES = 256;
const EPHEMERAL_TTL_MS = KV_TTL_SECONDS * 1000;
const VALID_ACTIONS = new Set<SoarActionId>([
  'WAF_BLOCK_ASN',
  'CAEP_UNIVERSAL_LOGOUT',
  'AGENT_KILL_SWITCH'
]);

const ephemeralContainStore = new Map<
  string,
  { record: SecopsSessionKvRecord; expiresAt: number }
>();

function getEphemeralContain(key: string): SecopsSessionKvRecord | null {
  const entry = ephemeralContainStore.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    ephemeralContainStore.delete(key);
    return null;
  }
  return entry.record;
}

function setEphemeralContain(key: string, record: SecopsSessionKvRecord): void {
  const now = Date.now();
  for (const [k, v] of ephemeralContainStore) {
    if (now > v.expiresAt) ephemeralContainStore.delete(k);
  }
  if (ephemeralContainStore.has(key)) ephemeralContainStore.delete(key);
  while (ephemeralContainStore.size >= MAX_EPHEMERAL_ENTRIES) {
    const oldest = ephemeralContainStore.keys().next().value;
    if (oldest === undefined) break;
    ephemeralContainStore.delete(oldest);
  }
  ephemeralContainStore.set(key, { record, expiresAt: now + EPHEMERAL_TTL_MS });
}

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

  let body: ContainRequest = {};
  if (rawText.trim().length > 0) {
    try {
      body = JSON.parse(rawText) as ContainRequest;
    } catch {
      return jsonResponse(
        { error: 'INVALID_JSON', message: 'Request body must be valid JSON.' },
        400
      );
    }
  }

  if (!body.action || !VALID_ACTIONS.has(body.action)) {
    return jsonResponse(
      {
        error: 'INVALID_ACTION',
        message:
          'action must be one of WAF_BLOCK_ASN, CAEP_UNIVERSAL_LOGOUT, or AGENT_KILL_SWITCH.'
      },
      400
    );
  }

  const sessionId = sanitizeSessionId(
    context.request.headers.get('X-Session-Id') || body.sessionId
  );
  const kvKey = `lab6:soar:${sessionId}`;
  const timestamp = new Date().toISOString();

  let existing: SecopsSessionKvRecord | null = null;
  if (context.env.STATE_KV) {
    try {
      const raw = await context.env.STATE_KV.get(kvKey);
      if (raw) {
        existing = JSON.parse(raw) as SecopsSessionKvRecord;
      }
    } catch {
      existing = null;
    }
  } else {
    existing = getEphemeralContain(kvKey);
  }

  const prevActions = existing?.executed_actions ?? [];
  const nextActions = prevActions.includes(body.action)
    ? prevActions
    : [...prevActions, body.action];

  const compromisedUserRevoked =
    Boolean(existing?.compromised_user_revoked) ||
    body.action === 'CAEP_UNIVERSAL_LOGOUT';
  const wafBlocked =
    Boolean(existing?.waf_blocked) || body.action === 'WAF_BLOCK_ASN';
  const killSwitchActive =
    Boolean(existing?.kill_switch_active) || body.action === 'AGENT_KILL_SWITCH';

  const mttdMs = existing?.mttd_ms ?? 310;
  const mttrMs = existing?.mttr_ms ?? 3850;
  const incidentId =
    existing?.incident_id ||
    (body.incident_id ? body.incident_id.slice(0, 64) : `INC-SOAR-${Date.now().toString(36).toUpperCase().slice(-6)}`);

  const record: SecopsSessionKvRecord = {
    session_id: sessionId,
    incident_id: incidentId,
    scenario: existing?.scenario ?? body.scenario ?? 'IMPOSSIBLE_TRAVEL',
    sigma_rule_id: existing?.sigma_rule_id ?? 'SIGMA-GEO-002',
    risk_score: existing?.risk_score ?? 94,
    incident_status: 'CONTAINED',
    compromised_user_revoked: compromisedUserRevoked,
    waf_blocked: wafBlocked,
    kill_switch_active: killSwitchActive,
    executed_actions: nextActions,
    mttd_ms: mttdMs,
    mttr_ms: mttrMs,
    updated_at: timestamp
  };

  if (context.env.STATE_KV) {
    await context.env.STATE_KV.put(kvKey, JSON.stringify(record), {
      expirationTtl: KV_TTL_SECONDS
    });
  } else {
    setEphemeralContain(kvKey, record);
  }

  return jsonResponse({
    status: 'CONTAINED',
    action_executed: body.action,
    incident_id: incidentId,
    executed_actions: nextActions,
    compromised_user_revoked: compromisedUserRevoked,
    waf_blocked: wafBlocked,
    kill_switch_active: killSwitchActive,
    mttd_ms: mttdMs,
    mttr_ms: mttrMs,
    webhook_dispatched: {
      event_type:
        body.action === 'CAEP_UNIVERSAL_LOGOUT'
          ? 'https://schemas.openid.net/secevent/caep/event-type/session-revoked'
          : body.action === 'WAF_BLOCK_ASN'
            ? 'cloudflare.waf.rule.block_asn'
            : '0trust.governance.kill_switch.quarantine',
      subject: 'tyler.brooks@0trust.dev',
      timestamp
    },
    storage: context.env.STATE_KV ? 'cloudflare-kv' : 'ephemeral-edge',
    kv_ttl_seconds: KV_TTL_SECONDS,
    timestamp
  });
}
