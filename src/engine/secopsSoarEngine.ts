import {
  ATTACK_SCENARIOS,
  AttackScenarioId,
  NormalizedTelemetryEvent,
  SOAR_PLAYBOOKS,
  SecopsSoarState,
  SoarActionId,
  SoarWebhookDispatch,
  TimelineEntry
} from '../contracts/secopsSoarContract';
import { ObservabilitySpan } from '../types';

function randomHex(byteCount: number): string {
  const bytes = new Uint8Array(byteCount);
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < byteCount; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function createSecopsSessionId(): string {
  return `soar-${randomHex(6)}`;
}

export function createTraceparent(): {
  traceparent: string;
  trace_id: string;
  span_id: string;
} {
  const trace_id = randomHex(16);
  const span_id = randomHex(8);
  return {
    traceparent: `00-${trace_id}-${span_id}-01`,
    trace_id,
    span_id
  };
}

export function createInitialSecopsState(sessionId: string): SecopsSoarState {
  return {
    session_id: sessionId,
    active_seat: 'soc-analyst',
    active_phase: 1,
    auto_remediate: false,
    selected_scenario: 'IMPOSSIBLE_TRAVEL',
    incident_id: null,
    incident_status: 'HEALTHY',
    risk_score: 12,
    compromised_user_revoked: false,
    waf_blocked: false,
    kill_switch_active: false,
    matched_sigma: null,
    telemetry_events: [],
    executed_actions: [],
    webhook_dispatches: [],
    timeline: [],
    mttd_ms: null,
    mttr_ms: null,
    storage_mode: 'client-sandbox',
    last_updated: new Date().toISOString()
  };
}

function buildWebhookDispatch(
  action: SoarActionId,
  scenario: AttackScenarioId,
  incidentId: string,
  mode: 'AUTO_REMEDIATE' | 'MANUAL_PLAYBOOK',
  timestamp: string
): SoarWebhookDispatch {
  const playbook = SOAR_PLAYBOOKS[action];
  const scenarioMeta = ATTACK_SCENARIOS[scenario];

  let payload: Record<string, unknown>;
  if (action === 'CAEP_UNIVERSAL_LOGOUT') {
    payload = {
      iss: 'https://idp.0trust.dev',
      jti: `caep-${randomHex(6)}`,
      iat: Math.floor(Date.now() / 1000),
      events: {
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked': {
          subject: {
            format: 'email',
            email: 'tyler.brooks@0trust.dev'
          },
          initiating_entity: mode === 'AUTO_REMEDIATE' ? 'policy' : 'admin',
          reason_admin: {
            en: `SOAR automated containment for ${incidentId} (${scenarioMeta.sigmaRule.id})`
          },
          event_timestamp: timestamp
        }
      }
    };
  } else if (action === 'WAF_BLOCK_ASN') {
    payload = {
      rule_id: `waf-soar-${incidentId.toLowerCase()}`,
      action: 'block',
      http_status: 403,
      filter: {
        expression: `(ip.src eq ${scenarioMeta.sourceIp} or ip.geoip.asnum eq ${scenarioMeta.asn.replace('AS', '')})`
      },
      incident_id: incidentId,
      ttl_seconds: 3600
    };
  } else {
    payload = {
      signal: 'KILL_SWITCH_QUARANTINE',
      incident_id: incidentId,
      target_principal: 'role/erp-automation-worker',
      iam_policy_attached: 'arn:aws:iam::0trust:policy/DenyAllQuarantine',
      bucket_acl_remediated: 's3://0trust-prod-ledger -> private',
      canary_token: 'CANARY-TOKEN-7741',
      timestamp
    };
  }

  return {
    action,
    webhook_target: playbook.webhookTarget,
    dispatched_at: timestamp,
    http_status: 200,
    mode,
    payload
  };
}

function buildTimeline(
  scenario: AttackScenarioId,
  incidentId: string,
  executedActions: SoarActionId[],
  autoRemediate: boolean
): TimelineEntry[] {
  const def = ATTACK_SCENARIOS[scenario];
  const entries: TimelineEntry[] = [
    {
      t_plus_ms: 0,
      phase: 'INGEST',
      actor: 'Telemetry Collector',
      title: `Attack Telemetry Ingested (${def.code}: ${def.shortLabel})`,
      detail: `${def.telemetryEvents.length} normalized events streamed from ${def.sourceIp} (${def.asn}).`
    },
    {
      t_plus_ms: def.mttdMs,
      phase: 'DETECTION',
      actor: 'Sigma Rule Matcher',
      title: `Matched ${def.sigmaRule.id} (${def.sigmaRule.level.toUpperCase()})`,
      detail: `Incident ${incidentId} created · Risk Score ${def.riskScoreDelta}/100 · MTTD ${def.mttdMs}ms.`
    }
  ];

  if (executedActions.length > 0) {
    const mttr = autoRemediate ? def.autoMttrMs : def.manualMttrMs;
    executedActions.forEach((action, idx) => {
      const playbook = SOAR_PLAYBOOKS[action];
      entries.push({
        t_plus_ms: mttr + idx * 90,
        phase: 'CONTAINMENT',
        actor: autoRemediate ? 'SOAR Auto-Playbook' : 'Amina Diallo (SOC Tier 2)',
        title: `Dispatched ${playbook.title}`,
        detail: `${playbook.description} (MTTR ${mttr + idx * 90}ms)`
      });
    });

    if (executedActions.includes('CAEP_UNIVERSAL_LOGOUT')) {
      entries.push({
        t_plus_ms: mttr + executedActions.length * 90 + 45,
        phase: 'VERIFICATION',
        actor: 'Tyler Brooks (Target Seat)',
        title: 'CAEP Session Revocation Verified (HTTP 401)',
        detail: 'Target identity JWT invalidated across Workforce Portal & Cloud App.'
      });
    }
  }

  return entries.sort((a, b) => a.t_plus_ms - b.t_plus_ms);
}

function shouldUseEdgeApi(): boolean {
  if (typeof window === 'undefined') return false;
  if (import.meta.env?.DEV) return false;
  if (window.location.port === '5181' || window.location.port === '4181') return false;
  return true;
}

export async function ingestAttackTelemetry(
  state: SecopsSoarState,
  scenario: AttackScenarioId,
  autoRemediate: boolean
): Promise<{
  nextState: SecopsSoarState;
  span: ObservabilitySpan;
}> {
  const start = performance.now();
  const trace = createTraceparent();
  const now = new Date().toISOString();
  const def = ATTACK_SCENARIOS[scenario];

  let executionOrigin: 'cloudflare-edge' | 'browser-webcrypto-fallback' =
    'browser-webcrypto-fallback';
  let storageMode: SecopsSoarState['storage_mode'] = 'client-sandbox';
  let incidentId = `INC-SOAR-${Date.now().toString(36).toUpperCase().slice(-6)}`;
  let httpStatus = 200;
  let edgeSummary: Record<string, unknown> | null = null;

  if (shouldUseEdgeApi()) {
    try {
      const res = await fetch('/api/secops-soar/ingest', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': state.session_id,
          traceparent: trace.traceparent
        },
        body: JSON.stringify({
          sessionId: state.session_id,
          scenario,
          auto_remediate: autoRemediate
        })
      });

      const contentType = res.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        const data = (await res.json()) as Record<string, unknown>;
        if (res.ok && typeof data.incident_id === 'string') {
          executionOrigin = 'cloudflare-edge';
          storageMode =
            data.storage === 'cloudflare-kv' ? 'cloudflare-kv' : 'ephemeral-edge';
          incidentId = data.incident_id;
          httpStatus = res.status;
          edgeSummary = data;
        }
      }
    } catch {
      // Expected in local vite dev without Pages Functions; deterministic fallback below
    }
  }

  const latencyMs = Math.max(4, Math.round(performance.now() - start));
  const telemetryEvents: NormalizedTelemetryEvent[] = def.telemetryEvents.map(
    (evt, index) => ({
      ...evt,
      timestamp: new Date(Date.now() + index * 120).toISOString()
    })
  );

  const executedActions: SoarActionId[] = autoRemediate ? [def.recommendedAction] : [];
  const webhookDispatches: SoarWebhookDispatch[] = autoRemediate
    ? [
        buildWebhookDispatch(
          def.recommendedAction,
          scenario,
          incidentId,
          'AUTO_REMEDIATE',
          now
        )
      ]
    : [];

  const compromisedUserRevoked = executedActions.includes('CAEP_UNIVERSAL_LOGOUT');
  const wafBlocked = executedActions.includes('WAF_BLOCK_ASN');
  const killSwitchActive = executedActions.includes('AGENT_KILL_SWITCH');
  const mttrMs = autoRemediate ? def.autoMttrMs : null;

  const nextState: SecopsSoarState = {
    ...state,
    selected_scenario: scenario,
    auto_remediate: autoRemediate,
    incident_id: incidentId,
    incident_status: autoRemediate ? 'CONTAINED' : 'ACTIVE_INCIDENT',
    risk_score: def.riskScoreDelta,
    compromised_user_revoked: compromisedUserRevoked,
    waf_blocked: wafBlocked,
    kill_switch_active: killSwitchActive,
    matched_sigma: def.sigmaRule,
    telemetry_events: telemetryEvents,
    executed_actions: executedActions,
    webhook_dispatches: webhookDispatches,
    timeline: buildTimeline(scenario, incidentId, executedActions, autoRemediate),
    mttd_ms: def.mttdMs,
    mttr_ms: mttrMs,
    storage_mode: storageMode,
    last_updated: now
  };

  const span: ObservabilitySpan = {
    id: `span-${randomHex(4)}`,
    traceparent: trace.traceparent,
    trace_id: trace.trace_id,
    span_id: trace.span_id,
    parent_span_id: '0000000000000000',
    session_id: state.session_id,
    method: 'POST',
    path: '/api/secops-soar/ingest',
    status: httpStatus,
    latency_ms: latencyMs,
    timestamp: now,
    otlp_export: 'in-lab-only',
    redacted_auth_header: null,
    redaction_applied: false,
    execution_origin: executionOrigin,
    response_summary: edgeSummary || {
      status: nextState.incident_status,
      incident_id: incidentId,
      scenario,
      sigma_rule_id: def.sigmaRule.id,
      risk_score: def.riskScoreDelta,
      mttd_ms: def.mttdMs,
      mttr_ms: mttrMs,
      storage: storageMode
    }
  };

  return { nextState, span };
}

export async function executeSoarContainment(
  state: SecopsSoarState,
  action: SoarActionId
): Promise<{
  nextState: SecopsSoarState;
  span: ObservabilitySpan;
}> {
  const start = performance.now();
  const trace = createTraceparent();
  const now = new Date().toISOString();
  const scenario = state.selected_scenario;
  const def = ATTACK_SCENARIOS[scenario];
  const incidentId =
    state.incident_id || `INC-SOAR-${Date.now().toString(36).toUpperCase().slice(-6)}`;

  let executionOrigin: 'cloudflare-edge' | 'browser-webcrypto-fallback' =
    'browser-webcrypto-fallback';
  let storageMode: SecopsSoarState['storage_mode'] = state.storage_mode;
  let httpStatus = 200;
  let edgeSummary: Record<string, unknown> | null = null;

  if (shouldUseEdgeApi()) {
    try {
      const res = await fetch('/api/secops-soar/contain', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Session-Id': state.session_id,
          traceparent: trace.traceparent
        },
        body: JSON.stringify({
          sessionId: state.session_id,
          action,
          incident_id: incidentId,
          scenario
        })
      });

      const contentType = res.headers.get('Content-Type') || '';
      if (contentType.includes('application/json')) {
        const data = (await res.json()) as Record<string, unknown>;
        if (res.ok && data.status === 'CONTAINED') {
          executionOrigin = 'cloudflare-edge';
          storageMode =
            data.storage === 'cloudflare-kv' ? 'cloudflare-kv' : 'ephemeral-edge';
          httpStatus = res.status;
          edgeSummary = data;
        }
      }
    } catch {
      // Expected in local vite dev without Pages Functions; deterministic fallback below
    }
  }

  const latencyMs = Math.max(4, Math.round(performance.now() - start));
  const nextActions = state.executed_actions.includes(action)
    ? state.executed_actions
    : [...state.executed_actions, action];

  const dispatch = buildWebhookDispatch(
    action,
    scenario,
    incidentId,
    state.auto_remediate ? 'AUTO_REMEDIATE' : 'MANUAL_PLAYBOOK',
    now
  );

  const nextDispatches = [
    ...state.webhook_dispatches.filter((d) => d.action !== action),
    dispatch
  ];

  const mttrMs =
    state.mttr_ms ?? (state.auto_remediate ? def.autoMttrMs : def.manualMttrMs);

  const nextState: SecopsSoarState = {
    ...state,
    incident_id: incidentId,
    incident_status: 'CONTAINED',
    compromised_user_revoked:
      state.compromised_user_revoked || action === 'CAEP_UNIVERSAL_LOGOUT',
    waf_blocked: state.waf_blocked || action === 'WAF_BLOCK_ASN',
    kill_switch_active: state.kill_switch_active || action === 'AGENT_KILL_SWITCH',
    executed_actions: nextActions,
    webhook_dispatches: nextDispatches,
    timeline: buildTimeline(
      scenario,
      incidentId,
      nextActions,
      state.auto_remediate
    ),
    mttd_ms: state.mttd_ms ?? def.mttdMs,
    mttr_ms: mttrMs,
    storage_mode: storageMode,
    last_updated: now
  };

  const span: ObservabilitySpan = {
    id: `span-${randomHex(4)}`,
    traceparent: trace.traceparent,
    trace_id: trace.trace_id,
    span_id: trace.span_id,
    parent_span_id: '0000000000000000',
    session_id: state.session_id,
    method: 'POST',
    path: '/api/secops-soar/contain',
    status: httpStatus,
    latency_ms: latencyMs,
    timestamp: now,
    otlp_export: 'in-lab-only',
    redacted_auth_header: null,
    redaction_applied: false,
    execution_origin: executionOrigin,
    response_summary: edgeSummary || {
      status: 'CONTAINED',
      action_executed: action,
      incident_id: incidentId,
      compromised_user_revoked: nextState.compromised_user_revoked,
      waf_blocked: nextState.waf_blocked,
      kill_switch_active: nextState.kill_switch_active,
      mttd_ms: nextState.mttd_ms,
      mttr_ms: nextState.mttr_ms,
      storage: storageMode
    }
  };

  return { nextState, span };
}

export function exportPostIncidentReport(state: SecopsSoarState): string {
  return JSON.stringify(
    {
      report_type: '0trust.dev Lab 6 Post-Incident SecOps & SOAR Summary',
      session_id: state.session_id,
      incident_id: state.incident_id,
      scenario: state.selected_scenario,
      incident_status: state.incident_status,
      sigma_rule: state.matched_sigma
        ? {
            id: state.matched_sigma.id,
            title: state.matched_sigma.title,
            level: state.matched_sigma.level,
            mitre_attack: state.matched_sigma.mitre_attack
          }
        : null,
      containment_state: {
        compromised_user_revoked: state.compromised_user_revoked,
        waf_blocked: state.waf_blocked,
        kill_switch_active: state.kill_switch_active,
        executed_actions: state.executed_actions
      },
      metrics: {
        mttd_ms: state.mttd_ms,
        mttr_ms: state.mttr_ms,
        mode: state.auto_remediate ? 'AUTO_REMEDIATE' : 'MANUAL_PLAYBOOK'
      },
      timeline: state.timeline,
      generated_at: new Date().toISOString()
    },
    null,
    2
  );
}
