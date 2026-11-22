export type SecopsSoarSeatId = 'compromised-user' | 'soc-analyst';

export type SoarPhase = 1 | 2 | 3 | 4;

export type AttackScenarioId =
  | 'CREDENTIAL_STUFFING'
  | 'IMPOSSIBLE_TRAVEL'
  | 'PUBLIC_BUCKET_CANARY';

export type SoarActionId =
  | 'WAF_BLOCK_ASN'
  | 'CAEP_UNIVERSAL_LOGOUT'
  | 'AGENT_KILL_SWITCH';

export type SigmaRuleId =
  | 'SIGMA-AUTH-001'
  | 'SIGMA-GEO-002'
  | 'SIGMA-CLOUD-003';

export interface NormalizedTelemetryEvent {
  event_id: string;
  timestamp: string;
  source: 'okta_system_log' | 'cloudflare_edge_waf' | 'aws_cloudtrail';
  event_type: string;
  actor: string;
  source_ip: string;
  asn: string;
  geo: string;
  http_status: number;
  resource: string;
  raw_indicator: string;
}

export interface SigmaRuleMatch {
  id: SigmaRuleId;
  title: string;
  level: 'high' | 'critical';
  status: 'MATCHED';
  mitre_attack: string;
  detection_summary: string;
  yaml: string;
}

export interface SoarWebhookDispatch {
  action: SoarActionId;
  webhook_target: string;
  dispatched_at: string;
  http_status: number;
  mode: 'AUTO_REMEDIATE' | 'MANUAL_PLAYBOOK';
  payload: Record<string, unknown>;
}

export interface TimelineEntry {
  t_plus_ms: number;
  phase: 'INGEST' | 'DETECTION' | 'CONTAINMENT' | 'VERIFICATION';
  actor: string;
  title: string;
  detail: string;
}

export interface AttackScenarioDefinition {
  id: AttackScenarioId;
  code: string;
  title: string;
  shortLabel: string;
  description: string;
  severity: 'HIGH' | 'CRITICAL';
  riskScoreDelta: number;
  sigmaRule: SigmaRuleMatch;
  recommendedAction: SoarActionId;
  allRelevantActions: SoarActionId[];
  mttdMs: number;
  autoMttrMs: number;
  manualMttrMs: number;
  sourceIp: string;
  asn: string;
  telemetryEvents: Omit<NormalizedTelemetryEvent, 'timestamp'>[];
}

export const ATTACK_SCENARIOS: Record<AttackScenarioId, AttackScenarioDefinition> = {
  CREDENTIAL_STUFFING: {
    id: 'CREDENTIAL_STUFFING',
    code: '6A',
    title: 'Credential Stuffing Burst (401/429 Flood)',
    shortLabel: '6A · Credential Stuffing',
    description:
      'High-velocity distributed credential stuffing against Tyler Brooks SSO endpoint from AS49870 (185.220.101.42) triggering 401/429 burst.',
    severity: 'HIGH',
    riskScoreDelta: 78,
    recommendedAction: 'WAF_BLOCK_ASN',
    allRelevantActions: ['WAF_BLOCK_ASN', 'CAEP_UNIVERSAL_LOGOUT'],
    mttdMs: 420,
    autoMttrMs: 890,
    manualMttrMs: 4200,
    sourceIp: '185.220.101.42',
    asn: 'AS49870',
    sigmaRule: {
      id: 'SIGMA-AUTH-001',
      title: 'High-Velocity Credential Stuffing Burst Against Workforce SSO',
      level: 'high',
      status: 'MATCHED',
      mitre_attack: 'T1110.004 · Credential Stuffing',
      detection_summary: 'count(http_status in [401, 429]) >= 25 within 10s by source_ip/asn',
      yaml: `title: High-Velocity Credential Stuffing Burst Against Workforce SSO
id: SIGMA-AUTH-001
status: stable
level: high
logsource:
  product: okta_cloudflare_edge
  category: authentication
detection:
  selection:
    event_type: 'user.authentication.sso'
    http_status: [401, 429]
  timeframe: 10s
  condition: selection | count() by source_ip >= 25
tags:
  - attack.credential_access
  - attack.t1110.004`
    },
    telemetryEvents: [
      {
        event_id: 'evt-6a-001',
        source: 'cloudflare_edge_waf',
        event_type: 'http.request.auth_attempt',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '185.220.101.42',
        asn: 'AS49870',
        geo: 'NL-AMS',
        http_status: 401,
        resource: '/oauth2/v1/token',
        raw_indicator: 'burst_rate=48_req_per_sec; user_agent=python-requests/2.32'
      },
      {
        event_id: 'evt-6a-002',
        source: 'okta_system_log',
        event_type: 'user.authentication.sso',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '185.220.101.42',
        asn: 'AS49870',
        geo: 'NL-AMS',
        http_status: 429,
        resource: 'app/0trust-workforce-portal',
        raw_indicator: 'rate_limit_exceeded; outcome=FAILURE; reason=INVALID_CREDENTIALS'
      }
    ]
  },
  IMPOSSIBLE_TRAVEL: {
    id: 'IMPOSSIBLE_TRAVEL',
    code: '6B',
    title: 'Impossible Travel (Tokyo → Frankfurt in 4m)',
    shortLabel: '6B · Impossible Travel',
    description:
      'Active session token for Tyler Brooks used in Tokyo (203.0.113.10) and replayed 4 minutes later from Frankfurt (198.51.100.77) — 9,340 km velocity anomaly.',
    severity: 'CRITICAL',
    riskScoreDelta: 94,
    recommendedAction: 'CAEP_UNIVERSAL_LOGOUT',
    allRelevantActions: ['CAEP_UNIVERSAL_LOGOUT', 'WAF_BLOCK_ASN'],
    mttdMs: 310,
    autoMttrMs: 640,
    manualMttrMs: 3850,
    sourceIp: '198.51.100.77',
    asn: 'AS24940',
    sigmaRule: {
      id: 'SIGMA-GEO-002',
      title: 'Impossible Travel Geo-Velocity Session Replay',
      level: 'critical',
      status: 'MATCHED',
      mitre_attack: 'T1078 · Valid Accounts (Session Hijack)',
      detection_summary: 'geo_velocity_kmh > 900 across same session_jti within 15m',
      yaml: `title: Impossible Travel Geo-Velocity Session Replay
id: SIGMA-GEO-002
status: stable
level: critical
logsource:
  product: okta_system_log
  category: session
detection:
  selection:
    event_type: 'user.session.access'
    geo_velocity_kmh|gt: 900
  condition: selection
falsepositives:
  - Approved corporate VPN egress change
tags:
  - attack.initial_access
  - attack.t1078`
    },
    telemetryEvents: [
      {
        event_id: 'evt-6b-001',
        source: 'okta_system_log',
        event_type: 'user.session.access',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '203.0.113.10',
        asn: 'AS2516',
        geo: 'JP-TYO',
        http_status: 200,
        resource: 'app/0trust-workforce-portal',
        raw_indicator: 'session_jti=jti-tyler-8821; lat=35.6762; lon=139.6503'
      },
      {
        event_id: 'evt-6b-002',
        source: 'okta_system_log',
        event_type: 'user.session.access',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '198.51.100.77',
        asn: 'AS24940',
        geo: 'DE-FRA',
        http_status: 200,
        resource: 'app/0trust-cloud-ledger',
        raw_indicator: 'session_jti=jti-tyler-8821; delta_t=252s; distance_km=9340; velocity_kmh=133428'
      }
    ]
  },
  PUBLIC_BUCKET_CANARY: {
    id: 'PUBLIC_BUCKET_CANARY',
    code: '6C',
    title: 'Public Bucket ACL Drift + Canary Token Tripwire',
    shortLabel: '6C · Public Bucket + Canary',
    description:
      'Compromised workload identity flips S3/R2 bucket 0trust-prod-ledger to public-read and accesses honey-token CANARY-TOKEN-7741.',
    severity: 'CRITICAL',
    riskScoreDelta: 98,
    recommendedAction: 'AGENT_KILL_SWITCH',
    allRelevantActions: ['AGENT_KILL_SWITCH', 'CAEP_UNIVERSAL_LOGOUT'],
    mttdMs: 260,
    autoMttrMs: 520,
    manualMttrMs: 3600,
    sourceIp: '192.0.2.199',
    asn: 'AS14061',
    sigmaRule: {
      id: 'SIGMA-CLOUD-003',
      title: 'Public Cloud Storage ACL Drift & Canary Honey-Token Access',
      level: 'critical',
      status: 'MATCHED',
      mitre_attack: 'T1530 · Data from Cloud Storage',
      detection_summary: 'PutBucketAcl(public-read) OR object_key contains CANARY-TOKEN-7741',
      yaml: `title: Public Cloud Storage ACL Drift & Canary Honey-Token Access
id: SIGMA-CLOUD-003
status: stable
level: critical
logsource:
  product: aws_cloudtrail
  service: s3_r2
detection:
  acl_drift:
    event_type: 'PutBucketAcl'
    acl: 'public-read'
  canary_hit:
    event_type: 'GetObject'
    raw_indicator|contains: 'CANARY-TOKEN-7741'
  condition: acl_drift or canary_hit
tags:
  - attack.collection
  - attack.t1530`
    },
    telemetryEvents: [
      {
        event_id: 'evt-6c-001',
        source: 'aws_cloudtrail',
        event_type: 'PutBucketAcl',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '192.0.2.199',
        asn: 'AS14061',
        geo: 'US-NYC',
        http_status: 200,
        resource: 's3://0trust-prod-ledger',
        raw_indicator: 'acl_changed=private->public-read; principal=role/erp-automation-worker'
      },
      {
        event_id: 'evt-6c-002',
        source: 'aws_cloudtrail',
        event_type: 'GetObject',
        actor: 'tyler.brooks@0trust.dev',
        source_ip: '192.0.2.199',
        asn: 'AS14061',
        geo: 'US-NYC',
        http_status: 200,
        resource: 's3://0trust-prod-ledger/honeypot/CANARY-TOKEN-7741.json',
        raw_indicator: 'canary_tripwire=CANARY-TOKEN-7741; exfil_bytes=14200'
      }
    ]
  }
};

export interface SoarPlaybookDefinition {
  id: SoarActionId;
  title: string;
  webhookTarget: string;
  description: string;
  badgeText: string;
}

export const SOAR_PLAYBOOKS: Record<SoarActionId, SoarPlaybookDefinition> = {
  WAF_BLOCK_ASN: {
    id: 'WAF_BLOCK_ASN',
    title: 'Cloudflare WAF IP / ASN Block',
    webhookTarget: 'https://api.cloudflare.com/client/v4/zones/0trust-edge/firewall/rules',
    description: 'Deploys edge WAF block (HTTP 403) against attacker source IP and ASN.',
    badgeText: 'WAF Edge Blocked'
  },
  CAEP_UNIVERSAL_LOGOUT: {
    id: 'CAEP_UNIVERSAL_LOGOUT',
    title: 'CAEP Universal Logout (Session Revoke)',
    webhookTarget: 'https://idp.0trust.dev/caep/v1/events/session-revoked',
    description: 'Broadcasts Shared Signals CAEP session-revoked event to immediately terminate Tyler Brooks active JWT.',
    badgeText: 'CAEP Revoked'
  },
  AGENT_KILL_SWITCH: {
    id: 'AGENT_KILL_SWITCH',
    title: 'Agent & IAM Kill Switch Quarantine',
    webhookTarget: 'https://governance.0trust.dev/api/kill-switch/quarantine',
    description: 'Attaches explicit AWS IAM Deny * + reverts bucket ACL to private.',
    badgeText: 'Kill Switch Active'
  }
};

export interface SecopsSoarState {
  session_id: string;
  active_seat: SecopsSoarSeatId;
  active_phase: SoarPhase;
  auto_remediate: boolean;
  selected_scenario: AttackScenarioId;
  incident_id: string | null;
  incident_status: 'HEALTHY' | 'ACTIVE_INCIDENT' | 'CONTAINED';
  risk_score: number;
  compromised_user_revoked: boolean;
  waf_blocked: boolean;
  kill_switch_active: boolean;
  matched_sigma: SigmaRuleMatch | null;
  telemetry_events: NormalizedTelemetryEvent[];
  executed_actions: SoarActionId[];
  webhook_dispatches: SoarWebhookDispatch[];
  timeline: TimelineEntry[];
  mttd_ms: number | null;
  mttr_ms: number | null;
  storage_mode: 'cloudflare-kv' | 'ephemeral-edge' | 'client-sandbox';
  last_updated: string;
}
