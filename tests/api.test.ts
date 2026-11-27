import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { onRequestPost as containPost } from '../functions/api/secops-soar/contain';
import { onRequestPost as ingestPost } from '../functions/api/secops-soar/ingest';
import { MemoryKvAdapter } from '../server/kvAdapter';

function makePostRequest(url: string, body: unknown, sessionId?: string): Request {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json'
  };
  if (sessionId) {
    headers['X-Session-Id'] = sessionId;
  }
  return new Request(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body)
  });
}

describe('Lab 6 (secops-soar) API Routes — Layer 2 Integration', () => {
  it('matches Sigma rules on ingest and rejects invalid/benign scenarios', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'secops-soar' });
    const sessionId = 'layer2-sigma-session';

    // Invalid/benign scenario fails closed with 400 and does not create ACTIVE_INCIDENT
    const badRes = await ingestPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/ingest',
        { scenario: 'BENIGN_HEALTHCHECK', auto_remediate: false },
        sessionId
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(badRes.status, 400);
    const badBody = (await badRes.json()) as { error: string };
    assert.equal(badBody.error, 'INVALID_SCENARIO');
    assert.equal(await kv.get(`lab6:soar:${sessionId}`), null);

    // Valid scenario matches Sigma rule and generates incident_id
    const goodRes = await ingestPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/ingest',
        { scenario: 'CREDENTIAL_STUFFING', auto_remediate: false },
        sessionId
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(goodRes.status, 200);
    const goodBody = (await goodRes.json()) as {
      incident_id: string;
      status: string;
      sigma_rule_id: string;
      risk_score: number;
    };
    assert.ok(goodBody.incident_id.startsWith('INC-'));
    assert.equal(goodBody.status, 'ACTIVE_INCIDENT');
    assert.equal(goodBody.sigma_rule_id, 'SIGMA-AUTH-001');
    assert.equal(goodBody.risk_score, 78);
  });

  it('enforces SOAR containment idempotency and preserves mttr_ms', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'secops-soar' });
    const sessionId = 'layer2-contain-idempotency';

    // 1. Ingest incident
    const ingestRes = await ingestPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/ingest',
        { scenario: 'IMPOSSIBLE_TRAVEL', auto_remediate: false },
        sessionId
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(ingestRes.status, 200);
    const ingestBody = (await ingestRes.json()) as { incident_id: string };

    // 2. First containment
    const contain1 = await containPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/contain',
        { action: 'CAEP_UNIVERSAL_LOGOUT', incident_id: ingestBody.incident_id },
        sessionId
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(contain1.status, 200);
    const body1 = (await contain1.json()) as {
      status: string;
      incident_id: string;
      executed_actions: string[];
      mttr_ms: number;
      compromised_user_revoked: boolean;
    };
    assert.equal(body1.status, 'CONTAINED');
    assert.equal(body1.incident_id, ingestBody.incident_id);
    assert.deepEqual(body1.executed_actions, ['CAEP_UNIVERSAL_LOGOUT']);
    assert.equal(body1.compromised_user_revoked, true);

    // 3. Second containment with same action is idempotent and preserves mttr_ms
    const contain2 = await containPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/contain',
        { action: 'CAEP_UNIVERSAL_LOGOUT', incident_id: ingestBody.incident_id },
        sessionId
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });
    assert.equal(contain2.status, 200);
    const body2 = (await contain2.json()) as {
      status: string;
      incident_id: string;
      executed_actions: string[];
      mttr_ms: number;
    };
    assert.equal(body2.status, 'CONTAINED');
    assert.equal(body2.incident_id, ingestBody.incident_id);
    assert.deepEqual(body2.executed_actions, ['CAEP_UNIVERSAL_LOGOUT']);
    assert.equal(body2.mttr_ms, body1.mttr_ms);
  });

  it('isolates state across different session IDs', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'secops-soar' });

    await ingestPost({
      request: makePostRequest(
        'https://lab.0trust.dev/api/secops-soar/ingest',
        { scenario: 'IMPOSSIBLE_TRAVEL', auto_remediate: true },
        'session-alpha'
      ),
      env: { STATE_KV: kv, ENVIRONMENT: 'test' }
    });

    const alphaRaw = await kv.get('lab6:soar:session-alpha');
    const betaRaw = await kv.get('lab6:soar:session-beta');
    assert.ok(alphaRaw);
    assert.equal(betaRaw, null);
  });
});
