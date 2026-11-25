import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createCloudRunApp, verifyRouterSecret } from '../server/app';
import {
  buildKvDocId,
  FirestoreKvAdapter,
  MemoryKvAdapter,
  type FirestoreCollectionLike,
  type FirestoreKvDoc
} from '../server/kvAdapter';
import { resolvePublicOrigin } from '../server/origin';

const TEST_ROUTER_SECRET = 'test-router-secret-value-0123456789';

function createMockFirestoreCollection(): {
  collection: FirestoreCollectionLike;
  store: Map<string, FirestoreKvDoc>;
} {
  const store = new Map<string, FirestoreKvDoc>();
  const collection: FirestoreCollectionLike = {
    doc(id: string) {
      return {
        async get() {
          const data = store.get(id);
          return {
            exists: Boolean(data),
            data: () => data
          };
        },
        async set(data: FirestoreKvDoc) {
          store.set(id, data);
        },
        async delete() {
          store.delete(id);
        }
      };
    }
  };
  return { collection, store };
}

describe('Lab 6 (secops-soar) Cloud Run Adapter — Red-Team & Security Invariants', () => {
  it('blocks direct *.run.app /api/* requests without or with invalid X-Lab-Router-Secret (fail-closed 403)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'secops-soar',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'secops-soar' })
    });

    const ingestPayload = JSON.stringify({
      scenario: 'IMPOSSIBLE_TRAVEL',
      auto_remediate: false
    });

    // Missing header
    const resMissing = await app.request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: ingestPayload
      }
    );
    assert.equal(resMissing.status, 403);
    assert.deepEqual(await resMissing.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Wrong secret (same length & different length)
    const resWrongSameLen = await app.request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'wrong-router-secret-value-987654321'
        },
        body: ingestPayload
      }
    );
    assert.equal(resWrongSameLen.status, 403);
    assert.deepEqual(await resWrongSameLen.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    const resWrongDiffLen = await app.request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': 'short'
        },
        body: ingestPayload
      }
    );
    assert.equal(resWrongDiffLen.status, 403);

    // Fail-closed when LAB_ROUTER_SECRET is unset in production
    const appUnconfigured = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'secops-soar'
      },
      kv: new MemoryKvAdapter({ labSlug: 'secops-soar' })
    });
    const resUnconfigured = await appUnconfigured.request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: ingestPayload
      }
    );
    assert.equal(resUnconfigured.status, 403);
    assert.deepEqual(await resUnconfigured.json(), { error: 'FORBIDDEN_DIRECT_ORIGIN' });

    // Valid secret succeeds
    const resValid = await app.request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-lab-router-secret': TEST_ROUTER_SECRET
        },
        body: ingestPayload
      }
    );
    assert.equal(resValid.status, 200);
    const json = (await resValid.json()) as Record<string, unknown>;
    assert.equal(json.status, 'ACTIVE_INCIDENT');
    assert.equal(json.sigma_rule_id, 'SIGMA-GEO-002');
    assert.equal(verifyRouterSecret(TEST_ROUTER_SECRET, TEST_ROUTER_SECRET), true);
  });

  it('serves GET /healthz without X-Lab-Router-Secret (Cloud Run probe)', async () => {
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'production',
        LAB_SLUG: 'secops-soar',
        LAB_ROUTER_SECRET: TEST_ROUTER_SECRET
      },
      kv: new MemoryKvAdapter({ labSlug: 'secops-soar' })
    });

    const res = await app.request('https://0trust-lab-secops-soar-abc.run.app/healthz');
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, lab: 'secops-soar' });
  });

  it('synchronously returns null on expired TTL docs in FirestoreKvAdapter & MemoryKvAdapter', async () => {
    let nowMs = 1_700_000_000_000;
    const { collection, store } = createMockFirestoreCollection();
    const firestoreKv = new FirestoreKvAdapter({
      labSlug: 'secops-soar',
      collectionRef: collection,
      nowFn: () => nowMs
    });

    await firestoreKv.put('lab6:soar:session/1', '{"v":1}', { expirationTtl: 3600 });
    const expectedDocId = buildKvDocId('secops-soar', 'lab6:soar:session/1');
    assert.equal(expectedDocId, 'secops-soar:lab6%3Asoar%3Asession%2F1');

    const storedDoc = store.get(expectedDocId);
    assert.ok(storedDoc);
    assert.equal(storedDoc.labSlug, 'secops-soar');
    assert.equal(storedDoc.value, '{"v":1}');
    assert.equal(storedDoc.expireAt?.toMillis(), nowMs + 3_600_000);

    // Before expiry
    assert.equal(await firestoreKv.get('lab6:soar:session/1'), '{"v":1}');

    // Advance clock past TTL without deleting doc from Firestore
    nowMs += 3_600_000;
    assert.equal(store.has(expectedDocId), true);
    assert.equal(await firestoreKv.get('lab6:soar:session/1'), null);

    // MemoryKvAdapter parity
    let memNow = 1_700_000_000_000;
    const memKv = new MemoryKvAdapter({ labSlug: 'secops-soar', nowFn: () => memNow });
    await memKv.put('lab6:soar:abc', 'ok', { expirationTtl: 10 });
    assert.equal(await memKv.get('lab6:soar:abc'), 'ok');
    memNow += 10_000;
    assert.equal(await memKv.get('lab6:soar:abc'), null);
  });

  it('rejects forged X-Forwarded-Host headers and allows lab.0trust.dev + localhost', () => {
    const forgedReq = new Request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        headers: {
          'x-forwarded-host': 'evil.com',
          'x-forwarded-proto': 'https'
        }
      }
    );
    assert.equal(resolvePublicOrigin(forgedReq), 'https://0trust-lab-secops-soar-abc.run.app');

    const prodReq = new Request(
      'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
      {
        headers: {
          'x-forwarded-host': 'lab.0trust.dev',
          'x-forwarded-proto': 'https'
        }
      }
    );
    assert.equal(resolvePublicOrigin(prodReq), 'https://lab.0trust.dev');

    const localReq = new Request('http://127.0.0.1:8080/api/secops-soar/ingest', {
      headers: {
        'x-forwarded-host': 'localhost:5181',
        'x-forwarded-proto': 'http'
      }
    });
    assert.equal(resolvePublicOrigin(localReq), 'http://localhost:5181');
  });

  it('redacts JWT signatures in _telemetry and never leaks X-Lab-Router-Secret or OTLP_AUTH_HEADER', async () => {
    const otlpAuthSecret = 'Bearer otlp-super-secret-header-token';
    const capturedOtlpBodies: string[] = [];
    const originalFetch = globalThis.fetch;

    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      capturedOtlpBodies.push(String(init?.body || ''));
      return new Response('{}', { status: 200 });
    }) as typeof fetch;

    try {
      const app = createCloudRunApp({
        env: {
          ENVIRONMENT: 'production',
          LAB_SLUG: 'secops-soar',
          LAB_ROUTER_SECRET: TEST_ROUTER_SECRET,
          OTLP_ENDPOINT: 'https://otlp.example.com',
          OTLP_AUTH_HEADER: otlpAuthSecret
        },
        kv: new MemoryKvAdapter({ labSlug: 'secops-soar' })
      });

      const fakeJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.SuperSecretSignatureXYZ123';
      const res = await app.request(
        'https://0trust-lab-secops-soar-abc.run.app/api/secops-soar/ingest',
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-lab-router-secret': TEST_ROUTER_SECRET,
            authorization: `Bearer ${fakeJwt}`,
            traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
          },
          body: JSON.stringify({ scenario: 'CREDENTIAL_STUFFING', auto_remediate: false })
        }
      );

      assert.equal(res.status, 200);
      assert.ok(res.headers.get('traceparent')?.startsWith('00-4bf92f3577b34da6a3ce929d0e0e4736-'));
      assert.ok(res.headers.get('X-Edge-Latency-Ms'));

      const bodyText = await res.text();
      assert.ok(!bodyText.includes('SuperSecretSignatureXYZ123'), 'JWT signature must be redacted');
      assert.ok(!bodyText.includes(TEST_ROUTER_SECRET), 'Router secret must never appear in response');
      assert.ok(!bodyText.includes(otlpAuthSecret), 'OTLP auth header must never appear in response');

      const parsed = JSON.parse(bodyText) as {
        _telemetry: { redacted_auth_header: string; redaction_applied: boolean };
      };
      assert.equal(parsed._telemetry.redaction_applied, true);
      assert.equal(
        parsed._telemetry.redacted_auth_header,
        'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.***REDACTED***'
      );

      await new Promise((r) => setTimeout(r, 10));
      assert.equal(capturedOtlpBodies.length, 2);
      for (const otlpBody of capturedOtlpBodies) {
        assert.ok(!otlpBody.includes(TEST_ROUTER_SECRET));
        assert.ok(!otlpBody.includes('SuperSecretSignatureXYZ123'));
        assert.ok(!otlpBody.includes(otlpAuthSecret));
      }
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it('executes full Lab 6 SecOps ingest → SOAR contain lifecycle on Cloud Run adapter', async () => {
    const kv = new MemoryKvAdapter({ labSlug: 'secops-soar' });
    const app = createCloudRunApp({
      env: {
        ENVIRONMENT: 'development',
        LAB_SLUG: 'secops-soar'
      },
      kv
    });

    const sessionId = 'test-soar-session';

    // 1. Ingest Impossible Travel telemetry -> ACTIVE_INCIDENT
    const ingestRes = await app.request('http://127.0.0.1:8080/api/secops-soar/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        scenario: 'IMPOSSIBLE_TRAVEL',
        auto_remediate: false
      })
    });
    assert.equal(ingestRes.status, 200);
    const ingestData = (await ingestRes.json()) as {
      status: string;
      incident_id: string;
      sigma_rule_id: string;
      compromised_user_revoked: boolean;
    };
    assert.equal(ingestData.status, 'ACTIVE_INCIDENT');
    assert.equal(ingestData.sigma_rule_id, 'SIGMA-GEO-002');
    assert.equal(ingestData.compromised_user_revoked, false);
    assert.ok(ingestData.incident_id.startsWith('INC-SOAR-'));

    // 2. Contain via CAEP_UNIVERSAL_LOGOUT -> CONTAINED + revoked
    const containRes = await app.request('http://127.0.0.1:8080/api/secops-soar/contain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({
        action: 'CAEP_UNIVERSAL_LOGOUT',
        incident_id: ingestData.incident_id
      })
    });
    assert.equal(containRes.status, 200);
    const containData = (await containRes.json()) as {
      status: string;
      compromised_user_revoked: boolean;
      executed_actions: string[];
      webhook_dispatched: { event_type: string };
    };
    assert.equal(containData.status, 'CONTAINED');
    assert.equal(containData.compromised_user_revoked, true);
    assert.deepEqual(containData.executed_actions, ['CAEP_UNIVERSAL_LOGOUT']);
    assert.equal(
      containData.webhook_dispatched.event_type,
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked'
    );

    // 3. Invalid scenario rejected with 400
    const badRes = await app.request('http://127.0.0.1:8080/api/secops-soar/ingest', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Session-Id': sessionId },
      body: JSON.stringify({ scenario: 'UNKNOWN_SCENARIO' })
    });
    assert.equal(badRes.status, 400);

    // Verify persisted session KV state
    const rawState = await kv.get(`lab6:soar:${sessionId}`);
    assert.ok(rawState);
    const state = JSON.parse(rawState) as {
      incident_id: string;
      incident_status: string;
      compromised_user_revoked: boolean;
    };
    assert.equal(state.incident_id, ingestData.incident_id);
    assert.equal(state.incident_status, 'CONTAINED');
    assert.equal(state.compromised_user_revoked, true);
  });
});
