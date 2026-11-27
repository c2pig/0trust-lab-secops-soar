import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  createInitialSecopsState,
  createSecopsSessionId,
  createTraceparent,
  exportPostIncidentReport
} from '../src/engine/secopsSoarEngine';

describe('Lab 6 (secops-soar) Engine — Layer 3', () => {
  it('creates initial state with HEALTHY status and clean telemetry', () => {
    const sessionId = createSecopsSessionId();
    assert.ok(sessionId.startsWith('soar-'));

    const state = createInitialSecopsState(sessionId);
    assert.equal(state.session_id, sessionId);
    assert.equal(state.incident_status, 'HEALTHY');
    assert.equal(state.incident_id, null);
    assert.equal(state.compromised_user_revoked, false);
    assert.equal(state.executed_actions.length, 0);
  });

  it('generates valid W3C traceparent headers', () => {
    const tp = createTraceparent();
    assert.match(tp.traceparent, /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/);
    assert.equal(tp.trace_id.length, 32);
    assert.equal(tp.span_id.length, 16);
  });

  it('exports a valid JSON post-incident report', () => {
    const state = createInitialSecopsState('engine-export-1');
    const raw = exportPostIncidentReport({
      ...state,
      incident_id: 'INC-TEST-001',
      incident_status: 'CONTAINED',
      compromised_user_revoked: true
    });
    const parsed = JSON.parse(raw) as {
      incident_id: string;
      incident_status: string;
    };
    assert.equal(parsed.incident_id, 'INC-TEST-001');
    assert.equal(parsed.incident_status, 'CONTAINED');
  });
});
