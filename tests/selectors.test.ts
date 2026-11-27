import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { createInitialSecopsState } from '../src/engine/secopsSoarEngine';
import {
  selectContainmentActionGates,
  selectGlobalStatusLabel,
  selectSeatNotifications
} from '../src/engine/secopsSoarSelectors';

describe('Lab 6 (secops-soar) UI Selectors — Layer 3', () => {
  it('derives global status label across HEALTHY, ACTIVE_INCIDENT, and CONTAINED', () => {
    const base = createInitialSecopsState('sel-1');
    assert.equal(selectGlobalStatusLabel(base), 'Monitoring');

    assert.equal(
      selectGlobalStatusLabel({ ...base, incident_status: 'ACTIVE_INCIDENT' }),
      'Active Incident'
    );
    assert.equal(
      selectGlobalStatusLabel({ ...base, incident_status: 'CONTAINED' }),
      'Incident Contained'
    );
  });

  it('clears employeeUpdated seat badge after replay verification', () => {
    const base = createInitialSecopsState('sel-2');

    // Healthy: no badges
    assert.deepEqual(selectSeatNotifications(base, false), {
      employeeUpdated: false,
      socAlertActive: false,
      employeeBadgeText: null
    });

    // Active incident: SOC alert active, employee not yet updated
    assert.deepEqual(
      selectSeatNotifications({ ...base, incident_status: 'ACTIVE_INCIDENT' }, false),
      {
        employeeUpdated: false,
        socAlertActive: true,
        employeeBadgeText: null
      }
    );

    // Contained before replay: employeeUpdated is true
    assert.deepEqual(
      selectSeatNotifications(
        {
          ...base,
          incident_status: 'CONTAINED',
          compromised_user_revoked: true
        },
        false
      ),
      {
        employeeUpdated: true,
        socAlertActive: false,
        employeeBadgeText: 'Session Revoked'
      }
    );

    // Contained after replay verification: employeeUpdated clears
    assert.deepEqual(
      selectSeatNotifications(
        {
          ...base,
          incident_status: 'CONTAINED',
          compromised_user_revoked: true
        },
        true
      ),
      {
        employeeUpdated: false,
        socAlertActive: false,
        employeeBadgeText: null
      }
    );
  });

  it('enforces containment and replay action gates', () => {
    const base = createInitialSecopsState('sel-3');
    assert.deepEqual(selectContainmentActionGates(base), {
      canContain: false,
      canReplayAccess: false
    });

    assert.deepEqual(
      selectContainmentActionGates({ ...base, incident_status: 'ACTIVE_INCIDENT' }),
      {
        canContain: true,
        canReplayAccess: true
      }
    );

    assert.deepEqual(
      selectContainmentActionGates({ ...base, incident_status: 'CONTAINED' }),
      {
        canContain: false,
        canReplayAccess: true
      }
    );
  });
});
