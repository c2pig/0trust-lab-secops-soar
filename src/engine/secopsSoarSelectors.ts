import type { SecopsSoarState } from '../contracts/secopsSoarContract';

export interface SeatNotificationSummary {
  employeeUpdated: boolean;
  socAlertActive: boolean;
  employeeBadgeText: string | null;
}

export interface ContainmentActionGates {
  canContain: boolean;
  canReplayAccess: boolean;
}

export function selectGlobalStatusLabel(state: SecopsSoarState): string {
  if (state.incident_status === 'CONTAINED') return 'Incident Contained';
  if (state.incident_status === 'ACTIVE_INCIDENT') return 'Active Incident';
  return 'Monitoring';
}

export function selectSeatNotifications(
  state: SecopsSoarState,
  verifiedAfterContain: boolean
): SeatNotificationSummary {
  const employeeUpdated = state.incident_status === 'CONTAINED' && !verifiedAfterContain;
  const socAlertActive = state.incident_status === 'ACTIVE_INCIDENT';
  const employeeBadgeText = employeeUpdated
    ? state.compromised_user_revoked
      ? 'Session Revoked'
      : 'Access Contained'
    : null;

  return {
    employeeUpdated,
    socAlertActive,
    employeeBadgeText
  };
}

export function selectContainmentActionGates(
  state: SecopsSoarState
): ContainmentActionGates {
  return {
    canContain: state.incident_status === 'ACTIVE_INCIDENT',
    canReplayAccess:
      state.incident_status === 'ACTIVE_INCIDENT' ||
      state.incident_status === 'CONTAINED'
  };
}
