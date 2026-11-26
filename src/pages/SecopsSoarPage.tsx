import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, Briefcase, Compass, Download, RotateCcw, ShieldCheck } from 'lucide-react';
import { driver } from 'driver.js';
import 'driver.js/dist/driver.css';
import {
  ATTACK_SCENARIOS,
  AttackScenarioId,
  SOAR_PLAYBOOKS,
  SecopsSoarSeatId,
  SecopsSoarState,
  SoarActionId
} from '../contracts/secopsSoarContract';
import {
  createInitialSecopsState,
  createSecopsSessionId,
  createTraceparent,
  executeSoarContainment,
  exportPostIncidentReport,
  ingestAttackTelemetry
} from '../engine/secopsSoarEngine';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import {
  XRayDecodedProofSection,
  XRayTelemetryDrawer
} from '../components/XRayTelemetryDrawer';
import { ObservabilitySpan } from '../types';

export interface SecopsSoarPageProps {
  onBack: () => void;
}

interface AccessProbeResult {
  appName: string;
  status: number;
  code: string;
  message: string;
}

const SCENARIO_ORDER: AttackScenarioId[] = [
  'IMPOSSIBLE_TRAVEL',
  'CREDENTIAL_STUFFING',
  'PUBLIC_BUCKET_CANARY'
];

const PLAYBOOK_ORDER: SoarActionId[] = [
  'CAEP_UNIVERSAL_LOGOUT',
  'WAF_BLOCK_ASN',
  'AGENT_KILL_SWITCH'
];

const WORKFORCE_APPS = [
  {
    id: 'workforce-portal',
    name: 'Workforce Identity Portal',
    resource: 'app/0trust-workforce-portal',
    scope: 'SSO Profile & Directory'
  },
  {
    id: 'cloud-ledger',
    name: 'Cloud Financial Ledger',
    resource: 'app/0trust-cloud-ledger',
    scope: 'Read/Write Accounting Records'
  },
  {
    id: 'prod-storage',
    name: 'Production Ledger Storage',
    resource: 's3://0trust-prod-ledger',
    scope: 'Encrypted Bucket Artifacts'
  }
] as const;

export const SecopsSoarPage: React.FC<SecopsSoarPageProps> = ({ onBack }) => {
  const [state, setState] = useState<SecopsSoarState>(() => ({
    ...createInitialSecopsState(createSecopsSessionId()),
    active_seat: 'compromised-user'
  }));
  const stateRef = useRef<SecopsSoarState>(state);
  stateRef.current = state;

  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [probeResult, setProbeResult] = useState<AccessProbeResult | null>(null);
  const [verifiedAfterContain, setVerifiedAfterContain] = useState<boolean>(false);

  const tourLaunchedRef = useRef<boolean>(false);
  const bootIngestedRef = useRef<boolean>(false);

  const recordSpan = useCallback((span: ObservabilitySpan) => {
    setSpans((prev) => [span, ...prev].slice(0, 40));
  }, []);

  const seedInitialAlert = useCallback(
    async (baseState: SecopsSoarState) => {
      const { nextState, span } = await ingestAttackTelemetry(
        baseState,
        'IMPOSSIBLE_TRAVEL',
        false
      );
      if (stateRef.current.session_id !== baseState.session_id) return;
      setState({
        ...nextState,
        active_seat: baseState.active_seat
      });
      recordSpan(span);
    },
    [recordSpan]
  );

  useEffect(() => {
    if (bootIngestedRef.current) return;
    bootIngestedRef.current = true;
    void seedInitialAlert(stateRef.current);
  }, [seedInitialAlert]);

  const startLabTour = useCallback(() => {
    const driverObj = driver({
      showProgress: true,
      animate: true,
      allowClose: true,
      overlayOpacity: 0.5,
      steps: [
        {
          popover: {
            title: 'Lab Orientation: Live SecOps Detection & Automated SOAR',
            description:
              'Observe how real-time Sigma detections correlate anomalous identity and cloud events and trigger sub-second SOAR containment webhooks (CAEP Universal Logout, WAF ASN Block, and IAM Kill Switch).'
          }
        },
        {
          element: '#tour-role-switcher',
          popover: {
            title: 'Role Switcher',
            description:
              'Switch between Tyler Brooks (Employee) and Amina Diallo (Security Ops). Notification dots alert you when a live incident needs triage or when session access changes.'
          }
        },
        {
          element: '#tour-workspace',
          popover: {
            title: 'Role Workspace',
            description:
              'Start as Tyler Brooks in the Workforce SaaS Portal to confirm active session access, then switch to Amina Diallo to triage Sigma alerts and run SOAR containment playbooks.'
          }
        },
        {
          element: '.xray-drawer',
          popover: {
            title: 'X-Ray Telemetry Drawer',
            description:
              'Expand this bottom drawer anytime to inspect live HTTP spans, normalized telemetry events, matched Sigma YAML rules, SOAR webhook payloads, and MTTD/MTTR metrics.'
          }
        },
        {
          element: '#tour-lab-controls',
          popover: {
            title: 'Lab Controls',
            description:
              'Use Lab Tour to replay this orientation, or Reset to restore a clean session and fresh active incident.'
          }
        }
      ]
    });
    driverObj.drive();
  }, []);

  useEffect(() => {
    if (tourLaunchedRef.current) return;
    tourLaunchedRef.current = true;
    const timer = window.setTimeout(() => {
      startLabTour();
    }, 300);
    return () => window.clearTimeout(timer);
  }, [startLabTour]);

  const handleReset = useCallback(() => {
    const fresh: SecopsSoarState = {
      ...createInitialSecopsState(createSecopsSessionId()),
      active_seat: 'compromised-user'
    };
    stateRef.current = fresh;
    setState(fresh);
    setSpans([]);
    setProbeResult(null);
    setVerifiedAfterContain(false);
    setBusyKey(null);
    void seedInitialAlert(fresh);
  }, [seedInitialAlert]);

  const handleSelectSeat = useCallback((seatId: SecopsSoarSeatId) => {
    setState((prev) => ({ ...prev, active_seat: seatId }));
  }, []);

  const handleIngestScenario = useCallback(
    async (scenario: AttackScenarioId, autoRemediate: boolean) => {
      const currentSid = stateRef.current.session_id;
      setBusyKey(`ingest:${scenario}`);
      try {
        const { nextState, span } = await ingestAttackTelemetry(
          stateRef.current,
          scenario,
          autoRemediate
        );
        if (stateRef.current.session_id !== currentSid) return;
        setState({
          ...nextState,
          active_seat: stateRef.current.active_seat
        });
        recordSpan(span);
        setProbeResult(null);
        setVerifiedAfterContain(false);
      } finally {
        setBusyKey(null);
      }
    },
    [recordSpan]
  );

  const handleExecuteContainment = useCallback(
    async (action: SoarActionId) => {
      const currentSid = stateRef.current.session_id;
      setBusyKey(`contain:${action}`);
      try {
        const { nextState, span } = await executeSoarContainment(stateRef.current, action);
        if (stateRef.current.session_id !== currentSid) return;
        setState({
          ...nextState,
          active_seat: stateRef.current.active_seat
        });
        recordSpan(span);
        setProbeResult(null);
        setVerifiedAfterContain(false);
      } finally {
        setBusyKey(null);
      }
    },
    [recordSpan]
  );

  const handleOpenWorkforceApp = useCallback(
    (appName: string, resource: string) => {
      const cur = stateRef.current;
      const trace = createTraceparent();
      let result: AccessProbeResult;

      if (cur.compromised_user_revoked) {
        result = {
          appName,
          status: 401,
          code: 'CAEP_SESSION_REVOKED',
          message:
            'HTTP 401 Unauthorized: Session JWT was revoked via Shared Signals CAEP Universal Logout.'
        };
      } else if (cur.waf_blocked) {
        result = {
          appName,
          status: 403,
          code: 'WAF_ASN_BLOCKED',
          message:
            'HTTP 403 Forbidden: Source IP/ASN blocked at Cloudflare Edge WAF.'
        };
      } else if (cur.kill_switch_active) {
        result = {
          appName,
          status: 423,
          code: 'KILL_SWITCH_QUARANTINE',
          message:
            'HTTP 423 Locked: Workload identity quarantined with explicit AWS IAM Deny * and private bucket ACL.'
        };
      } else {
        result = {
          appName,
          status: 200,
          code: 'SESSION_ACTIVE',
          message: `HTTP 200 OK: Authenticated session jti-tyler-8821 granted access to ${appName}.`
        };
      }

      setProbeResult(result);
      if (cur.incident_status === 'CONTAINED') {
        setVerifiedAfterContain(true);
      }

      recordSpan({
        id: `span-probe-${Date.now().toString(36)}`,
        traceparent: trace.traceparent,
        trace_id: trace.trace_id,
        span_id: trace.span_id,
        parent_span_id: '0000000000000000',
        session_id: cur.session_id,
        method: 'GET',
        path: `/api/workforce-portal/session-check?resource=${encodeURIComponent(resource)}`,
        status: result.status,
        latency_ms: 6,
        timestamp: new Date().toISOString(),
        otlp_export: 'in-lab-only',
        redacted_auth_header: 'Bearer ***REDACTED***',
        redaction_applied: true,
        execution_origin: 'browser-webcrypto-fallback',
        response_summary: {
          app: appName,
          resource,
          code: result.code,
          status: result.status
        }
      });
    },
    [recordSpan]
  );

  const handleDownloadReport = useCallback(() => {
    const json = exportPostIncidentReport(stateRef.current);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lab6-secops-soar-${stateRef.current.incident_id || stateRef.current.session_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const globalStatusLabel =
    state.incident_status === 'CONTAINED'
      ? 'Incident Contained'
      : state.incident_status === 'ACTIVE_INCIDENT'
        ? 'Active Incident'
        : 'Monitoring';

  const seats: RoleSeatItem<SecopsSoarSeatId>[] = useMemo(() => {
    const employeeUpdated = state.incident_status === 'CONTAINED' && !verifiedAfterContain;
    const socAlertActive = state.incident_status === 'ACTIVE_INCIDENT';

    return [
      {
        id: 'compromised-user',
        name: 'Tyler Brooks',
        roleLabel: 'Employee',
        appLabel: 'Workforce SaaS Portal',
        avatarInitials: 'TB',
        badge: employeeUpdated
          ? {
              text: state.compromised_user_revoked ? 'Session Revoked' : 'Access Contained',
              tone: 'amber',
              pulse: true
            }
          : null
      },
      {
        id: 'soc-analyst',
        name: 'Amina Diallo',
        roleLabel: 'Security Ops',
        appLabel: 'Incident & SOAR Containment Console',
        avatarInitials: 'AD',
        badge: socAlertActive
          ? { text: '1 Active Alert', tone: 'crimson', pulse: true }
          : null
      }
    ];
  }, [state.incident_status, state.compromised_user_revoked, verifiedAfterContain]);

  const decodedProofSections: XRayDecodedProofSection[] = useMemo(() => {
    const sections: XRayDecodedProofSection[] = [];
    if (state.telemetry_events.length > 0) {
      sections.push({
        id: 'telemetry-events',
        label: `Normalized Telemetry Events (${state.telemetry_events.length})`,
        payload: state.telemetry_events
      });
    }
    if (state.matched_sigma) {
      sections.push({
        id: 'sigma-rule',
        label: `Matched Sigma Rule (${state.matched_sigma.id})`,
        payload: state.matched_sigma
      });
    }
    if (state.webhook_dispatches.length > 0) {
      sections.push({
        id: 'soar-webhooks',
        label: `SOAR Webhook Dispatches (${state.webhook_dispatches.length})`,
        payload: state.webhook_dispatches
      });
    }
    if (state.timeline.length > 0) {
      sections.push({
        id: 'mttd-mttr-timeline',
        label: `MTTD / MTTR Timeline (${state.mttd_ms ?? 0}ms / ${state.mttr_ms ?? 'pending'}ms)`,
        payload: {
          mttd_ms: state.mttd_ms,
          mttr_ms: state.mttr_ms,
          timeline: state.timeline
        }
      });
    }
    return sections;
  }, [state]);

  const sessionStatusBadge = state.compromised_user_revoked ? (
    <span className="badge badge-crimson">REVOKED · CAEP</span>
  ) : state.waf_blocked ? (
    <span className="badge badge-amber">WAF BLOCKED</span>
  ) : state.kill_switch_active ? (
    <span className="badge badge-crimson">QUARANTINED</span>
  ) : (
    <span className="badge badge-emerald">ACTIVE SESSION</span>
  );

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: 'var(--bg-canvas)',
        color: 'var(--text-primary)'
      }}
    >
      {/* 1. Compact AppShell Top Header */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 40,
          backgroundColor: 'rgba(255, 255, 255, 0.96)',
          backdropFilter: 'blur(8px)',
          borderBottom: '1px solid var(--border-subtle)'
        }}
      >
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            padding: '0 16px',
            height: '56px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <button
              type="button"
              onClick={onBack}
              className="btn btn-sm"
              style={{ padding: '5px 9px' }}
              title="All Labs"
            >
              <ArrowLeft size={13} />
              <span>All Labs</span>
            </button>
            <span
              style={{
                fontSize: '14px',
                fontWeight: 700,
                color: 'var(--text-primary)',
                whiteSpace: 'nowrap'
              }}
            >
              Live SecOps Detection &amp; Automated SOAR
            </span>
            <span
              className={`badge ${
                state.incident_status === 'CONTAINED'
                  ? 'badge-emerald'
                  : state.incident_status === 'ACTIVE_INCIDENT'
                    ? 'badge-crimson'
                    : 'badge-blue'
              }`}
              style={{ whiteSpace: 'nowrap', fontSize: '12px' }}
            >
              {globalStatusLabel}
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <RoleSwitcherBar
              seats={seats}
              activeSeatId={state.active_seat}
              onSelectSeat={handleSelectSeat}
              variant="dropdown"
              ariaLabel="Switch workspace persona"
            />

            <div id="tour-lab-controls" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <button
                type="button"
                onClick={startLabTour}
                className="btn btn-sm"
                style={{
                  backgroundColor: 'var(--accent-primary-dim)',
                  borderColor: 'var(--accent-primary-border)',
                  color: 'var(--accent-primary-ink)',
                  fontSize: '13px'
                }}
              >
                <Compass size={14} />
                <span>Lab Tour</span>
              </button>
              <button
                type="button"
                onClick={handleReset}
                className="btn btn-sm"
                style={{ fontSize: '13px' }}
              >
                <RotateCcw size={14} />
                <span>Reset</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      {/* 2. Center Role Workspace */}
      <main id="tour-workspace" style={{ flex: 1, padding: '16px', paddingBottom: '88px' }}>
        <div
          style={{
            maxWidth: '1280px',
            margin: '0 auto',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px'
          }}
        >
          {/* ==================== SEAT 1: TYLER BROOKS — WORKFORCE SAAS PORTAL ==================== */}
          {state.active_seat === 'compromised-user' && (
            <section
              aria-label="Workforce SaaS Portal"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: '#0f172a',
                  color: '#ffffff',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#2563eb',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    <Briefcase size={15} />
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    Workforce SaaS Portal
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: '#e2e8f0' }}>
                  Tyler Brooks · Employee
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div
                  style={{
                    padding: '12px 16px',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '10px'
                  }}
                >
                  <div>
                    <div style={{ fontSize: '14.5px', fontWeight: 700 }}>
                      Signed in as <code className="mono">tyler.brooks@0trust.dev</code>
                    </div>
                    <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                      SSO Session <code className="mono">jti-tyler-8821</code> · Primary Region: Tokyo (JP-TYO)
                    </div>
                  </div>
                  {sessionStatusBadge}
                </div>

                <div>
                  <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                    Assigned Enterprise Applications
                  </h2>
                  <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                    Launch a corporate application to verify live SSO token validity and edge policy status.
                  </p>
                </div>

                <div className="data-table-wrapper">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Application</th>
                        <th>Resource Identifier</th>
                        <th>Access Scope</th>
                        <th>Session Status</th>
                        <th style={{ textAlign: 'right' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {WORKFORCE_APPS.map((app) => (
                        <tr key={app.id}>
                          <td style={{ fontWeight: 700, fontSize: '14px' }}>{app.name}</td>
                          <td className="mono" style={{ fontSize: '13px' }}>{app.resource}</td>
                          <td>{app.scope}</td>
                          <td>{sessionStatusBadge}</td>
                          <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                            <button
                              type="button"
                              className="btn btn-primary btn-sm"
                              style={{ fontSize: '13px', padding: '6px 12px' }}
                              onClick={() => handleOpenWorkforceApp(app.name, app.resource)}
                            >
                              Open App
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {probeResult && (
                  <div
                    style={{
                      padding: '12px 14px',
                      borderRadius: '8px',
                      backgroundColor:
                        probeResult.status === 200
                          ? 'var(--accent-emerald-dim)'
                          : 'var(--accent-crimson-dim)',
                      border: `1px solid ${
                        probeResult.status === 200
                          ? 'var(--accent-emerald-border)'
                          : 'var(--accent-crimson-border)'
                      }`,
                      color:
                        probeResult.status === 200
                          ? 'var(--accent-emerald-ink)'
                          : 'var(--accent-crimson-ink)',
                      fontSize: '13.5px'
                    }}
                  >
                    <strong>
                      {probeResult.appName} ({probeResult.code}):
                    </strong>{' '}
                    {probeResult.message}
                  </div>
                )}
              </div>
            </section>
          )}

          {/* ==================== SEAT 2: AMINA DIALLO — INCIDENT & SOAR CONTAINMENT CONSOLE ==================== */}
          {state.active_seat === 'soc-analyst' && (
            <section
              aria-label="Incident and SOAR Containment Console"
              style={{
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-lg)',
                boxShadow: 'var(--shadow-sm)',
                overflow: 'hidden'
              }}
            >
              <div
                style={{
                  padding: '10px 18px',
                  backgroundColor: 'var(--bg-canvas)',
                  borderBottom: '1px solid var(--border-subtle)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px',
                  flexWrap: 'wrap'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span
                    style={{
                      width: '26px',
                      height: '26px',
                      borderRadius: '5px',
                      backgroundColor: '#7c3aed',
                      color: '#ffffff',
                      display: 'inline-flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontWeight: 700,
                      fontSize: '12px'
                    }}
                  >
                    SO
                  </span>
                  <span style={{ fontSize: '15px', fontWeight: 700 }}>
                    Incident &amp; SOAR Containment Console
                  </span>
                </div>
                <span style={{ fontSize: '13.5px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                  Amina Diallo · Security Ops
                </span>
              </div>

              <div style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
                {/* Metrics & Auto-Remediate Strip */}
                <div
                  style={{
                    padding: '12px 16px',
                    borderRadius: 'var(--radius-md)',
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-subtle)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px', flexWrap: 'wrap', fontSize: '13.5px' }}>
                    <span>
                      Incident:{' '}
                      <strong className="mono">{state.incident_id || 'Pending'}</strong>
                    </span>
                    <span>
                      Risk Score:{' '}
                      <strong
                        style={{
                          color:
                            state.risk_score >= 80
                              ? 'var(--accent-crimson)'
                              : 'var(--accent-emerald)'
                        }}
                      >
                        {state.risk_score}/100
                      </strong>
                    </span>
                    <span>
                      MTTD: <strong>{state.mttd_ms !== null ? `${state.mttd_ms}ms` : '—'}</strong>
                    </span>
                    <span>
                      MTTR: <strong>{state.mttr_ms !== null ? `${state.mttr_ms}ms` : 'Pending'}</strong>
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className={`btn btn-sm ${state.auto_remediate ? 'btn-emerald' : ''}`}
                      style={{ fontSize: '13px', padding: '6px 12px' }}
                      onClick={() =>
                        setState((prev) => ({
                          ...prev,
                          auto_remediate: !prev.auto_remediate
                        }))
                      }
                    >
                      <ShieldCheck size={14} />
                      <span>
                        Auto-SOAR: {state.auto_remediate ? 'ON' : 'Manual'}
                      </span>
                    </button>
                    {state.incident_id && (
                      <button
                        type="button"
                        className="btn btn-sm"
                        style={{ fontSize: '13px', padding: '6px 12px' }}
                        onClick={handleDownloadReport}
                      >
                        <Download size={14} />
                        <span>Export Report</span>
                      </button>
                    )}
                  </div>
                </div>

                {/* Table 1: SIEM Detection Queue */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      SIEM Security Detections (Sigma Rules)
                    </h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Inspect active alerts correlated from Okta, Cloudflare Edge WAF, and AWS CloudTrail telemetry.
                    </p>
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Alert &amp; Sigma Rule</th>
                          <th>Severity</th>
                          <th>Source IP / ASN</th>
                          <th>Status</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {SCENARIO_ORDER.map((scenarioId) => {
                          const def = ATTACK_SCENARIOS[scenarioId];
                          const isSelected = state.selected_scenario === scenarioId && state.incident_id !== null;
                          const isBusy = busyKey === `ingest:${scenarioId}`;
                          return (
                            <tr
                              key={scenarioId}
                              className={isSelected ? 'selected-row' : undefined}
                            >
                              <td>
                                <div style={{ fontWeight: 700, fontSize: '14px' }}>{def.title}</div>
                                <div className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                  {def.sigmaRule.id} · {def.sigmaRule.mitre_attack}
                                </div>
                              </td>
                              <td>
                                <span
                                  className={`badge ${
                                    def.severity === 'CRITICAL' ? 'badge-crimson' : 'badge-amber'
                                  }`}
                                >
                                  {def.severity}
                                </span>
                              </td>
                              <td className="mono" style={{ fontSize: '13px' }}>
                                {def.sourceIp} ({def.asn})
                              </td>
                              <td>
                                {isSelected ? (
                                  state.incident_status === 'CONTAINED' ? (
                                    <span className="badge badge-emerald">CONTAINED</span>
                                  ) : (
                                    <span className="badge badge-crimson">ACTIVE</span>
                                  )
                                ) : (
                                  <span className="badge">QUEUED</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className="btn btn-sm"
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  disabled={busyKey !== null}
                                  onClick={() =>
                                    void handleIngestScenario(scenarioId, state.auto_remediate)
                                  }
                                >
                                  {isBusy ? 'Ingesting…' : isSelected ? 'Re-Correlate' : 'Triage Alert'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Table 2: SOAR Containment Playbooks */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div>
                    <h2 style={{ fontSize: '15.5px', fontWeight: 700, margin: 0 }}>
                      SOAR Containment Playbooks
                    </h2>
                    <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '2px 0 0' }}>
                      Dispatch automated containment webhooks to revoke sessions, block source networks, or quarantine workloads.
                    </p>
                  </div>

                  <div className="data-table-wrapper">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Playbook</th>
                          <th>Target Endpoint</th>
                          <th>Status</th>
                          <th style={{ textAlign: 'right' }}>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {PLAYBOOK_ORDER.map((actionId) => {
                          const playbook = SOAR_PLAYBOOKS[actionId];
                          const executed = state.executed_actions.includes(actionId);
                          const isBusy = busyKey === `contain:${actionId}`;
                          return (
                            <tr key={actionId}>
                              <td>
                                <div style={{ fontWeight: 700, fontSize: '14px' }}>{playbook.title}</div>
                                <div style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                                  {playbook.description}
                                </div>
                              </td>
                              <td className="mono" style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
                                {playbook.webhookTarget}
                              </td>
                              <td>
                                {executed ? (
                                  <span className="badge badge-emerald">{playbook.badgeText}</span>
                                ) : (
                                  <span className="badge">READY</span>
                                )}
                              </td>
                              <td style={{ textAlign: 'right', whiteSpace: 'nowrap' }}>
                                <button
                                  type="button"
                                  className={`btn btn-sm ${executed ? '' : 'btn-primary'}`}
                                  style={{ fontSize: '13px', padding: '6px 12px' }}
                                  disabled={busyKey !== null || executed}
                                  onClick={() => void handleExecuteContainment(actionId)}
                                >
                                  {isBusy ? 'Dispatching…' : executed ? 'Executed' : 'Run Playbook'}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Matched Sigma Rule Preview */}
                {state.matched_sigma && (
                  <div>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                      Matched Detection Rule ({state.matched_sigma.id})
                    </div>
                    <pre
                      className="mono"
                      style={{
                        margin: 0,
                        padding: '12px 14px',
                        borderRadius: 'var(--radius-sm)',
                        backgroundColor: 'var(--bg-canvas)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '13px',
                        lineHeight: 1.55,
                        overflowX: 'auto',
                        color: 'var(--text-primary)'
                      }}
                    >
                      {state.matched_sigma.yaml}
                    </pre>
                  </div>
                )}
              </div>
            </section>
          )}
        </div>
      </main>

      {/* 3. Sticky-Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
};
