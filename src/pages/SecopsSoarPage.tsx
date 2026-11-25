import React, { useCallback, useMemo, useState } from 'react';
import {
  Activity,
  ArrowLeft,
  ArrowRight,
  Play,
  RotateCcw,
  ShieldAlert,
  Terminal,
  Zap
} from 'lucide-react';
import {
  ATTACK_SCENARIOS,
  AttackScenarioId,
  SecopsSoarSeatId,
  SecopsSoarState,
  SoarActionId,
  SoarPhase
} from '../contracts/secopsSoarContract';
import {
  createInitialSecopsState,
  createSecopsSessionId,
  executeSoarContainment,
  exportPostIncidentReport,
  ingestAttackTelemetry
} from '../engine/secopsSoarEngine';
import { RoleSeatItem, RoleSwitcherBar } from '../components/RoleSwitcherBar';
import {
  XRayDecodedProofSection,
  XRayTelemetryDrawer
} from '../components/XRayTelemetryDrawer';
import {
  AccessProbeResult,
  SoarWarRoomPractice
} from '../components/secops-soar/SoarWarRoomPractice';
import { SoarReflectionSection } from '../components/secops-soar/SoarReflectionSection';
import { ObservabilitySpan } from '../types';

export interface SecopsSoarPageProps {
  onBack: () => void;
}

const PHASE_LABELS: { phase: SoarPhase; title: string; subtitle: string }[] = [
  { phase: 1, title: '1. Discovery', subtitle: 'Telemetry & Sigma Pipeline' },
  { phase: 2, title: '2. Understanding', subtitle: 'Inject Attack & Match Sigma' },
  { phase: 3, title: '3. Practice', subtitle: 'SOAR Containment & Verify' },
  { phase: 4, title: '4. Reflection', subtitle: 'MTTD / MTTR Timeline' }
];

export const SecopsSoarPage: React.FC<SecopsSoarPageProps> = ({ onBack }) => {
  const [state, setState] = useState<SecopsSoarState>(() =>
    createInitialSecopsState(createSecopsSessionId())
  );
  const [spans, setSpans] = useState<ObservabilitySpan[]>([]);
  const [busy, setBusy] = useState(false);
  const [copiedNotice, setCopiedNotice] = useState(false);
  const [probeResult, setProbeResult] = useState<AccessProbeResult | null>(null);

  const handleReset = useCallback(() => {
    setState(createInitialSecopsState(createSecopsSessionId()));
    setSpans([]);
    setProbeResult(null);
    setCopiedNotice(false);
  }, []);

  const handleSelectSeat = useCallback((seatId: SecopsSoarSeatId) => {
    setState((prev) => ({ ...prev, active_seat: seatId }));
  }, []);

  const handleSetPhase = useCallback((phase: SoarPhase) => {
    setState((prev) => ({ ...prev, active_phase: phase }));
  }, []);

  const handleInjectTelemetry = useCallback(
    async (scenario: AttackScenarioId, autoRemediate: boolean) => {
      setBusy(true);
      try {
        const { nextState, span } = await ingestAttackTelemetry(
          state,
          scenario,
          autoRemediate
        );
        setState({
          ...nextState,
          active_phase: autoRemediate ? 3 : 2
        });
        setSpans((prev) => [span, ...prev]);
        setProbeResult(null);
      } finally {
        setBusy(false);
      }
    },
    [state]
  );

  const handleExecuteContainment = useCallback(
    async (action: SoarActionId) => {
      setBusy(true);
      try {
        const { nextState, span } = await executeSoarContainment(state, action);
        setState(nextState);
        setSpans((prev) => [span, ...prev]);
        setProbeResult(null);
      } finally {
        setBusy(false);
      }
    },
    [state]
  );

  const handleProbeUserAccess = useCallback(() => {
    if (state.compromised_user_revoked) {
      setProbeResult({
        status: 401,
        code: 'CAEP_SESSION_REVOKED',
        message:
          'HTTP 401 Unauthorized: Tyler Brooks session JWT was revoked via Shared Signals CAEP Universal Logout.'
      });
      return;
    }
    if (state.waf_blocked) {
      setProbeResult({
        status: 403,
        code: 'WAF_ASN_BLOCKED',
        message:
          'HTTP 403 Forbidden: Request from attacker IP/ASN blocked at Cloudflare Edge WAF.'
      });
      return;
    }
    if (state.kill_switch_active) {
      setProbeResult({
        status: 423,
        code: 'KILL_SWITCH_QUARANTINE',
        message:
          'HTTP 423 Locked: Workload identity quarantined with AWS IAM Deny * and bucket ACL restored to private.'
      });
      return;
    }
    setProbeResult({
      status: 200,
      code: 'SESSION_ACTIVE',
      message:
        state.incident_status === 'ACTIVE_INCIDENT'
          ? 'HTTP 200 OK (EXPOSED): Compromised session still holds valid access until SOAR containment runs!'
          : 'HTTP 200 OK: Normal workforce session active.'
    });
  }, [state]);

  const handleCopyReport = useCallback(async () => {
    const json = exportPostIncidentReport(state);
    try {
      await navigator.clipboard.writeText(json);
      setCopiedNotice(true);
      setTimeout(() => setCopiedNotice(false), 2000);
    } catch {
      // Clipboard may be unavailable in headless environments
    }
  }, [state]);

  const handleDownloadReport = useCallback(() => {
    const json = exportPostIncidentReport(state);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `secops-soar-${state.incident_id || state.session_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state]);

  const seats: RoleSeatItem<SecopsSoarSeatId>[] = useMemo(() => {
    const userBadge = state.compromised_user_revoked
      ? { text: 'Session Revoked', tone: 'crimson' as const }
      : state.waf_blocked
        ? { text: 'WAF Blocked', tone: 'amber' as const }
        : state.kill_switch_active
          ? { text: 'Kill Switch Active', tone: 'crimson' as const }
          : state.incident_status === 'ACTIVE_INCIDENT'
            ? { text: 'Compromised', tone: 'amber' as const, pulse: true }
            : { text: 'Session Active', tone: 'emerald' as const };

    const socBadge =
      state.incident_status === 'CONTAINED'
        ? { text: 'Contained', tone: 'emerald' as const }
        : state.incident_status === 'ACTIVE_INCIDENT'
          ? { text: 'Active Alert', tone: 'crimson' as const, pulse: true }
          : { text: 'Monitoring', tone: 'blue' as const };

    return [
      {
        id: 'compromised-user',
        name: 'Tyler Brooks',
        roleLabel: 'Target Identity · Compromised Session',
        appLabel: 'Workforce Session & Cloud App',
        avatarInitials: 'TB',
        badge: userBadge
      },
      {
        id: 'soc-analyst',
        name: 'Amina Diallo',
        roleLabel: 'SOC Tier 2 · Detection & SOAR',
        appLabel: 'SIEM Queue & SOAR Playbook Engine',
        avatarInitials: 'AD',
        badge: socBadge
      }
    ];
  }, [state]);

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

  const activeScenarioDef = ATTACK_SCENARIOS[state.selected_scenario];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#f8fafc' }}>
      {/* Top Navigation Bar */}
      <header className="navbar">
        <div className="navbar-brand">
          <button
            type="button"
            className="btn btn-sm"
            onClick={onBack}
            aria-label="Back to All Labs"
          >
            <ArrowLeft size={14} />
            <span>All Labs</span>
          </button>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <span className="brand-title">Live SecOps Detection &amp; Automated SOAR</span>
            <span className="brand-subtitle">
              Lab 6 · Sigma Rule Matcher · CAEP Universal Logout · WAF &amp; Kill Switch
            </span>
          </div>
        </div>

        <div className="navbar-actions">
          <span className="badge badge-emerald">Guided Sandbox · $0.00/mo</span>
          <span className="badge badge-blue mono">{state.storage_mode}</span>
          <button
            type="button"
            className="btn btn-sm btn-danger-soft"
            onClick={handleReset}
            aria-label="Reset Lab"
          >
            <RotateCcw size={14} />
            <span>Reset</span>
          </button>
        </div>
      </header>

      {/* Main Mission Control Workspace */}
      <main className="mission-control" style={{ flex: 1, paddingBottom: '88px' }}>
        <div className="page-container">
          {/* 2-Seat Role Switcher Bar */}
          <RoleSwitcherBar
            seats={seats}
            activeSeatId={state.active_seat}
            onSelectSeat={handleSelectSeat}
            ariaLabel="SecOps & Target Identity Role Switcher"
          />

          {/* 4-Phase Cognitive Arc Stepper */}
          <nav className="stepper-bar" aria-label="4-Phase Cognitive Arc" style={{ marginTop: '16px' }}>
            {PHASE_LABELS.map((item) => {
              const isActive = state.active_phase === item.phase;
              const isCompleted = state.active_phase > item.phase;
              return (
                <button
                  key={item.phase}
                  type="button"
                  className={`stage-pill${isActive ? ' active' : ''}${isCompleted ? ' completed' : ''}`}
                  onClick={() => handleSetPhase(item.phase)}
                >
                  <span className="stage-number">{item.phase}</span>
                  <div style={{ textAlign: 'left' }}>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>{item.title}</div>
                    <div style={{ fontSize: '0.72rem', opacity: 0.8 }}>{item.subtitle}</div>
                  </div>
                </button>
              );
            })}
          </nav>

          {/* Status Summary Strip */}
          <div
            className="surface-card"
            style={{
              marginTop: '16px',
              display: 'flex',
              flexWrap: 'wrap',
              gap: '12px',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}
          >
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '10px', alignItems: 'center' }}>
              <span
                className={`badge ${
                  state.incident_status === 'CONTAINED'
                    ? 'badge-emerald'
                    : state.incident_status === 'ACTIVE_INCIDENT'
                      ? 'badge-crimson'
                      : 'badge-blue'
                }`}
              >
                {state.incident_status === 'CONTAINED'
                  ? 'INCIDENT CONTAINED'
                  : state.incident_status === 'ACTIVE_INCIDENT'
                    ? 'ACTIVE INCIDENT'
                    : 'BASELINE HEALTHY'}
              </span>
              <span className="mono" style={{ fontSize: '0.8rem', color: '#475569' }}>
                Session: {state.session_id}
              </span>
              {state.incident_id && (
                <span className="mono" style={{ fontSize: '0.8rem', color: '#0f172a', fontWeight: 600 }}>
                  Incident: {state.incident_id}
                </span>
              )}
            </div>

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '12px', alignItems: 'center' }}>
              <span style={{ fontSize: '0.82rem', color: '#334155' }}>
                Risk Score:{' '}
                <strong
                  style={{
                    color:
                      state.risk_score >= 80
                        ? '#dc2626'
                        : state.risk_score >= 50
                          ? '#d97706'
                          : '#059669'
                  }}
                >
                  {state.risk_score}/100
                </strong>
              </span>
              <span style={{ fontSize: '0.82rem', color: '#334155' }}>
                MTTD: <strong>{state.mttd_ms !== null ? `${state.mttd_ms}ms` : '—'}</strong>
              </span>
              <span style={{ fontSize: '0.82rem', color: '#334155' }}>
                MTTR: <strong>{state.mttr_ms !== null ? `${state.mttr_ms}ms` : '—'}</strong>
              </span>
            </div>
          </div>

          {/* PHASE 1: DISCOVERY */}
          {state.active_phase === 1 && (
            <section className="surface-card" style={{ marginTop: '16px' }}>
              <div className="section-header">
                <h2 className="section-title">Phase 1 · Discovery: Telemetry-to-SOAR Pipeline</h2>
                <p className="section-subtitle">
                  Trace how workforce auth logs, Cloudflare Edge WAF events, and AWS CloudTrail telemetry flow through
                  real-time Sigma rules into automated SOAR containment webhooks.
                </p>
              </div>

              <div className="grid-2" style={{ marginTop: '16px', gap: '16px' }}>
                <div className="surface-card" style={{ background: '#f8fafc' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <Activity size={18} color="#2563eb" />
                    <strong>1. Normalized Telemetry Sources</strong>
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.85rem', color: '#475569', lineHeight: 1.6 }}>
                    <li><code>okta_system_log</code> — SSO logins, geo-velocity, session JTI</li>
                    <li><code>cloudflare_edge_waf</code> — 401/429 bursts, ASN/IP reputation</li>
                    <li><code>aws_cloudtrail</code> — S3/R2 ACL mutations &amp; canary tripwires</li>
                  </ul>
                </div>

                <div className="surface-card" style={{ background: '#f8fafc' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <Terminal size={18} color="#7c3aed" />
                    <strong>2. Sigma Rule Matcher</strong>
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.85rem', color: '#475569', lineHeight: 1.6 }}>
                    <li><code>SIGMA-AUTH-001</code> — Credential Stuffing Burst (T1110.004)</li>
                    <li><code>SIGMA-GEO-002</code> — Impossible Travel Replay (T1078)</li>
                    <li><code>SIGMA-CLOUD-003</code> — Public Bucket + Canary Hit (T1530)</li>
                  </ul>
                </div>

                <div className="surface-card" style={{ background: '#f8fafc' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <ShieldAlert size={18} color="#d97706" />
                    <strong>3. SIEM Incident Queue</strong>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.85rem', color: '#475569', lineHeight: 1.6 }}>
                    Elevates session risk score, correlates actor &amp; source ASN, and queues structured incident in{' '}
                    <code>STATE_KV (lab6:soar:*)</code> with 1h TTL.
                  </p>
                </div>

                <div className="surface-card" style={{ background: '#f8fafc' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <Zap size={18} color="#059669" />
                    <strong>4. Automated SOAR Webhooks</strong>
                  </div>
                  <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.85rem', color: '#475569', lineHeight: 1.6 }}>
                    <li><strong>CAEP Universal Logout</strong> — Revokes target identity JWT</li>
                    <li><strong>Cloudflare WAF Block</strong> — Drops attacker IP/ASN at edge</li>
                    <li><strong>Agent Kill Switch</strong> — Attaches IAM Deny * &amp; locks ACL</li>
                  </ul>
                </div>
              </div>

              <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleSetPhase(2)}
                >
                  <span>Proceed to Phase 2: Attack Injector</span>
                  <ArrowRight size={15} />
                </button>
              </div>
            </section>
          )}

          {/* PHASE 2: UNDERSTANDING */}
          {state.active_phase === 2 && (
            <section className="surface-card" style={{ marginTop: '16px' }}>
              <div className="section-header">
                <h2 className="section-title">Phase 2 · Understanding: Attack Telemetry Injector</h2>
                <p className="section-subtitle">
                  Select an attack scenario and remediation mode, then inject live telemetry to watch Sigma rules match
                  and generate a SIEM incident.
                </p>
              </div>

              {/* Remediation Mode Toggle */}
              <div
                style={{
                  marginTop: '14px',
                  padding: '12px 14px',
                  borderRadius: '10px',
                  background: '#f1f5f9',
                  display: 'flex',
                  flexWrap: 'wrap',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '12px'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.88rem', color: '#0f172a' }}>
                    SOAR Execution Mode
                  </div>
                  <div style={{ fontSize: '0.78rem', color: '#475569' }}>
                    Compare manual Tier-2 analyst triage vs. sub-second automated SOAR containment.
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    type="button"
                    className={`btn btn-sm ${!state.auto_remediate ? 'btn-dark' : ''}`}
                    onClick={() => setState((prev) => ({ ...prev, auto_remediate: false }))}
                  >
                    Manual SOAR Playbook
                  </button>
                  <button
                    type="button"
                    className={`btn btn-sm ${state.auto_remediate ? 'btn-emerald' : ''}`}
                    onClick={() => setState((prev) => ({ ...prev, auto_remediate: true }))}
                  >
                    Auto-Remediate SOAR
                  </button>
                </div>
              </div>

              {/* 3 Scenario Cards */}
              <div className="grid-3" style={{ marginTop: '16px', gap: '14px' }}>
                {(Object.keys(ATTACK_SCENARIOS) as AttackScenarioId[]).map((scenarioId) => {
                  const def = ATTACK_SCENARIOS[scenarioId];
                  const isSelected = state.selected_scenario === scenarioId;
                  return (
                    <div
                      key={scenarioId}
                      className={`surface-card${isSelected ? ' surface-card-featured' : ''}`}
                      style={{
                        cursor: 'pointer',
                        borderColor: isSelected ? '#2563eb' : undefined,
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        gap: '10px'
                      }}
                      onClick={() =>
                        setState((prev) => ({ ...prev, selected_scenario: scenarioId }))
                      }
                    >
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                          <span className="badge badge-crimson">{def.code} · {def.severity}</span>
                          <span className="mono" style={{ fontSize: '0.75rem', color: '#475569' }}>
                            {def.sigmaRule.id}
                          </span>
                        </div>
                        <h3 style={{ margin: '10px 0 6px', fontSize: '0.96rem', color: '#0f172a' }}>
                          {def.title}
                        </h3>
                        <p style={{ margin: 0, fontSize: '0.82rem', color: '#475569', lineHeight: 1.5 }}>
                          {def.description}
                        </p>
                      </div>

                      <button
                        type="button"
                        className={`btn btn-sm ${isSelected ? 'btn-primary' : 'btn-dark'}`}
                        disabled={busy}
                        onClick={(e) => {
                          e.stopPropagation();
                          void handleInjectTelemetry(scenarioId, state.auto_remediate);
                        }}
                      >
                        <Play size={13} />
                        <span>Inject {def.code} Telemetry</span>
                      </button>
                    </div>
                  );
                })}
              </div>

              {/* Live Ingested Telemetry & Sigma Match */}
              {state.matched_sigma && (
                <div className="grid-2" style={{ marginTop: '18px', gap: '16px' }}>
                  <div className="surface-card" style={{ background: '#0f172a', color: '#e2e8f0' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.86rem', color: '#93c5fd' }}>
                        Matched Sigma Rule ({state.matched_sigma.id})
                      </span>
                      <span className="badge badge-crimson">{state.matched_sigma.level.toUpperCase()}</span>
                    </div>
                    <pre
                      className="mono"
                      style={{
                        margin: 0,
                        fontSize: '0.74rem',
                        lineHeight: 1.5,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word'
                      }}
                    >
                      {state.matched_sigma.yaml}
                    </pre>
                  </div>

                  <div className="surface-card" style={{ background: '#f8fafc' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                      <span style={{ fontWeight: 600, fontSize: '0.86rem', color: '#0f172a' }}>
                        Normalized Telemetry Stream ({state.telemetry_events.length} events)
                      </span>
                      <span className="badge badge-amber">MTTD {state.mttd_ms}ms</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {state.telemetry_events.map((evt) => (
                        <div
                          key={evt.event_id}
                          style={{
                            padding: '8px 10px',
                            borderRadius: '8px',
                            background: '#ffffff',
                            border: '1px solid #e2e8f0',
                            fontSize: '0.76rem'
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 600 }}>
                            <span className="mono">{evt.source}</span>
                            <span className="mono">HTTP {evt.http_status} · {evt.geo}</span>
                          </div>
                          <div className="mono" style={{ color: '#475569', marginTop: '4px', wordBreak: 'break-word' }}>
                            {evt.source_ip} ({evt.asn}) → {evt.resource}
                          </div>
                          <div className="mono" style={{ color: '#b91c1c', marginTop: '2px', wordBreak: 'break-word' }}>
                            {evt.raw_indicator}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
                <button type="button" className="btn btn-sm" onClick={() => handleSetPhase(1)}>
                  Back to Discovery
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => handleSetPhase(3)}
                >
                  <span>Proceed to Phase 3: SOAR Containment</span>
                  <ArrowRight size={15} />
                </button>
              </div>
            </section>
          )}

          {/* PHASE 3: PRACTICE (2-Seat War Room) */}
          {state.active_phase === 3 && (
            <SoarWarRoomPractice
              state={state}
              activeScenarioDef={activeScenarioDef}
              busy={busy}
              probeResult={probeResult}
              onInjectTelemetry={(scenario, autoRemediate) =>
                void handleInjectTelemetry(scenario, autoRemediate)
              }
              onExecuteContainment={(action) => void handleExecuteContainment(action)}
              onSelectSeat={handleSelectSeat}
              onProbeUserAccess={handleProbeUserAccess}
              onSetPhase={handleSetPhase}
            />
          )}

          {/* PHASE 4: REFLECTION */}
          {state.active_phase === 4 && (
            <SoarReflectionSection
              state={state}
              activeScenarioDef={activeScenarioDef}
              copiedNotice={copiedNotice}
              onSetPhase={handleSetPhase}
              onCopyReport={handleCopyReport}
              onDownloadReport={handleDownloadReport}
            />
          )}
        </div>
      </main>

      {/* Sticky Bottom X-Ray Telemetry Drawer */}
      <XRayTelemetryDrawer
        spans={spans}
        decodedProofSections={decodedProofSections}
        onClear={() => setSpans([])}
      />
    </div>
  );
};
