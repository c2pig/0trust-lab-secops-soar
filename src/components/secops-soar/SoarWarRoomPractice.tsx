import React from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Lock,
  Play,
  ShieldCheck,
  Zap
} from 'lucide-react';
import {
  AttackScenarioDefinition,
  AttackScenarioId,
  SOAR_PLAYBOOKS,
  SecopsSoarSeatId,
  SecopsSoarState,
  SoarActionId,
  SoarPhase
} from '../../contracts/secopsSoarContract';

export interface AccessProbeResult {
  status: number;
  code: string;
  message: string;
}

export interface SoarWarRoomPracticeProps {
  state: SecopsSoarState;
  activeScenarioDef: AttackScenarioDefinition;
  busy: boolean;
  probeResult: AccessProbeResult | null;
  onInjectTelemetry: (scenario: AttackScenarioId, autoRemediate: boolean) => void;
  onExecuteContainment: (action: SoarActionId) => void;
  onSelectSeat: (seatId: SecopsSoarSeatId) => void;
  onProbeUserAccess: () => void;
  onSetPhase: (phase: SoarPhase) => void;
}

export const SoarWarRoomPractice: React.FC<SoarWarRoomPracticeProps> = ({
  state,
  activeScenarioDef,
  busy,
  probeResult,
  onInjectTelemetry,
  onExecuteContainment,
  onSelectSeat,
  onProbeUserAccess,
  onSetPhase
}) => {
  return (
    <section className="surface-card" style={{ marginTop: '16px' }}>
      <div className="section-header">
        <h2 className="section-title">
          Phase 3 · Practice:{' '}
          {state.active_seat === 'soc-analyst'
            ? 'SOC Tier 2 Playbook Engine (Amina Diallo)'
            : 'Target Identity Session & Cloud App (Tyler Brooks)'}
        </h2>
        <p className="section-subtitle">
          {state.active_seat === 'soc-analyst'
            ? 'Execute SOAR containment playbooks against the active incident, then switch to Tyler Brooks seat to verify session revocation.'
            : 'Probe Tyler Brooks active session and cloud app access to verify CAEP Universal Logout, WAF block, or Kill Switch containment.'}
        </p>
      </div>

      {!state.incident_id && (
        <div
          style={{
            marginTop: '14px',
            padding: '12px 14px',
            borderRadius: '10px',
            background: '#fffbeb',
            border: '1px solid #fde68a',
            display: 'flex',
            flexWrap: 'wrap',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '10px'
          }}
        >
          <span style={{ fontSize: '0.84rem', color: '#92400e' }}>
            No attack telemetry injected yet. Inject{' '}
            <strong>{activeScenarioDef.shortLabel}</strong> now or return to Phase 2.
          </span>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            disabled={busy}
            onClick={() =>
              void onInjectTelemetry(state.selected_scenario, state.auto_remediate)
            }
          >
            <Play size={13} />
            <span>Quick-Inject {activeScenarioDef.code}</span>
          </button>
        </div>
      )}

      {state.active_seat === 'soc-analyst' ? (
        <div style={{ marginTop: '16px' }}>
          <div className="grid-3" style={{ gap: '14px' }}>
            {(Object.keys(SOAR_PLAYBOOKS) as SoarActionId[]).map((actionId) => {
              const playbook = SOAR_PLAYBOOKS[actionId];
              const isExecuted = state.executed_actions.includes(actionId);
              const isRecommended =
                activeScenarioDef.recommendedAction === actionId;

              return (
                <div
                  key={actionId}
                  className={`surface-card${isRecommended ? ' surface-card-featured' : ''}`}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    gap: '12px'
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
                      <span
                        className={`badge ${
                          isExecuted
                            ? 'badge-emerald'
                            : isRecommended
                              ? 'badge-amber'
                              : 'badge-blue'
                        }`}
                      >
                        {isExecuted
                          ? 'EXECUTED'
                          : isRecommended
                            ? 'RECOMMENDED'
                            : 'STANDBY'}
                      </span>
                    </div>
                    <h3 style={{ margin: '10px 0 6px', fontSize: '0.95rem', color: '#0f172a' }}>
                      {playbook.title}
                    </h3>
                    <p style={{ margin: 0, fontSize: '0.82rem', color: '#475569', lineHeight: 1.5 }}>
                      {playbook.description}
                    </p>
                  </div>

                  <button
                    type="button"
                    className={`btn btn-sm ${isExecuted ? 'btn-emerald' : 'btn-primary'}`}
                    disabled={busy}
                    onClick={() => void onExecuteContainment(actionId)}
                  >
                    {isExecuted ? <CheckCircle2 size={14} /> : <Zap size={14} />}
                    <span>{isExecuted ? playbook.badgeText : 'Execute Playbook'}</span>
                  </button>
                </div>
              );
            })}
          </div>

          <div
            style={{
              marginTop: '16px',
              padding: '12px 14px',
              borderRadius: '10px',
              background: '#eff6ff',
              border: '1px solid #bfdbfe',
              display: 'flex',
              flexWrap: 'wrap',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '10px'
            }}
          >
            <span style={{ fontSize: '0.84rem', color: '#1e3a8a' }}>
              Switch to <strong>Tyler Brooks (Target Identity)</strong> seat to prove live session revocation &amp; edge block.
            </span>
            <button
              type="button"
              className="btn btn-sm btn-dark"
              onClick={() => onSelectSeat('compromised-user')}
            >
              <span>Switch to Tyler Brooks Seat</span>
              <ArrowRight size={13} />
            </button>
          </div>
        </div>
      ) : (
        <div style={{ marginTop: '16px' }}>
          <div className="grid-2" style={{ gap: '16px' }}>
            <div className="surface-card" style={{ background: '#f8fafc' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <strong>Tyler Brooks · Workforce Session Status</strong>
                <span
                  className={`badge ${
                    state.compromised_user_revoked ? 'badge-crimson' : 'badge-emerald'
                  }`}
                >
                  {state.compromised_user_revoked ? 'CAEP REVOKED (401)' : 'JWT ACTIVE'}
                </span>
              </div>
              <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '0.84rem', color: '#334155', lineHeight: 1.7 }}>
                <li>
                  Identity: <code>tyler.brooks@0trust.dev</code>
                </li>
                <li>
                  CAEP Universal Logout:{' '}
                  <strong>{state.compromised_user_revoked ? 'REVOKED' : 'NOT TRIGGERED'}</strong>
                </li>
                <li>
                  Cloudflare Edge WAF:{' '}
                  <strong>{state.waf_blocked ? '403 ASN BLOCKED' : 'ALLOWING'}</strong>
                </li>
                <li>
                  IAM / Bucket Kill Switch:{' '}
                  <strong>{state.kill_switch_active ? 'QUARANTINED (Deny *)' : 'NORMAL'}</strong>
                </li>
              </ul>

              <div style={{ marginTop: '14px', display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={onProbeUserAccess}
                >
                  <Lock size={13} />
                  <span>Test Cloud App Access</span>
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={() => onSelectSeat('soc-analyst')}
                >
                  Return to SOC Analyst Seat
                </button>
              </div>
            </div>

            <div className="surface-card" style={{ background: '#ffffff' }}>
              <strong style={{ display: 'block', marginBottom: '8px' }}>
                Live Access Probe Result
              </strong>
              {probeResult ? (
                <div
                  style={{
                    padding: '12px',
                    borderRadius: '8px',
                    background:
                      probeResult.status === 200 ? '#fef2f2' : '#ecfdf5',
                    border: `1px solid ${
                      probeResult.status === 200 ? '#fecaca' : '#a7f3d0'
                    }`
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    {probeResult.status === 200 ? (
                      <AlertTriangle size={16} color="#dc2626" />
                    ) : (
                      <ShieldCheck size={16} color="#059669" />
                    )}
                    <span className="mono" style={{ fontWeight: 700, fontSize: '0.84rem' }}>
                      HTTP {probeResult.status} · {probeResult.code}
                    </span>
                  </div>
                  <p style={{ margin: 0, fontSize: '0.82rem', color: '#334155', lineHeight: 1.5 }}>
                    {probeResult.message}
                  </p>
                </div>
              ) : (
                <p style={{ margin: 0, fontSize: '0.83rem', color: '#64748b' }}>
                  Click <strong>Test Cloud App Access</strong> to verify whether Tyler Brooks&apos;s compromised
                  session is still active or blocked by SOAR containment.
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
        <button type="button" className="btn btn-sm" onClick={() => onSetPhase(2)}>
          Back to Understanding
        </button>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => onSetPhase(4)}
        >
          <span>Proceed to Phase 4: MTTD/MTTR Reflection</span>
          <ArrowRight size={15} />
        </button>
      </div>
    </section>
  );
};
