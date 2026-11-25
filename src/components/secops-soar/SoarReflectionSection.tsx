import React from 'react';
import { Clock, Copy, Download, ShieldCheck, Zap } from 'lucide-react';
import {
  AttackScenarioDefinition,
  SecopsSoarState,
  SoarPhase
} from '../../contracts/secopsSoarContract';

export interface SoarReflectionSectionProps {
  state: SecopsSoarState;
  activeScenarioDef: AttackScenarioDefinition;
  copiedNotice: boolean;
  onSetPhase: (phase: SoarPhase) => void;
  onCopyReport: () => void;
  onDownloadReport: () => void;
}

export const SoarReflectionSection: React.FC<SoarReflectionSectionProps> = ({
  state,
  activeScenarioDef,
  copiedNotice,
  onSetPhase,
  onCopyReport,
  onDownloadReport
}) => {
  return (
    <section className="surface-card" style={{ marginTop: '16px' }}>
      <div className="section-header">
        <h2 className="section-title">Phase 4 · Reflection: MTTD / MTTR Timeline &amp; Export</h2>
        <p className="section-subtitle">
          Review deterministic detection and containment latency, compare manual vs. automated SOAR MTTR, and
          export the post-incident tabletop summary.
        </p>
      </div>

      <div className="grid-3" style={{ marginTop: '16px', gap: '14px' }}>
        <div className="surface-card" style={{ background: '#f8fafc' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#475569', fontSize: '0.8rem' }}>
            <Clock size={14} />
            <span>Mean Time to Detect (MTTD)</span>
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#0f172a', marginTop: '6px' }}>
            {state.mttd_ms !== null ? `${state.mttd_ms} ms` : 'Not measured'}
          </div>
        </div>

        <div className="surface-card" style={{ background: '#f8fafc' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#475569', fontSize: '0.8rem' }}>
            <Zap size={14} />
            <span>Mean Time to Respond (MTTR)</span>
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: '#059669', marginTop: '6px' }}>
            {state.mttr_ms !== null ? `${state.mttr_ms} ms` : 'Pending'}
          </div>
        </div>

        <div className="surface-card" style={{ background: '#f8fafc' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#475569', fontSize: '0.8rem' }}>
            <ShieldCheck size={14} />
            <span>Auto vs Manual Delta</span>
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 700, color: '#2563eb', marginTop: '8px' }}>
            {activeScenarioDef.autoMttrMs}ms vs {activeScenarioDef.manualMttrMs}ms
          </div>
        </div>
      </div>

      {/* Chronological Timeline */}
      <div className="surface-card" style={{ marginTop: '16px', background: '#f8fafc' }}>
        <strong style={{ display: 'block', marginBottom: '10px' }}>
          Chronological Post-Incident Timeline
        </strong>
        {state.timeline.length === 0 ? (
          <p style={{ margin: 0, fontSize: '0.83rem', color: '#64748b' }}>
            Inject an attack scenario in Phase 2 and execute SOAR containment in Phase 3 to populate the
            post-incident timeline.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {state.timeline.map((entry, idx) => (
              <div
                key={`${entry.phase}-${idx}`}
                style={{
                  padding: '10px 12px',
                  borderRadius: '8px',
                  background: '#ffffff',
                  border: '1px solid #e2e8f0',
                  display: 'flex',
                  flexWrap: 'wrap',
                  justifyContent: 'space-between',
                  gap: '8px'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.86rem', color: '#0f172a' }}>
                    <span className="mono" style={{ color: '#2563eb', marginRight: '8px' }}>
                      T+{entry.t_plus_ms}ms
                    </span>
                    {entry.title}
                  </div>
                  <div style={{ fontSize: '0.8rem', color: '#475569', marginTop: '3px' }}>
                    {entry.detail}
                  </div>
                </div>
                <span className="badge badge-blue">{entry.actor}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Export Actions */}
      <div style={{ marginTop: '16px', display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: '10px' }}>
        <button type="button" className="btn btn-sm" onClick={() => onSetPhase(3)}>
          Back to Practice
        </button>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button type="button" className="btn btn-sm btn-dark" onClick={onCopyReport}>
            <Copy size={14} />
            <span>{copiedNotice ? 'Copied JSON!' : 'Copy Post-Incident JSON'}</span>
          </button>
          <button type="button" className="btn btn-sm btn-primary" onClick={onDownloadReport}>
            <Download size={14} />
            <span>Export Tabletop Report</span>
          </button>
        </div>
      </div>
    </section>
  );
};
