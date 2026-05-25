import { useState } from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts';
import RiskGauge from './RiskGauge';

const CATEGORY_COLORS = {
  structural:  '#60a5fa',
  domain:      '#a78bfa',
  content:     '#34d399',
  deception:   '#f87171',
  threat_intel:'#f59e0b',
};

function FeatureBar({ signal }) {
  const color = CATEGORY_COLORS[signal.category] || '#94a3b8';
  return (
    <div className="feature-bar-row">
      <div className="feature-bar-header">
        <span className="feature-name">{signal.name}</span>
        <div className="feature-badges">
          <span className="feature-category" style={{ color, borderColor: color }}>
            {signal.category}
          </span>
          <span
            className="feature-score"
            style={{ color: signal.active ? color : '#475569' }}
          >
            {signal.score}
          </span>
        </div>
      </div>
      <div className="feature-bar-track">
        <div
          className="feature-bar-fill"
          style={{
            width: `${signal.score}%`,
            background: signal.active
              ? `linear-gradient(90deg, ${color}60, ${color})`
              : '#1e293b',
            boxShadow: signal.active ? `0 0 8px ${color}60` : 'none',
          }}
        />
      </div>
    </div>
  );
}

function TimelineStep({ step, index }) {
  return (
    <div className={`timeline-step ${step.status}`}>
      <div className="timeline-connector">
        <div className="timeline-dot" />
        {index < 7 && <div className="timeline-line" />}
      </div>
      <div className="timeline-content">
        <div className="timeline-step-name">{step.step}</div>
        <div className="timeline-detail">{step.detail}</div>
      </div>
    </div>
  );
}

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <p className="tooltip-name">{payload[0].payload.name}</p>
      <p className="tooltip-score">Risk Score: <strong>{payload[0].value}</strong></p>
    </div>
  );
};

export default function ResultsDashboard({ result, isLoading, error }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [exportMsg, setExportMsg] = useState('');

  if (!result && !isLoading && !error) {
    return (
      <div className="results-empty">
        <div className="empty-icon">⬡</div>
        <h3 className="empty-title">No Analysis Yet</h3>
        <p className="empty-subtitle">
          Enter a URL in the left panel and click "Analyze URL" to begin
          threat detection.
        </p>
        <div className="empty-features">
          {['Structural Analysis', 'Domain Intelligence', 'ML Risk Scoring', 'Threat Timeline'].map(f => (
            <span key={f} className="empty-feature-chip">{f}</span>
          ))}
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="results-error">
        <div className="error-icon">⚠</div>
        <h3>Analysis Failed</h3>
        <p>{error}</p>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="results-loading">
        <div className="loading-grid">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="skeleton-card" style={{ animationDelay: `${i * 0.1}s` }} />
          ))}
        </div>
      </div>
    );
  }

  const { features, model } = result;
  const { probability, confidence, risk, featureSignals, explanationLines, timeline, activeSignals } = model;

  function handleExportJSON() {
    const data = {
      sentinel_orbit_report: true,
      version: '2.4.1',
      generated: new Date().toISOString(),
      url: features.rawUrl,
      risk: {
        probability,
        level: risk.level,
        confidence,
      },
      features: {
        hostname: features.hostname,
        tld: features.tld,
        hasHTTPS: features.hasHTTPS,
        urlLength: features.urlLength,
        subdomainCount: features.subdomainCount,
        hasIPAddress: features.hasIPAddress,
        domainEntropy: features.domainEntropy,
        keywordCount: features.keywordCount,
        foundKeywords: features.foundKeywords,
        brandImpersonation: features.brandImpersonation,
      },
      signals: featureSignals,
      explanation: explanationLines,
      timeline,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinel-orbit-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    setExportMsg('JSON exported!');
    setTimeout(() => setExportMsg(''), 2500);
  }

  function handleExportText() {
    const text = [
      '=== SENTINEL ORBIT THREAT REPORT ===',
      `Generated: ${new Date().toLocaleString()}`,
      `URL: ${features.rawUrl}`,
      '',
      `Risk Level: ${risk.level.toUpperCase()}`,
      `Phishing Probability: ${probability}%`,
      `Model Confidence: ${confidence}%`,
      '',
      '--- Active Threat Signals ---',
      ...activeSignals.map(s => `  [${s.score}] ${s.name}`),
      '',
      '--- Analysis Summary ---',
      ...explanationLines.map(l => `  ${l}`),
      '',
      '--- Feature Scores ---',
      ...featureSignals.map(s => `  ${s.name}: ${s.score}/100`),
    ].join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sentinel-orbit-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
    setExportMsg('Text report exported!');
    setTimeout(() => setExportMsg(''), 2500);
  }

  const chartData = featureSignals
    .sort((a, b) => b.score - a.score)
    .map(s => ({ name: s.name, score: s.score, category: s.category, active: s.active }));

  return (
    <div className="results-dashboard">
      {/* Top bar with URL and export */}
      <div className="results-topbar">
        <div className="scanned-url-block">
          <span className="scanned-label">SCANNING</span>
          <span className="scanned-url">{features.rawUrl}</span>
        </div>
        <div className="export-actions">
          {exportMsg && <span className="export-msg">{exportMsg}</span>}
          <button id="export-json-btn" className="export-btn" onClick={handleExportJSON}>
            ↓ JSON
          </button>
          <button id="export-txt-btn" className="export-btn" onClick={handleExportText}>
            ↓ Report
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="results-tabs" role="tablist">
        {['overview', 'signals', 'timeline'].map(tab => (
          <button
            key={tab}
            id={`tab-${tab}`}
            role="tab"
            aria-selected={activeTab === tab}
            className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
          >
            {tab.charAt(0).toUpperCase() + tab.slice(1)}
          </button>
        ))}
      </div>

      {/* ── TAB: OVERVIEW ── */}
      {activeTab === 'overview' && (
        <div className="tab-content" role="tabpanel" aria-labelledby="tab-overview">
          <div className="overview-grid">

            {/* Gauge */}
            <div className="card gauge-card">
              <RiskGauge
                probability={probability}
                riskLevel={risk.level}
                confidence={confidence}
              />
            </div>

            {/* Active Signals */}
            <div className="card signals-summary-card">
              <h3 className="card-title">Active Threat Signals</h3>
              {activeSignals.length === 0 ? (
                <p className="no-signals">No threat signals detected</p>
              ) : (
                <ul className="signal-list">
                  {activeSignals.map((s, i) => (
                    <li key={i} className="signal-item">
                      <span
                        className="signal-dot"
                        style={{ background: CATEGORY_COLORS[s.category] }}
                      />
                      <span className="signal-name">{s.name}</span>
                      <span
                        className="signal-score-badge"
                        style={{
                          color: CATEGORY_COLORS[s.category],
                          borderColor: CATEGORY_COLORS[s.category]
                        }}
                      >
                        {s.score}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Meta stats */}
            <div className="card meta-card">
              <h3 className="card-title">URL Metadata</h3>
              <table className="meta-table" aria-label="URL analysis metadata">
                <tbody>
                  <tr><td>Protocol</td><td className={features.hasHTTPS ? 'safe' : 'danger'}>{features.protocol}</td></tr>
                  <tr><td>Hostname</td><td>{features.hostname}</td></tr>
                  <tr><td>TLD</td><td>.{features.tld}</td></tr>
                  <tr><td>URL Length</td><td>{features.urlLength} chars</td></tr>
                  <tr><td>Subdomains</td><td>{features.subdomainCount}</td></tr>
                  <tr><td>Domain Entropy</td><td>{features.domainEntropy.toFixed(3)}</td></tr>
                  <tr><td>Suspicious Keywords</td><td className={features.keywordCount > 0 ? 'danger' : 'safe'}>{features.keywordCount}</td></tr>
                  <tr><td>IP-Based Host</td><td className={features.hasIPAddress ? 'danger' : 'safe'}>{features.hasIPAddress ? 'Yes' : 'No'}</td></tr>
                </tbody>
              </table>
            </div>

            {/* Analyst explanation */}
            <div className="card explanation-card">
              <h3 className="card-title">
                <span className="card-title-icon">◈</span>
                Analyst Report
              </h3>
              <div className="explanation-body">
                {explanationLines.map((line, i) => (
                  <p
                    key={i}
                    className={`explanation-line ${
                      line.startsWith('VERDICT') ? 'verdict-line' : ''
                    } ${
                      line.startsWith('⚠') ? 'warning-line' : ''
                    }`}
                  >
                    {line}
                  </p>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: SIGNALS ── */}
      {activeTab === 'signals' && (
        <div className="tab-content" role="tabpanel" aria-labelledby="tab-signals">
          <div className="signals-grid">

            {/* Bar chart */}
            <div className="card chart-card">
              <h3 className="card-title">Feature Risk Contribution</h3>
              <div style={{ width: '100%', height: 260 }}>
                <ResponsiveContainer>
                  <BarChart
                    data={chartData}
                    layout="vertical"
                    margin={{ left: 8, right: 24, top: 4, bottom: 4 }}
                  >
                    <XAxis type="number" domain={[0, 100]} tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} />
                    <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={110} axisLine={false} tickLine={false} />
                    <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1e293b' }} />
                    <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                      {chartData.map((entry, index) => (
                        <Cell
                          key={index}
                          fill={entry.active
                            ? CATEGORY_COLORS[entry.category] || '#60a5fa'
                            : '#1e293b'}
                          opacity={entry.active ? 1 : 0.5}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              {/* Legend */}
              <div className="chart-legend">
                {Object.entries(CATEGORY_COLORS).map(([cat, color]) => (
                  <span key={cat} className="legend-item">
                    <span className="legend-dot" style={{ background: color }} />
                    {cat.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>

            {/* Per-feature breakdown */}
            <div className="card feature-breakdown-card">
              <h3 className="card-title">Feature Breakdown</h3>
              <div className="feature-bars-list">
                {featureSignals.map((signal, i) => (
                  <FeatureBar key={i} signal={signal} />
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB: TIMELINE ── */}
      {activeTab === 'timeline' && (
        <div className="tab-content" role="tabpanel" aria-labelledby="tab-timeline">
          <div className="card timeline-card">
            <h3 className="card-title">
              <span className="card-title-icon">⊙</span>
              Analysis Timeline
            </h3>
            <p className="timeline-subtitle">
              Step-by-step reasoning trace of the threat intelligence pipeline
            </p>
            <div className="timeline-list">
              {model.timeline.map((step, i) => (
                <TimelineStep key={i} step={step} index={i} />
              ))}
            </div>
          </div>

          {/* Model internals summary */}
          <div className="card model-card">
            <h3 className="card-title">
              <span className="card-title-icon">⬡</span>
              Model Internals
            </h3>
            <div className="model-stats">
              <div className="model-stat">
                <span className="model-stat-value">{probability}%</span>
                <span className="model-stat-label">Phishing Probability</span>
              </div>
              <div className="model-stat">
                <span className="model-stat-value">{confidence}%</span>
                <span className="model-stat-label">Confidence Score</span>
              </div>
              <div className="model-stat">
                <span className="model-stat-value">15</span>
                <span className="model-stat-label">Trees in Ensemble</span>
              </div>
              <div className="model-stat">
                <span className="model-stat-value">{activeSignals.length}</span>
                <span className="model-stat-label">Active Signals</span>
              </div>
            </div>

            {/* Tree votes minimap */}
            <h4 className="card-subtitle">Ensemble Tree Votes</h4>
            <div className="tree-votes">
              {model.treeVotes.map(({ tree, vote }) => (
                <div key={tree} className="tree-vote-bar" title={`Tree ${tree}: ${vote}%`}>
                  <div
                    className="tree-vote-fill"
                    style={{
                      height: `${vote}%`,
                      background: vote >= 70 ? '#ef4444' : vote >= 40 ? '#f97316' : '#22c55e',
                    }}
                  />
                  <span className="tree-vote-label">{tree}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
