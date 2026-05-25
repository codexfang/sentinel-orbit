import { useState } from 'react';

const RISK_COLORS = {
  Critical: '#ef4444',
  High:     '#f97316',
  Medium:   '#eab308',
  Low:      '#22c55e',
};

function timeAgo(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(diff / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function ScanHistory({ history, onRescan, onClear }) {
  const [expanded, setExpanded] = useState(true);

  if (!history || history.length === 0) return null;

  return (
    <div className="scan-history">
      <div className="history-header" onClick={() => setExpanded(!expanded)}>
        <span className="history-title">
          <span>◈</span> Scan History
          <span className="history-count">{history.length}</span>
        </span>
        <div className="history-header-actions">
          <button
            className="history-clear-btn"
            onClick={e => { e.stopPropagation(); onClear(); }}
            aria-label="Clear scan history"
          >
            Clear
          </button>
          <span className={`chevron ${expanded ? 'open' : ''}`}>▾</span>
        </div>
      </div>

      {expanded && (
        <div className="history-list">
          {history.map((item, i) => {
            const color = RISK_COLORS[item.riskLevel] || '#94a3b8';
            return (
              <button
                key={i}
                className="history-item"
                onClick={() => onRescan(item.url)}
                title={`Re-scan: ${item.url}`}
              >
                <div
                  className="history-risk-bar"
                  style={{ background: color }}
                  aria-hidden="true"
                />
                <div className="history-item-content">
                  <div className="history-item-top">
                    <span
                      className="history-risk-badge"
                      style={{ color, borderColor: color }}
                    >
                      {item.riskLevel}
                    </span>
                    <span className="history-prob">{item.probability}%</span>
                    <span className="history-time">{timeAgo(item.timestamp)}</span>
                  </div>
                  <span className="history-url">{item.url}</span>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
