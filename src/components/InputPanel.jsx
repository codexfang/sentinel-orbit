import { useState } from 'react';
import sampleUrls from '../data/sampleUrls.json';

const ALL_SAMPLES = [
  ...sampleUrls.safe.map(u => ({ ...u, tag: 'SAFE' })),
  ...sampleUrls.phishing.map(u => ({ ...u, tag: 'PHISHING' })),
  ...sampleUrls.mixed.map(u => ({ ...u, tag: 'MIXED' })),
];

const TAG_COLORS = {
  SAFE: '#22c55e',
  PHISHING: '#ef4444',
  MIXED: '#eab308',
};

const SCAN_STEPS = [
  'Initializing threat engine…',
  'Parsing URL structure…',
  'Querying domain intelligence…',
  'Running entropy analysis…',
  'Scanning for keywords & patterns…',
  'Checking brand impersonation…',
  'Running ensemble model…',
  'Generating threat report…',
];

export default function InputPanel({ onAnalyze, isLoading, scanStep }) {
  const [url, setUrl] = useState('');
  const [showSamples, setShowSamples] = useState(false);
  const [selectedTag, setSelectedTag] = useState('ALL');

  const filtered = selectedTag === 'ALL'
    ? ALL_SAMPLES
    : ALL_SAMPLES.filter(s => s.tag === selectedTag);

  function handleSubmit(e) {
    e.preventDefault();
    if (!url.trim()) return;
    onAnalyze(url.trim());
  }

  function handleSampleClick(sampleUrl) {
    setUrl(sampleUrl);
    setShowSamples(false);
    onAnalyze(sampleUrl);
  }

  function handlePaste(e) {
    const pasted = e.clipboardData.getData('text');
    if (pasted) setUrl(pasted);
  }

  const currentStep = SCAN_STEPS[scanStep % SCAN_STEPS.length];

  return (
    <div className="input-panel">
      {/* Header */}
      <div className="panel-header">
        <div className="panel-icon">⬡</div>
        <div>
          <h2 className="panel-title">Threat Analysis</h2>
          <p className="panel-subtitle">Enter a URL to begin scanning</p>
        </div>
      </div>

      {/* URL Input Form */}
      <form onSubmit={handleSubmit} className="url-form">
        <div className="input-wrapper">
          <span className="input-prefix">URL</span>
          <input
            id="url-input"
            type="text"
            className="url-input"
            placeholder="https://example.com/login"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onPaste={handlePaste}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            aria-label="URL to analyze"
          />
          {url && (
            <button
              type="button"
              className="clear-btn"
              onClick={() => setUrl('')}
              aria-label="Clear URL"
            >
              ✕
            </button>
          )}
        </div>

        <button
          id="analyze-btn"
          type="submit"
          className={`analyze-btn ${isLoading ? 'analyzing' : ''}`}
          disabled={isLoading || !url.trim()}
        >
          {isLoading ? (
            <>
              <span className="spinner" aria-hidden="true" />
              <span>{currentStep}</span>
            </>
          ) : (
            <>
              <span className="btn-icon" aria-hidden="true">⬡</span>
              <span>Analyze URL</span>
            </>
          )}
        </button>
      </form>

      {/* Sample URL Picker */}
      {showSamples && (
        <div className="sample-panel" role="listbox" aria-label="Sample URLs">
          <div className="sample-filter-bar">
            {['ALL', 'SAFE', 'PHISHING', 'MIXED'].map(tag => (
              <button
                key={tag}
                className={`filter-chip ${selectedTag === tag ? 'active' : ''}`}
                style={selectedTag === tag && tag !== 'ALL'
                  ? { borderColor: TAG_COLORS[tag], color: TAG_COLORS[tag] }
                  : {}}
                onClick={() => setSelectedTag(tag)}
              >
                {tag}
              </button>
            ))}
          </div>
          <div className="sample-list">
            {filtered.map((sample, i) => (
              <button
                key={i}
                className="sample-item"
                role="option"
                onClick={() => handleSampleClick(sample.url)}
              >
                <span
                  className="sample-tag"
                  style={{ color: TAG_COLORS[sample.tag], borderColor: TAG_COLORS[sample.tag] }}
                >
                  {sample.tag}
                </span>
                <div className="sample-info">
                  <span className="sample-label">{sample.label}</span>
                  <span className="sample-url">{sample.url}</span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Quick Tips */}
      <div className="quick-tips">
        <p className="tips-title">⬡ How It Works</p>
        <ul className="tips-list">
          <li>Structural & domain analysis</li>
          <li>15-tree ensemble ML model</li>
          <li>Entropy &amp; keyword scanning</li>
          <li>Brand impersonation detection</li>
        </ul>
      </div>

      {/* Status Indicator */}
      <div className="engine-status">
        <span className="status-dot" />
        <span>Threat Engine Online</span>
        <span className="engine-version">v1.0</span>
      </div>
    </div>
  );
}
