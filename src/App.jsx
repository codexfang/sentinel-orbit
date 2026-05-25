import { useState, useEffect, useRef } from 'react';
import InputPanel from './components/InputPanel';
import ResultsDashboard from './components/ResultsDashboard';
import ScanHistory from './components/ScanHistory';
import { analyzeUrl } from './engine/urlAnalyzer';
import { runPhishingModel } from './engine/phishingModel';

const HISTORY_KEY = 'sentinel_orbit_history';
const MAX_HISTORY = 20;
const TOTAL_SCAN_STEPS = 8;

function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
  } catch {
    return [];
  }
}

function saveHistory(history) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  } catch {}
}

export default function App() {
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [scanStep, setScanStep] = useState(0);
  const [history, setHistory] = useState(loadHistory);
  const stepIntervalRef = useRef(null);

  useEffect(() => {
    saveHistory(history);
  }, [history]);

  async function handleAnalyze(url) {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setScanStep(0);

    // Animate scan steps
    stepIntervalRef.current = setInterval(() => {
      setScanStep(s => (s + 1) % TOTAL_SCAN_STEPS);
    }, 380);

    // Minimum display time for scan animation (UX feel)
    const minDelay = new Promise(r => setTimeout(r, 2800));

    try {
      const [features] = await Promise.all([analyzeUrl(url), minDelay]);
      const model = runPhishingModel(features);

      setResult({ features, model });

      // Update history
      setHistory(prev => {
        const entry = {
          url: features.rawUrl,
          probability: model.probability,
          riskLevel: model.risk.level,
          timestamp: new Date().toISOString(),
        };
        const filtered = prev.filter(h => h.url !== features.rawUrl);
        return [entry, ...filtered].slice(0, MAX_HISTORY);
      });
    } catch (err) {
      setError(err.message || 'Analysis failed. Please check the URL and try again.');
    } finally {
      clearInterval(stepIntervalRef.current);
      setIsLoading(false);
      setScanStep(0);
    }
  }

  function handleClearHistory() {
    setHistory([]);
  }

  return (
    <div className="app-root">
      {/* Header */}
      <header className="app-header">
        <div className="header-inner">
          <div className="header-brand">
            <h1 className="header-title">Sentinel Orbit</h1>
            <span className="header-subtitle">URL Threat Intelligence System</span>
          </div>
          <div className="header-meta">
            <div className="header-status-group">
              <span className="header-status-dot" />
              <span className="header-status-text">All Systems Operational</span>
            </div>
            <span className="header-divider" />
            <span className="header-tag">AI · ML · Cybersecurity</span>
          </div>
        </div>
        <div className="header-scanline" aria-hidden="true" />
      </header>

      {/* Main Layout */}
      <main className="app-main">
        <div className="app-layout">
          <aside className="left-column">
            <InputPanel
              onAnalyze={handleAnalyze}
              isLoading={isLoading}
              scanStep={scanStep}
            />
            <ScanHistory
              history={history}
              onRescan={handleAnalyze}
              onClear={handleClearHistory}
            />
          </aside>

          <section className="right-column" aria-label="Analysis results">
            <ResultsDashboard
              result={result}
              isLoading={isLoading}
              error={error}
            />
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-inner">
          <span>Sentinel Orbit &copy; {new Date().getFullYear()}</span>
          <span className="footer-divider">·</span>
          <span>Static Analysis Only · No Data Transmitted</span>
          <span className="footer-divider">·</span>
          <span>MIT License</span>
        </div>
      </footer>
    </div>
  );
}
