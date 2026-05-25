import { useEffect, useRef, useState } from 'react';

const RADIUS = 80;
const STROKE = 12;
const CENTER = 100;
const CIRCUMFERENCE = Math.PI * RADIUS; // half-circle arc

function getRiskColor(probability) {
  if (probability >= 80) return { stroke: '#ef4444', glow: '#ef444480', text: '#ef4444' };
  if (probability >= 60) return { stroke: '#f97316', glow: '#f9731680', text: '#f97316' };
  if (probability >= 35) return { stroke: '#eab308', glow: '#eab30880', text: '#eab308' };
  return { stroke: '#22c55e', glow: '#22c55e80', text: '#22c55e' };
}

export default function RiskGauge({ probability = 0, riskLevel = 'Low', confidence = 0, animating = false }) {
  const [displayValue, setDisplayValue] = useState(0);
  const animRef = useRef(null);
  const colors = getRiskColor(probability);

  useEffect(() => {
    if (animRef.current) cancelAnimationFrame(animRef.current);
    const start = displayValue;
    const end = probability;
    const duration = 1200;
    const startTime = performance.now();

    function step(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setDisplayValue(Math.round(start + (end - start) * eased));
      if (progress < 1) animRef.current = requestAnimationFrame(step);
    }
    animRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(animRef.current);
  }, [probability]);

  const arcLength = (displayValue / 100) * CIRCUMFERENCE;
  const gapLength = CIRCUMFERENCE - arcLength;

  return (
    <div className="gauge-container">
      <svg
        viewBox="0 0 200 120"
        className="gauge-svg"
        role="img"
        aria-label={`Risk score: ${probability} out of 100, ${riskLevel} risk`}
      >
        <defs>
          <filter id="glow-filter" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="gauge-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#22c55e" />
            <stop offset="45%" stopColor="#eab308" />
            <stop offset="75%" stopColor="#f97316" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
        </defs>

        {/* Background track */}
        <path
          d={`M ${CENTER - RADIUS} ${CENTER} A ${RADIUS} ${RADIUS} 0 0 1 ${CENTER + RADIUS} ${CENTER}`}
          fill="none"
          stroke="#1e293b"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />

        {/* Colored arc */}
        <path
          d={`M ${CENTER - RADIUS} ${CENTER} A ${RADIUS} ${RADIUS} 0 0 1 ${CENTER + RADIUS} ${CENTER}`}
          fill="none"
          stroke="url(#gauge-gradient)"
          strokeWidth={STROKE}
          strokeLinecap="round"
          strokeDasharray={`${arcLength} ${gapLength}`}
          filter="url(#glow-filter)"
          style={{ transition: 'stroke-dasharray 0.05s ease' }}
        />

        {/* Tick marks */}
        {[0, 25, 50, 75, 100].map((pct) => {
          const angle = Math.PI + (pct / 100) * Math.PI;
          const innerR = RADIUS - STROKE / 2 - 4;
          const outerR = RADIUS + STROKE / 2 + 4;
          const x1 = CENTER + Math.cos(angle) * innerR;
          const y1 = CENTER + Math.sin(angle) * innerR;
          const x2 = CENTER + Math.cos(angle) * outerR;
          const y2 = CENTER + Math.sin(angle) * outerR;
          return (
            <line key={pct} x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="#334155" strokeWidth="1.5" />
          );
        })}

        {/* Needle */}
        {(() => {
          const angle = Math.PI + (displayValue / 100) * Math.PI;
          const nx = CENTER + Math.cos(angle) * (RADIUS - 4);
          const ny = CENTER + Math.sin(angle) * (RADIUS - 4);
          return (
            <>
              <line
                x1={CENTER} y1={CENTER}
                x2={nx} y2={ny}
                stroke={colors.stroke}
                strokeWidth="2"
                strokeLinecap="round"
                filter="url(#glow-filter)"
                style={{ transition: 'all 0.05s ease' }}
              />
              <circle cx={CENTER} cy={CENTER} r="4" fill={colors.stroke} filter="url(#glow-filter)" />
            </>
          );
        })()}

        {/* Center score */}
        <text
          x={CENTER} y={CENTER - 14}
          textAnchor="middle"
          fill={colors.text}
          fontSize="28"
          fontWeight="700"
          fontFamily="Inter, system-ui, sans-serif"
          style={{ filter: `drop-shadow(0 0 6px ${colors.glow})` }}
        >
          {displayValue}
        </text>
        <text
          x={CENTER} y={CENTER - 2}
          textAnchor="middle"
          fill="#94a3b8"
          fontSize="8"
          fontFamily="Inter, system-ui, sans-serif"
        >
          PHISHING PROBABILITY
        </text>

        {/* Labels */}
        <text x={CENTER - RADIUS + 4} y={CENTER + 16} fill="#475569" fontSize="7" fontFamily="Inter, system-ui, sans-serif">0</text>
        <text x={CENTER + RADIUS - 8} y={CENTER + 16} fill="#475569" fontSize="7" fontFamily="Inter, system-ui, sans-serif">100</text>
      </svg>

      <div className="gauge-labels">
        <div className="gauge-risk-badge" style={{ color: colors.text, boxShadow: `0 0 12px ${colors.glow}`, borderColor: colors.stroke }}>
          {riskLevel.toUpperCase()} RISK
        </div>
        <div className="gauge-confidence">
          <span className="confidence-label">Model Confidence</span>
          <span className="confidence-value">{confidence}%</span>
        </div>
      </div>
    </div>
  );
}
