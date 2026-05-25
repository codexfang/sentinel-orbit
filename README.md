# Sentinel Orbit

A production-quality cybersecurity intelligence tool that analyzes URLs for phishing risk using client-side ML simulation, entropy analysis, and threat intelligence heuristics.

## Features

| Feature | Description |
|---|---|
| 🔍 URL Feature Extraction | Structural analysis: length, subdomains, special chars, path depth |
| 🧠 Entropy Analysis | Shannon entropy calculation to detect DGA/throwaway domains |
| 🛡️ Brand Impersonation Detection | Identifies known brands spoofed in subdomain structure |
| 📚 Domain Intelligence | TLD risk scoring, known benign/malicious pattern matching |
| 🤖 Ensemble ML Model | 15-tree weighted random forest–style rule system |
| 📊 Risk Visualization | Animated semi-circular gauge, feature bar charts, tree vote minimap |
| 📋 Analyst Report | Human-readable threat explanation in security analyst tone |
| ⏱️ Timeline Trace | Step-by-step reasoning pipeline visualization |
| 💾 Scan History | localStorage-persisted recent scans with one-click re-scan |
| 📤 Export Reports | Download results as JSON or plain-text report |
| 🎯 Sample URL Library | Curated safe, phishing, and mixed-risk URLs for demo |

## Tech Stack

- **Framework:** React 19 + Vite 8
- **Charts:** Recharts (bar charts, custom tooltips)
- **Visualization:** Custom SVG gauge with animation
- **Styling:** Vanilla CSS with CSS custom properties (design tokens)
- **Typography:** Inter (UI) + JetBrains Mono (code/data)
- **Storage:** Browser `localStorage` (scan history)

## Limitations & Notes

- **No backend required** — all analysis is client-side JavaScript
- **HTML signal analysis** is disabled for cross-origin URLs due to CORS (as expected in a static deployment)
- **WHOIS age** is simulated deterministically from entropy + TLD signals; real WHOIS requires a backend proxy
- **False positives** are possible for legitimate sites with long URLs or unusual TLDs

## License

MIT
