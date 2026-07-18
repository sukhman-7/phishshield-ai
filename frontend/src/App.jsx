import { useState, useEffect } from 'react';
import './App.css';

const API_BASE_URL = 'http://127.0.0.1:8000/api';

function App() {
  // State Management
  const [activeTab, setActiveTab] = useState('home');
  const [sender, setSender] = useState('');
  const [emailContent, setEmailContent] = useState('');
  const [imageFile, setImageFile] = useState(null);
  const [targetUrl, setTargetUrl] = useState('');
  const [scanHistory, setScanHistory] = useState([]);

  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  // Reactive Data Fetching
  useEffect(() => {
    if (activeTab === 'home' || activeTab === 'history') {
      const loadHistory = async () => {
        try {
          const res = await fetch(`${API_BASE_URL}/history`);
          const data = await res.json();
          setScanHistory(data);
        } catch (err) {
          console.error("Failed to retrieve SOC audit logs:", err);
        }
      };

      loadHistory();
    }
  }, [activeTab]);

  // Telemetry Metric Evaluation
  const totalScans = scanHistory.length;
  const threatsDetected = scanHistory.filter(log => log.verdict === 'SUSPICIOUS').length;
  const avgThreatScore = totalScans > 0
    ? Math.round(scanHistory.reduce((acc, curr) => acc + curr.threat_score, 0) / totalScans)
    : 0;

  // Core Request Handler
  const submitAnalysis = async (endpoint, options) => {
    setLoading(true);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE_URL}/${endpoint}`, options);
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        console.error("Backend Error Details:", errData);
        alert(`Backend Error: Check terminal (Status ${response.status})`);
        return;
      }

      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Network Error:", error);
      alert("Could not connect to the FastAPI server. Ensure it is running.");
    } finally {
      setLoading(false);
    }
  };

  // Event Handlers
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setResult(null);
    setLoading(false);
  };

  const handleTextAnalyze = async (e) => {
    e.preventDefault();
    if (!emailContent.trim()) return alert("Please enter text to scan.");

    submitAnalysis('analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: emailContent, sender: sender.trim() }),
    });
  };

  const handleImageAnalyze = async (e) => {
    e.preventDefault();
    if (!imageFile) return alert("Please select an image file first.");

    const formData = new FormData();
    formData.append("sender", sender.trim());
    formData.append("file", imageFile);

    submitAnalysis('scan-image', {
      method: 'POST',
      body: formData,
    });
  };

  const handleUrlAnalyze = async (e) => {
    e.preventDefault();
    if (!targetUrl.trim()) return alert("Please enter a URL to sandbox.");

    submitAnalysis('scan-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: targetUrl.trim() }),
    });
  };

  const renderSenderInput = () => (
    <div className="input-group">
      <label>Target Sender Address (Optional)</label>
      <input
        type="text"
        placeholder="e.g., support@paypal.com"
        value={sender}
        onChange={(e) => setSender(e.target.value)}
      />
    </div>
  );

  return (
    <div className="app-container">
      {/* Sticky Top Bar Area */}
      <header className="top-bar">
        <div className="top-bar-branding" onClick={() => handleTabChange('home')}>
          <h1>
            <span className="logo-emoji">🛡️</span>
            <span className="gradient-text">PhishShield</span>
          </h1>
          <p className="subtitle">Enterprise Multi-Layered Text, Vision & Sandbox Defense</p>
        </div>

        <div className="top-bar-nav">
          <button className={`top-nav-tab ${activeTab === 'about' ? 'active' : ''}`} onClick={() => handleTabChange('about')}>
            about system
          </button>
          <button className={`top-nav-tab ${activeTab === 'awareness' ? 'active' : ''}`} onClick={() => handleTabChange('awareness')}>
            public awareness
          </button>
        </div>
      </header>

      {/* Main Execution Workspace */}
      <div className="workspace-layout">
        {/* Module Controller Sidebar */}
        <aside className="sidebar">
          <nav className="app-nav">
            <button className={`nav-tab ${activeTab === 'home' ? 'active' : ''}`} onClick={() => handleTabChange('home')}>
              🏠 Dashboard Home
            </button>
            <button className={`nav-tab ${activeTab === 'mail' ? 'active' : ''}`} onClick={() => handleTabChange('mail')}>
              💬 Mail Scanner
            </button>
            <button className={`nav-tab ${activeTab === 'qr' ? 'active' : ''}`} onClick={() => handleTabChange('qr')}>
              👁️ Vision Engine
            </button>
            <button className={`nav-tab ${activeTab === 'url' ? 'active' : ''}`} onClick={() => handleTabChange('url')}>
              🌐 Active Sandbox
            </button>
            <button className={`nav-tab ${activeTab === 'history' ? 'active' : ''}`} onClick={() => handleTabChange('history')}>
              📜 Threat Logs
            </button>
          </nav>
        </aside>

        {/* Content Viewer Workspace */}
        <main className="main-content">
          <div className="tab-content">

            {activeTab === 'home' && (
              <div className="home-content">
                <div style={{ marginBottom: '2rem' }}>
                  <h2>Security Operations Center</h2>
                  <p className="subtitle">System Overview & Threat Metrics</p>
                </div>

                <div className="kpi-grid">
                  <div className="kpi-card">
                    <div className="kpi-icon blue">🔍</div>
                    <div className="kpi-data">
                      <span className="kpi-value">{totalScans}</span>
                      <span className="kpi-label">Total Scans</span>
                    </div>
                  </div>
                  <div className="kpi-card">
                    <div className="kpi-icon red">🛡️</div>
                    <div className="kpi-data">
                      <span className="kpi-value">{threatsDetected}</span>
                      <span className="kpi-label">Threats Blocked</span>
                    </div>
                  </div>
                  <div className="kpi-card">
                    <div className="kpi-icon amber">⚠️</div>
                    <div className="kpi-data">
                      <span className="kpi-value">{avgThreatScore}%</span>
                      <span className="kpi-label">Avg Threat Score</span>
                    </div>
                  </div>
                  <div className="kpi-card clickable" onClick={() => handleTabChange('history')}>
                    <div className="kpi-icon green">📊</div>
                    <div className="kpi-data">
                      <span className="kpi-value" style={{ fontSize: '1.2rem', marginTop: '5px' }}>Audit Logs</span>
                      <span className="kpi-label">View Full History ➔</span>
                    </div>
                  </div>
                </div>

                <h3 className="section-title">Active Defense Modules</h3>
                <div className="feature-grid">
                  <div className="feature-card clickable" onClick={() => handleTabChange('mail')}>
                    <h3>💬 Zero-Shot NLP</h3>
                    <p>Analyzes text intent and urgency contextually to catch zero-day phishing.</p>
                  </div>
                  <div className="feature-card clickable" onClick={() => handleTabChange('qr')}>
                    <h3>👁️ Vision AI</h3>
                    <p>Cracks open images and QR codes to read hidden visual payloads.</p>
                  </div>
                  <div className="feature-card clickable" onClick={() => handleTabChange('url')}>
                    <h3>🌐 Active Sandbox</h3>
                    <p>Visits suspicious links in a headless browser to intercept runtime telemetry.</p>
                  </div>
                </div>

                {scanHistory.length > 0 && (
                  <div style={{ marginTop: '3rem' }}>
                    <h3 className="section-title">Recent Interceptions</h3>
                    <div className="table-responsive">
                      <table className="history-table">
                        <thead>
                          <tr>
                            <th>Timestamp</th>
                            <th>Vector Type</th>
                            <th>Target Signature</th>
                            <th>Verdict</th>
                          </tr>
                        </thead>
                        <tbody>
                          {scanHistory.slice(0, 3).map((log) => (
                            <tr key={log.id} className={`row-verdict-${log.verdict.toLowerCase()}`}>
                              <td>{log.timestamp}</td>
                              <td><span className={`badge badge-${log.scan_type}`}>{log.scan_type.toUpperCase()}</span></td>
                              <td className="target-cell">{log.target}</td>
                              <td>
                                <span className={`verdict-pill verdict-${log.verdict.toLowerCase()}`}>
                                  {log.verdict}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'about' && (
              <div className="info-content-panel">
                <h2>About PhishShield AI Architecture</h2>
                <p className="subtitle">Operational Matrix & Comparative Framework</p>

                <section className="info-section">
                  <h3>System Core Functionalities</h3>
                  <p>
                    PhishShield is an automated multi-layered Security Operations center engineering node. Instead of relying on legacy signature detection sets, it provisions containerized orchestration layers to actively reason over threats:
                  </p>
                  <ul className="info-bullet-list">
                    <li><strong>Cognitive Semantic Analysis:</strong> Utilizes Gemini's advanced textual reasoning to analyze communication payloads contextually rather than reacting to static blacklisted phrasing keywords.</li>
                    <li><strong>Computer Vision Inspection:</strong> Uses an integrated OCR extraction tool combined with matrix ZBar spatial decoding to identify visual data structures and evasive payloads hidden within images.</li>
                    <li><strong>Dynamic Sandbox Forensics:</strong>spins up an isolated asynchronous Playwright headless environment, intercepting DOM structural metrics and wiretapping deep background network communication pipelines.</li>
                  </ul>
                </section>

                <section className="info-section">
                  <h3>Structural Matrix: PhishShield vs VirusTotal</h3>
                  <p>
                    While aggregators like VirusTotal provide vital intelligence infrastructure, their architecture relies on fundamentally different detection premises:
                  </p>
                  <table className="comparison-metro-table">
                    <thead>
                      <tr>
                        <th>Capability Vector</th>
                        <th>VirusTotal Vector</th>
                        <th>PhishShield AI Engine</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td><strong>Analysis Paradigm</strong></td>
                        <td>Reputational matching using global vendor file hash ($MD5$/$SHA-256$) indices and known domain logs.</td>
                        <td>Contextual cognitive reasoning utilizing deep LLM analysis over incoming payloads.</td>
                      </tr>
                      <tr>
                        <td><strong>Zero-Day Tracking</strong></td>
                        <td>Limited until a signature file is built by a commercial engine and pushed to the repository.</td>
                        <td>Immediate. Evaluates absolute textual logic, urgency, intent anomalies, and unexpected structural deviations.</td>
                      </tr>
                      <tr>
                        <td><strong>Sandbox Scope</strong></td>
                        <td>Executes heavy file environments inside rigid virtual networks, providing static summary results.</td>
                        <td>Performs real-time, lightweight containerized web rendering with native network request packet wiretapping.</td>
                      </tr>
                    </tbody>
                  </table>
                </section>
              </div>
            )}

            {activeTab === 'awareness' && (
              <div className="info-content-panel">
                <h2>Public Safety & Operational Awareness</h2>
                <p className="subtitle">System Defensive Protocols for Web Surfing</p>

                <section className="info-section">
                  <h3>Critical Surfing Best Practices</h3>
                  <p>
                    Social engineering functions by exploiting psychological cognitive load rather than breaking technical defense layers. Enforce these strict operational guidelines:
                  </p>
                  <div className="awareness-metro-grid">
                    <div className="awareness-tile red-accent">
                      <h4>1. Isolate Absolute Domain Roots</h4>
                      <p>Attackers conceal subdomains to look like trusted infrastructure (e.g., <code>login.microsoft.com.attacker-node.xyz</code>). Always scan from the absolute right side of the main authority domain string back to the first single slash.</p>
                    </div>
                    <div className="awareness-tile blue-accent">
                      <h4>2. Audit Cognitive Urgency Triggers</h4>
                      <p>Phrases like "Immediate Verification Required" or "Account Terminated within 24 Hours" are semantic indicators designed to bypass deliberate human reasoning. Treat structural panic as an active attack signature.</p>
                    </div>
                    <div className="awareness-tile amber-accent">
                      <h4>3. Verify Visual Asset Traps</h4>
                      <p>Evasive actors routinely map text into graphics or embed payload links inside scannable QR structures to bypass standard text filters. Treat unexpected text-in-image payloads as potentially hostile until verified.</p>
                    </div>
                    <div className="awareness-tile green-accent">
                      <h4>4. Inspect Dynamic Call Pathways</h4>
                      <p>Before executing interactive options on unknown locations, use sandboxed runtime inspection proxies to track whether the target environment attempts multi-hop browser redirects or initiates secondary asset drops.</p>
                    </div>
                  </div>
                </section>
              </div>
            )}

            {activeTab === 'mail' && (
              <div className="scanner-card">
                <h3>💬 Scan Mail / Text Payload</h3>
                {renderSenderInput()}
                <textarea
                  placeholder="Paste email body or SMS..."
                  value={emailContent}
                  onChange={(e) => setEmailContent(e.target.value)}
                  className="tall-textarea"
                />
                <button className="action-btn" onClick={handleTextAnalyze} disabled={loading}>
                  {loading ? 'Analyzing Semantic Threat...' : 'Scan Payload'}
                </button>
              </div>
            )}

            {activeTab === 'qr' && (
              <div className="scanner-card">
                <h3>👁️ Scan Vision (OCR/QR)</h3>
                {renderSenderInput()}
                <div className="file-drop-area">
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => setImageFile(e.target.files[0])}
                  />
                </div>
                <button className="action-btn" onClick={handleImageAnalyze} disabled={loading}>
                  {loading ? 'Extracting Vision Metrics...' : 'Scan Image'}
                </button>
              </div>
            )}

            {activeTab === 'url' && (
              <div className="scanner-card active-border">
                <h3>🌐 Deep URL Sandbox</h3>
                <p className="subtitle" style={{ marginBottom: '1.5rem' }}>
                  Safely navigates to the link and evaluates the destination page visually and semantically.
                </p>
                <input
                  type="text"
                  placeholder="https://suspicious-link.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="standalone-input"
                />
                <button className="action-btn" onClick={handleUrlAnalyze} disabled={loading}>
                  {loading ? 'Sandboxing Target Environment...' : 'Initiate Sandbox'}
                </button>
              </div>
            )}

            {/* Dynamic Results Panel */}
            {['mail', 'qr', 'url'].includes(activeTab) && result && (
              <section className={`results-panel ${result.verdict.toLowerCase().replace(' ', '-')}`}>
                <div className="results-header">
                  <div>
                    <span className="verdict-label">VERDICT:</span>
                    <span className="verdict-badge">{result.verdict}</span>
                  </div>
                  <div className="threat-score">
                    Threat Score: <strong>{result.threat_score}</strong> / 100
                  </div>
                </div>

                <div className="results-body">
                  <div className="flags-container">
                    <h4>Triggered Intelligence Flags:</h4>
                    <ul className="flags-list">
                      {result.analysis_details.map((detail, index) => (
                        <li key={index}>{detail}</li>
                      ))}
                    </ul>
                  </div>

                  {result.network_map && result.network_map.length > 0 && (
                    <div className="network-container">
                      <h4>Network Forensics (Hidden Connections):</h4>
                      <div className="network-scroll-box">
                        <ul className="network-list">
                          {result.network_map.map((domain, index) => (
                            <li key={index}>
                              <span className="network-icon">🔌</span> {domain}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}

                  {result.screenshot && (
                    <div className="screenshot-container">
                      <h4>Sandbox Visual Intel:</h4>
                      <img
                        src={`data:image/png;base64,${result.screenshot}`}
                        alt="Sandbox Snapshot"
                      />
                    </div>
                  )}
                </div>
              </section>
            )}

            {activeTab === 'history' && (
              <div className="history-panel">
                <h3>Enterprise Security Audit Log</h3>
                <p className="subtitle">Historical system analysis tracking indices generated across processing nodes.</p>

                <div className="table-responsive">
                  <table className="history-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Vector Type</th>
                        <th>Target Signature</th>
                        <th>Threat Index</th>
                        <th>Verdict</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanHistory.length === 0 ? (
                        <tr><td colSpan="5" className="text-center">No security records index found inside SQLite container file storage.</td></tr>
                      ) : (
                        scanHistory.map((log) => (
                          <tr key={log.id} className={`row-verdict-${log.verdict.toLowerCase()}`}>
                            <td>{log.timestamp}</td>
                            <td><span className={`badge badge-${log.scan_type}`}>{log.scan_type.toUpperCase()}</span></td>
                            <td className="target-cell">{log.target}</td>
                            <td className="score-cell font-mono">{log.threat_score}%</td>
                            <td>
                              <span className={`verdict-pill verdict-${log.verdict.toLowerCase()}`}>
                                {log.verdict}
                              </span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

          </div>
        </main>
      </div>
    </div>
  );
}

export default App;