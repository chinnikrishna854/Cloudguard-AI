import { useEffect, useState } from "react";
import { useAuth } from "react-oidc-context";
import "./App.css";

const API_BASE =
  "https://jdi61khfga.execute-api.us-west-1.amazonaws.com";

function App() {
  const auth = useAuth();

  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");

  const getToken = () => auth.user?.id_token;

  // ========================================================
  // LOAD FINDINGS
  // ========================================================

  const loadFindings = async () => {
    try {
      setError("");

      const token = getToken();

      if (!token) {
        throw new Error(
          "Authentication token unavailable. Please sign in again."
        );
      }

      const response = await fetch(`${API_BASE}/findings`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (response.status === 401) {
        throw new Error(
          "Your session is not authorized. Please sign in again."
        );
      }

      if (!response.ok) {
        throw new Error(
          "Unable to load CloudGuard findings."
        );
      }

      const result = await response.json();

      setData(result);
    } catch (err) {
      console.error("Load findings error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // ========================================================
  // RUN SCAN
  // ========================================================

  const runScan = async () => {
    try {
      setScanning(true);
      setError("");

      const token = getToken();

      if (!token) {
        throw new Error(
          "Authentication token unavailable. Please sign in again."
        );
      }

      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({}),
      });

      if (response.status === 401) {
        throw new Error(
          "Your session is not authorized. Please sign in again."
        );
      }

      if (!response.ok) {
        throw new Error("Cloud scan failed.");
      }

      await response.json();

      await loadFindings();
    } catch (err) {
      console.error("Cloud scan error:", err);
      setError(err.message);
    } finally {
      setScanning(false);
    }
  };

  // ========================================================
  // LOAD AFTER LOGIN
  // ========================================================

  useEffect(() => {
    if (
      auth.isAuthenticated &&
      auth.user?.id_token
    ) {
      loadFindings();
    }
  }, [
    auth.isAuthenticated,
    auth.user?.id_token,
  ]);

  // ========================================================
  // AUTH LOADING
  // ========================================================

  if (auth.isLoading) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="brand-icon auth-logo">
            CG
          </div>

          <h1>CloudGuard AI</h1>

          <p className="auth-description">
            Connecting securely...
          </p>
        </div>
      </div>
    );
  }

  // ========================================================
  // AUTH ERROR
  // ========================================================

  if (auth.error) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="brand-icon auth-logo">
            CG
          </div>

          <h1>Authentication Error</h1>

          <p className="auth-description">
            {auth.error.message}
          </p>

          <button
            className="scan-button login-button"
            onClick={() =>
              auth.signinRedirect()
            }
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  // ========================================================
  // LOGIN
  // ========================================================

  if (!auth.isAuthenticated) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="brand-icon auth-logo">
            CG
          </div>

          <p className="eyebrow">
            CLOUD SECURITY PLATFORM
          </p>

          <h1>CloudGuard AI</h1>

          <p className="auth-description">
            Secure your AWS environment with
            intelligent security and cost analysis.
          </p>

          <button
            className="scan-button login-button"
            onClick={() =>
              auth.signinRedirect()
            }
          >
            Sign in with CloudGuard
          </button>

          <p className="auth-security">
            Protected by Amazon Cognito
          </p>
        </div>
      </div>
    );
  }

  // ========================================================
  // DASHBOARD VALUES
  // ========================================================

  const findings = data?.findings || [];

  const critical =
    data?.severityCounts?.CRITICAL || 0;

  const high =
    data?.severityCounts?.HIGH || 0;

  const medium =
    data?.severityCounts?.MEDIUM || 0;

  const security =
    data?.categoryCounts?.SECURITY || 0;

  const cost =
    data?.categoryCounts?.COST || 0;

  const healthScore = Math.max(
    0,
    100 -
      critical * 15 -
      high * 10 -
      medium * 5
  );

  const userEmail =
    auth.user?.profile?.email ||
    "Authenticated User";

  // ========================================================
  // DASHBOARD
  // ========================================================

  return (
    <div className="app">
      {/* HEADER */}

      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            CG
          </div>

          <div>
            <h1>CloudGuard AI</h1>

            <p>
              Cloud Security & Cost Intelligence
            </p>
          </div>
        </div>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "22px",
          }}
        >
          <div className="environment">
            <span className="status-dot" />
            AWS Connected
          </div>

          <div
            style={{
              textAlign: "right",
              fontSize: "12px",
            }}
          >
            <div
              style={{
                color: "#cbd5e1",
                marginBottom: "3px",
              }}
            >
              {userEmail}
            </div>

            <button
              onClick={() =>
                auth.signoutRedirect()
              }
              style={{
                border: "none",
                background: "transparent",
                color: "#60a5fa",
                cursor: "pointer",
                padding: 0,
                fontSize: "11px",
              }}
            >
              Sign out
            </button>
          </div>
        </div>
      </header>

      <main className="container">
        {/* HERO */}

        <section className="hero">
          <div>
            <p className="eyebrow">
              CLOUD INTELLIGENCE PLATFORM
            </p>

            <h2>
              Secure your cloud.
              <br />
              Optimize your spend.
            </h2>

            <p className="hero-description">
              CloudGuard AI analyzes AWS resources
              for security risks and cost
              optimization opportunities using
              serverless automation and generative AI.
            </p>
          </div>

          <button
            className="scan-button"
            onClick={runScan}
            disabled={scanning}
          >
            {scanning
              ? "AI Scan Running..."
              : "Scan AWS Environment"}
          </button>
        </section>

        {/* ERROR */}

        {error && (
          <div className="error-box">
            {error}
          </div>
        )}

        {/* OVERVIEW */}

        <section className="overview">
          <div className="health-card">
            <div>
              <p className="card-label">
                CLOUD HEALTH SCORE
              </p>

              <div className="score-row">
                <span className="score">
                  {healthScore}
                </span>

                <span className="score-total">
                  /100
                </span>
              </div>

              <p className="health-message">
                {critical > 0
                  ? "Critical security issues require attention."
                  : "Your cloud environment looks healthy."}
              </p>
            </div>

            <div className="score-ring">
              <span>{healthScore}</span>
            </div>
          </div>

          <div className="metric-card">
            <span className="metric-icon critical-icon">
              !
            </span>

            <p>Critical</p>

            <h3>{critical}</h3>

            <span className="metric-description">
              Immediate attention
            </span>
          </div>

          <div className="metric-card">
            <span className="metric-icon security-icon">
              S
            </span>

            <p>Security</p>

            <h3>{security}</h3>

            <span className="metric-description">
              Security findings
            </span>
          </div>

          <div className="metric-card">
            <span className="metric-icon cost-icon">
              $
            </span>

            <p>Cost</p>

            <h3>{cost}</h3>

            <span className="metric-description">
              Optimization findings
            </span>
          </div>
        </section>

        {/* FINDINGS */}

        <section className="findings-section">
          <div className="section-header">
            <div>
              <p className="eyebrow">
                AI-POWERED ANALYSIS
              </p>

              <h2>Recent Findings</h2>
            </div>

            <button
              className="refresh-button"
              onClick={loadFindings}
            >
              Refresh
            </button>
          </div>

          {loading ? (
            <div className="empty-state">
              Loading CloudGuard findings...
            </div>
          ) : findings.length === 0 ? (
            <div className="empty-state">
              <h3>No findings detected</h3>

              <p>
                Run a cloud scan to analyze your
                AWS environment.
              </p>
            </div>
          ) : (
            <div className="findings-list">
              {findings.map((finding) => {
                const ai =
                  finding.aiAnalysis;

                return (
                  <article
                    className="finding-card"
                    key={finding.findingId}
                  >
                    {/* FINDING HEADER */}

                    <div className="finding-top">
                      <div>
                        <span
                          className={`severity ${
                            finding.severity?.toLowerCase()
                          }`}
                        >
                          {finding.severity}
                        </span>

                        <span className="category">
                          {finding.category}
                        </span>
                      </div>

                      <span className="rule-id">
                        {finding.ruleId}
                      </span>
                    </div>

                    {/* FINDING */}

                    <h3>
                      {finding.title}
                    </h3>

                    <p className="resource-name">
                      {finding.resourceName}
                    </p>

                    <p className="description">
                      {finding.description}
                    </p>

                    {/* STANDARD RECOMMENDATION */}

                    <div className="recommendation">
                      <span>
                        RECOMMENDATION
                      </span>

                      <p>
                        {finding.recommendation}
                      </p>
                    </div>

                    {/* ===================================
                        BEDROCK AI ANALYSIS
                    =================================== */}

                    {ai && (
                      <div className="ai-analysis">
                        <div className="ai-analysis-header">
                          <div className="ai-icon">
                            AI
                          </div>

                          <div>
                            <span className="ai-label">
                              AMAZON BEDROCK
                            </span>

                            <h4>
                              AI Security Analysis
                            </h4>
                          </div>
                        </div>

                        <div className="ai-analysis-grid">
                          <div className="ai-analysis-item">
                            <span>
                              WHY THIS IS DANGEROUS
                            </span>

                            <p>
                              {
                                ai.riskExplanation
                              }
                            </p>
                          </div>

                          <div className="ai-analysis-item">
                            <span>
                              BUSINESS IMPACT
                            </span>

                            <p>
                              {
                                ai.businessImpact
                              }
                            </p>
                          </div>

                          <div className="ai-analysis-item ai-remediation">
                            <span>
                              AI RECOMMENDED REMEDIATION
                            </span>

                            <p>
                              {ai.remediation}
                            </p>
                          </div>
                        </div>

                        <div className="ai-powered">
                          Generated with Amazon
                          Bedrock • Nova 2 Lite
                        </div>
                      </div>
                    )}

                    {/* FOOTER */}

                    <div className="finding-footer">
                      <span>
                        {finding.resourceType}
                      </span>

                      <span>
                        {finding.timestamp
                          ? new Date(
                              finding.timestamp
                            ).toLocaleString()
                          : ""}
                      </span>
                    </div>
                  </article>
                );
              })}
            </div>
          )}
        </section>

        {/* FOOTER */}

        <footer>
          <span>
            CloudGuard AI
          </span>

          <span>
            AWS Lambda • DynamoDB • Bedrock •
            Cognito • SNS • EventBridge
          </span>
        </footer>
      </main>
    </div>
  );
}

export default App;