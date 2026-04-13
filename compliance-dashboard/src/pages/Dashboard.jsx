import React from "react";
import { useNavigate } from "react-router-dom";
import { computeStats } from "../utils/helpers";
import SeverityDonut from "../components/charts/SeverityDonut";
import ScannerBarChart from "../components/charts/ScannerBarChart";
import ComplianceScore from "../components/charts/ComplianceScore";

export default function Dashboard({ findings, loading, scanning, scannedAccountId }) {
  const navigate = useNavigate();
  const stats = computeStats(findings);

  const statMetrics = [
    { label: "Total Findings", value: stats.total, color: "var(--accent-cyan)", sub: `${stats.openCount || 0} Open` },
    { label: "Critical Risk", value: stats.CRITICAL || 0, color: "var(--critical)", sub: "Immediate Action" },
    { label: "High Risk", value: stats.HIGH || 0, color: "var(--high)", sub: "Urgent Review" },
    { label: "Medium Risk", value: stats.MEDIUM || 0, color: "var(--medium)", sub: "Plan Fixes" },
    { label: "Low Risk", value: stats.LOW || 0, color: "var(--low)", sub: "Monitor" },
  ];

  return (
    <div style={{ 
      maxWidth: "1600px", 
      margin: "0 auto",
      animation: "fadeIn 0.4s ease-out"
    }}>
      {/* ── Modern Header / Top Nav Area ── */}
      <div style={{ 
        display: "flex",
        alignItems: "flex-end",
        justifyContent: "space-between",
        marginBottom: "24px",
        paddingBottom: "24px",
      }}>
        <div>
          <h1 style={{ 
            fontFamily: "var(--font-display)",
            fontSize: "28px",
            fontWeight: 800,
            letterSpacing: "-0.5px",
            color: "var(--text-primary)",
            marginBottom: "8px",
            display: "flex",
            alignItems: "center",
            gap: "12px"
          }}>
            Security Command Center
            {scannedAccountId && (
              <span style={{
                fontFamily: "var(--font-mono)",
                fontSize: "12px",
                fontWeight: 600,
                color: "var(--accent-cyan)",
                background: "var(--accent-cyan-dim)",
                padding: "4px 10px",
                borderRadius: "20px",
                border: "1px solid rgba(255, 255, 255, 0.1)"
              }}>
                {scannedAccountId}
              </span>
            )}
          </h1>
          <p style={{ 
            fontFamily: "var(--font-mono)",
            fontSize: "12px", 
            color: "var(--text-muted)",
            letterSpacing: "0.02em"
          }}>
            Real-time compliance posture and threat detection for AWS infrastructure.
          </p>
        </div>
        
        <div style={{ display: "flex", gap: "12px" }}>
          <button 
            className="btn btn-secondary" 
            onClick={() => navigate("/scan")}
            style={{ fontSize: "13px", padding: "8px 16px" }}
          >
            ⟳ New Scan
          </button>
          <button 
            className="btn btn-primary" 
            onClick={() => navigate("/findings")}
            style={{ fontSize: "13px", padding: "8px 20px" }}
          >
            View All Findings →
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading-overlay" style={{ minHeight: "400px" }}>
          <div className="spinner" style={{ width: "32px", height: "32px", borderWidth: "3px" }}></div>
          <p className="loading-text" style={{ fontSize: "12px", marginTop: "16px" }}>ANALYZING INFRASTRUCTURE...</p>
        </div>
      ) : findings.length === 0 ? (
        /* ── Modern Empty State ── */
        <div style={{
          background: "var(--bg-surface)",
          border: "1px dashed var(--border)",
          borderRadius: "var(--radius-lg)",
          padding: "80px 40px",
          textAlign: "center",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center"
        }}>
          <div style={{ fontSize: "48px", opacity: 0.2, marginBottom: "20px" }}>◧</div>
          <h2 style={{ fontSize: "18px", fontWeight: 700, color: "var(--text-primary)", marginBottom: "8px" }}>
            No Infrastructure Scanned
          </h2>
          <p style={{ fontSize: "13px", color: "var(--text-secondary)", marginBottom: "24px", maxWidth: "400px", lineHeight: "1.6" }}>
            Connect a target AWS account to instantly detect misconfigurations, IAM vulnerabilities, and compliance drifts.
          </p>
          <button className="btn btn-primary" onClick={() => navigate("/scan")}>
            Initialize Scanner
          </button>
        </div>
      ) : (
        <>
          {/* ── Unified Metrics Strip (Replaces separate cards) ── */}
          <div style={{
            display: "flex",
            background: "var(--bg-surface)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-lg)",
            marginBottom: "24px",
            overflow: "hidden",
            boxShadow: "var(--shadow-sm)"
          }}>
            {statMetrics.map((stat, idx) => (
              <div 
                key={stat.label}
                style={{
                  flex: 1,
                  padding: "20px 24px",
                  borderRight: idx !== statMetrics.length - 1 ? "1px solid var(--border)" : "none",
                  position: "relative",
                  background: "transparent",
                  transition: "background 0.2s ease"
                }}
                onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-elevated)"}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
              >
                {/* Subtle top border glow for severity */}
                <div style={{
                  position: "absolute", top: 0, left: 0, right: 0, height: "2px",
                  background: stat.color, opacity: 0.5
                }} />
                
                <div style={{ 
                  fontFamily: "var(--font-mono)", 
                  fontSize: "10px", 
                  color: "var(--text-muted)",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  marginBottom: "8px"
                }}>
                  {stat.label}
                </div>
                <div style={{ 
                  fontFamily: "var(--font-display)", 
                  fontSize: "32px", 
                  fontWeight: 800, 
                  color: stat.color,
                  lineHeight: 1,
                  marginBottom: "6px"
                }}>
                  {stat.value}
                </div>
                <div style={{ 
                  fontFamily: "var(--font-mono)", 
                  fontSize: "10px", 
                  color: "var(--text-secondary)",
                }}>
                  {stat.sub}
                </div>
              </div>
            ))}
          </div>

          {/* ── Bento Box Grid (Top Row: Charts) ── */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "24px",
            marginBottom: "24px"
          }}>
            <div style={{ gridColumn: "span 1" }}>
              <SeverityDonut stats={stats} />
            </div>
            <div style={{ gridColumn: "span 1" }}>
              <ScannerBarChart scanners={stats.byScanner || {}} />
            </div>
            <div style={{ gridColumn: "span 1" }}>
              <ComplianceScore findings={findings} />
            </div>
          </div>

          {/* ── Bottom Row: Lists & Feed ── */}
          <div style={{
            display: "grid",
            gridTemplateColumns: "2fr 1fr",
            gap: "24px",
            marginBottom: "40px"
          }}>
            {/* Left: Sleek Threat Feed */}
            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ 
                padding: "20px 24px", 
                borderBottom: "1px solid var(--border)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: "var(--bg-elevated)"
              }}>
                <h3 style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>
                  Priority Threat Feed
                </h3>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--critical)" }}>
                  CRITICAL & HIGH ONLY
                </span>
              </div>
              
              <div>
                {findings
                  .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
                  .slice(0, 6)
                  .map((f, idx, arr) => (
                    <div
                      key={idx}
                      onClick={() => navigate("/findings")}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: "16px",
                        padding: "16px 24px",
                        borderBottom: idx !== arr.length - 1 ? "1px solid var(--border)" : "none",
                        cursor: "pointer",
                        transition: "background 0.2s"
                      }}
                      onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-hover)"}
                      onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
                    >
                      <span className={`badge ${f.severity}`} style={{ width: "84px", flexShrink: 0 }}>
                        {f.severity}
                      </span>
                      
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)", marginBottom: "4px", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                          {f.title}
                        </div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-muted)", display: "flex", gap: "12px" }}>
                          <span>{f.scanner}</span>
                          <span>{f.resourceId?.split("/").pop().split(":").pop() || "Unknown Resource"}</span>
                        </div>
                      </div>

                      <div style={{ fontFamily: "var(--font-mono)", fontSize: "13px", fontWeight: 700, color: f.severity === "CRITICAL" ? "var(--critical)" : "var(--high)" }}>
                        {parseFloat(f.riskScore).toFixed(1)}
                      </div>
                    </div>
                  ))}
                
                {findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0 && (
                  <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
                    <div style={{ fontSize: "24px", marginBottom: "8px", opacity: 0.5 }}>✓</div>
                    <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)" }}>Zero critical threats detected.</div>
                  </div>
                )}
              </div>
            </div>

            {/* Right: Framework Mapping */}
            <div className="card" style={{ padding: 0, overflow: "hidden" }}>
              <div style={{ 
                padding: "20px 24px", 
                borderBottom: "1px solid var(--border)",
                background: "var(--bg-elevated)"
              }}>
                <h3 style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>
                  Framework Violations
                </h3>
              </div>
              <div style={{ padding: "24px" }}>
                <FrameworkSummary findings={findings} />
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Framework Summary Sub-Component ──
function FrameworkSummary({ findings }) {
  const frameworkCounts = {};
  for (const f of findings) {
    for (const fw of f.complianceFramework || []) {
      frameworkCounts[fw] = (frameworkCounts[fw] || 0) + 1;
    }
  }

  const entries = Object.entries(frameworkCounts).sort((a, b) => b[1] - a[1]);

  if (!entries.length) {
    return (
      <div style={{ textAlign: "center", color: "var(--text-muted)", padding: "20px 0" }}>
        <div style={{ fontSize: "12px", fontFamily: "var(--font-mono)" }}>No framework data mapped.</div>
      </div>
    );
  }

  const max = entries[0][1];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
      {entries.slice(0, 6).map(([fw, count]) => {
        const percentage = (count / max) * 100;
        return (
          <div key={fw}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-primary)" }}>
                {fw}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)" }}>
                {count}
              </span>
            </div>
            <div style={{ height: "4px", background: "var(--bg-elevated)", borderRadius: "2px", overflow: "hidden" }}>
              <div style={{
                height: "100%",
                width: `${percentage}%`,
                background: "var(--accent-cyan)",
                borderRadius: "2px",
                opacity: 0.8
              }}></div>
            </div>
          </div>
        );
      })}
    </div>
  );
}