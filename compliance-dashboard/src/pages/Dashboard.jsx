import React from "react";
import { useNavigate } from "react-router-dom";
import { computeStats } from "../utils/helpers";
import SeverityDonut from "../components/charts/SeverityDonut";
import ScannerBarChart from "../components/charts/ScannerBarChart";
import ComplianceScore from "../components/charts/ComplianceScore";

export default function Dashboard({ findings, loading, scanning, scannedAccountId }) {
  const navigate = useNavigate();
  const stats = computeStats(findings);

  const statCards = [
    { cls: "total",    label: "Total Findings", value: stats.total },
    { cls: "critical", label: "Critical",        value: stats.CRITICAL },
    { cls: "high",     label: "High",            value: stats.HIGH },
    { cls: "medium",   label: "Medium",          value: stats.MEDIUM },
    { cls: "low",      label: "Low",             value: stats.LOW },
  ];

  return (
    <div>
      {/* Page Header — no scan button */}
      <div className="page-header">
        <div>
          <div className="page-title">Security Dashboard</div>
          <div className="page-title-sub">
            Cloud Compliance &amp; Audit Overview · AWS ap-south-1
            {scannedAccountId && (
              <span style={{
                marginLeft: 12,
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                color: "var(--accent-cyan)",
                background: "var(--bg-elevated)",
                border: "1px solid var(--accent-cyan)33",
                padding: "2px 10px",
                borderRadius: "20px",
              }}>
                Account: {scannedAccountId}
              </span>
            )}
          </div>
        </div>
        <button className="btn btn-secondary" onClick={() => navigate("/findings")}>
          View All Findings
        </button>
      </div>

      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">LOADING DASHBOARD...</div>
        </div>
      ) : findings.length === 0 ? (
        /* ── Empty state — no scan run yet ── */
        <div style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          padding: "80px 20px",
          gap: 16,
          textAlign: "center",
        }}>
          <div style={{
            width: 64,
            height: 64,
            borderRadius: "50%",
            background: "var(--bg-elevated)",
            border: "1px solid var(--border)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 28,
          }}>
            🛡
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>
            No scan results yet
          </div>
          <div style={{ fontSize: 13, color: "var(--text-secondary)", maxWidth: 400, lineHeight: 1.6 }}>
            Go to the <strong style={{ color: "var(--accent-cyan)" }}>Scan</strong> page, enter a target AWS account ID, and run a compliance scan to see findings here.
          </div>
          <button className="btn btn-primary" style={{ marginTop: 8 }} onClick={() => navigate("/scan")}>
            Go to Scan →
          </button>
        </div>
      ) : (
        <>
          <div className="stats-grid">
            {statCards.map((s) => (
              <div key={s.cls} className={`stat-card ${s.cls}`}>
                <div className="stat-label">{s.label}</div>
                <div className="stat-value">{s.value}</div>
                <div className="stat-trend">
                  {s.cls === "total"
                    ? `${stats.openCount} open · ${stats.resolvedCount} resolved`
                    : s.cls === "critical" || s.cls === "high"
                    ? "Requires immediate attention"
                    : "Monitored"}
                </div>
              </div>
            ))}
          </div>

          <div className="charts-grid">
            <SeverityDonut stats={stats} />
            <ScannerBarChart scanners={stats.scanners} />
          </div>

          <div className="charts-grid">
            <ComplianceScore findings={findings} />

            <div className="card" style={{ height: "280px", display: "flex", flexDirection: "column" }}>
              <div className="card-header">
                <span className="card-title">Recent Critical Findings</span>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 11 }}
                  onClick={() => navigate("/findings")}
                >
                  View All →
                </button>
              </div>
              <div style={{ flex: 1, overflowY: "auto" }}>
                {findings
                  .filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
                  .slice(0, 5)
                  .map((f) => (
                    <div
                      key={f.findingId}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        gap: 10,
                        padding: "10px 0",
                        borderBottom: "1px solid var(--border)",
                      }}
                    >
                      <span className={`badge ${f.severity?.toUpperCase()}`} style={{ flexShrink: 0 }}>
                        {f.severity}
                      </span>
                      <div style={{ overflow: "hidden" }}>
                        <div style={{
                          color: "var(--text-primary)",
                          fontSize: 12,
                          fontWeight: 500,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}>
                          {f.title}
                        </div>
                        <div style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: 10,
                          color: "var(--text-muted)",
                          marginTop: 2,
                        }}>
                          {f.resourceType} · {f.scanner}
                        </div>
                      </div>
                      <div style={{
                        marginLeft: "auto",
                        fontFamily: "var(--font-mono)",
                        fontSize: 12,
                        fontWeight: 700,
                        color: parseFloat(f.riskScore) >= 8 ? "var(--critical)" : "var(--high)",
                        flexShrink: 0,
                      }}>
                        {parseFloat(f.riskScore).toFixed(1)}
                      </div>
                    </div>
                  ))}
                {findings.filter(f => f.severity === "CRITICAL" || f.severity === "HIGH").length === 0 && (
                  <div className="empty-state" style={{ padding: "30px" }}>
                    <div className="empty-state-icon" style={{ fontSize: 24 }}>✓</div>
                    <div className="empty-state-title" style={{ fontSize: 13 }}>No critical findings</div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 16 }}>
            <div className="card-header">
              <span className="card-title">Compliance Framework Coverage</span>
            </div>
            <FrameworkSummary findings={findings} />
          </div>
        </>
      )}
    </div>
  );
}

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
      <div style={{ color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 12 }}>
        No compliance framework data available
      </div>
    );
  }

  const max = entries[0][1];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {entries.map(([fw, count]) => (
        <div key={fw} style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--info)",
            width: 140,
            flexShrink: 0,
          }}>
            {fw}
          </div>
          <div style={{ flex: 1, background: "var(--bg-elevated)", borderRadius: 2, height: 6 }}>
            <div style={{
              width: `${(count / max) * 100}%`,
              height: "100%",
              background: "var(--info)",
              borderRadius: 2,
              transition: "width 0.5s ease",
            }} />
          </div>
          <div style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: "var(--text-muted)",
            width: 50,
            textAlign: "right",
          }}>
            {count} issues
          </div>
        </div>
      ))}
    </div>
  );
}