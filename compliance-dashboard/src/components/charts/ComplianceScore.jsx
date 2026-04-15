import React from "react";
import { computeComplianceScore } from "../../utils/helpers";

export default function ComplianceScore({ findings }) {
  const score = computeComplianceScore(findings);
  
  // 1. Safe score for math and logic
  const safeScore = isNaN(score) || score === null ? 0 : score;

  // 2. NIST Tier Logic
  let label = "";
  let tier = "";
  let color = "";

  if (safeScore >= 90) {
    label = "Compliant";
    tier = "Tier 4: Adaptive";
    color = "var(--low)";
  } else if (safeScore >= 70) {
    label = "Acceptable Risk";
    tier = "Tier 3: Repeatable";
    color = "var(--medium)";
  } else if (safeScore >= 40) {
    label = "At Risk";
    tier = "Tier 2: Risk Informed";
    color = "var(--high)";
  } else {
    label = "Non-Compliant";
    tier = "Tier 1: Partial";
    color = "var(--critical)";
  }

  // 3. SVG Math
  const circumference = 2 * Math.PI * 52;
  const dashOffset = circumference - (safeScore / 100) * circumference;

  return (
 <div className="card" style={{ height: "100%", minHeight: "280px", display: "flex", flexDirection: "column" }}>
      <div className="card-header">
        <span className="card-title">Compliance Score</span>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 11,
            color: color,
            fontWeight: 700,
          }}
        >
          {label.toUpperCase()}
        </span>
      </div>

      <div
        style={{
          flex: 1,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          gap: 32,
        }}
      >
        {/* SVG Ring */}
        <div style={{ position: "relative" }}>
          <svg width="130" height="130" viewBox="0 0 130 130">
            <circle
              cx="65" cy="65" r="52"
              fill="none"
              stroke="var(--bg-elevated)"
              strokeWidth="10"
            />
            <circle
              cx="65" cy="65" r="52"
              fill="none"
              stroke={color}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={dashOffset}
              strokeLinecap="round"
              transform="rotate(-90 65 65)"
              style={{
                transition: "stroke-dashoffset 1s ease, stroke 0.5s ease",
                filter: `drop-shadow(0 0 8px ${color}66)`,
              }}
            />
          </svg>
          <div
            style={{
              position: "absolute",
              inset: 0,
              display: "flex",
              flexDirection: "column",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <div style={{
              fontFamily: "var(--font-display)",
              fontSize: 32,
              fontWeight: 800,
              color,
              lineHeight: 1,
            }}>
              {score === 0 ? "0" : score}
            </div>
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: 9,
              color: "var(--text-muted)",
              letterSpacing: "0.1em",
              marginTop: 4,
            }}>
              / 100
            </div>
          </div>
        </div>
        <div style={{ 
  marginTop: 6,
  padding: "4px 10px", 
  borderRadius: "12px", 
  background: `color-mix(in srgb, ${color} 15%, transparent)`, 
  border: `1px solid color-mix(in srgb, ${color} 30%, transparent)`,
  fontSize: 10, 
  fontFamily: "var(--font-mono)", 
  fontWeight: 700,
  color: color,
  letterSpacing: "0.05em",
  display: "inline-block"
}}>
  {tier.toUpperCase()}
</div>

        {/* Legend */}
        <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          {[
            { label: "Open Issues", value: findings.filter(f => f.status === "OPEN").length, color: "var(--high)" },
            { label: "Resolved", value: findings.filter(f => f.status === "RESOLVED").length, color: "var(--low)" },
            { label: "Avg Risk", value: findings.length
                ? (findings.reduce((a, f) => a + (parseFloat(f.riskScore) || 0), 0) / findings.length).toFixed(1)
                : "0.0", color: "var(--accent-cyan)" },
          ].map((item) => (
            <div key={item.label}>
              <div style={{
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                color: "var(--text-muted)",
                letterSpacing: "0.08em",
                marginBottom: 2,
              }}>
                {item.label.toUpperCase()}
              </div>
              <div style={{
                fontFamily: "var(--font-display)",
                fontSize: 20,
                fontWeight: 700,
                color: item.color,
              }}>
                {item.value}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}