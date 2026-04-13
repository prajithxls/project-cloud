import React, { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import { useFilter, usePagination } from "../hooks/useCompliance";
import { getRiskClass, formatDateTime } from "../utils/helpers";
import FindingDetailModal from "../components/ui/FindingDetailModal";

// Official AWS Architecture Vector Icons

const getServiceKey = (type) => {
  if (!type) return "ec2";
  const t = type.toLowerCase();
  if (t.includes("s3")) return "s3";
  if (t.includes("ec2")) return "ec2";
  if (t.includes("iam")) return "iam";
  if (t.includes("lambda")) return "lambda";
  if (t.includes("rds") || t.includes("aurora")) return "rds";
  if (t.includes("cloudtrail")) return "cloudtrail";
  if (t.includes("api")) return "apigw";
  return "ec2";
};
const AwsIcon = ({ service, color = "currentColor", size = 24 }) => {
  const icons = {
    s3: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
        <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
      </svg>
    ),
    ec2: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
        <line x1="6" y1="6" x2="6.01" y2="6" />
        <line x1="6" y1="18" x2="6.01" y2="18" />
      </svg>
    ),
    iam: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
    lambda: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <path d="M5 19L14 4l7 15" />
        <path d="M10 13l-4 6" />
      </svg>
    ),
    rds: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <ellipse cx="12" cy="5" rx="9" ry="3" />
        <path d="M3 5V19c0 1.66 4 3 9 3s9-1.34 9-3V5" />
        <path d="M3 12c0 1.66 4 3 9 3s9-1.34 9-3" />
        <path d="M3 15.5c0 1.66 4 3 9 3s9-1.34 9-3" />
      </svg>
    ),
    cloudtrail: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="9" y1="15" x2="15" y2="15" />
        <line x1="9" y1="11" x2="11" y2="11" />
      </svg>
    ),
    apigw: (
      <svg viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" width="100%" height="100%">
        <circle cx="18" cy="5" r="3" />
        <circle cx="6" cy="12" r="3" />
        <circle cx="18" cy="19" r="3" />
        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
      </svg>
    )
  };
  return (
    <div style={{ width: size, height: size, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {icons[service.toLowerCase()] || icons.ec2}
    </div>
  );
};


export default function FindingsPage({ findings, loading, onRefresh }) {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const defaultScanner = params.get("scanner") || "ALL";

  const {
    filtered,
    search, setSearch,
    severityFilter, setSeverityFilter,
    statusFilter, setStatusFilter,
    scannerFilter, setScannerFilter,
    sortKey, sortDir, toggleSort,
  } = useFilter(findings);

  // Pre-set scanner filter from URL
  useEffect(() => {
    setScannerFilter(defaultScanner);
  }, [defaultScanner, setScannerFilter]);

  // Unique scanners for filter dropdown
  const scanners = ["ALL", ...new Set(findings.map((f) => f.scanner).filter(Boolean))];

  // ═══════════════════════════════════════════════════════════════
  // GROUP FINDINGS BY RESOURCE
  // ═══════════════════════════════════════════════════════════════
  
  const groupedFindings = filtered.reduce((acc, finding) => {
    const resourceId = finding.resourceId || "unknown";
    if (!acc[resourceId]) {
      acc[resourceId] = {
        resourceId,
        resourceType: finding.resourceType,
        scanner: finding.scanner,
        accountId: finding.accountId,
        findings: [],
        severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        highestSeverity: "LOW",
        highestRiskScore: 0,
        timestamp: finding.timestamp,
      };
    }
    
    acc[resourceId].findings.push(finding);
    
    // Update severity counts
    const severity = finding.severity || "LOW";
    acc[resourceId].severityCounts[severity]++;
    
    // Track highest severity
    const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if (severityRank[severity] > severityRank[acc[resourceId].highestSeverity]) {
      acc[resourceId].highestSeverity = severity;
    }
    
    // Track highest risk score
    const riskScore = parseFloat(finding.riskScore) || 0;
    if (riskScore > acc[resourceId].highestRiskScore) {
      acc[resourceId].highestRiskScore = riskScore;
    }
    
    // Keep most recent timestamp
    if (finding.timestamp > acc[resourceId].timestamp) {
      acc[resourceId].timestamp = finding.timestamp;
    }
    
    return acc;
  }, {});
  
  // Convert to array and sort by highest severity then risk score
  const resourceGroups = Object.values(groupedFindings).sort((a, b) => {
    const severityRank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const aSeverity = severityRank[a.highestSeverity] || 0;
    const bSeverity = severityRank[b.highestSeverity] || 0;
    
    if (aSeverity !== bSeverity) return bSeverity - aSeverity;
    return b.highestRiskScore - a.highestRiskScore;
  });

  const {
    page, setPage, totalPages, paginated, total, start, end,
  } = usePagination(resourceGroups, 20);

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Findings</div>
          <div className="page-title-sub">
            {total} resources with {filtered.length} total findings
          </div>
        </div>
        <button
          className="btn btn-secondary"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading ? <><div className="spinner" /> Refreshing</> : "⟳ Refresh"}
        </button>
      </div>

      {/* Controls */}
      <div className="table-controls">
        <div className="search-input-wrapper">
          <span className="search-icon">⌕</span>
          <input
            className="search-input"
            placeholder="Search resources, issues, ARNs..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        <select
          className="filter-select"
          value={severityFilter}
          onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select
          className="filter-select"
          value={statusFilter}
          onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
        >
          <option value="ALL">All Status</option>
          <option value="OPEN">Open</option>
          <option value="RESOLVED">Resolved</option>
        </select>

        <select
          className="filter-select"
          value={scannerFilter}
          onChange={(e) => { setScannerFilter(e.target.value); setPage(1); }}
        >
          {scanners.map((s) => (
            <option key={s} value={s}>{s === "ALL" ? "All Scanners" : s}</option>
          ))}
        </select>

        {(search || severityFilter !== "ALL" || statusFilter !== "ALL" || scannerFilter !== "ALL") && (
          <button
            className="btn btn-ghost"
            onClick={() => {
              setSearch("");
              setSeverityFilter("ALL");
              setStatusFilter("ALL");
              setScannerFilter("ALL");
              setPage(1);
            }}
          >
            ✕ Clear
          </button>
        )}
      </div>

      {/* Resource Groups */}
      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">LOADING FINDINGS...</div>
        </div>
      ) : resourceGroups.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">⚑</div>
          <div className="empty-state-title">No findings match your filters</div>
          <div className="empty-state-sub">Try adjusting your search query or filters</div>
        </div>
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {paginated.map((group) => (
              <ResourceGroup key={group.resourceId} group={group} />
            ))}
          </div>

          {/* Pagination */}
          {!loading && total > 0 && totalPages > 1 && (
            <div className="pagination">
              <div className="pagination-info">
                Showing {start + 1}–{end} of {total} resources
              </div>
              <div className="pagination-controls">
                <button className="page-btn" onClick={() => setPage(1)} disabled={page === 1}>
                  «
                </button>
                <button className="page-btn" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
                  ‹
                </button>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const start = Math.max(1, Math.min(page - 2, totalPages - 4));
                  const p = start + i;
                  return (
                    <button
                      key={p}
                      className={`page-btn${page === p ? " active" : ""}`}
                      onClick={() => setPage(p)}
                    >
                      {p}
                    </button>
                  );
                })}
                <button className="page-btn" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
                  ›
                </button>
                <button className="page-btn" onClick={() => setPage(totalPages)} disabled={page === totalPages}>
                  »
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// RESOURCE GROUP COMPONENT (Expandable Accordion)
// ═══════════════════════════════════════════════════════════════

function ResourceGroup({ group }) {
  const [expanded, setExpanded] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const { resourceId, resourceType, scanner, findings, severityCounts, highestSeverity, highestRiskScore, timestamp } = group;
  
  // Get short resource name (last part of ARN or ID)
  const shortResourceId = resourceId.split("/").pop().split(":").pop();
  
  const totalFindings = findings.length;

  return (
    <>
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {/* Resource Header (Always Visible) */}
        <div
          onClick={() => setExpanded(!expanded)}
          style={{
            padding: "16px 20px",
            cursor: "pointer",
            borderLeft: `4px solid ${
              highestSeverity === "CRITICAL" ? "var(--critical)" :
              highestSeverity === "HIGH" ? "var(--high)" :
              highestSeverity === "MEDIUM" ? "var(--medium)" :
              "var(--low)"
            }`,
            display: "flex",
            alignItems: "center",
            gap: 16,
            transition: "background 0.15s",
          }}
          onMouseEnter={(e) => e.currentTarget.style.background = "var(--bg-elevated)"}
          onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}
        >
          {/* Expand/Collapse Icon */}
          <div
            style={{
              width: 28,
              height: 28,
              borderRadius: "var(--radius-sm)",
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontSize: 12,
              color: "var(--text-muted)",
              flexShrink: 0,
              transform: expanded ? "rotate(90deg)" : "rotate(0deg)",
              transition: "transform 0.2s",
            }}
          >
            ▶
          </div>

         {/* Official AWS Logo */}
          <div
            style={{
              width: 44,
              height: 44,
              borderRadius: "var(--radius-md)",
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <AwsIcon service={getServiceKey(resourceType)} size={24} />
          </div>

          {/* Resource Info */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: 14,
              fontWeight: 600,
              color: "var(--text-primary)",
              marginBottom: 4,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}>
              {shortResourceId}
            </div>
            <div style={{
              fontSize: 11,
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)",
              display: "flex",
              alignItems: "center",
              gap: 12,
              flexWrap: "wrap",
            }}>
              <span>{resourceType}</span>
              <span>·</span>
              <span>{scanner}</span>
              <span>·</span>
              <span>{formatDateTime(timestamp)}</span>
            </div>
          </div>

        {/* ── RIGHT SIDE METRICS (Perfectly Aligned) ── */}
          <div style={{ display: "flex", gap: 8, flexShrink: 0, alignItems: "center", height: "28px" }}>
            
            {/* Counters: Added inline minWidth: 'auto' so these don't get forced to 84px */}
            <div style={{ display: "flex", gap: 6, height: "100%" }}>
              {severityCounts.CRITICAL > 0 && (
                <span className="badge CRITICAL" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", borderRadius: "var(--radius-sm)", minWidth: "auto" }}>
                  {severityCounts.CRITICAL} CRITICAL
                </span>
              )}
              {severityCounts.HIGH > 0 && (
                <span className="badge HIGH" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", borderRadius: "var(--radius-sm)", minWidth: "auto" }}>
                  {severityCounts.HIGH} HIGH
                </span>
              )}
              {severityCounts.MEDIUM > 0 && (
                <span className="badge MEDIUM" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", borderRadius: "var(--radius-sm)", minWidth: "auto" }}>
                  {severityCounts.MEDIUM} MEDIUM
                </span>
              )}
              {severityCounts.LOW > 0 && (
                <span className="badge LOW" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", borderRadius: "var(--radius-sm)", minWidth: "auto" }}>
                  {severityCounts.LOW} LOW
                </span>
              )}
            </div>

            {/* Total Findings Counter */}
            <div
              style={{
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "0 12px",
                height: "100%",
                boxSizing: "border-box",
                display: "inline-flex",
                alignItems: "center",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                fontWeight: 700,
                color: "var(--text-primary)",
              }}
            >
              {totalFindings} issue{totalFindings !== 1 ? "s" : ""}
            </div>

            {/* Risk Score */}
            <div
              className={`risk-score ${getRiskClass(highestRiskScore)}`}
              style={{ 
                fontSize: 14, 
                width: "32px",
                display: "flex",
                justifyContent: "flex-end",
                alignItems: "center",
                height: "100%"
              }}
            >
              {highestRiskScore.toFixed(1)}
            </div>
          </div>
        </div>

        {/* Expanded Findings List */}
        {expanded && (
          <div
            style={{
              borderTop: "1px solid var(--border)",
              background: "var(--bg-base)",
              animation: "slideDown 0.2s ease-out",
            }}
          >
            {findings.map((finding, idx) => (
              <FindingRow
                key={finding.findingId}
                finding={finding}
                isLast={idx === findings.length - 1}
                onClick={() => setSelectedFinding(finding)}
              />
            ))}
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}

      <style>{`
        @keyframes slideDown {
          from {
            opacity: 0;
            max-height: 0;
          }
          to {
            opacity: 1;
            max-height: 2000px;
          }
        }
      `}</style>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════
// INDIVIDUAL FINDING ROW (Inside Accordion)
// ═══════════════════════════════════════════════════════════════

function FindingRow({ finding, isLast, onClick }) {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding: "14px 20px 14px 72px",
        borderBottom: isLast ? "none" : "1px solid var(--border)",
        background: hovered ? "var(--bg-elevated)" : "transparent",
        transition: "background 0.15s",
        display: "flex",
        alignItems: "center",
        gap: 16,
      }}
    >
      {/* Severity Badge - will automatically grab the new 84px centered width from CSS */}
      <span className={`badge ${finding.severity?.toUpperCase()}`} style={{ fontSize: 10, flexShrink: 0 }}>
        {finding.severity}
      </span>

      {/* Risk Score */}
      <span className={`risk-score ${getRiskClass(finding.riskScore)}`} style={{ fontSize: 13, flexShrink: 0 }}>
        {parseFloat(finding.riskScore).toFixed(1)}
      </span>

      {/* Issue Title */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontSize: 13,
            fontWeight: 500,
            color: "var(--text-primary)",
            marginBottom: 3,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {finding.title}
        </div>
        <div style={{
          fontSize: 10,
          color: "var(--text-muted)",
          fontFamily: "var(--font-mono)",
          display: "flex",
          alignItems: "center",
          gap: 8,
        }}>
          <span>{finding.findingId?.split("-").pop() || "ID"}</span>
          {finding.complianceFramework && finding.complianceFramework.length > 0 && (
            <>
              <span>·</span>
              <span>{finding.complianceFramework[0]}</span>
            </>
          )}
        </div>
      </div>

      {/* Status Badge */}
      <span className={`badge ${finding.status?.toUpperCase()}`} style={{ fontSize: 10, flexShrink: 0 }}>
        {finding.status}
      </span>

      {/* View Button */}
      <button
        className="btn btn-ghost"
        style={{
          fontSize: 11,
          padding: "6px 12px",
          flexShrink: 0,
        }}
        onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}
      >
        View →
      </button>
    </div>
  );
}