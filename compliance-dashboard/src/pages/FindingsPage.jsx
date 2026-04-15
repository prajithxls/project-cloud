import React, { useState, useEffect, useCallback } from "react";
import { useLocation } from "react-router-dom";
import { useFilter, usePagination } from "../hooks/useCompliance";
import { getRiskClass, formatDateTime } from "../utils/helpers";
import FindingDetailModal from "../components/ui/FindingDetailModal";

const API_BASE =
  import.meta.env.VITE_API_BASE ||
  "https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev";

// ── AWS service icons ─────────────────────────────────────────────────────────
const getServiceKey = (type) => {
  if (!type) return "ec2";
  const t = type.toLowerCase();
  if (t.includes("s3"))                       return "s3";
  if (t.includes("ec2"))                      return "ec2";
  if (t.includes("iam"))                      return "iam";
  if (t.includes("lambda"))                   return "lambda";
  if (t.includes("rds") || t.includes("aurora")) return "rds";
  if (t.includes("cloudtrail"))               return "cloudtrail";
  if (t.includes("api"))                      return "apigw";
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
        <rect x="2" y="2" width="20" height="8" rx="2" />
        <rect x="2" y="14" width="20" height="8" rx="2" />
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
    ),
  };
  return (
    <div style={{ width: size, height: size, display: "flex", alignItems: "center", justifyContent: "center" }}>
      {icons[service?.toLowerCase()] || icons.ec2}
    </div>
  );
};

// ── API helper: PATCH status ──────────────────────────────────────────────────
async function patchFindingStatus(findingId, newStatus) {
  const res = await fetch(`${API_BASE}/findings/${findingId}/status`, {
    method:  "PATCH",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ status: newStatus }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.message || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── Tab bar ───────────────────────────────────────────────────────────────────
function StatusTabs({ activeTab, onChange, openCount, resolvedCount }) {
  const tabs = [
    { id: "OPEN",     label: "Open",     count: openCount,     color: "var(--high)"  },
    { id: "RESOLVED", label: "Resolved", count: resolvedCount, color: "var(--low)"   },
    { id: "ALL",      label: "All",      count: openCount + resolvedCount, color: "var(--accent-cyan)" },
  ];

  return (
    <div style={{
      display:      "flex",
      gap:          4,
      background:   "var(--bg-elevated)",
      border:       "1px solid var(--border)",
      borderRadius: "var(--radius-md)",
      padding:      4,
      marginBottom: 20,
    }}>
      {tabs.map(tab => {
        const active = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            onClick={() => onChange(tab.id)}
            style={{
              flex:           1,
              padding:        "8px 16px",
              border:         "none",
              borderRadius:   "var(--radius-sm)",
              cursor:         "pointer",
              fontFamily:     "var(--font-display)",
              fontSize:       13,
              fontWeight:     600,
              transition:     "all 0.15s",
              background:     active ? "var(--bg-surface)" : "transparent",
              color:          active ? tab.color : "var(--text-muted)",
              boxShadow:      active ? "var(--shadow-sm)" : "none",
              display:        "flex",
              alignItems:     "center",
              justifyContent: "center",
              gap:            8,
            }}
          >
            {tab.label}
            <span style={{
              fontFamily:     "var(--font-mono)",
              fontSize:       10,
              fontWeight:     700,
              padding:        "1px 7px",
              borderRadius:   10,
              background:     active ? `color-mix(in srgb, ${tab.color} 15%, transparent)` : "var(--bg-elevated)",
              color:          active ? tab.color : "var(--text-muted)",
              border:         active ? `1px solid color-mix(in srgb, ${tab.color} 30%, transparent)` : "1px solid var(--border)",
            }}>
              {tab.count}
            </span>
          </button>
        );
      })}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function FindingsPage({ findings: allFindings, loading, onRefresh, scannedAccountId }) {
  const location = useLocation();
  const params   = new URLSearchParams(location.search);
  const defaultScanner = params.get("scanner") || "ALL";

  // Active status tab — drives which findings are visible
  const [activeTab, setActiveTab] = useState("OPEN");

  // Optimistic local overrides: { [findingId]: "OPEN" | "RESOLVED" }
  const [localOverrides, setLocalOverrides] = useState({});
  // Track which findingIds are mid-update (to show spinner on button)
  const [updatingIds, setUpdatingIds] = useState(new Set());

  // Apply local overrides on top of server data
  const findings = allFindings.map(f => {
    const override = localOverrides[f.findingId];
    return override ? { ...f, status: override } : f;
  });

  // Counts for tabs (after overrides applied)
  const openCount     = findings.filter(f => f.status === "OPEN").length;
  const resolvedCount = findings.filter(f => f.status === "RESOLVED").length;

  // Filter to active tab
  const tabFiltered = activeTab === "ALL"
    ? findings
    : findings.filter(f => f.status === activeTab);

  const {
    filtered,
    search, setSearch,
    severityFilter, setSeverityFilter,
    statusFilter, setStatusFilter,
    scannerFilter, setScannerFilter,
    sortKey, sortDir, toggleSort,
  } = useFilter(tabFiltered);

  // Disable the status dropdown filter when a tab is active (redundant)
  useEffect(() => { setScannerFilter(defaultScanner); }, [defaultScanner, setScannerFilter]);

  const scanners = ["ALL", ...new Set(allFindings.map(f => f.scanner).filter(Boolean))];

  // Group filtered findings by resource
  const groupedFindings = filtered.reduce((acc, finding) => {
    const resourceId = finding.resourceId || "unknown";
    if (!acc[resourceId]) {
      acc[resourceId] = {
        resourceId,
        resourceType: finding.resourceType,
        scanner:      finding.scanner,
        accountId:    finding.accountId,
        findings:     [],
        severityCounts:  { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        highestSeverity: "LOW",
        highestRiskScore: 0,
        timestamp:    finding.timestamp,
      };
    }
    acc[resourceId].findings.push(finding);
    const sev = finding.severity || "LOW";
    acc[resourceId].severityCounts[sev]++;
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    if (rank[sev] > rank[acc[resourceId].highestSeverity]) {
      acc[resourceId].highestSeverity = sev;
    }
    const rs = parseFloat(finding.riskScore) || 0;
    if (rs > acc[resourceId].highestRiskScore) acc[resourceId].highestRiskScore = rs;
    if (finding.timestamp > acc[resourceId].timestamp) acc[resourceId].timestamp = finding.timestamp;
    return acc;
  }, {});

  const resourceGroups = Object.values(groupedFindings).sort((a, b) => {
    const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const diff = (rank[b.highestSeverity] || 0) - (rank[a.highestSeverity] || 0);
    return diff !== 0 ? diff : b.highestRiskScore - a.highestRiskScore;
  });

  const { page, setPage, totalPages, paginated, total, start, end } =
    usePagination(resourceGroups, 20);

  // ── Mark as Resolved / Reopen ─────────────────────────────────────────────
  const handleToggleStatus = useCallback(async (findingId, currentStatus) => {
    const newStatus = currentStatus === "OPEN" ? "RESOLVED" : "OPEN";

    // Optimistic update — instant UI feedback
    setLocalOverrides(prev => ({ ...prev, [findingId]: newStatus }));
    setUpdatingIds(prev => new Set(prev).add(findingId));

    try {
      await patchFindingStatus(findingId, newStatus);
    } catch (err) {
      // Revert on failure
      setLocalOverrides(prev => {
        const next = { ...prev };
        delete next[findingId];
        return next;
      });
      console.error("Status update failed:", err.message);
    } finally {
      setUpdatingIds(prev => {
        const next = new Set(prev);
        next.delete(findingId);
        return next;
      });
    }
  }, []);

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Findings</div>
          <div className="page-title-sub">
            {total} resource{total !== 1 ? "s" : ""} with {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
            {activeTab !== "ALL" && (
              <span style={{
                marginLeft: 8,
                fontFamily: "var(--font-mono)", fontSize: 10,
                color:      activeTab === "OPEN" ? "var(--high)" : "var(--low)",
                background: activeTab === "OPEN" ? "var(--high-dim)" : "var(--low-dim)",
                border:     `1px solid ${activeTab === "OPEN" ? "rgba(251,146,60,0.2)" : "rgba(52,211,153,0.2)"}`,
                padding: "1px 8px", borderRadius: 10,
              }}>
                {activeTab}
              </span>
            )}
          </div>
        </div>
        <button className="btn btn-secondary" onClick={onRefresh} disabled={loading}>
          {loading ? <><div className="spinner" /> Refreshing</> : "⟳ Refresh"}
        </button>
      </div>

      {/* Status tabs */}
      <StatusTabs
        activeTab={activeTab}
        onChange={(tab) => { setActiveTab(tab); setPage(1); }}
        openCount={openCount}
        resolvedCount={resolvedCount}
      />

      {/* Filters */}
      <div className="table-controls">
        <div className="search-input-wrapper">
          <span className="search-icon">⌕</span>
          <input
            className="search-input"
            placeholder="Search resources, issues, ARNs..."
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
          />
        </div>

        <select className="filter-select" value={severityFilter}
          onChange={e => { setSeverityFilter(e.target.value); setPage(1); }}>
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>

        <select className="filter-select" value={scannerFilter}
          onChange={e => { setScannerFilter(e.target.value); setPage(1); }}>
          {scanners.map(s => (
            <option key={s} value={s}>{s === "ALL" ? "All Scanners" : s}</option>
          ))}
        </select>

        {(search || severityFilter !== "ALL" || scannerFilter !== "ALL") && (
          <button className="btn btn-ghost" onClick={() => {
            setSearch(""); setSeverityFilter("ALL"); setScannerFilter("ALL"); setPage(1);
          }}>
            ✕ Clear
          </button>
        )}
      </div>

      {/* Resource groups */}
      {loading ? (
        <div className="loading-overlay">
          <div className="spinner" />
          <div className="loading-text">LOADING FINDINGS...</div>
        </div>
      ) : resourceGroups.length === 0 ? (
        <div className="empty-state">
          <div className="empty-state-icon">
            {activeTab === "RESOLVED" ? "✓" : "⚑"}
          </div>
          <div className="empty-state-title">
            {activeTab === "RESOLVED"
              ? "No resolved findings yet"
              : activeTab === "OPEN"
              ? "No open findings — great posture!"
              : "No findings match your filters"}
          </div>
          <div className="empty-state-sub">
            {activeTab === "OPEN"
              ? "All findings have been remediated or no scan has been run."
              : "Try adjusting your search query or filters."}
          </div>
        </div>
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {paginated.map(group => (
              <ResourceGroup
                key={group.resourceId}
                group={group}
                activeTab={activeTab}
                onToggleStatus={handleToggleStatus}
                updatingIds={updatingIds}
              />
            ))}
          </div>

          {total > 0 && totalPages > 1 && (
            <div className="pagination">
              <div className="pagination-info">
                Showing {start + 1}–{end} of {total} resources
              </div>
              <div className="pagination-controls">
                <button className="page-btn" onClick={() => setPage(1)} disabled={page === 1}>«</button>
                <button className="page-btn" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}>‹</button>
                {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                  const s = Math.max(1, Math.min(page - 2, totalPages - 4));
                  const p = s + i;
                  return (
                    <button key={p} className={`page-btn${page === p ? " active" : ""}`} onClick={() => setPage(p)}>
                      {p}
                    </button>
                  );
                })}
                <button className="page-btn" onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages}>›</button>
                <button className="page-btn" onClick={() => setPage(totalPages)} disabled={page === totalPages}>»</button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Resource Group accordion ──────────────────────────────────────────────────
function ResourceGroup({ group, activeTab, onToggleStatus, updatingIds }) {
  const [expanded, setExpanded] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  const { resourceId, resourceType, scanner, findings, severityCounts,
          highestSeverity, highestRiskScore, timestamp } = group;

  const shortResourceId = resourceId.split("/").pop().split(":").pop();
  const totalFindings   = findings.length;

  const borderColor = {
    CRITICAL: "var(--critical)", HIGH: "var(--high)",
    MEDIUM: "var(--medium)", LOW: "var(--low)",
  }[highestSeverity] || "var(--low)";

  return (
    <>
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        {/* Accordion header */}
        <div
          onClick={() => setExpanded(!expanded)}
          style={{
            padding:     "16px 20px",
            cursor:      "pointer",
            borderLeft:  `4px solid ${borderColor}`,
            display:     "flex",
            alignItems:  "center",
            gap:         16,
            transition:  "background 0.15s",
          }}
          onMouseEnter={e => e.currentTarget.style.background = "var(--bg-elevated)"}
          onMouseLeave={e => e.currentTarget.style.background = "transparent"}
        >
          {/* Expand toggle */}
          <div style={{
            width: 28, height: 28, borderRadius: "var(--radius-sm)",
            background: "var(--bg-elevated)", border: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 12, color: "var(--text-muted)", flexShrink: 0,
            transform: expanded ? "rotate(90deg)" : "rotate(0deg)",
            transition: "transform 0.2s",
          }}>
            ▶
          </div>

          {/* AWS icon */}
          <div style={{
            width: 44, height: 44, borderRadius: "var(--radius-md)",
            background: "var(--bg-elevated)", border: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
          }}>
            <AwsIcon service={getServiceKey(resourceType)} size={24} />
          </div>

          {/* Resource info */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: 14, fontWeight: 600, color: "var(--text-primary)",
              marginBottom: 4, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>
              {shortResourceId}
            </div>
            <div style={{
              fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
              display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap",
            }}>
              <span>{resourceType}</span>
              <span>·</span>
              <span>{scanner}</span>
              <span>·</span>
              <span>{formatDateTime(timestamp)}</span>
            </div>
          </div>

          {/* Right-side metrics */}
          <div style={{ display: "flex", gap: 8, flexShrink: 0, alignItems: "center", height: 28 }}>
            <div style={{ display: "flex", gap: 6, height: "100%" }}>
              {severityCounts.CRITICAL > 0 && (
                <span className="badge CRITICAL" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", minWidth: "auto" }}>
                  {severityCounts.CRITICAL} CRITICAL
                </span>
              )}
              {severityCounts.HIGH > 0 && (
                <span className="badge HIGH" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", minWidth: "auto" }}>
                  {severityCounts.HIGH} HIGH
                </span>
              )}
              {severityCounts.MEDIUM > 0 && (
                <span className="badge MEDIUM" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", minWidth: "auto" }}>
                  {severityCounts.MEDIUM} MEDIUM
                </span>
              )}
              {severityCounts.LOW > 0 && (
                <span className="badge LOW" style={{ fontSize: 10, padding: "0 10px", height: "100%", boxSizing: "border-box", display: "inline-flex", alignItems: "center", minWidth: "auto" }}>
                  {severityCounts.LOW} LOW
                </span>
              )}
            </div>

            <div style={{
              background: "var(--bg-elevated)", border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)", padding: "0 12px", height: "100%",
              boxSizing: "border-box", display: "inline-flex", alignItems: "center",
              fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: "var(--text-primary)",
            }}>
              {totalFindings} issue{totalFindings !== 1 ? "s" : ""}
            </div>

            <div className={`risk-score ${getRiskClass(highestRiskScore)}`}
              style={{ fontSize: 14, width: 32, display: "flex", justifyContent: "flex-end", alignItems: "center", height: "100%" }}>
              {highestRiskScore.toFixed(1)}
            </div>
          </div>
        </div>

        {/* Expanded findings */}
        {expanded && (
          <div style={{
            borderTop: "1px solid var(--border)", background: "var(--bg-base)",
            animation: "slideDown 0.2s ease-out",
          }}>
            {findings.map((finding, idx) => (
              <FindingRow
                key={finding.findingId}
                finding={finding}
                isLast={idx === findings.length - 1}
                activeTab={activeTab}
                onView={() => setSelectedFinding(finding)}
                onToggleStatus={onToggleStatus}
                isUpdating={updatingIds.has(finding.findingId)}
              />
            ))}
          </div>
        )}
      </div>

      {selectedFinding && (
        <FindingDetailModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}

      <style>{`
        @keyframes slideDown {
          from { opacity: 0; max-height: 0; }
          to   { opacity: 1; max-height: 2000px; }
        }
      `}</style>
    </>
  );
}

// ── Individual finding row ─────────────────────────────────────────────────────
function FindingRow({ finding, isLast, activeTab, onView, onToggleStatus, isUpdating }) {
  const [hovered, setHovered] = useState(false);
  const isResolved = finding.status === "RESOLVED";

  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        padding:      "14px 20px 14px 72px",
        borderBottom: isLast ? "none" : "1px solid var(--border)",
        background:   hovered ? "var(--bg-elevated)" : "transparent",
        transition:   "background 0.15s",
        display:      "flex",
        alignItems:   "center",
        gap:          16,
        opacity:      isResolved ? 0.65 : 1,
      }}
    >
      <span className={`badge ${finding.severity?.toUpperCase()}`} style={{ fontSize: 10, flexShrink: 0 }}>
        {finding.severity}
      </span>

      <span className={`risk-score ${getRiskClass(finding.riskScore)}`} style={{ fontSize: 13, flexShrink: 0 }}>
        {parseFloat(finding.riskScore).toFixed(1)}
      </span>

      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontSize: 13, fontWeight: 500, color: "var(--text-primary)",
          marginBottom: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          textDecoration: isResolved ? "line-through" : "none",
        }}>
          {finding.title}
        </div>
        <div style={{
          fontSize: 10, color: "var(--text-muted)", fontFamily: "var(--font-mono)",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <span>{finding.findingId?.split("-").pop() || "ID"}</span>
          {finding.complianceFramework?.length > 0 && (
            <>
              <span>·</span>
              <span>{finding.complianceFramework[0]}</span>
            </>
          )}
          {finding.updatedAt && isResolved && (
            <>
              <span>·</span>
              <span style={{ color: "var(--low)" }}>
                resolved {formatDateTime(finding.updatedAt)}
              </span>
            </>
          )}
        </div>
      </div>

      {/* Status badge */}
      <span className={`badge ${finding.status?.toUpperCase()}`} style={{ fontSize: 10, flexShrink: 0 }}>
        {finding.status}
      </span>

      {/* Mark Resolved / Reopen button */}
      <button
        className="btn btn-ghost"
        style={{
          fontSize:    11,
          padding:     "5px 10px",
          flexShrink:  0,
          color:       isResolved ? "var(--accent-cyan)" : "var(--low)",
          borderColor: isResolved ? "var(--border)" : "rgba(52,211,153,0.3)",
          border:      "1px solid",
          borderRadius: "var(--radius-sm)",
          minWidth:    104,
          opacity:     isUpdating ? 0.5 : 1,
        }}
        disabled={isUpdating}
        onClick={e => {
          e.stopPropagation();
          onToggleStatus(finding.findingId, finding.status);
        }}
      >
        {isUpdating
          ? <><div className="spinner dark" style={{ width: 10, height: 10, borderWidth: 1.5 }} /> Saving...</>
          : isResolved ? "↺ Reopen" : "✓ Resolve"}
      </button>

      {/* View detail button */}
      <button
        className="btn btn-ghost"
        style={{ fontSize: 11, padding: "6px 12px", flexShrink: 0 }}
        onClick={e => { e.stopPropagation(); onView(); }}
      >
        View →
      </button>
    </div>
  );
}