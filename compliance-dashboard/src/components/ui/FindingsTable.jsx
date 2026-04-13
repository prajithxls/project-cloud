import React, { useState } from "react";
import { getRiskClass, formatDateTime } from "../../utils/helpers";
import FindingDetailModal from "./FindingDetailModal";

const COLUMNS = [
  { key: "severity",    label: "Severity",      sortable: true, width: "100px"  },
  { key: "scanner",     label: "Scanner",       sortable: true, width: "100px"  },
  { key: "resourceType",label: "Resource",      sortable: true, width: "140px"  },
  { key: "title",       label: "Issue",         sortable: true, width: "auto"   },
  { key: "riskScore",   label: "Risk",          sortable: true, width: "80px"   },
  { key: "timestamp",   label: "Detected",      sortable: true, width: "140px"  },
  { key: "status",      label: "Status",        sortable: true, width: "90px"   },
];

export default function FindingsTable({ findings, sortKey, sortDir, onSort, loading }) {
  const [selectedFinding, setSelectedFinding] = useState(null);

  if (loading) {
    return (
      <div className="loading-overlay">
        <div className="spinner" />
        <div className="loading-text">LOADING FINDINGS...</div>
      </div>
    );
  }

  if (!findings.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-icon">⚑</div>
        <div className="empty-state-title">No findings match your filters</div>
        <div className="empty-state-sub">Try adjusting your search query or filters</div>
      </div>
    );
  }

  return (
    <>
      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              {COLUMNS.map((col) => (
                <th
                  key={col.key}
                  className={sortKey === col.key ? "sorted" : ""}
                  onClick={col.sortable ? () => onSort(col.key) : undefined}
                  style={{ 
                    cursor: col.sortable ? "pointer" : "default",
                    width: col.width,
                  }}
                >
                  {col.label}
                  {col.sortable && (
                    <span className="sort-indicator">
                      {sortKey === col.key ? (sortDir === "asc" ? " ↑" : " ↓") : " ↕"}
                    </span>
                  )}
                </th>
              ))}
              <th style={{ width: "80px" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <FindingRow 
                key={f.findingId} 
                finding={f} 
                onClick={() => setSelectedFinding(f)}
              />
            ))}
          </tbody>
        </table>
      </div>

      {/* Detail Modal */}
      {selectedFinding && (
        <FindingDetailModal 
          finding={selectedFinding} 
          onClose={() => setSelectedFinding(null)} 
        />
      )}
    </>
  );
}

function FindingRow({ finding: f, onClick }) {
  return (
    <tr 
      onClick={onClick}
      style={{ cursor: "pointer" }}
      onMouseEnter={(e) => e.currentTarget.style.backgroundColor = "var(--bg-elevated)"}
      onMouseLeave={(e) => e.currentTarget.style.backgroundColor = "transparent"}
    >
      {/* Severity */}
      <td>
        <span className={`badge ${f.severity?.toUpperCase()}`}>
          {f.severity || "—"}
        </span>
      </td>

      {/* Scanner */}
      <td>
        <span style={{
          padding: "3px 8px",
          background: "var(--accent-cyan-dim)",
          color: "var(--accent-cyan)",
          borderRadius: "var(--radius-sm)",
          fontFamily: "var(--font-mono)",
          fontSize: 10,
          fontWeight: 700,
          whiteSpace: "nowrap",
        }}>
          {f.scanner || "—"}
        </span>
      </td>

      {/* Resource Type */}
      <td style={{ 
        fontSize: 12,
        color: "var(--text-primary)",
        fontWeight: 500,
      }}>
        {f.resourceType || "—"}
      </td>

      {/* Title (Issue) */}
      <td style={{ 
        color: "var(--text-primary)",
        fontSize: 13,
        fontWeight: 500,
      }}>
        <div style={{
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          maxWidth: "400px",
        }}>
          {f.title || "—"}
        </div>
        {/* Resource ID as subtitle */}
        <div style={{
          fontFamily: "var(--font-mono)",
          fontSize: 10,
          color: "var(--text-muted)",
          marginTop: 2,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
        }}>
          {f.resourceId?.split("/").pop()?.slice(0, 40) || "—"}
        </div>
      </td>

      {/* Risk Score */}
      <td>
        <span className={`risk-score ${getRiskClass(f.riskScore)}`}>
          {parseFloat(f.riskScore).toFixed(1) || "—"}
        </span>
      </td>

      {/* Timestamp */}
      <td style={{ 
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "var(--text-muted)",
      }}>
        {formatDateTime(f.timestamp)}
      </td>

      {/* Status */}
      <td>
        <span className={`badge ${f.status?.toUpperCase()}`}>
          {f.status || "—"}
        </span>
      </td>

      {/* Actions */}
      <td onClick={(e) => e.stopPropagation()}>
        <button
          className="btn btn-ghost"
          style={{ 
            fontSize: 11,
            padding: "4px 8px",
          }}
          onClick={(e) => {
            e.stopPropagation();
            onClick();
          }}
        >
          View →
        </button>
      </td>
    </tr>
  );
}