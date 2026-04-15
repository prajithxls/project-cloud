import React, { useEffect, useState } from "react";
import { useApp } from "../App";
import { useNavigate } from "react-router-dom";

export default function HistoryPage() {
  // 1. Pull in your setter function and userId from App context
  const { scanHistory, setScanHistory, userId } = useApp();
  const navigate = useNavigate();
  
  // 2. Add a loading state so it doesn't flash the empty screen
  const [isLoading, setIsLoading] = useState(true);

  // 3. THE FIX: Fetch from DynamoDB when the page loads!
  useEffect(() => {
    // If there's no user, stop loading
    if (!userId) {
      setIsLoading(false);
      return; 
    }

    // Replace this URL with your actual API Gateway URL!
    fetch(`https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev/history?userId=${userId}`)
      .then((res) => res.json())
      .then((data) => {
        // Save the DynamoDB data into your React global state
        if (setScanHistory) setScanHistory(data);
        setIsLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching history:", err);
        setIsLoading(false);
      });
  }, [userId, setScanHistory]);

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">My Scan History</div>
          <div className="page-title-sub">
            Past compliance audits executed by your account
          </div>
        </div>
        <button className="btn btn-secondary" onClick={() => navigate("/scan")}>
          ⊕ New Scan
        </button>
      </div>

      <div className="card">
        {/* 4. Show a loading message while waiting for the database */}
        {isLoading ? (
          <div style={{ padding: "60px 20px", textAlign: "center", color: "var(--text-muted)" }}>
            Loading scan history...
          </div>
        ) : (!scanHistory || scanHistory.length === 0) ? (
          <div style={{
            display: "flex", flexDirection: "column", alignItems: "center",
            padding: "60px 20px", textAlign: "center",
          }}>
            <div style={{ fontSize: 24, marginBottom: 12 }}>◴</div>
            <div style={{ fontSize: 16, fontWeight: 600, color: "var(--text-primary)" }}>
              No scan history found
            </div>
            <div style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: 8 }}>
              You haven't run any compliance scans yet.
            </div>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--text-muted)", fontSize: 11, fontFamily: "var(--font-mono)" }}>
                <th style={{ padding: "12px 16px", fontWeight: "normal" }}>DATE & TIME</th>
                <th style={{ padding: "12px 16px", fontWeight: "normal" }}>TARGET ACCOUNT</th>
                <th style={{ padding: "12px 16px", fontWeight: "normal" }}>FINDINGS</th>
                <th style={{ padding: "12px 16px", fontWeight: "normal" }}>STATUS</th>
              </tr>
            </thead>
            <tbody>
              {scanHistory.map((record, i) => {
                const date = new Date(record.timestamp || Date.now());
                const dateStr = date.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
                const timeStr = date.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });

                return (
                  <tr key={i} style={{ borderBottom: "1px solid var(--border)", transition: "background 0.2s" }} onMouseEnter={e => e.currentTarget.style.background = "var(--bg-elevated)"} onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                    <td style={{ padding: "16px", fontSize: 13, color: "var(--text-primary)" }}>
                      {dateStr} <span style={{ color: "var(--text-muted)", marginLeft: 6 }}>{timeStr}</span>
                    </td>
                    <td style={{ padding: "16px", fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--accent-cyan)" }}>
                      {record.accountId}
                    </td>
                   {/* Findings Column */}
                    <td style={{ padding: "16px", fontSize: 13, color: "var(--text-primary)", fontWeight: 500 }}>
                      {record.status === "Failed" || record.findingsCount === "nil" 
                        ? <span style={{ color: "var(--text-muted)" }}>nil</span>
                        : record.findingsCount !== undefined ? `${record.findingsCount} issues` : "—"}
                    </td>
                    
                    {/* Status Column */}
                    <td style={{ padding: "16px" }}>
                      {record.status === "Failed" ? (
                        <span style={{
                          display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
                          padding: "4px 10px", borderRadius: "20px", minWidth: "85px",
                          background: "var(--critical-dim)", border: "1px solid rgba(239, 68, 68, 0.3)",
                          fontSize: 10, fontFamily: "var(--font-mono)", color: "var(--critical)"
                        }}>
                          <span>✕</span> Failed
                        </span>
                      ) : (
                        <span style={{
                          display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 6,
                          padding: "4px 10px", borderRadius: "20px", minWidth: "85px",
                          background: "var(--bg-elevated)", border: "1px solid var(--low)33",
                          fontSize: 11, fontFamily: "var(--font-mono)", color: "var(--low)"
                        }}>
                          <span>✓</span> Success
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}