import React, { useState } from "react";
import { getRiskClass } from "../../utils/helpers";

export default function FindingDetailModal({ finding, onClose }) {
  const [copiedField, setCopiedField] = useState(null);

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  // Parse CLI commands (handle both array and DynamoDB format)
  const cliCommands = (() => {
    const raw = finding.cliCommands;
    if (!raw) return [];
    if (Array.isArray(raw)) {
      return raw.map(cmd => {
        // Handle DynamoDB nested format: {"S": "aws s3api..."}
        if (typeof cmd === 'object' && cmd.S) return cmd.S;
        return String(cmd);
      });
    }
    return [];
  })();

  return (
    <div 
      className="modal-overlay"
      onClick={onClose}
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: "rgba(0, 0, 0, 0.85)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: "20px",
        animation: "fadeIn 0.2s ease-out",
      }}
    >
      <div 
        className="modal-content"
        onClick={(e) => e.stopPropagation()}
        style={{
          background: "var(--bg-base)",
          border: "1px solid var(--border)",
          borderRadius: "var(--radius-lg)",
          maxWidth: "900px",
          width: "100%",
          maxHeight: "90vh",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
          boxShadow: "0 20px 60px rgba(0, 0, 0, 0.5)",
          animation: "slideUp 0.3s ease-out",
        }}
      >
        {/* Header */}
        <div style={{
          padding: "24px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "flex-start",
          gap: "16px",
        }}>
          <div style={{ flex: 1 }}>
            <div style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              marginBottom: "8px",
            }}>
              <span className={`badge ${finding.severity?.toUpperCase()}`}>
                {finding.severity}
              </span>
              <span className={`risk-score ${getRiskClass(finding.riskScore)}`} style={{ fontSize: 14 }}>
                {parseFloat(finding.riskScore).toFixed(1)}
              </span>
              <span style={{
                padding: "3px 10px",
                background: "var(--accent-cyan-dim)",
                color: "var(--accent-cyan)",
                borderRadius: "var(--radius-sm)",
                fontFamily: "var(--font-mono)",
                fontSize: 11,
                fontWeight: 700,
              }}>
                {finding.scanner}
              </span>
            </div>
            <h2 style={{
              fontSize: "20px",
              fontWeight: 700,
              color: "var(--text-primary)",
              margin: 0,
              lineHeight: 1.4,
            }}>
              {finding.title}
            </h2>
            <div style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              color: "var(--text-muted)",
              marginTop: "8px",
            }}>
              {finding.resourceType} · Detected {new Date(finding.timestamp).toLocaleString()}
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              width: "32px",
              height: "32px",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              cursor: "pointer",
              fontSize: "18px",
              color: "var(--text-muted)",
              flexShrink: 0,
            }}
          >
            ×
          </button>
        </div>

        {/* Scrollable Content */}
        <div style={{
          flex: 1,
          overflowY: "auto",
          padding: "24px",
        }}>
          {/* Resource Details */}
          <Section title="Resource Details">
            <DetailRow 
              label="Resource ID" 
              value={finding.resourceId}
              copyable
              onCopy={() => copyToClipboard(finding.resourceId, 'resourceId')}
              copied={copiedField === 'resourceId'}
            />
            <DetailRow 
              label="Account ID" 
              value={finding.accountId}
              copyable
              onCopy={() => copyToClipboard(finding.accountId, 'accountId')}
              copied={copiedField === 'accountId'}
            />
            <DetailRow 
              label="Finding ID" 
              value={finding.findingId}
              copyable
              onCopy={() => copyToClipboard(finding.findingId, 'findingId')}
              copied={copiedField === 'findingId'}
            />
            <DetailRow label="Status" value={finding.status} badge />
          </Section>

          {/* Compliance Frameworks */}
          {finding.complianceFramework && finding.complianceFramework.length > 0 && (
            <Section title="Compliance Frameworks">
              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {finding.complianceFramework.map((fw, i) => (
                  <span
                    key={i}
                    style={{
                      padding: "4px 12px",
                      background: "var(--info-dim)",
                      color: "var(--info)",
                      borderRadius: "var(--radius-sm)",
                      fontFamily: "var(--font-mono)",
                      fontSize: "11px",
                      fontWeight: 600,
                    }}
                  >
                    {fw}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {/* Remediation Steps */}
          <Section title="Remediation Steps">
            <div style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              padding: "16px",
            }}>
              <pre style={{
                margin: 0,
                fontSize: "12px",
                lineHeight: 1.7,
                color: "var(--text-primary)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
                fontFamily: "var(--font-primary)",
              }}>
                {finding.remediation || "No remediation steps available"}
              </pre>
            </div>
          </Section>

          {/* CLI Commands */}
          {cliCommands.length > 0 && (
            <Section title="AWS CLI Commands">
              <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {cliCommands.map((cmd, i) => (
                  <CodeBlock
                    key={i}
                    code={cmd}
                    onCopy={() => copyToClipboard(cmd, `cli-${i}`)}
                    copied={copiedField === `cli-${i}`}
                  />
                ))}
              </div>
            </Section>
          )}

          {/* AI Analysis Badge */}
          {finding.severity !== "LOW" && (
            <div style={{
              marginTop: "24px",
              padding: "12px 16px",
              background: "linear-gradient(135deg, rgba(56, 189, 248, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%)",
              border: "1px solid rgba(56, 189, 248, 0.2)",
              borderRadius: "var(--radius-md)",
              display: "flex",
              alignItems: "center",
              gap: "12px",
            }}>
              <span style={{ fontSize: "20px" }}>🛠</span>
              <div>
                <div style={{
                  fontSize: "12px",
                  fontWeight: 600,
                  color: "var(--accent-cyan)",
                  marginBottom: "2px",
                }}>
                  AI-Powered Analysis
                </div>
                <div style={{
                  fontSize: "11px",
                  color: "var(--text-secondary)",
                  lineHeight: 1.5,
                }}>
                  This finding was analyzed using RAG (Retrieval-Augmented Generation) with compliance rules from CIS, NIST, and ISO 27001 frameworks.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes slideUp {
          from { 
            opacity: 0;
            transform: translateY(20px);
          }
          to { 
            opacity: 1;
            transform: translateY(0);
          }
        }
      `}</style>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: "24px" }}>
      <h3 style={{
        fontSize: "13px",
        fontWeight: 700,
        color: "var(--text-primary)",
        marginBottom: "12px",
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}>
        {title}
      </h3>
      {children}
    </div>
  );
}

function DetailRow({ label, value, copyable, onCopy, copied, badge }) {
  return (
    <div style={{
      display: "flex",
      padding: "10px 0",
      borderBottom: "1px solid var(--border)",
    }}>
      <div style={{
        width: "140px",
        fontSize: "11px",
        color: "var(--text-muted)",
        fontFamily: "var(--font-mono)",
        flexShrink: 0,
      }}>
        {label}
      </div>
      <div style={{
        flex: 1,
        fontSize: "12px",
        color: "var(--text-primary)",
        fontFamily: copyable ? "var(--font-mono)" : "inherit",
        wordBreak: "break-all",
        display: "flex",
        alignItems: "center",
        gap: "8px",
      }}>
        {badge ? (
          <span className={`badge ${value?.toUpperCase()}`}>
            {value}
          </span>
        ) : (
          <span>{value || "—"}</span>
        )}
        {copyable && value && (
          <button
            onClick={onCopy}
            style={{
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "2px 8px",
              fontSize: "10px",
              cursor: "pointer",
              color: copied ? "var(--low)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}
          >
            {copied ? "✓ Copied" : "Copy"}
          </button>
        )}
      </div>
    </div>
  );
}

function CodeBlock({ code, onCopy, copied }) {
  return (
    <div style={{
      position: "relative",
      background: "#0d1117",
      border: "1px solid #30363d",
      borderRadius: "var(--radius-md)",
      padding: "12px 16px",
    }}>
      <pre style={{
        margin: 0,
        fontSize: "11px",
        lineHeight: 1.6,
        color: "#c9d1d9",
        whiteSpace: "pre-wrap",
        wordBreak: "break-all",
        fontFamily: "var(--font-mono)",
        paddingRight: "60px",
      }}>
        {code}
      </pre>
      <button
        onClick={onCopy}
        style={{
          position: "absolute",
          top: "12px",
          right: "12px",
          background: "#21262d",
          border: "1px solid #30363d",
          borderRadius: "var(--radius-sm)",
          padding: "4px 10px",
          fontSize: "10px",
          cursor: "pointer",
          color: copied ? "#58a6ff" : "#8b949e",
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
        }}
      >
        {copied ? "✓ Copied" : "Copy"}
      </button>
    </div>
  );
}