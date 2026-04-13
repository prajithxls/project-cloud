import React, { useState } from "react";



// Official AWS Architecture Vector Icons
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

const SCANNERS = [
  {
    id: "s3",
    icon: <AwsIcon service="s3" />,
    label: "S3 Scanner",
    desc: "Evaluates S3 bucket policies, ACLs, and public access block configurations.",
    checks: ["Public access block", "Bucket ACLs", "Encryption settings"],
    color: "var(--high)",
    defaultEnabled: true,
  },
  {
    id: "ec2",
    icon: <AwsIcon service="ec2" />,
    label: "EC2 Scanner",
    desc: "Audits EC2 security groups for overly permissive inbound rules.",
    checks: ["Inbound 0.0.0.0/0 rules", "Port exposure", "Security group hygiene"],
    color: "var(--accent-cyan)",
    defaultEnabled: true,
  },
  {
    id: "iam",
    icon: <AwsIcon service="iam" />,
    label: "IAM Scanner",
    desc: "Checks IAM users and roles for missing MFA and over-privileged policies.",
    checks: ["MFA enforcement", "Access key rotation", "Role policy review"],
    color: "var(--info)",
    defaultEnabled: true,
  },
  {
    id: "lambda",
    icon: <AwsIcon service="lambda" />,
    label: "Lambda Scanner",
    desc: "Audits Lambda functions for deprecated runtimes, overly permissive roles, and missing encryption.",
    checks: ["Deprecated runtimes", "Overpermissive execution roles", "Unencrypted environment variables"],
    color: "var(--medium)",
    defaultEnabled: true,
  },
  {
    id: "rds",
    icon: <AwsIcon service="rds" />,
    label: "RDS Scanner",
    desc: "Inspects RDS instances and Aurora clusters for encryption, public access, and backup gaps.",
    checks: ["Storage encryption", "Public accessibility", "Deletion protection", "Backup retention ≥ 7 days"],
    color: "var(--critical)",
    defaultEnabled: true,
  },
  {
    id: "cloudtrail",
    icon: <AwsIcon service="cloudtrail" />,
    label: "CloudTrail Scanner",
    desc: "Verifies CloudTrail trails are active, multi-region, validated, and integrated with CloudWatch.",
    checks: ["Trail active & logging", "Multi-region coverage", "Log file validation", "CloudWatch integration"],
    color: "var(--low)",
    defaultEnabled: true,
  },
  {
    id: "apigw",
    icon: <AwsIcon service="apigw" />,
    label: "API Gateway Scanner",
    desc: "Audits REST and HTTP APIs for missing WAF, disabled logging, weak CORS, and no throttling.",
    checks: ["WAF association", "Access logging", "CORS wildcard origins", "Throttling limits"],
    color: "var(--accent-cyan)",
    defaultEnabled: true,
  }
];

const SETUP_STEPS = [
  {
    number: "01",
    title: "Sign in to the target AWS account",
    detail: "Log in to the AWS Management Console of the account you want to scan. You will need administrator access to create IAM roles.",
  },
  {
    number: "02",
    title: "Open the IAM console",
    detail: "Navigate to the IAM (Identity and Access Management) service. In the left sidebar, click on Roles, then click the Create role button.",
  },
  {
    number: "03",
    title: "Set up a trusted entity",
    detail: "Select AWS account as the trusted entity type. Choose Another AWS account and enter the 12-digit Account ID of the account where this scanner is hosted.",
  },
  {
    number: "04",
    title: "Attach the SecurityAudit policy",
    detail: "On the permissions step, search for and attach the AWS managed policy named SecurityAudit. This is a read-only policy that allows inspection of resource configurations — it cannot modify or delete anything.",
  },
  {
    number: "05",
    title: "Name the role exactly as shown",
    detail: "On the final step, set the role name to CrossAccountComplianceRole. This exact name is required — the scanner will look for this role when assuming access to the target account.",
  },
  {
    number: "06",
    title: "Save the role and enter the account ID below",
    detail: "Once the role is created, come back here and enter the 12-digit Account ID of the target account. The scanner will assume the role automatically and begin auditing.",
  },
];

export default function ScanPage({ scanning, scanLog, onScan, findingsCount, scannedAccountId }) {
  const [accountId, setAccountId] = useState("");
  const [accountIdError, setAccountIdError] = useState("");
  const [setupOpen, setSetupOpen] = useState(false);
  
  // Scanner selection state
  const [selectedScanners, setSelectedScanners] = useState(
    SCANNERS.reduce((acc, scanner) => {
      acc[scanner.id] = false;
      return acc;
    }, {})
  );

  const toggleScanner = (scannerId) => {
    setSelectedScanners(prev => ({
      ...prev,
      [scannerId]: !prev[scannerId]
    }));
  };

  const selectAll = () => {
    setSelectedScanners(
      SCANNERS.reduce((acc, scanner) => {
        acc[scanner.id] = true;
        return acc;
      }, {})
    );
  };

  const deselectAll = () => {
    setSelectedScanners(
      SCANNERS.reduce((acc, scanner) => {
        acc[scanner.id] = false;
        return acc;
      }, {})
    );
  };

  const selectedCount = Object.values(selectedScanners).filter(Boolean).length;

  const handleScan = () => {
    const trimmed = accountId.trim();
    if (!trimmed) {
      setAccountIdError("Account ID is required");
      return;
    }
    if (!/^\d{12}$/.test(trimmed)) {
      setAccountIdError("Account ID must be exactly 12 digits");
      return;
    }
    if (selectedCount === 0) {
      setAccountIdError("Please select at least one scanner");
      return;
    }
    setAccountIdError("");
    
    // Get list of selected scanner IDs
    const scannersToRun = Object.keys(selectedScanners).filter(key => selectedScanners[key]);
    
    // Pass both accountId and selected scanners to onScan
    onScan(trimmed, scannersToRun);
  };

  return (
    <div>
      {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">
            Compliance Scan
            <span
              style={{
                marginLeft: "12px",
                fontSize: "11px",
                fontWeight: 600,
                color: "var(--accent-cyan)",
                background: "var(--accent-cyan-dim)",
                padding: "3px 10px",
                borderRadius: "12px",
                fontFamily: "var(--font-mono)",
              }}
            >
              v2.0
            </span>
          </div>
          <div className="page-title-sub">
            Trigger targeted AWS resource audits across 7 available services
          </div>
        </div>
        {scannedAccountId && (
          <div
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 11,
              color: "var(--low)",
              background: "var(--bg-elevated)",
              border: "1px solid var(--low)44",
              padding: "6px 14px",
              borderRadius: "20px",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            <span style={{ color: "var(--low)" }}>✓</span>
            Last scanned: <span style={{ color: "var(--accent-cyan)" }}>{scannedAccountId}</span>
          </div>
        )}
      </div>

      {/* Cross-Account Scan Card */}
      <div className="card" style={{ marginBottom: 16, border: "1px solid #1a3a5c" }}>
        <div className="card-header">
          <span className="card-title">Cross-Account Scanning</span>
        </div>

        <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 20 }}>
          Enter the 12-digit Account ID of the AWS account you want to audit. The scanner will securely assume a
          read-only role in that account via AWS STS and run compliance checks across your selected services —
          without requiring any credentials from you.
        </p>

        {/* Account ID input */}
        <div style={{ display: "flex", gap: 12, alignItems: "flex-start", flexWrap: "wrap", marginBottom: 20 }}>
          <div style={{ flex: 1, minWidth: 260 }}>
            <div
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 10,
                color: "var(--text-muted)",
                marginBottom: 6,
                letterSpacing: "0.08em",
              }}
            >
              TARGET AWS ACCOUNT ID
            </div>
            <input
              type="text"
              placeholder="e.g. 123456789012"
              value={accountId}
              onChange={(e) => {
                setAccountId(e.target.value.replace(/\D/g, ""));
                setAccountIdError("");
              }}
              maxLength={12}
              disabled={scanning}
              style={{
                width: "100%",
                padding: "10px 14px",
                background: "var(--bg-base)",
                border: `1px solid ${accountIdError ? "var(--critical)" : "var(--border)"}`,
                borderRadius: "var(--radius-md)",
                color: "var(--text-primary)",
                fontFamily: "var(--font-mono)",
                fontSize: 15,
                letterSpacing: "0.1em",
                outline: "none",
                transition: "border-color 0.15s",
                boxSizing: "border-box",
              }}
              onFocus={(e) => (e.target.style.borderColor = "var(--accent-cyan)")}
              onBlur={(e) =>
                (e.target.style.borderColor = accountIdError ? "var(--critical)" : "var(--border)")
              }
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            {accountIdError && (
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  color: "var(--critical)",
                  marginTop: 6,
                }}
              >
                ⚠ {accountIdError}
              </div>
            )}
            {accountId.length > 0 && !accountIdError && (
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 11,
                  color: "var(--text-muted)",
                  marginTop: 6,
                }}
              >
                {accountId.length}/12 digits
                {accountId.length === 12 && (
                  <span style={{ color: "var(--low)", marginLeft: 8 }}>✓ Valid format</span>
                )}
              </div>
            )}
          </div>
          <button
            className="btn btn-primary"
            style={{ fontSize: 14, padding: "10px 28px", flexShrink: 0, marginTop: 20 }}
            onClick={handleScan}
            disabled={scanning || accountId.length !== 12 || selectedCount === 0}
          >
            {scanning ? (
              <>
                <div className="spinner dark" /> Scanning...
              </>
            ) : (
              <>⟳ Scan {selectedCount} Service{selectedCount !== 1 ? 's' : ''}</>
            )}
          </button>
        </div>

        <div style={{ display: "flex", gap: 20, flexWrap: "wrap", marginBottom: 20 }}>
          {[
            "STS AssumeRole integration",
            "Read-only SecurityAudit policy",
            "Findings isolated per account ID",
            "No credentials stored",
          ].map((f) => (
            <div
              key={f}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 6,
                fontSize: 12,
                color: "var(--text-secondary)",
              }}
            >
              <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span> {f}
            </div>
          ))}
        </div>

        {/* Setup instructions — collapsible */}
        <div
          style={{
            borderTop: "1px solid var(--border)",
            paddingTop: 16,
          }}
        >
          <button
            className="btn btn-ghost"
            style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 8, padding: "6px 0" }}
            onClick={() => setSetupOpen((o) => !o)}
          >
            <span
              style={{
                display: "inline-block",
                transform: setupOpen ? "rotate(90deg)" : "rotate(0deg)",
                transition: "transform 0.2s",
                fontSize: 10,
              }}
            >
              ▶
            </span>
            How to set up the target account — step by step guide
          </button>

          {setupOpen && (
            <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 0 }}>
              {SETUP_STEPS.map((step, i) => (
                <div
                  key={step.number}
                  style={{
                    display: "flex",
                    gap: 16,
                    paddingBottom: i < SETUP_STEPS.length - 1 ? 20 : 0,
                    position: "relative",
                  }}
                >
                  {/* Vertical connector line */}
                  {i < SETUP_STEPS.length - 1 && (
                    <div
                      style={{
                        position: "absolute",
                        left: 19,
                        top: 38,
                        bottom: 0,
                        width: 1,
                        background: "var(--border)",
                      }}
                    />
                  )}

                  {/* Step number circle */}
                  <div
                    style={{
                      flexShrink: 0,
                      width: 38,
                      height: 38,
                      borderRadius: "50%",
                      background: "var(--bg-elevated)",
                      border: "1px solid var(--accent-cyan)44",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontFamily: "var(--font-mono)",
                      fontSize: 11,
                      fontWeight: 700,
                      color: "var(--accent-cyan)",
                      zIndex: 1,
                    }}
                  >
                    {step.number}
                  </div>

                  <div style={{ paddingTop: 8 }}>
                    <div
                      style={{
                        fontSize: 13,
                        fontWeight: 600,
                        color: "var(--text-primary)",
                        marginBottom: 4,
                      }}
                    >
                      {step.title}
                    </div>
                    <div
                      style={{
                        fontSize: 12,
                        color: "var(--text-secondary)",
                        lineHeight: 1.65,
                      }}
                    >
                      {step.detail}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Scan Log */}
      {scanLog.length > 0 && (
        <div className="scan-log">
          {scanLog.map((entry, i) => (
            <div key={i} className="scan-log-entry">
              <span className="time">[{entry.time}]</span>
              <span className={entry.type}>{entry.msg}</span>
            </div>
          ))}
        </div>
      )}

      {/* Scanner Selection */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ 
          display: "flex", 
          justifyContent: "space-between", 
          alignItems: "center", 
          marginBottom: 12 
        }}>
          <h3 style={{
            fontSize: 14,
            fontWeight: 700,
            color: "var(--text-primary)",
            margin: 0,
          }}>
            Select Services to Scan
            <span style={{
              marginLeft: 12,
              fontSize: 11,
              fontWeight: 600,
              color: selectedCount > 0 ? "var(--accent-cyan)" : "var(--text-muted)",
              fontFamily: "var(--font-mono)",
            }}>
              {selectedCount}/{SCANNERS.length} selected
            </span>
          </h3>
         <div style={{ display: "flex", gap: 10 }}>
            <button
              style={{ 
                fontSize: 13, 
                fontWeight: 600,
                padding: "6px 16px",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                color: "var(--text-primary)",
                cursor: scanning ? "not-allowed" : "pointer",
                transition: "all 0.2s"
              }}
              onClick={selectAll}
              disabled={scanning}
            >
              Select All
            </button>
            <button
              style={{ 
                fontSize: 13, 
                fontWeight: 600,
                padding: "6px 16px",
                background: "var(--bg-elevated)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                color: "var(--text-primary)",
                cursor: scanning ? "not-allowed" : "pointer",
                transition: "all 0.2s"
              }}
              onClick={deselectAll}
              disabled={scanning}
            >
              Deselect All
            </button>
          </div>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: 16,
          }}
        >
          {SCANNERS.map((scanner) => {
            const isSelected = selectedScanners[scanner.id];
            return (
              <div
                key={scanner.id}
                className="card"
                onClick={() => !scanning && toggleScanner(scanner.id)}
                style={{
                  borderTop: `2px solid ${isSelected ? scanner.color : "var(--border)"}`,
                  cursor: scanning ? "not-allowed" : "pointer",
                  opacity: isSelected ? 1 : 0.6,
                  transition: "all 0.2s",
                  position: "relative",
                }}
                onMouseEnter={(e) => {
                  if (!scanning) e.currentTarget.style.opacity = 1;
                }}
                onMouseLeave={(e) => {
                  if (!scanning && !isSelected) e.currentTarget.style.opacity = 0.6;
                }}
              >
                {/* Checkbox */}
                <div
                  style={{
                    position: "absolute",
                    top: 12,
                    right: 12,
                    width: 20,
                    height: 20,
                    borderRadius: "4px",
                    border: `2px solid ${isSelected ? scanner.color : "var(--border)"}`,
                    background: isSelected ? scanner.color : "transparent",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "white",
                    fontSize: 12,
                    fontWeight: 700,
                  }}
                >
                  {isSelected && "✓"}
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 12 }}>
                  <div
                    style={{
                      width: 44,
                      height: 44,
                      background: `${scanner.color}18`,
                      border: `1px solid ${scanner.color}33`,
                      borderRadius: "var(--radius-md)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      fontSize: 22,
                      color: scanner.color,
                    }}
                  >
                    {scanner.icon}
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: 15, color: "var(--text-primary)" }}>
                      {scanner.label}
                    </div>
                    <div
                      style={{
                        fontFamily: "var(--font-mono)",
                        fontSize: 10,
                        color: isSelected ? scanner.color : "var(--text-muted)",
                        letterSpacing: "0.06em",
                      }}
                    >
                      {isSelected ? "SELECTED" : "CLICK TO SELECT"}
                    </div>
                  </div>
                </div>
                <p
                  style={{
                    fontSize: 13,
                    color: "var(--text-secondary)",
                    lineHeight: 1.5,
                    marginBottom: 14,
                  }}
                >
                  {scanner.desc}
                </p>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {scanner.checks.map((check) => (
                    <div
                      key={check}
                      style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}
                    >
                      <span style={{ color: isSelected ? "var(--low)" : "var(--text-muted)", fontSize: 10 }}>
                        ✓
                      </span>
                      <span style={{ color: "var(--text-secondary)" }}>{check}</span>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Current State */}
      <div className="card" style={{ marginTop: 16 }}>
        <div className="card-header">
          <span className="card-title">System Information</span>
        </div>
        <div style={{ display: "flex", gap: 40, flexWrap: "wrap" }}>
          {[
            { label: "Version", value: "v2.0", color: "var(--accent-cyan)" },
            { label: "AI Engine", value: "RAG-Powered", color: "var(--info)" },
            { label: "Findings Loaded", value: findingsCount || "—", color: "var(--accent-cyan)" },
            { label: "Target Account", value: scannedAccountId || "None", color: scannedAccountId ? "var(--low)" : "var(--text-muted)" },
            { label: "Scan Region", value: "ap-south-1", color: "var(--text-secondary)" },
            { label: "Scanners Available", value: "7", color: "var(--low)" },
            { label: "Storage", value: "DynamoDB + S3", color: "var(--low)" },
            { label: "Knowledge Base", value: "Pinecone + Groq", color: "var(--info)" },
          ].map((item) => (
            <div key={item.label}>
              <div
                style={{
                  fontFamily: "var(--font-mono)",
                  fontSize: 10,
                  color: "var(--text-muted)",
                  letterSpacing: "0.08em",
                  marginBottom: 4,
                }}
              >
                {item.label.toUpperCase()}
              </div>
              <div
                style={{
                  fontFamily: "var(--font-display)",
                  fontSize: 18,
                  fontWeight: 700,
                  color: item.color,
                }}
              >
                {item.value}
              </div>
            </div>
          ))}
        </div>

        {/* RAG Integration Banner */}
        <div
          style={{
            marginTop: "20px",
            padding: "12px 16px",
            background: "linear-gradient(135deg, rgba(56, 189, 248, 0.08) 0%, rgba(99, 102, 241, 0.08) 100%)",
            border: "1px solid rgba(56, 189, 248, 0.2)",
            borderRadius: "var(--radius-md)",
            display: "flex",
            alignItems: "center",
            gap: "12px",
          }}
        >
          <span style={{ fontSize: "24px" }}>🛠</span>
          <div style={{ flex: 1 }}>
            <div
              style={{
                fontSize: "13px",
                fontWeight: 700,
                color: "var(--accent-cyan)",
                marginBottom: "4px",
              }}
            >
              AI-Powered Security Analysis
            </div>
            <div
              style={{
                fontSize: "12px",
                color: "var(--text-secondary)",
                lineHeight: 1.6,
              }}
            >
              This scanner uses <strong style={{ color: "var(--text-primary)" }}>Retrieval-Augmented
              Generation (RAG)</strong> with Pinecone vector database and Groq LLM to analyze findings against
              compliance frameworks (CIS AWS, NIST, ISO 27001) and generate intelligent remediation steps with
              AWS CLI commands.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}