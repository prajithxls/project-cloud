// ============================================================
// Severity helpers
// ============================================================
export const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

export const getSeverityColor = (severity) => {
  const map = {
    CRITICAL: "var(--critical)",
    HIGH: "var(--high)",
    MEDIUM: "var(--medium)",
    LOW: "var(--low)",
  };
  return map[severity?.toUpperCase()] || "var(--text-muted)";
};

export const getRiskClass = (score) => {
  const n = parseFloat(score) || 0;
  if (n >= 8) return "high";
  if (n >= 5) return "medium";
  return "low";
};

// ============================================================
// Stats computation
// ============================================================
export const computeStats = (findings) => {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  const scanners = {};
  const accounts = new Set();
  let totalRisk = 0;

  for (const f of findings) {
    const sev = f.severity?.toUpperCase();
    if (sev in counts) counts[sev]++;
    if (f.scanner) scanners[f.scanner] = (scanners[f.scanner] || 0) + 1;
    if (f.accountId) accounts.add(f.accountId);
    totalRisk += parseFloat(f.riskScore) || 0;
  }

  const avgRisk = findings.length ? (totalRisk / findings.length).toFixed(1) : 0;
  const openCount = findings.filter((f) => f.status === "OPEN").length;
  const resolvedCount = findings.filter((f) => f.status === "RESOLVED").length;

  return {
    total: findings.length,
    ...counts,
    scanners,
    accounts: accounts.size,
    avgRisk,
    openCount,
    resolvedCount,
  };
};

// ============================================================
// Compliance score (0-100)
// ============================================================
// ── src/utils/helpers.js ─────────────────────────────────────────────────────

export function computeComplianceScore(findings) {
  // If there are no findings, the environment is perfectly compliant
  if (!findings || findings.length === 0) return 100; 

  let penalty = 0;

  findings.forEach(finding => {
    // Heavily penalize severe issues based on industry standards
    switch (finding.severity?.toUpperCase()) {
      case 'CRITICAL': 
        penalty += 25; 
        break; 
      case 'HIGH':     
        penalty += 10; 
        break;
      case 'MEDIUM':   
        penalty += 3;  
        break;
      case 'LOW':      
        penalty += 1;  
        break;
      default:         
        penalty += 0;
    }
  });

  // Calculate final score, ensuring it never drops below 0
  const finalScore = 100 - penalty;
  return Math.max(0, finalScore);
}

// (Leave your other helper functions, like computeStats, exactly as they are!)

// ============================================================
// Date formatting
// ============================================================
export const formatDate = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleDateString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  });
};

export const formatDateTime = (iso) => {
  if (!iso) return "—";
  const d = new Date(iso);
  return (
    d.toLocaleDateString("en-IN", { day: "2-digit", month: "short", year: "numeric" }) +
    " " +
    d.toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit" })
  );
};

export const timeAgo = (date) => {
  if (!date) return "";
  const diff = Math.floor((Date.now() - new Date(date)) / 1000);
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
};

// ============================================================
// Truncation
// ============================================================
export const truncate = (str, len = 30) => {
  if (!str) return "—";
  return str.length > len ? str.slice(0, len) + "…" : str;
};

// ============================================================
// Chart colours (matching CSS vars)
// ============================================================
export const CHART_COLORS = {
  CRITICAL: "#ff3b5c",
  HIGH: "#ff6b2b",
  MEDIUM: "#ffb800",
  LOW: "#00d88a",
};

export const SCANNER_COLORS = ["#00d4ff", "#6b8cff", "#ff6b2b", "#00d88a", "#ffb800"];
