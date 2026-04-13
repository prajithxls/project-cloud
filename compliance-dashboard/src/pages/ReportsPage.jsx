import React, { useState } from "react";
import { getReportDownloadUrl, refreshFindings } from "../services/api";

// ── Load jsPDF ────────────────────────────────────────────────────────────────
function loadJsPDF() {
  return new Promise((resolve, reject) => {
    if (window.jspdf?.jsPDF) { resolve(window.jspdf.jsPDF); return; }
    const script = document.createElement("script");
    script.src = "https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js";
    script.onload = () => {
      const ctor = window.jspdf?.jsPDF;
      ctor ? resolve(ctor) : reject(new Error("jsPDF not found"));
    };
    script.onerror = () => reject(new Error("Failed to load jsPDF"));
    document.head.appendChild(script);
  });
}

// ── PDF — updated for all 7 scanners ─────────────────────────────────────────
async function generatePDF(findings, scannedAccountId) {
  const jsPDF  = await loadJsPDF();
  const doc    = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });
  const W      = 210;
  const margin = 16;
  const cW     = W - margin * 2;
  let y        = 0;

  const now     = new Date();
  const dateStr = now.toLocaleDateString("en-GB", { day: "2-digit", month: "long", year: "numeric" });
  const timeStr = now.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" });
  const accountId = scannedAccountId || findings[0]?.accountId || "N/A";

  const counts = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
    HIGH:     findings.filter(f => f.severity === "HIGH").length,
    MEDIUM:   findings.filter(f => f.severity === "MEDIUM").length,
    LOW:      findings.filter(f => f.severity === "LOW").length,
  };

  const ALL_SCANNERS = ["S3", "EC2", "IAM", "LAMBDA", "RDS", "CLOUDTRAIL", "APIGW"];

  // ── helpers ────────────────────────────────────────────────────────────────
  const addPageIfNeeded = (needed = 18) => {
    if (y + needed > 280) {
      doc.addPage();
      doc.setFillColor(6, 15, 26); doc.rect(0, 0, W, 297, "F");
      doc.setFillColor(8, 20, 32); doc.rect(0, 0, W, 10, "F");
      doc.setFillColor(0, 212, 255); doc.rect(0, 10, W, 0.8, "F");
      doc.setFont("helvetica", "italic"); doc.setFontSize(8);
      doc.setTextColor(80, 110, 140);
      doc.text("Cloud Security Compliance & Audit Management System — Continued", margin, 7);
      y = 18;
    }
  };

  // ── Page 1 background ─────────────────────────────────────────────────────
  doc.setFillColor(6, 15, 26); doc.rect(0, 0, W, 297, "F");

  // ── Header ────────────────────────────────────────────────────────────────
  doc.setFillColor(8, 20, 32); doc.rect(0, 0, W, 54, "F");
  doc.setFillColor(0, 212, 255); doc.rect(0, 54, W, 1.5, "F");

  doc.setFont("helvetica", "bold"); doc.setFontSize(19); doc.setTextColor(232, 244, 253);
  doc.text("Cloud Security Compliance", margin, 18);
  doc.text("and Audit Management System", margin, 28);

  doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(122, 154, 184);
  doc.text("AUTOMATED COMPLIANCE AUDIT REPORT", margin, 38);
  doc.text(`Generated: ${dateStr} at ${timeStr}`, margin, 45);

  // Account badge top-right
  doc.setFillColor(14, 36, 58);
  doc.roundedRect(W - 78, 10, 64, 20, 3, 3, "F");
  doc.setFontSize(8); doc.setTextColor(0, 212, 255); doc.setFont("helvetica", "bold");
  doc.text("AWS ACCOUNT", W - 46, 18, { align: "center" });
  doc.setTextColor(232, 244, 253); doc.setFont("helvetica", "normal"); doc.setFontSize(9);
  doc.text(accountId, W - 46, 25, { align: "center" });

  y = 64;

  // ── Executive Summary ─────────────────────────────────────────────────────
  doc.setFillColor(14, 26, 40); doc.rect(0, y - 4, W, 12, "F");
  doc.setFont("helvetica", "bold"); doc.setFontSize(12); doc.setTextColor(232, 244, 253);
  doc.text("Executive Summary", margin, y + 4);
  y += 14;

  doc.setFont("helvetica", "normal"); doc.setFontSize(9.5); doc.setTextColor(100, 130, 155);
  const critHigh  = counts.CRITICAL + counts.HIGH;
  const summary   = `This automated compliance report covers AWS account ${accountId}, scanned across ` +
    `${ALL_SCANNERS.length} services: S3, EC2, IAM, Lambda, RDS, CloudTrail, and API Gateway. ` +
    `${findings.length} finding${findings.length !== 1 ? "s" : ""} were identified in total. ` +
    (critHigh > 0
      ? `${critHigh} CRITICAL/HIGH finding${critHigh !== 1 ? "s" : ""} require immediate remediation.`
      : "No critical or high severity issues were detected.");
  const summaryLines = doc.splitTextToSize(summary, cW);
  doc.text(summaryLines, margin, y);
  y += summaryLines.length * 5 + 8;

  // ── Severity summary boxes ────────────────────────────────────────────────
  const sevBoxes = [
    { label: "CRITICAL", count: counts.CRITICAL, r: 220, g: 40,  b: 80  },
    { label: "HIGH",     count: counts.HIGH,     r: 255, g: 140, b: 0   },
    { label: "MEDIUM",   count: counts.MEDIUM,   r: 255, g: 190, b: 0   },
    { label: "LOW",      count: counts.LOW,       r: 0,   g: 200, b: 140 },
    { label: "TOTAL",    count: findings.length,  r: 0,   g: 180, b: 220 },
  ];
  const bW = cW / sevBoxes.length - 2.5;
  sevBoxes.forEach((box, i) => {
    const bx = margin + i * (bW + 3.1);
    doc.setFillColor(14, 26, 40); doc.roundedRect(bx, y, bW, 22, 3, 3, "F");
    doc.setDrawColor(box.r, box.g, box.b); doc.setLineWidth(0.5);
    doc.roundedRect(bx, y, bW, 22, 3, 3, "S");
    doc.setFont("helvetica", "bold"); doc.setFontSize(16);
    doc.setTextColor(box.r, box.g, box.b);
    doc.text(String(box.count), bx + bW / 2, y + 13, { align: "center" });
    doc.setFont("helvetica", "normal"); doc.setFontSize(7); doc.setTextColor(80, 110, 140);
    doc.text(box.label, bx + bW / 2, y + 19, { align: "center" });
  });
  y += 30;

  // ── Scanner Breakdown table (7 scanners) ──────────────────────────────────
  addPageIfNeeded(20);
  doc.setFillColor(14, 26, 40); doc.rect(0, y - 3, W, 10, "F");
  doc.setFont("helvetica", "bold"); doc.setFontSize(11); doc.setTextColor(232, 244, 253);
  doc.text("Scanner Breakdown", margin, y + 4);
  y += 12;

  const tHeaders  = ["Scanner", "Total", "Critical", "High", "Medium", "Low"];
  const tColWidths = [32, 22, 24, 22, 25, 22];
  let cx = margin;
  doc.setFillColor(20, 40, 60); doc.rect(margin, y - 4, cW, 9, "F");
  tHeaders.forEach((h, i) => {
    doc.setFont("helvetica", "bold"); doc.setFontSize(8); doc.setTextColor(0, 212, 255);
    doc.text(h, cx + 2, y + 2); cx += tColWidths[i];
  });
  y += 9;

  ALL_SCANNERS.forEach((scanner, si) => {
    const sf  = findings.filter(f => f.scanner === scanner);
    const row = [
      scanner, sf.length,
      sf.filter(f => f.severity === "CRITICAL").length,
      sf.filter(f => f.severity === "HIGH").length,
      sf.filter(f => f.severity === "MEDIUM").length,
      sf.filter(f => f.severity === "LOW").length,
    ];
    doc.setFillColor(
      si % 2 === 0 ? 12 : 15,
      si % 2 === 0 ? 22 : 28,
      si % 2 === 0 ? 36 : 44,
    );
    doc.rect(margin, y - 4, cW, 8, "F");
    cx = margin;
    row.forEach((val, i) => {
      doc.setFont("helvetica", i === 0 ? "bold" : "normal");
      doc.setFontSize(9);
      doc.setTextColor(i === 0 ? 232 : 122, i === 0 ? 244 : 154, i === 0 ? 253 : 184);
      doc.text(String(val), cx + 2, y + 1); cx += tColWidths[i];
    });
    y += 9;
  });
  y += 8;

  // ── Findings Detail ───────────────────────────────────────────────────────
  addPageIfNeeded(20);
  doc.setFillColor(14, 26, 40); doc.rect(0, y - 3, W, 10, "F");
  doc.setFont("helvetica", "bold"); doc.setFontSize(11); doc.setTextColor(232, 244, 253);
  doc.text("Findings Detail", margin, y + 4);
  y += 13;

  const sevColors = { CRITICAL: [220, 40, 80], HIGH: [255, 140, 0], MEDIUM: [255, 190, 0], LOW: [0, 200, 140] };
  const sevOrder  = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted    = [...findings].sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

  sorted.forEach(f => {
    doc.setFont("helvetica", "italic"); doc.setFontSize(7.5);
    const remLines  = doc.splitTextToSize("→ " + (f.remediation || ""), cW - 12);
    const cardH     = 30 + remLines.length * 4;
    addPageIfNeeded(cardH + 4);

    const [sr, sg, sb] = sevColors[f.severity] || [122, 154, 184];
    doc.setFillColor(12, 22, 34); doc.roundedRect(margin, y, cW, cardH, 2, 2, "F");
    doc.setFillColor(sr, sg, sb); doc.roundedRect(margin, y, 3, cardH, 1, 1, "F");
    doc.setFillColor(Math.round(sr * 0.14), Math.round(sg * 0.14), Math.round(sb * 0.14));
    doc.roundedRect(margin + 6, y + 3, 22, 7, 1, 1, "F");

    doc.setFont("helvetica", "bold"); doc.setFontSize(7); doc.setTextColor(sr, sg, sb);
    doc.text(f.severity || "", margin + 17, y + 8, { align: "center" });
    doc.setFontSize(11);
    doc.text(parseFloat(f.riskScore || 0).toFixed(1), margin + 32, y + 8.5);

    doc.setFontSize(9); doc.setTextColor(232, 244, 253);
    const titleLines = doc.splitTextToSize(f.title || "", cW - 58);
    doc.text(titleLines[0], margin + 50, y + 8);

    doc.setFont("helvetica", "normal"); doc.setFontSize(7.5); doc.setTextColor(80, 110, 140);
    doc.text(`${f.resourceType || ""} · ${(f.resourceId || "").slice(-52)}`, margin + 6, y + 17);

    doc.setFontSize(7); doc.setFont("helvetica", "bold"); doc.setTextColor(0, 180, 220);
    doc.text(`[${f.scanner || ""}]`, margin + 6, y + 24);
    doc.setFont("helvetica", "normal"); doc.setTextColor(60, 90, 110);
    doc.text(f.timestamp ? new Date(f.timestamp).toLocaleString() : "", margin + 22, y + 24);
    doc.setTextColor(60, 100, 130);
    doc.text((f.complianceFramework || []).slice(0, 3).join("  ·  "), W - margin - 2, y + 24, { align: "right" });

    doc.setFont("helvetica", "italic"); doc.setFontSize(7.5); doc.setTextColor(0, 160, 120);
    doc.text(remLines, margin + 6, y + 31);

    y += cardH + 4;
  });

  // ── Footer on last page ───────────────────────────────────────────────────
  addPageIfNeeded(18);
  y += 4;
  doc.setFillColor(8, 20, 32); doc.rect(0, y, W, 16, "F");
  doc.setFillColor(0, 212, 255); doc.rect(0, y, W, 0.8, "F");
  doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(80, 110, 140);
  doc.text("Cloud Security Compliance and Audit Management System", margin, y + 7);
  doc.text(`Report generated on ${dateStr}  ·  ${findings.length} findings  ·  Account: ${accountId}`, margin, y + 13);

  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal"); doc.setFontSize(7); doc.setTextColor(60, 90, 110);
    doc.text(`Page ${p} of ${totalPages}`, W - margin, 292, { align: "right" });
  }

  const filename = `CSC-AMS_Report_${accountId}_${now.toISOString().slice(0, 10)}.pdf`;
  doc.save(filename);
  return filename;
}

// ── Stat mini-card ────────────────────────────────────────────────────────────
function StatMini({ label, value, color, sub }) {
  return (
    <div style={{
      background:   "var(--bg-elevated)",
      border:       "1px solid var(--border)",
      borderRadius: "var(--radius-md)",
      padding:      "14px 18px",
      minWidth:     100,
      flex:         1,
    }}>
      <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontFamily: "var(--font-display)", fontSize: 26, fontWeight: 800, color, lineHeight: 1 }}>
        {value}
      </div>
      {sub && (
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
          {sub}
        </div>
      )}
    </div>
  );
}

// ── Scanner coverage bar ──────────────────────────────────────────────────────
function ScannerCoverage({ findings }) {
  const scanners = ["S3", "EC2", "IAM", "LAMBDA", "RDS", "CLOUDTRAIL", "APIGW"];
  const counts   = {};
  for (const f of findings) {
    if (f.scanner) counts[f.scanner] = (counts[f.scanner] || 0) + 1;
  }
  const max = Math.max(...Object.values(counts), 1);

  const colors = {
    S3: "var(--high)", EC2: "var(--accent-cyan)", IAM: "var(--info)",
    LAMBDA: "var(--medium)", RDS: "var(--critical)", CLOUDTRAIL: "var(--low)", APIGW: "var(--accent-cyan)",
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {scanners.map(sc => {
        const count = counts[sc] || 0;
        const pct   = (count / max) * 100;
        return (
          <div key={sc} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{
              fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
              color: colors[sc] || "var(--accent-cyan)",
              width: 88, flexShrink: 0,
            }}>
              {sc}
            </div>
            <div style={{ flex: 1, height: 6, background: "var(--bg-base)", borderRadius: 3 }}>
              <div style={{
                width:      `${pct}%`,
                height:     "100%",
                background: colors[sc] || "var(--accent-cyan)",
                borderRadius: 3,
                transition: "width 0.6s ease",
                minWidth:   count > 0 ? 6 : 0,
              }} />
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", width: 28, textAlign: "right", flexShrink: 0 }}>
              {count}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Severity ring (mini SVG) ──────────────────────────────────────────────────
function SeverityRing({ findings }) {
  const total    = findings.length;
  const critical = findings.filter(f => f.severity === "CRITICAL").length;
  const high     = findings.filter(f => f.severity === "HIGH").length;
  const medium   = findings.filter(f => f.severity === "MEDIUM").length;
  const low      = total - critical - high - medium;

  const segs = [
    { count: critical, color: "#dc2850", label: "Critical" },
    { count: high,     color: "#ff8c00", label: "High"     },
    { count: medium,   color: "#ffbe00", label: "Medium"   },
    { count: low,      color: "#00c88c", label: "Low"      },
  ].filter(s => s.count > 0);

  if (total === 0) return (
    <div style={{ textAlign: "center", color: "var(--text-muted)", fontFamily: "var(--font-mono)", fontSize: 12, padding: "20px 0" }}>
      No findings
    </div>
  );

  const r   = 40;
  const cx_ = 56;
  const cy_ = 56;
  const circ = 2 * Math.PI * r;

  let offset = 0;
  const slices = segs.map(s => {
    const len   = (s.count / total) * circ;
    const slice = { ...s, len, offset };
    offset += len;
    return slice;
  });

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <svg width={112} height={112} viewBox="0 0 112 112">
        <circle cx={cx_} cy={cy_} r={r} fill="none" stroke="var(--bg-base)" strokeWidth={14} />
        {slices.map((s, i) => (
          <circle key={i} cx={cx_} cy={cy_} r={r} fill="none"
            stroke={s.color} strokeWidth={14}
            strokeDasharray={`${s.len} ${circ - s.len}`}
            strokeDashoffset={-s.offset}
            transform={`rotate(-90 ${cx_} ${cy_})`}
            style={{ transition: "stroke-dasharray 0.5s ease" }}
          />
        ))}
        <text x={cx_} y={cy_ - 5} textAnchor="middle" fill="#e8f4fd" fontSize="18" fontWeight="800" fontFamily="sans-serif">
          {total}
        </text>
        <text x={cx_} y={cy_ + 10} textAnchor="middle" fill="#4a7a9b" fontSize="8" fontFamily="monospace">
          FINDINGS
        </text>
      </svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {segs.map(s => (
          <div key={s.label} style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: s.color, flexShrink: 0 }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)" }}>
              {s.label}
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 700, color: s.color, marginLeft: "auto" }}>
              {s.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Format file size ──────────────────────────────────────────────────────────
function estimatePDFPages(count) {
  return Math.max(2, Math.ceil(count / 8) + 2);
}

// ── Main component ────────────────────────────────────────────────────────────
export default function ReportsPage({ findings, addToast, scannedAccountId }) {
  const [currentReport,  setCurrentReport]  = useState(null);
  const [generating,     setGenerating]     = useState(false);
  const [generatingPDF,  setGeneratingPDF]  = useState(false);
  const [pdfProgress,    setPdfProgress]    = useState("");

  const noScanYet = !scannedAccountId || findings.length === 0;

  const counts = {
    CRITICAL: findings.filter(f => f.severity === "CRITICAL").length,
    HIGH:     findings.filter(f => f.severity === "HIGH").length,
    MEDIUM:   findings.filter(f => f.severity === "MEDIUM").length,
    LOW:      findings.filter(f => f.severity === "LOW").length,
    OPEN:     findings.filter(f => f.status === "OPEN").length,
  };

  const handleGenerateCSV = async () => {
    if (noScanYet) { addToast("Run a scan first.", "error"); return; }
    setGenerating(true);
    try {
      const res      = await refreshFindings(scannedAccountId);
      const filename = res.data.csvFile || `compliance_${scannedAccountId}_generated.csv`;
      setCurrentReport({ filename, generatedAt: new Date() });
      addToast("CSV report generated successfully.", "success");
    } catch (err) {
      addToast("Failed to generate CSV: " + err.message, "error");
    } finally {
      setGenerating(false);
    }
  };

  const handleGeneratePDF = async () => {
    if (noScanYet) { addToast("Run a scan first.", "error"); return; }
    setGeneratingPDF(true);
    setPdfProgress("Loading PDF engine...");
    try {
      setPdfProgress("Building report layout...");
      await new Promise(r => setTimeout(r, 200));
      setPdfProgress(`Rendering ${findings.length} findings...`);
      const filename = await generatePDF(findings, scannedAccountId);
      setPdfProgress("");
      addToast(`PDF downloaded: ${filename}`, "success");
    } catch (err) {
      addToast("PDF generation failed: " + err.message, "error");
      setPdfProgress("");
    } finally {
      setGeneratingPDF(false);
    }
  };

  const handleDownloadCSV = () => {
    if (!currentReport) return;
    const a    = document.createElement("a");
    a.href     = getReportDownloadUrl(currentReport.filename);
    a.download = currentReport.filename;
    a.click();
    addToast(`Downloading ${currentReport.filename}`, "info");
  };

  // ── Empty state ───────────────────────────────────────────────────────────
  if (noScanYet) {
    return (
      <div>
        <div className="page-header">
          <div>
            <div className="page-title">Compliance Reports</div>
            <div className="page-title-sub">Generate audit-ready PDF and CSV exports</div>
          </div>
        </div>
        <div style={{
          display: "flex", flexDirection: "column", alignItems: "center",
          justifyContent: "center", padding: "80px 20px", gap: 16, textAlign: "center",
        }}>
          <div style={{
            width: 68, height: 68, borderRadius: "50%",
            background: "var(--bg-elevated)", border: "1px solid var(--border)",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 30,
          }}>
            🗐
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, color: "var(--text-primary)" }}>
            No reports available yet
          </div>
          <div style={{ fontSize: 13, color: "var(--text-secondary)", maxWidth: 440, lineHeight: 1.7 }}>
            Complete a compliance scan on the{" "}
            <strong style={{ color: "var(--accent-cyan)" }}>Scan</strong> page first.
            Once findings are loaded, PDF and CSV reports will be generated scoped to that account.
          </div>
        </div>
      </div>
    );
  }

  // ── Reports available ─────────────────────────────────────────────────────
  return (
    <div>
      {/* Header */}
    {/* Header */}
      <div className="page-header">
        <div>
          <div className="page-title">Compliance Reports</div>
          <div className="page-title-sub">
            Audit reports for account{" "}
            <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
              {scannedAccountId}
            </span>
          </div>
        </div>
      </div>

      {/* ── Overview panel ─────────────────────────────────────────────── */}
      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-header">
          <span className="card-title">Scan Overview</span>
          <span style={{
            fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)",
            background: "var(--bg-elevated)", border: "1px solid var(--border)",
            padding: "3px 10px", borderRadius: "20px",
          }}>
            {scannedAccountId}
          </span>
        </div>

        {/* Top stats row */}
        <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
          <StatMini label="TOTAL FINDINGS" value={findings.length} color="var(--accent-cyan)" sub={`${counts.OPEN} open`} />
          <StatMini label="CRITICAL"       value={counts.CRITICAL} color="var(--critical)"    sub="Immediate action" />
          <StatMini label="HIGH"           value={counts.HIGH}     color="var(--high)"        sub="Urgent review" />
          <StatMini label="MEDIUM"         value={counts.MEDIUM}   color="var(--medium)"      sub="Plan remediation" />
          <StatMini label="LOW"            value={counts.LOW}      color="var(--low)"         sub="Monitor" />
        </div>

        {/* Two-column detail */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
          {/* Severity ring */}
          <div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 12 }}>
              SEVERITY DISTRIBUTION
            </div>
            <SeverityRing findings={findings} />
          </div>

          {/* Scanner coverage */}
          <div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 12 }}>
              FINDINGS BY SCANNER
            </div>
            <ScannerCoverage findings={findings} />
          </div>
        </div>
      </div>

      {/* ── PDF Report Card ─────────────────────────────────────────────── */}
      <div className="card" style={{
        marginBottom: 16,
        borderTop: "2px solid var(--accent-cyan)",
        position: "relative",
        overflow: "hidden",
      }}>
        {/* Background accent */}
        <div style={{
          position: "absolute", top: 0, right: 0,
          width: 180, height: "100%",
          background: "linear-gradient(270deg, var(--accent-cyan)06, transparent)",
          pointerEvents: "none",
        }} />

        <div className="card-header">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36,
              background: "rgba(0,212,255,0.08)",
              border: "1px solid rgba(0,212,255,0.2)",
              borderRadius: "var(--radius-md)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18,
            }}>
              🗐
            </div>
            <div>
              <span className="card-title">PDF Audit Report</span>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                ~{estimatePDFPages(findings.length)} pages · Dark-themed · Print-ready
              </div>
            </div>
          </div>
          <span style={{
            fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
            color: "var(--low)", background: "rgba(0,200,140,0.08)",
            border: "1px solid rgba(0,200,140,0.25)", padding: "3px 10px", borderRadius: "20px",
          }}>
            RECOMMENDED
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 20, flexWrap: "wrap" }}>
          <div style={{ flex: 1 }}>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7, marginBottom: 14 }}>
              A fully formatted compliance report for account{" "}
              <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                {scannedAccountId}
              </span>{" "}
              covering all <strong style={{ color: "var(--text-primary)" }}>7 scanners</strong> —
              includes executive summary, severity breakdown, per-scanner analysis, full findings
              with remediation guidance, and AWS CLI fix commands.
            </p>
            <div style={{ display: "flex", flexWrap: "wrap", gap: "8px 20px" }}>
              {[
                "Executive summary",
                "Severity breakdown",
                "All 7 scanners covered",
                "Full findings detail",
                "Compliance frameworks",
                "AI remediation guidance",
              ].map(item => (
                <div key={item} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                  <span style={{ color: "var(--low)", fontSize: 10 }}>✓</span> {item}
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 10, flexShrink: 0 }}>
            <button
              className="btn btn-primary"
              style={{ fontSize: 14, padding: "12px 28px", minWidth: 220 }}
              onClick={handleGeneratePDF}
              disabled={generatingPDF}
            >
              {generatingPDF
                ? <><div className="spinner dark" /> {pdfProgress || "Building..."}</>
                : `↓ Download PDF (${findings.length} findings)`}
            </button>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", textAlign: "right" }}>
              Generates instantly in your browser · No upload required
            </div>
          </div>
        </div>
      </div>

      {/* ── CSV Report Card ─────────────────────────────────────────────── */}
      <div className="card" style={{ borderTop: "2px solid var(--border)" }}>
        <div className="card-header">
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <div style={{
              width: 36, height: 36,
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 18,
            }}>
              🗐
            </div>
            <div>
              <span className="card-title">CSV Data Export</span>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 2 }}>
                Machine-readable · SIEM compatible · Spreadsheet ready
              </div>
            </div>
          </div>
          {currentReport && (
            <span style={{
              fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
              color: "var(--low)", background: "rgba(0,200,140,0.08)",
              border: "1px solid rgba(0,200,140,0.25)", padding: "3px 10px", borderRadius: "20px",
            }}>
              READY
            </span>
          )}
        </div>

        {!currentReport ? (
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.7, flex: 1, marginBottom: 0 }}>
              Export all{" "}
              <strong style={{ color: "var(--text-primary)" }}>{findings.length} findings</strong>{" "}
              for account{" "}
              <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent-cyan)" }}>
                {scannedAccountId}
              </span>{" "}
              as a structured CSV file. Includes all fields: severity, risk score, title, remediation,
              CLI commands, compliance frameworks, and resource ARNs.
            </p>
            <button
              className="btn btn-secondary"
              style={{ fontSize: 14, padding: "12px 28px", flexShrink: 0, minWidth: 210 }}
              onClick={handleGenerateCSV}
              disabled={generating}
            >
              {generating
                ? <><div className="spinner dark" /> Generating...</>
                : "⊕ Generate CSV Export"}
            </button>
          </div>
        ) : (
          <>
            {/* Ready state */}
            <div style={{
              display: "flex", alignItems: "center", gap: 16,
              padding: "14px 16px", marginBottom: 14,
              background: "var(--bg-elevated)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-md)",
              flexWrap: "wrap",
            }}>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-primary)", fontWeight: 600, marginBottom: 4 }}>
                  {currentReport.filename}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
                  {findings.length} rows · Account {scannedAccountId} · Generated{" "}
                  {currentReport.generatedAt.toLocaleString("en-GB", {
                    day: "2-digit", month: "short", year: "numeric",
                    hour: "2-digit", minute: "2-digit",
                  })}
                </div>
              </div>
              <div style={{ display: "flex", gap: 10, flexShrink: 0 }}>
                <button
                  className="btn btn-ghost"
                  style={{ fontSize: 12 }}
                  onClick={handleGenerateCSV}
                  disabled={generating}
                >
                  {generating ? "Regenerating..." : "↺ Regenerate"}
                </button>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: 13, padding: "9px 22px" }}
                  onClick={handleDownloadCSV}
                >
                  ↓ Download CSV
                </button>
              </div>
            </div>

            {/* Field reference */}
            <div style={{
              display: "flex", flexWrap: "wrap", gap: "6px 12px",
              padding: "10px 14px",
              background: "var(--bg-base)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
            }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginRight: 4 }}>
                COLUMNS:
              </span>
              {["FindingID", "AccountId", "ResourceType", "ResourceID", "Scanner", "Severity", "RiskScore", "Title", "Status", "Timestamp", "ComplianceFramework", "Remediation", "CLICommands"].map(col => (
                <span key={col} style={{
                  fontFamily: "var(--font-mono)", fontSize: 10,
                  color: "var(--accent-cyan)",
                  background: "rgba(0,212,255,0.06)",
                  border: "1px solid rgba(0,212,255,0.15)",
                  padding: "2px 7px", borderRadius: 3,
                }}>
                  {col}
                </span>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
}