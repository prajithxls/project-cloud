import React from "react";
import { Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { CHART_COLORS } from "../../utils/helpers";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function SeverityDonut({ stats }) {
  const total = stats.CRITICAL + stats.HIGH + stats.MEDIUM + stats.LOW;

  // Chart.js plugin that draws the number directly in the donut center
  const centerTextPlugin = {
    id: "centerText",
    afterDraw(chart) {
      const { ctx, chartArea } = chart;
      if (!chartArea) return;

      const centerX = (chartArea.left + chartArea.right) / 2;
      const centerY = (chartArea.top + chartArea.bottom) / 2;

      ctx.save();

      // Draw the number
      ctx.font = "800 32px 'Syne', sans-serif";
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-primary').trim() || "#e8f4fd";
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(total, centerX, centerY - 8);

      // Draw "FINDINGS" label below
      ctx.font = "400 10px 'Space Mono', monospace";
      ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() || "#3d5872";
      ctx.letterSpacing = "2px";
      ctx.fillText("FINDINGS", centerX, centerY + 16);

      ctx.restore();
    },
  };

  const data = {
    labels: ["Critical", "High", "Medium", "Low"],
    datasets: [
      {
        data: [stats.CRITICAL, stats.HIGH, stats.MEDIUM, stats.LOW],
        backgroundColor: [
          CHART_COLORS.CRITICAL + "dd",
          CHART_COLORS.HIGH + "dd",
          CHART_COLORS.MEDIUM + "dd",
          CHART_COLORS.LOW + "dd",
        ],
        borderColor: [
          CHART_COLORS.CRITICAL,
          CHART_COLORS.HIGH,
          CHART_COLORS.MEDIUM,
          CHART_COLORS.LOW,
        ],
        borderWidth: 2,
        hoverBorderWidth: 3,
        hoverOffset: 8,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "70%",
    plugins: {
      legend: {
        position: "right",
        labels: {
          color: "#7a9ab8",
          font: { family: "'Space Mono', monospace", size: 11, weight: "500" },
          padding: 18,
          usePointStyle: true,
          pointStyleWidth: 10,
          boxWidth: 10,
          boxHeight: 10,
        },
      },
      tooltip: {
        backgroundColor: "rgba(10, 10, 10, 0.95)",
        borderColor: "var(--border-bright)",
        borderWidth: 1,
        titleColor: "#ffffff",
        bodyColor: "#a1a1aa",
        titleFont: { family: "'Syne', sans-serif", weight: "700", size: 13 },
        bodyFont: { family: "'Space Mono', monospace", size: 11 },
        padding: 12,
        cornerRadius: 8,
        callbacks: {
          label: (ctx) => {
            const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
            const pct = total ? ((ctx.parsed / total) * 100).toFixed(1) : 0;
            return ` ${ctx.parsed} findings (${pct}%)`;
          },
        },
      },
    },
  };

  return (
    <div 
      className="card" 
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-lg)",
        padding: "24px",
        position: "relative",
        overflow: "hidden",
        transition: "all 0.3s ease"
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "var(--border-bright)";
        e.currentTarget.style.boxShadow = "var(--shadow-sm)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--border)";
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      {/* Subtle background gradient */}
      <div style={{
        position: "absolute",
        top: "-50%",
        right: "-20%",
        width: "200px",
        height: "200px",
        background: "radial-gradient(circle, var(--accent-cyan-dim) 0%, transparent 70%)",
        opacity: 0.2,
        pointerEvents: "none"
      }}></div>

      {/* Card Header */}
      <div style={{ 
        display: "flex", 
        alignItems: "center", 
        justifyContent: "space-between", 
        marginBottom: "20px",
        position: "relative",
        zIndex: 1
      }}>
        <div>
          <h3 style={{
            fontSize: "14px",
            fontWeight: 700,
            color: "var(--text-primary)",
            marginBottom: "4px",
            letterSpacing: "-0.2px"
          }}>
            Severity Distribution
          </h3>
          <p style={{
            fontFamily: "var(--font-mono)",
            fontSize: "10px",
            color: "var(--text-muted)",
            letterSpacing: "0.06em",
            textTransform: "uppercase"
          }}>
            {total} total findings
          </p>
        </div>
        {/* Visual indicator */}
        <div style={{
          display: "flex",
          alignItems: "center",
          gap: "4px",
          fontSize: "18px",
          opacity: 0.3
        }}>
          <span>◉</span>
        </div>
      </div>

      {/* Chart Content */}
      <div style={{ 
        height: "280px", 
        position: "relative",
        zIndex: 1
      }}>
        {total === 0 ? (
          <div style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            height: "100%",
            gap: "12px"
          }}>
            <div style={{ fontSize: "48px", opacity: 0.2 }}>◎</div>
            <div style={{
              fontSize: "13px",
              color: "var(--text-muted)",
              fontFamily: "var(--font-mono)"
            }}>
              No findings
            </div>
          </div>
        ) : (
          <Doughnut data={data} options={options} plugins={[centerTextPlugin]} />
        )}
      </div>
    </div>
  );
}