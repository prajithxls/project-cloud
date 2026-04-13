import React from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";
import { SCANNER_COLORS } from "../../utils/helpers";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function ScannerBarChart({ scanners }) {
  const labels = Object.keys(scanners);
  const values = Object.values(scanners);

  const data = {
    labels,
    datasets: [
      {
        label: "Findings",
        data: values,
        backgroundColor: labels.map((_, i) => SCANNER_COLORS[i % SCANNER_COLORS.length] + "33"),
        borderColor: labels.map((_, i) => SCANNER_COLORS[i % SCANNER_COLORS.length]),
        borderWidth: 1.5,
        borderRadius: 4,
        borderSkipped: false,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#111820",
        borderColor: "#1e2d3d",
        borderWidth: 1,
        titleColor: "#e8f4fd",
        bodyColor: "#7a9ab8",
        titleFont: { family: "'Syne', sans-serif", weight: "700" },
        callbacks: {
          label: (ctx) => ` ${ctx.parsed.y} findings`,
        },
      },
    },
    scales: {
      x: {
        grid: { color: "#1e2d3d", drawBorder: false },
        ticks: {
          color: "#7a9ab8",
          font: { family: "'Space Mono', monospace", size: 11 },
        },
        border: { color: "#1e2d3d" },
      },
      y: {
        grid: { color: "#1e2d3d", drawBorder: false },
        ticks: {
          color: "#7a9ab8",
          font: { family: "'Space Mono', monospace", size: 11 },
          precision: 0,
        },
        border: { color: "#1e2d3d" },
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="card" style={{ height: "280px" }}>
      <div className="card-header">
        <span className="card-title">Findings by Scanner</span>
        <span style={{
          fontFamily: "var(--font-mono)",
          fontSize: 11,
          color: "var(--text-muted)",
        }}>
          {labels.length} scanners
        </span>
      </div>
      <div style={{ height: "calc(100% - 48px)" }}>
        {labels.length === 0 ? (
          <div className="empty-state" style={{ padding: "30px" }}>
            <div className="empty-state-icon">▦</div>
            <div className="empty-state-title">No scanner data</div>
          </div>
        ) : (
          <Bar data={data} options={options} />
        )}
      </div>
    </div>
  );
}
