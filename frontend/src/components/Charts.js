import React from "react";
import { PieChart, Pie, Cell, Tooltip, Legend } from "recharts";

const Charts = ({ findings }) => {
  const severityData = [
    { name: "CRITICAL", value: findings.filter(f => f.severity === "CRITICAL").length },
    { name: "HIGH", value: findings.filter(f => f.severity === "HIGH").length },
    { name: "MEDIUM", value: findings.filter(f => f.severity === "MEDIUM").length },
  ];

  const scannerData = [
    { name: "IAM", value: findings.filter(f => f.scanner === "IAM").length },
    { name: "S3", value: findings.filter(f => f.scanner === "S3").length },
    { name: "EC2", value: findings.filter(f => f.scanner === "EC2").length },
  ];

  const COLORS = ["#e63946", "#f77f00", "#457b9d"];

  return (
    <div className="charts">
      <div id="severityChart">
        <h3>Findings by Severity</h3>
        <PieChart width={300} height={300}>
          <Pie data={severityData} dataKey="value" nameKey="name" outerRadius={100}>
            {severityData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </div>

      <div id="scannerChart">
        <h3>Findings by Scanner</h3>
        <PieChart width={300} height={300}>
          <Pie data={scannerData} dataKey="value" nameKey="name" outerRadius={100}>
            {scannerData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index]} />
            ))}
          </Pie>
          <Tooltip />
          <Legend />
        </PieChart>
      </div>
    </div>
  );
};

export default Charts;
