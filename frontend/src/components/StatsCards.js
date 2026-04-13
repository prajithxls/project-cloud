import React from "react";

const StatsCards = ({ findings }) => {
  // Count findings by severity
  const criticalCount = findings.filter(f => f.severity === "CRITICAL").length;
  const highCount = findings.filter(f => f.severity === "HIGH").length;
  const mediumCount = findings.filter(f => f.severity === "MEDIUM").length;
  const lowCount = findings.filter(f => f.severity === "LOW").length;

  return (
    <div className="stats-cards">
      <div className="card critical">
        <h3>Critical</h3>
        <p>{criticalCount}</p>
      </div>
      <div className="card high">
        <h3>High</h3>
        <p>{highCount}</p>
      </div>
      <div className="card medium">
        <h3>Medium</h3>
        <p>{mediumCount}</p>
      </div>
      <div className="card low">
        <h3>Low</h3>
        <p>{lowCount}</p>
      </div>
    </div>
  );
};

export default StatsCards;
