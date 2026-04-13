import React from "react";
import { NavLink } from "react-router-dom";

const navItems = [
  { to: "/",        label: "Dashboard",  icon: "◈" },
  { to: "/findings", label: "Findings",  icon: "⚑" },
  { to: "/scan",    label: "Run Scan",   icon: "⟳" },
  { to: "/reports", label: "Reports",    icon: "↓" },
  { to: "/history", label: "My History", icon: "◴" },
];

const ALL_SCANNERS = ["S3", "EC2", "IAM", "LAMBDA", "RDS", "CLOUDTRAIL", "APIGW"];

export default function Sidebar({ criticalCount }) {
  return (
    <aside className="sidebar">
      <div className="sidebar-section-label">Navigation</div>
      <ul className="sidebar-nav">
        {navItems.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) =>
                `sidebar-nav-item${isActive ? " active" : ""}`
              }
            >
              <span className="nav-icon">{item.icon}</span>
              {item.label}
              {item.label === "Findings" && criticalCount > 0 && (
                <span className="nav-badge">{criticalCount}</span>
              )}
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="sidebar-section-label">Scanners</div>
      <ul className="sidebar-nav">
        {ALL_SCANNERS.map((scanner) => (
          <li key={scanner}>
            <NavLink
              to={`/findings?scanner=${scanner}`}
              className="sidebar-nav-item"
              style={({ isActive }) => ({ opacity: isActive ? 1 : 0.85 })}
            >
              <span className="nav-icon" style={{ fontSize: 12 }}>▸</span>
              {scanner} Scanner
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        <div className="sidebar-version">v2.0 · ap-south-1</div>
      </div>
    </aside>
  );
}