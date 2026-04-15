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

export default function Sidebar({ criticalCount, isOpen, toggleSidebar }) {
  return (
    <aside className="sidebar">
      
      {/* ── TOGGLE BUTTON ── */}
      <div style={{ 
        display: "flex", 
        justifyContent: isOpen ? "flex-end" : "center", 
        marginBottom: "16px",
        padding: isOpen ? "0 8px" : "0"
      }}>
        <button 
          onClick={toggleSidebar}
          style={{
            background: "var(--bg-elevated)",
            border: "1px solid var(--border)",
            color: "var(--text-primary)",
            width: "32px", height: "32px",
            borderRadius: "var(--radius-md)",
            cursor: "pointer",
            display: "flex", alignItems: "center", justifyContent: "center",
            transition: "all 0.2s"
          }}
          onMouseEnter={e => e.currentTarget.style.borderColor = "var(--border-bright)"}
          onMouseLeave={e => e.currentTarget.style.borderColor = "var(--border)"}
        >
          {isOpen ? "◂" : "▸"}
        </button>
      </div>

      {isOpen && <div className="sidebar-section-label">Navigation</div>}
      <ul className="sidebar-nav" style={{ marginTop: isOpen ? 0 : 8 }}>
        {navItems.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.to === "/"}
              className={({ isActive }) => `sidebar-nav-item${isActive ? " active" : ""}`}
              style={{ justifyContent: isOpen ? "flex-start" : "center", padding: isOpen ? "9px 10px" : "12px 0" }}
              title={!isOpen ? item.label : ""} // Shows tooltip when collapsed
            >
              <span className="nav-icon" style={{ fontSize: isOpen ? 16 : 18 }}>{item.icon}</span>
              
              {isOpen && (
                <>
                  <span style={{ whiteSpace: "nowrap" }}>{item.label}</span>
                  {item.label === "Findings" && criticalCount > 0 && (
                    <span className="nav-badge">{criticalCount}</span>
                  )}
                </>
              )}
              {/* Show dot indicator if collapsed and has critical findings */}
              {!isOpen && item.label === "Findings" && criticalCount > 0 && (
                <div style={{ position: "absolute", top: 8, right: 14, width: 8, height: 8, background: "var(--critical)", borderRadius: "50%" }} />
              )}
            </NavLink>
          </li>
        ))}
      </ul>

      {isOpen && <div className="sidebar-section-label" style={{ marginTop: 24 }}>Scanners</div>}
      <ul className="sidebar-nav" style={{ marginTop: isOpen ? 0 : 24 }}>
        {ALL_SCANNERS.map((scanner) => (
          <li key={scanner}>
            <NavLink
              to={`/findings?scanner=${scanner}`}
              className="sidebar-nav-item"
              style={({ isActive }) => ({ 
                opacity: isActive ? 1 : 0.85,
                justifyContent: isOpen ? "flex-start" : "center",
                padding: isOpen ? "9px 10px" : "12px 0"
              })}
              title={!isOpen ? `${scanner} Scanner` : ""}
            >
              <span className="nav-icon" style={{ fontSize: 12 }}>▸</span>
              {isOpen && <span style={{ whiteSpace: "nowrap", fontSize: 12 }}>{scanner}</span>}
            </NavLink>
          </li>
        ))}
      </ul>

      <div className="sidebar-footer">
        {isOpen ? (
          <div className="sidebar-version" style={{ whiteSpace: "nowrap" }}>v2.0 · ap-south-1</div>
        ) : (
          <div className="sidebar-version" style={{ textAlign: "center" }}>v2</div>
        )}
      </div>
    </aside>
  );
}