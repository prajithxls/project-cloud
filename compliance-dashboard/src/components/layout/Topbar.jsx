import React, { useState } from "react";

export default function Topbar({ scanning, lastUpdated, user, onSignOut, theme, setTheme }) {
  const [showSettings, setShowSettings] = useState(false);

  return (
    <>
      <header className="topbar">
        <div className="topbar-title" style={{ fontWeight: 600 }}>
          Cloud Security Compliance and Audit Management System
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          {scanning && (
            <div style={{ display: "flex", alignItems: "center", gap: 8, fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--accent-cyan)" }}>
              <div className="spinner" style={{ width: 12, height: 12 }} />
              SCANNING
            </div>
          )}
          {lastUpdated && !scanning && (
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)" }}>
              Updated {lastUpdated.toLocaleTimeString()}
            </div>
          )}
          {user && (
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{
                fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-secondary)",
                background: "var(--bg-elevated)", border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)", padding: "4px 10px",
                maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}>
                {user.email}
              </div>
              
              {/* Settings Gear Button */}
              <button
                onClick={() => setShowSettings(true)}
                style={{
                  background: "transparent", border: "1px solid var(--border)",
                  borderRadius: "var(--radius-md)", padding: "4px 8px",
                  color: "var(--text-muted)", cursor: "pointer",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  transition: "color 0.15s, border-color 0.15s",
                }}
                onMouseEnter={e => { e.currentTarget.style.color = "var(--text-primary)"; e.currentTarget.style.borderColor = "var(--border-bright)"; }}
                onMouseLeave={e => { e.currentTarget.style.color = "var(--text-muted)"; e.currentTarget.style.borderColor = "var(--border)"; }}
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="3"/>
                  <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* ── SETTINGS MODAL ── */}
      {showSettings && (
        <div style={{
          position: "fixed", top: 0, left: 0, right: 0, bottom: 0,
          background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)",
          display: "flex", alignItems: "center", justifyContent: "center", zIndex: 999
        }}>
          <div className="card" style={{ width: "100%", maxWidth: "360px", margin: "0 20px" }}>
            
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 24 }}>
              <h3 style={{ fontSize: 16, fontFamily: "var(--font-display)", color: "var(--text-primary)", fontWeight: 700 }}>Settings</h3>
              <button 
                onClick={() => setShowSettings(false)} 
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: 20 }}
              >×</button>
            </div>
            
            {/* Theme Toggle */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 32 }}>
              <div>
                <div style={{ fontWeight: 600, color: "var(--text-primary)", fontSize: 13 }}>Appearance</div>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", fontFamily: "var(--font-mono)", marginTop: 2 }}>Select your UI theme</div>
              </div>
              
              {/* Light/Dark Switcher */}
              <div style={{ display: "flex", background: "var(--bg-base)", padding: 4, borderRadius: "var(--radius-sm)", border: "1px solid var(--border)" }}>
                <button 
                  onClick={() => setTheme("light")}
                  style={{
                    padding: "6px 12px", border: "none", borderRadius: 4, cursor: "pointer", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-mono)",
                    background: theme === "light" ? "var(--bg-elevated)" : "transparent",
                    color: theme === "light" ? "var(--text-primary)" : "var(--text-muted)",
                    boxShadow: theme === "light" ? "var(--shadow-sm)" : "none",
                  }}
                >LIGHT</button>
                <button 
                  onClick={() => setTheme("dark")}
                  style={{
                    padding: "6px 12px", border: "none", borderRadius: 4, cursor: "pointer", fontSize: 11, fontWeight: 700, fontFamily: "var(--font-mono)",
                    background: theme === "dark" ? "var(--bg-elevated)" : "transparent",
                    color: theme === "dark" ? "var(--text-primary)" : "var(--text-muted)",
                    boxShadow: theme === "dark" ? "var(--shadow-sm)" : "none",
                  }}
                >DARK</button>
              </div>
            </div>

            {/* Sign Out Section */}
            <div style={{ borderTop: "1px solid var(--border)", paddingTop: 20 }}>
              <button 
                className="btn" 
                style={{
                  width: "100%", padding: "10px", fontSize: 13, fontWeight: 600,
                  background: "var(--critical-dim)", color: "var(--critical)", border: "1px solid rgba(239, 68, 68, 0.3)",
                }} 
                onClick={() => { setShowSettings(false); onSignOut(); }}
              >
                Sign Out
              </button>
            </div>

          </div>
        </div>
      )}
    </>
  );
}