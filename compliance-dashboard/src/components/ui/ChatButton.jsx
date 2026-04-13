import React, { useState } from "react";

/**
 * Floating chat button — bottom right corner.
 * Shows unread dot when findings are loaded but chat hasn't been opened yet.
 */
export default function ChatButton({ onClick, isOpen, hasFindings, messageCount }) {
  const [hovered, setHovered] = useState(false);
  const showDot = hasFindings && messageCount === 0 && !isOpen;

  return (
    <button
      onClick={onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      title="Ask CloudGuard AI"
      style={{
        position:      "fixed",
        bottom:        28,
        right:         28,
        width:         52,
        height:        52,
        borderRadius:  "50%",
        background:    isOpen
          ? "var(--bg-elevated)"
          : "linear-gradient(135deg, rgb(110, 110, 110) 0%, rgba(99,102,241,0.25) 100%)",
        border:        `1px solid ${isOpen ? "var(--border)" : "rgb(0, 255, 4)"}`,
        boxShadow:     isOpen
          ? "none"
          : hovered
            ? "0 0 20px rgba(0,212,255,0.35), 0 4px 20px rgba(0,0,0,0.3)"
            : "0 0 12px rgba(0,212,255,0.2), 0 4px 16px rgba(0,0,0,0.25)",
        cursor:        "pointer",
        display:       "flex",
        alignItems:    "center",
        justifyContent: "center",
        fontSize:      22,
        zIndex:        1099,
        transition:    "all 0.2s cubic-bezier(0.16,1,0.3,1)",
        transform:     hovered && !isOpen ? "scale(1.1)" : "scale(1)",
      }}
    >
      {isOpen ? "✕" : "🤖"}

      {/* Unread dot */}
      {showDot && (
        <span style={{
          position:   "absolute",
          top:        4,
          right:      4,
          width:      10,
          height:     10,
          borderRadius: "50%",
          background: "var(--low)",
          border:     "2px solid var(--bg-card)",
          boxShadow:  "0 0 6px var(--low)",
          animation:  "pulse 2s ease infinite",
        }} />
      )}

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.5; }
        }
      `}</style>
    </button>
  );
}