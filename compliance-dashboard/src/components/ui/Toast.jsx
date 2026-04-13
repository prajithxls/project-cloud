import React from "react";

export default function ToastContainer({ toasts, onRemove }) {
  const icons = { success: "✓", error: "✕", info: "ℹ" };

  return (
    <div className="toast-container">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.type}`}>
          <span style={{ fontWeight: 700, fontSize: 14 }}>{icons[t.type] || "ℹ"}</span>
          <span style={{ flex: 1, color: "var(--text-primary)", fontSize: 13 }}>
            {t.message}
          </span>
          <button
            onClick={() => onRemove(t.id)}
            style={{
              background: "none",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              fontSize: 16,
              padding: 0,
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
