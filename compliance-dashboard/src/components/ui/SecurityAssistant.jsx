import React, { useState, useRef, useEffect, useCallback } from "react";
import { sendChatMessage } from "../../services/api";

// ── Suggested prompts shown when chat is empty ────────────────────────────────
const SUGGESTIONS = [
  "Which findings require immediate attention?",
  "Which S3 buckets are missing logging?",
  "How do I fix my CRITICAL findings?",
  "What is CIS-AWS-2.1.5 and do I violate it?",
  "Show me all IAM issues and how to fix them",
  "Which EC2 security groups are exposed to the internet?",
  "Explain my compliance score",
  "What AWS CLI commands can I run to fix my HIGH findings?",
];

// ── Markdown-lite renderer (bold, code blocks, bullet lists) ─────────────────
function RenderMessage({ text }) {
  const lines = text.split("\n");
  const elements = [];
  let inCode = false;
  let codeLines = [];
  let key = 0;

  const flush = () => {
    if (codeLines.length) {
      elements.push(
        <CodeBlock key={key++} code={codeLines.join("\n")} />
      );
      codeLines = [];
    }
  };

  for (const raw of lines) {
    const line = raw;
    if (line.startsWith("```")) {
      if (inCode) { flush(); inCode = false; }
      else          { inCode = true; }
      continue;
    }
    if (inCode) { codeLines.push(line); continue; }

    if (!line.trim()) { elements.push(<div key={key++} style={{ height: 6 }} />); continue; }

    // bullet
    if (line.match(/^[-*•]\s/)) {
      elements.push(
        <div key={key++} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
          <span style={{ color: "var(--accent-cyan)", flexShrink: 0, marginTop: 1 }}>▸</span>
          <span style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.6 }}>
            {renderInline(line.slice(2))}
          </span>
        </div>
      );
      continue;
    }

    // numbered list
    const numbered = line.match(/^(\d+)\.\s(.+)/);
    if (numbered) {
      elements.push(
        <div key={key++} style={{ display: "flex", gap: 8, marginBottom: 3 }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--accent-cyan)", flexShrink: 0, minWidth: 16 }}>
            {numbered[1]}.
          </span>
          <span style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.6 }}>
            {renderInline(numbered[2])}
          </span>
        </div>
      );
      continue;
    }

    elements.push(
      <p key={key++} style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.7, margin: "0 0 4px" }}>
        {renderInline(line)}
      </p>
    );
  }

  if (inCode) flush();

  return <div>{elements}</div>;
}

function renderInline(text) {
  // **bold** and `code`
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**"))
      return <strong key={i} style={{ color: "var(--text-primary)", fontWeight: 700 }}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`") && part.endsWith("`"))
      return <code key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 11, background: "var(--bg-base)", padding: "1px 5px", borderRadius: 3, color: "var(--accent-cyan)" }}>{part.slice(1, -1)}</code>;
    return part;
  });
}

function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false);
  return (
    <div style={{ position: "relative", margin: "8px 0" }}>
      <pre style={{
        background: "var(--bg-base)", border: "1px solid var(--border)",
        borderRadius: 6, padding: "10px 40px 10px 12px",
        fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--accent-cyan)",
        lineHeight: 1.6, overflowX: "auto", whiteSpace: "pre-wrap",
        wordBreak: "break-all", margin: 0,
      }}>
        {code}
      </pre>
      <button
        onClick={() => { navigator.clipboard.writeText(code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
        style={{
          position: "absolute", top: 6, right: 6,
          background: "var(--bg-elevated)", border: "1px solid var(--border)",
          borderRadius: 4, padding: "2px 7px", cursor: "pointer",
          fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700,
          color: copied ? "var(--low)" : "var(--text-muted)", transition: "color 0.15s",
        }}
      >
        {copied ? "✓" : "Copy"}
      </button>
    </div>
  );
}

// ── Typing indicator ──────────────────────────────────────────────────────────
function TypingDots() {
  return (
    <div style={{ display: "flex", gap: 4, alignItems: "center", padding: "4px 0" }}>
      {[0, 1, 2].map(i => (
        <span key={i} style={{
          width: 6, height: 6, borderRadius: "50%",
          background: "var(--accent-cyan)", display: "inline-block",
          animation: `typingDot 1.2s ease infinite`,
          animationDelay: `${i * 0.2}s`,
          opacity: 0.4,
        }} />
      ))}
      <style>{`
        @keyframes typingDot {
          0%, 60%, 100% { opacity: 0.4; transform: translateY(0); }
          30%            { opacity: 1;   transform: translateY(-3px); }
        }
      `}</style>
    </div>
  );
}

// ── Source/framework pill ─────────────────────────────────────────────────────
function SourcePill({ label }) {
  return (
    <span style={{
      fontFamily: "var(--font-mono)", fontSize: 9, fontWeight: 700,
      padding: "2px 7px", borderRadius: 3,
      background: "rgba(0,212,255,0.07)", border: "1px solid rgba(0,212,255,0.2)",
      color: "var(--info)", whiteSpace: "nowrap",
    }}>
      {label}
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function SecurityAssistant({ findings, scannedAccountId, isOpen, onClose }) {
  const [messages,  setMessages]  = useState([]);
  const [input,     setInput]     = useState("");
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState(null);
  const bottomRef  = useRef(null);
  const inputRef   = useRef(null);

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen) setTimeout(() => inputRef.current?.focus(), 150);
  }, [isOpen]);

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === "Escape" && isOpen) onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [isOpen, onClose]);

  const conversationHistory = messages.map(m => ({
    role:    m.role,
    content: m.text,
  }));

  const send = useCallback(async (messageText) => {
    const text = (messageText || input).trim();
    if (!text || loading) return;

    setInput("");
    setError(null);
    setMessages(prev => [...prev, { role: "user", text, id: Date.now() }]);
    setLoading(true);

    try {
      const res  = await sendChatMessage({
        message:             text,
        findings:            findings || [],
        conversationHistory: conversationHistory,
        accountId:           scannedAccountId || "",
      });

      const data = res.data;
      setMessages(prev => [...prev, {
        role:            "assistant",
        text:            data.reply || "No response received.",
        sources:         data.sources || [],
        relatedFindings: data.relatedFindings || [],
        id:              Date.now() + 1,
      }]);
    } catch (err) {
      setError(err.message || "Failed to reach Security Assistant.");
      setMessages(prev => [...prev, {
        role: "assistant",
        text: "I'm having trouble connecting right now. Please try again in a moment.",
        sources: [], relatedFindings: [],
        id: Date.now() + 1,
        isError: true,
      }]);
    } finally {
      setLoading(false);
    }
  }, [input, loading, findings, conversationHistory, scannedAccountId]);

  const handleKey = (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  };

  const isEmpty = messages.length === 0;

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop — semi-transparent, click to close */}
      <div
        onClick={onClose}
        style={{
          position: "fixed", inset: 0,
          background: "rgba(0,0,0,0.35)",
          zIndex: 1100,
          backdropFilter: "blur(1px)",
        }}
      />

      {/* Panel */}
      <div style={{
        position:      "fixed",
        bottom:        0,
        right:         24,
        width:         "min(480px, calc(100vw - 48px))",
        height:        "min(680px, calc(100vh - 80px))",
        background:    "var(--bg-base)",
        border:        "1px solid var(--border)",
        borderBottom:  "none",
        borderRadius:  "12px 12px 0 0",
        zIndex:        1101,
        display:       "flex",
        flexDirection: "column",
        boxShadow:     "0 -8px 40px rgba(0,0,0,0.4)",
        animation:     "assistantSlideUp 0.25s cubic-bezier(0.16,1,0.3,1)",
      }}>
        <style>{`
          @keyframes assistantSlideUp {
            from { transform: translateY(100%); opacity: 0; }
            to   { transform: translateY(0);    opacity: 1; }
          }
        `}</style>

        {/* ── Header ────────────────────────────────────────────────────────── */}
        <div style={{
          padding:        "14px 16px",
          borderBottom:   "1px solid var(--border)",
          display:        "flex",
          alignItems:     "center",
          gap:            12,
          flexShrink:     0,
          background:     "var(--bg-elevated)",
          borderRadius:   "12px 12px 0 0",
        }}>
          {/* AI avatar */}
          <div style={{
            width: 34, height: 34, borderRadius: "50%",
            background: "linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(99,102,241,0.2) 100%)",
            border: "1px solid rgba(0,212,255,0.3)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 16, flexShrink: 0,
          }}>
            🛡  
          </div>

          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text-primary)" }}>
              CloudGuard AI
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 1 }}>
              {findings?.length > 0
                ? `${findings.length} findings loaded · ${scannedAccountId || "no account"}`
                : "No scan data — run a scan first"}
            </div>
          </div>

          {/* Status dot */}
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginRight: 8 }}>
            <span style={{
              width: 7, height: 7, borderRadius: "50%",
              background: findings?.length > 0 ? "var(--low)" : "var(--text-muted)",
              boxShadow: findings?.length > 0 ? "0 0 6px var(--low)" : "none",
            }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)" }}>
              {findings?.length > 0 ? "LIVE DATA" : "NO DATA"}
            </span>
          </div>

          <button
            onClick={onClose}
            style={{
              background: "none", border: "1px solid var(--border)",
              borderRadius: 6, color: "var(--text-muted)", cursor: "pointer",
              fontSize: 14, padding: "3px 7px", transition: "all 0.1s",
            }}
            onMouseEnter={e => e.target.style.color = "var(--text-primary)"}
            onMouseLeave={e => e.target.style.color = "var(--text-muted)"}
          >
            ✕
          </button>
        </div>

        {/* ── Messages area ─────────────────────────────────────────────────── */}
        <div style={{ flex: 1, overflowY: "auto", padding: "16px" }}>

          {/* Welcome / empty state */}
          {isEmpty && (
            <div style={{ marginBottom: 20 }}>
              <div style={{
                background: "linear-gradient(135deg, rgba(0,212,255,0.05) 0%, rgba(99,102,241,0.05) 100%)",
                border: "1px solid rgba(0,212,255,0.15)",
                borderRadius: 10, padding: "14px 16px", marginBottom: 16,
              }}>
                <div style={{ fontSize: 13, color: "var(--text-primary)", lineHeight: 1.6, marginBottom: 6 }}>
                  Hi! I'm <strong>CloudGuard AI</strong> — your security consultant.
                </div>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", lineHeight: 1.6 }}>
                  Ask me anything about your findings, compliance frameworks, or how to fix specific issues.
                  I have full access to your live scan data.
                </div>
              </div>

              {/* Suggestion chips */}
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 8 }}>
                SUGGESTED QUESTIONS
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {SUGGESTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => send(s)}
                    disabled={loading}
                    style={{
                      background:   "var(--bg-elevated)",
                      border:       "1px solid var(--border)",
                      borderRadius: 6,
                      padding:      "5px 10px",
                      fontSize:     11,
                      color:        "var(--text-secondary)",
                      cursor:       "pointer",
                      transition:   "all 0.15s",
                      textAlign:    "left",
                      lineHeight:   1.4,
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.borderColor = "rgba(0,212,255,0.4)";
                      e.currentTarget.style.color = "var(--accent-cyan)";
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.borderColor = "var(--border)";
                      e.currentTarget.style.color = "var(--text-secondary)";
                    }}
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Message bubbles */}
          {messages.map((msg) => (
            <div key={msg.id} style={{
              display:       "flex",
              flexDirection: msg.role === "user" ? "row-reverse" : "row",
              gap:           10,
              marginBottom:  16,
              alignItems:    "flex-start",
            }}>
              {/* Avatar */}
              <div style={{
                width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                background: msg.role === "user"
                  ? "rgba(0,212,255,0.15)"
                  : "linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(99,102,241,0.2) 100%)",
                border: `1px solid ${msg.role === "user" ? "rgba(0,212,255,0.3)" : "rgba(99,102,241,0.3)"}`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 12,
              }}>
                {msg.role === "user" ? "👤" : "🛡"}
              </div>

              <div style={{ maxWidth: "80%", minWidth: 60 }}>
                {/* Bubble */}
                <div style={{
                  background: msg.role === "user"
                    ? "rgba(0,212,255,0.08)"
                    : msg.isError ? "rgba(220,40,80,0.06)" : "var(--bg-elevated)",
                  border: `1px solid ${msg.role === "user"
                    ? "rgba(0,212,255,0.2)"
                    : msg.isError ? "rgba(220,40,80,0.2)" : "var(--border)"}`,
                  borderRadius: msg.role === "user" ? "12px 2px 12px 12px" : "2px 12px 12px 12px",
                  padding: "10px 14px",
                }}>
                  {msg.role === "user" ? (
                    <p style={{ fontSize: 13, color: "var(--text-primary)", margin: 0, lineHeight: 1.6 }}>
                      {msg.text}
                    </p>
                  ) : (
                    <RenderMessage text={msg.text} />
                  )}
                </div>

                {/* Sources */}
                {msg.sources?.length > 0 && (
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginTop: 6 }}>
                    {msg.sources.map(s => <SourcePill key={s} label={s} />)}
                  </div>
                )}

                {/* Timestamp */}
                <div style={{
                  fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)",
                  marginTop: 4, textAlign: msg.role === "user" ? "right" : "left",
                }}>
                  {new Date(msg.id).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit" })}
                </div>
              </div>
            </div>
          ))}

          {/* Typing indicator */}
          {loading && (
            <div style={{ display: "flex", gap: 10, alignItems: "flex-start", marginBottom: 16 }}>
              <div style={{
                width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                background: "linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(99,102,241,0.2) 100%)",
                border: "1px solid rgba(99,102,241,0.3)",
                display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12,
              }}>🛡</div>
              <div style={{
                background: "var(--bg-elevated)", border: "1px solid var(--border)",
                borderRadius: "2px 12px 12px 12px", padding: "10px 14px",
              }}>
                <TypingDots />
              </div>
            </div>
          )}

          <div ref={bottomRef} />
        </div>

        {/* ── Input area ────────────────────────────────────────────────────── */}
        <div style={{
          padding:        "12px 14px",
          borderTop:      "1px solid var(--border)",
          flexShrink:     0,
          background:     "var(--bg-elevated)",
        }}>
          {error && (
            <div style={{
              fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--critical)",
              marginBottom: 8, padding: "4px 8px",
              background: "rgba(220,40,80,0.08)", borderRadius: 4,
            }}>
              ⚠ {error}
            </div>
          )}

          <div style={{ display: "flex", gap: 8, alignItems: "flex-end" }}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKey}
              placeholder="Ask about your findings, frameworks, or how to fix issues..."
              disabled={loading}
              rows={1}
              style={{
                flex:         1,
                background:   "var(--bg-base)",
                border:       "1px solid var(--border)",
                borderRadius: 8,
                padding:      "9px 12px",
                color:        "var(--text-primary)",
                fontSize:     13,
                fontFamily:   "inherit",
                resize:       "none",
                outline:      "none",
                lineHeight:   1.5,
                maxHeight:    100,
                overflowY:    "auto",
                transition:   "border-color 0.15s",
              }}
              onFocus={e => e.target.style.borderColor = "rgba(0,212,255,0.5)"}
              onBlur={e => e.target.style.borderColor = "var(--border)"}
              onInput={e => {
                e.target.style.height = "auto";
                e.target.style.height = Math.min(e.target.scrollHeight, 100) + "px";
              }}
            />
            <button
              onClick={() => send()}
              disabled={loading || !input.trim()}
              style={{
                background:    loading || !input.trim()
                  ? "var(--bg-elevated)"
                  : "linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(99,102,241,0.2) 100%)",
                border:        `1px solid ${loading || !input.trim() ? "var(--border)" : "rgba(0,212,255,0.4)"}`,
                borderRadius:  8,
                width:         36, height: 36,
                display:       "flex", alignItems: "center", justifyContent: "center",
                cursor:        loading || !input.trim() ? "not-allowed" : "pointer",
                fontSize:      16,
                color:         loading || !input.trim() ? "var(--text-muted)" : "var(--accent-cyan)",
                flexShrink:    0,
                transition:    "all 0.15s",
              }}
            >
              {loading ? <div className="spinner" style={{ width: 14, height: 14 }} /> : "↑"}
            </button>
          </div>

          <div style={{
            fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--text-muted)",
            marginTop: 6, display: "flex", justifyContent: "space-between",
          }}>
            <span>Enter to send · Shift+Enter for new line</span>
            {messages.length > 0 && (
              <button
                onClick={() => setMessages([])}
                style={{ background: "none", border: "none", cursor: "pointer", color: "var(--text-muted)", fontSize: 9, fontFamily: "var(--font-mono)", padding: 0 }}
              >
                Clear chat
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}