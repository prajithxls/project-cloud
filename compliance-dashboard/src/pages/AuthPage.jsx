import React, { useState } from "react";
import { signIn, signUp, confirmSignUp, resendCode, forgotPassword, confirmForgotPassword } from "../services/auth";

// ── views: "login" | "signup" | "verify" | "forgot" | "reset"
export default function AuthPage({ onLogin }) {
  const [view,     setView]     = useState("login");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [code,     setCode]     = useState("");
  const [newPass,  setNewPass]  = useState("");
  const [error,    setError]    = useState("");
  const [info,     setInfo]     = useState("");
  const [loading,  setLoading]  = useState(false);

  const reset = () => { setError(""); setInfo(""); };

  // ── LOGIN ──────────────────────────────────────────────────────────────────
  const handleLogin = async () => {
    reset();
    if (!email || !password) { setError("Please enter your email and password."); return; }
    setLoading(true);
    try {
      await signIn(email, password);
      onLogin();
    } catch (e) {
      if (e.message.includes("not confirmed")) {
        setInfo("Your account is not verified yet. Enter the code sent to your email.");
        setView("verify");
      } else {
        setError(e.message);
      }
    } finally { setLoading(false); }
  };

  // ── SIGN UP ────────────────────────────────────────────────────────────────
  const handleSignUp = async () => {
    reset();
    if (!email || !password) { setError("Email and password are required."); return; }
    if (password !== confirm) { setError("Passwords do not match."); return; }
    if (password.length < 8)  { setError("Password must be at least 8 characters."); return; }
    setLoading(true);
    try {
      await signUp(email, password);
      setInfo("Account created! Check your email for a verification code.");
      setView("verify");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── VERIFY ─────────────────────────────────────────────────────────────────
  const handleVerify = async () => {
    reset();
    if (!code) { setError("Enter the 6-digit code from your email."); return; }
    setLoading(true);
    try {
      await confirmSignUp(email, code);
      setInfo("Email verified! Signing you in...");
      await signIn(email, password);
      onLogin();
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── FORGOT PASSWORD ────────────────────────────────────────────────────────
  const handleForgot = async () => {
    reset();
    if (!email) { setError("Enter your email address."); return; }
    setLoading(true);
    try {
      await forgotPassword(email);
      setInfo("Reset code sent to your email.");
      setView("reset");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── RESET PASSWORD ─────────────────────────────────────────────────────────
  const handleReset = async () => {
    reset();
    if (!code || !newPass) { setError("Enter the code and your new password."); return; }
    if (newPass.length < 8) { setError("Password must be at least 8 characters."); return; }
    setLoading(true);
    try {
      await confirmForgotPassword(email, code, newPass);
      setInfo("Password reset! You can now log in.");
      setView("login");
    } catch (e) {
      setError(e.message);
    } finally { setLoading(false); }
  };

  // ── STEALTH MONOCHROME STYLES ──────────────────────────────────────────────
  const inputStyle = {
    width: "100%",
    padding: "11px 14px",
    background: "#000000",
    border: "1px solid #27272a",
    borderRadius: 8,
    color: "#ffffff",
    fontFamily: "var(--font-mono)",
    fontSize: 14,
    outline: "none",
    boxSizing: "border-box",
    transition: "border-color 0.15s",
  };

  const labelStyle = {
    fontFamily: "var(--font-mono)",
    fontSize: 10,
    color: "#a1a1aa",
    letterSpacing: "0.08em",
    marginBottom: 6,
    display: "block",
  };

  const primaryButtonStyle = {
    width: "100%", 
    padding: "12px", 
    fontSize: 14, 
    background: "#ffffff", 
    color: "#000000",
    border: "none",
    fontWeight: 700,
    cursor: "pointer",
    borderRadius: "var(--radius-md)"
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#000000",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      padding: 20,
    }}>
      {/* Subtle grid background */}
      <div style={{
        position: "fixed", inset: 0, opacity: 0.04,
        backgroundImage: "linear-gradient(#ffffff 1px, transparent 1px), linear-gradient(90deg, #ffffff 1px, transparent 1px)",
        backgroundSize: "40px 40px",
        pointerEvents: "none",
      }} />

      <div style={{
        width: "100%",
        maxWidth: 420,
        background: "#0a0a0a",
        border: "1px solid #27272a",
        borderRadius: 16,
        overflow: "hidden",
        boxShadow: "0 24px 80px rgba(0,0,0,0.8)",
        position: "relative",
      }}>
        {/* Top accent line */}
        <div style={{ height: 3, background: "linear-gradient(90deg, #ffffff, #52525b)" }} />

        <div style={{ padding: "36px 36px 32px" }}>
          {/* Logo / Title */}
          <div style={{ textAlign: "center", marginBottom: 32 }}>
            <div style={{
              width: 52, height: 52,
              background: "linear-gradient(135deg, #18181b, #f6f6f6)",
              border: "1px solid #ffffff",
              borderRadius: 14,
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 24, margin: "0 auto 16px",
            }}>
              🔒︎
            </div>
            <div style={{
              fontFamily: "var(--font-display, monospace)",
              fontSize: 17,
              fontWeight: 800,
              color: "#ffffff",
              letterSpacing: "0.02em",
              lineHeight: 1.3,
            }}>
              Cloud Security Compliance
            </div>
            <div style={{
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 10,
              color: "#a1a1aa",
              letterSpacing: "0.12em",
              marginTop: 4,
            }}>
              & AUDIT MANAGEMENT SYSTEM
            </div>
          </div>

          {/* View Title */}
          <div style={{
            fontFamily: "var(--font-mono, monospace)",
            fontSize: 11,
            color: "#a1a1aa",
            letterSpacing: "0.1em",
            marginBottom: 20,
            textAlign: "center",
          }}>
            {view === "login"  && "SIGN IN TO YOUR ACCOUNT"}
            {view === "signup" && "CREATE AN ACCOUNT"}
            {view === "verify" && "VERIFY YOUR EMAIL"}
            {view === "forgot" && "RESET PASSWORD"}
            {view === "reset"  && "SET NEW PASSWORD"}
          </div>

          {/* Error / Info */}
          {error && (
            <div style={{
              background: "#2e0f0f",
              border: "1px solid #ef444444",
              borderRadius: 8,
              padding: "10px 14px",
              marginBottom: 16,
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 12,
              color: "#ef4444",
            }}>
              ⚠ {error}
            </div>
          )}
          {info && (
            <div style={{
              background: "#0f2e1b",
              border: "1px solid #22c55e44",
              borderRadius: 8,
              padding: "10px 14px",
              marginBottom: 16,
              fontFamily: "var(--font-mono, monospace)",
              fontSize: 12,
              color: "#22c55e",
            }}>
              ✓ {info}
            </div>
          )}

          {/* ── LOGIN FORM ── */}
          {view === "login" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleLogin()} />
              </div>
              <div>
                <label style={labelStyle}>PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="••••••••"
                  value={password} onChange={e => setPassword(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleLogin()} />
              </div>
              <div style={{ textAlign: "right", marginTop: -8 }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "#ffffff", cursor: "pointer" }}
                  onClick={() => { reset(); setView("forgot"); }}>
                  Forgot password?
                </span>
              </div>
              <button className="btn btn-primary" style={{ ...primaryButtonStyle, marginTop: 4 }}
                onClick={handleLogin} disabled={loading}>
                {loading ? "Signing in..." : "→ Sign In"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#a1a1aa" }}>
                No account?{" "}
                <span style={{ color: "#ffffff", cursor: "pointer" }} onClick={() => { reset(); setView("signup"); }}>
                  Create one
                </span>
              </div>
            </div>
          )}

          {/* ── SIGNUP FORM ── */}
          {view === "signup" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"} />
              </div>
              <div>
                <label style={labelStyle}>PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="Min. 8 characters"
                  value={password} onChange={e => setPassword(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"} />
              </div>
              <div>
                <label style={labelStyle}>CONFIRM PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="••••••••"
                  value={confirm} onChange={e => setConfirm(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleSignUp()} />
              </div>
              <button className="btn btn-primary" style={primaryButtonStyle}
                onClick={handleSignUp} disabled={loading}>
                {loading ? "Creating account..." : "→ Create Account"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#a1a1aa" }}>
                Already have an account?{" "}
                <span style={{ color: "#ffffff", cursor: "pointer" }} onClick={() => { reset(); setView("login"); }}>
                  Sign in
                </span>
              </div>
            </div>
          )}

          {/* ── VERIFY FORM ── */}
          {view === "verify" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#a1a1aa", marginBottom: 4 }}>
                A 6-digit code was sent to<br />
                <span style={{ color: "#ffffff" }}>{email}</span>
              </div>
              <div>
                <label style={labelStyle}>VERIFICATION CODE</label>
                <input style={{ ...inputStyle, fontSize: 22, textAlign: "center", letterSpacing: "0.3em" }}
                  type="text" placeholder="000000" maxLength={6}
                  value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleVerify()} />
              </div>
              <button className="btn btn-primary" style={primaryButtonStyle}
                onClick={handleVerify} disabled={loading}>
                {loading ? "Verifying..." : "✓ Verify Email"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#a1a1aa" }}>
                Didn't get it?{" "}
                <span style={{ color: "#ffffff", cursor: "pointer" }}
                  onClick={() => resendCode(email).then(() => setInfo("Code resent!")).catch(e => setError(e.message))}>
                  Resend code
                </span>
              </div>
            </div>
          )}

          {/* ── FORGOT PASSWORD FORM ── */}
          {view === "forgot" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>EMAIL ADDRESS</label>
                <input style={inputStyle} type="email" placeholder="you@example.com"
                  value={email} onChange={e => setEmail(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleForgot()} />
              </div>
              <button className="btn btn-primary" style={primaryButtonStyle}
                onClick={handleForgot} disabled={loading}>
                {loading ? "Sending..." : "→ Send Reset Code"}
              </button>
              <div style={{ textAlign: "center", fontFamily: "var(--font-mono)", fontSize: 12, color: "#a1a1aa" }}>
                <span style={{ color: "#ffffff", cursor: "pointer" }} onClick={() => { reset(); setView("login"); }}>
                  ← Back to Sign In
                </span>
              </div>
            </div>
          )}

          {/* ── RESET PASSWORD FORM ── */}
          {view === "reset" && (
            <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
              <div>
                <label style={labelStyle}>RESET CODE (from email)</label>
                <input style={{ ...inputStyle, textAlign: "center", letterSpacing: "0.2em" }}
                  type="text" placeholder="000000" maxLength={6}
                  value={code} onChange={e => setCode(e.target.value.replace(/\D/g, ""))}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"} />
              </div>
              <div>
                <label style={labelStyle}>NEW PASSWORD</label>
                <input style={inputStyle} type="password" placeholder="Min. 8 characters"
                  value={newPass} onChange={e => setNewPass(e.target.value)}
                  onFocus={e => e.target.style.borderColor = "#ffffff"}
                  onBlur={e => e.target.style.borderColor = "#27272a"}
                  onKeyDown={e => e.key === "Enter" && handleReset()} />
              </div>
              <button className="btn btn-primary" style={primaryButtonStyle}
                onClick={handleReset} disabled={loading}>
                {loading ? "Resetting..." : "✓ Reset Password"}
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}