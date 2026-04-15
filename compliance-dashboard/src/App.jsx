import React, { createContext, useContext, useState, useEffect } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";

import Topbar          from "./components/layout/Topbar";
import Sidebar         from "./components/layout/Sidebar";
import ToastContainer  from "./components/ui/Toast";
import AuthPage        from "./pages/AuthPage";
import SecurityAssistant from "./components/ui/SecurityAssistant";
import ChatButton      from "./components/ui/ChatButton";

import Dashboard    from "./pages/Dashboard";
import FindingsPage from "./pages/FindingsPage";
import ScanPage     from "./pages/ScanPage";
import ReportsPage  from "./pages/ReportsPage";
import HistoryPage  from "./pages/HistoryPage";

import { useFindings, useScan, useToast, useScanHistory } from "./hooks/useCompliance";
import { computeStats, computeComplianceScore } from "./utils/helpers";
import { getCurrentUser, signOut } from "./services/auth";

const AppContext = createContext(null);
export const useApp = () => useContext(AppContext);

export default function App() {
  const [user, setUser] = useState(() => getCurrentUser());

  const [theme, setTheme] = useState(() => localStorage.getItem("csc_theme") || "dark");
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("csc_theme", theme);
  }, [theme]);

  // ── Chat state ───────────────────────────────────────────────────────────
  const [chatOpen,       setChatOpen]       = useState(false);
  const [chatMsgCount,   setChatMsgCount]   = useState(0);

  const { findings, loading, error, lastUpdated, scannedAccountId, refetch, clearFindings } = useFindings();
  const { toasts, addToast, removeToast } = useToast();
  const navigate = useNavigate();

  const { scanning, scanLog, triggerScan } = useScan(async (accountId) => {
    await new Promise(resolve => setTimeout(resolve, 8000));
    const freshFindings = await refetch(accountId) || [];
    const score = computeComplianceScore(freshFindings);
    addScanRecord(accountId, freshFindings.length, score);
    addToast(`Scan completed. ${freshFindings.length} findings found.`, "success");
    // Pulse the chat button after scan so user knows they can ask questions
    setChatMsgCount(0);
  });

  const { history: scanHistory, addScanRecord, clearHistory } = useScanHistory(user?.userId);
  const stats = computeStats(findings);
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);

  const handleScan = (accountId, scanners) => {
    if (!accountId || accountId.length !== 12) {
      addToast("Please enter a valid 12-digit target account ID.", "error");
      return;
    }
    clearFindings();
    
    // Pass the selected scanners array into the triggerScan function
    triggerScan(accountId, scanners).catch(() =>
      addToast("Scan failed. Check API connection.", "error")
    );
  };

  const handleLogin = () => {
    setUser(getCurrentUser());
    navigate("/");
  };

  const handleSignOut = () => {
    signOut();
    clearFindings();
    setUser(null);
    setChatOpen(false);
    navigate("/");
  };

  if (!user) return <AuthPage onLogin={handleLogin} />;

  return (
    <AppContext.Provider value={{
      findings, loading, stats, addToast,
      scannedAccountId, scanHistory, addScanRecord, user,
    }}>
      <div className={`app-shell ${!isSidebarOpen ? 'collapsed' : ''}`}>
        <Topbar
          scanning={scanning}
          lastUpdated={lastUpdated}
          user={user}
          onSignOut={handleSignOut}
          theme={theme}
          setTheme={setTheme}
          isSidebarOpen={isSidebarOpen}
        />
        <Sidebar 
        criticalCount={stats.CRITICAL} 
        isOpen={isSidebarOpen} 
        toggleSidebar={() => setIsSidebarOpen(!isSidebarOpen)} 
      />

        <main className="main-content">
          {error && (
            <div style={{
              background: "var(--critical-dim)",
              border: "1px solid rgba(255,59,92,0.3)",
              borderRadius: "var(--radius-md)",
              padding: "12px 16px",
              marginBottom: 20,
              color: "var(--critical)",
              fontFamily: "var(--font-mono)",
              fontSize: 12,
            }}>
              ⚠ API Error: {error}
            </div>
          )}

          <Routes>
            <Route path="/" element={
              <Dashboard
                findings={findings}
                loading={loading}
                scanning={scanning}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/findings" element={
              <FindingsPage
                findings={findings}
                loading={loading}
                onRefresh={scannedAccountId ? () => refetch(scannedAccountId) : null}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/scan" element={
              <ScanPage
                scanning={scanning}
                scanLog={scanLog}
                onScan={handleScan}
                findingsCount={findings.length}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/reports" element={
              <ReportsPage
                findings={findings}
                addToast={addToast}
                scannedAccountId={scannedAccountId}
              />
            } />
            <Route path="/history"  element={<HistoryPage />} />
          </Routes>
        </main>

        <ToastContainer toasts={toasts} onRemove={removeToast} />

        {/* ── Security Assistant ─────────────────────────────────────────── */}
        <ChatButton
          onClick={() => setChatOpen(o => !o)}
          isOpen={chatOpen}
          hasFindings={findings.length > 0}
          messageCount={chatMsgCount}
        />

        <SecurityAssistant
          findings={findings}
          scannedAccountId={scannedAccountId}
          isOpen={chatOpen}
          onClose={() => setChatOpen(false)}
        />
      </div>
    </AppContext.Provider>
  );
}