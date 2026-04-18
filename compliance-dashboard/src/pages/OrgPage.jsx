// src/pages/OrgPage.jsx
import React, { useState, useEffect } from "react";
import { useApp } from "../App";

export default function OrgPage() {
  const { user, addToast, setOrgId } = useApp();
  const [org, setOrg]               = useState(null);
  const [orgName, setOrgName]       = useState("");
  const [uploading, setUploading]   = useState(false);
  
  const [mode, setMode] = useState("join");
  const [joinOrgId, setJoinOrgId] = useState("");
  const [docs, setDocs]             = useState([]);
  const [creating, setCreating]     = useState(false);

  // Replace this with your actual API Gateway URL if it's not in env variables
  const API = import.meta.env.VITE_API_BASE || "https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev"; 

  // Load user's org on mount
  useEffect(() => {
    if (!user?.userId) return;
    fetch(`${API}/orgs/me?userId=${user.userId}`)
      .then(r => r.json())
      .then(d => { 
        if (d.orgId) { 
          setOrg(d); 
          setOrgId(d.orgId); 
          if (d.documents) setDocs(d.documents);
        } 
      })
      .catch(console.error);
  }, [user?.userId, setOrgId]);

  // Create new org
  const handleCreateOrg = async () => {
    if (!orgName.trim()) return;
    setCreating(true);
    try {
      const res  = await fetch(`${API}/orgs`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ orgName, userId: user.userId }),
      });
      const data = await res.json();
      setOrg(data);
      setOrgId(data.orgId);
      addToast(`Organisation "${orgName}" created.`, "success");
    } catch (e) {
      addToast("Failed to create org: " + e.message, "error");
    } finally { setCreating(false); }
  };

  const handleJoinOrg = async () => {
  if (!joinOrgId.trim()) return;
  setCreating(true);
  try {
    const res = await fetch(`${API}/orgs/${joinOrgId.trim()}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ userId: user.userId }),
    });
    
    if (!res.ok) throw new Error("Organisation not found or invalid ID");
    
    const data = await res.json();
    setOrg(data);
    setOrgId(data.orgId);
    addToast(`Successfully joined ${data.orgName}!`, "success");
  } catch (e) {
    addToast(e.message, "error");
  } finally { setCreating(false); }
};

  const handleLeaveOrg = async () => {
    if (!window.confirm("Are you sure you want to leave this organisation?")) return;
    try {
      const res = await fetch(`${API}/orgs/leave?userId=${user.userId}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Failed to leave organisation");
      setOrg(null);
      setOrgId(null);
      setDocs([]);
      addToast("Successfully left organisation.", "success");
    } catch (e) {
      addToast(e.message, "error");
    }
  };
  // Upload PDF
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file || !org?.orgId) return;
    
    setUploading(true);
    try {
      // 1: Get pre-signed URL from your upload_document Lambda
      const urlRes = await fetch(`${API}/documents/upload-url`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ orgId: org.orgId, userId: user.userId, filename: file.name }),
      });
      const { uploadUrl, s3Key } = await urlRes.json();

      // 2: PUT file directly to S3 (bypasses API Gateway 10MB limit!)
      await fetch(uploadUrl, {
        method:  "PUT",
        headers: { "Content-Type": "application/pdf" },
        body:    file,
      });

      // 3: Trigger the processing Lambda
      await fetch(`${API}/documents/process`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ s3Key }),
      });

      setDocs(prev => [...prev, { name: file.name, uploadedAt: new Date().toLocaleString() }]);
      addToast(`"${file.name}" uploaded and indexed successfully.`, "success");
    } catch (err) {
      addToast("Upload failed: " + err.message, "error");
    } finally { 
      setUploading(false); 
    }
  };

  return (
    <div style={{ maxWidth: "1200px", margin: "0 auto", animation: "fadeIn 0.4s ease-out" }}>
      <div className="page-header">
        <div>
          <div className="page-title">Organisation & Knowledge Base</div>
          <div className="page-title-sub">
            Upload internal compliance policies — the AI Assistant will reference them
          </div>
        </div>
      </div>

      {!org ? (
        <div className="card" style={{ maxWidth: 480 }}>
          <div className="card-header" style={{ display: 'flex', gap: '16px', borderBottom: '1px solid var(--border)', paddingBottom: '12px' }}>
            <span 
              onClick={() => setMode("join")} 
              style={{ cursor: "pointer", fontWeight: mode === "join" ? 600 : 400, color: mode === "join" ? "var(--accent-cyan)" : "var(--text-muted)" }}
            >
              Join Existing
            </span>
            <span 
              onClick={() => setMode("create")} 
              style={{ cursor: "pointer", fontWeight: mode === "create" ? 600 : 400, color: mode === "create" ? "var(--accent-cyan)" : "var(--text-muted)" }}
            >
              Create New
            </span>
          </div>
          
          <div style={{ marginTop: '20px' }}>
            {mode === "join" ? (
              <>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 16 }}>
                  Enter the Organisation ID provided by your team administrator to join their workspace.
                </p>
                <input
                  style={{ width: "100%", padding: "10px", background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: "6px", color: "white", marginBottom: 12 }}
                  placeholder="e.g. org_123abc..."
                  value={joinOrgId}
                  onChange={e => setJoinOrgId(e.target.value)}
                />
                <button className="btn btn-primary" onClick={handleJoinOrg} disabled={creating || !joinOrgId.trim()}>
                  {creating ? "Joining..." : "Join Organisation"}
                </button>
              </>
            ) : (
              <>
                <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 16 }}>
                  Create a new organisation to group your team and build a private knowledge base.
                </p>
                <input
                  style={{ width: "100%", padding: "10px", background: "var(--bg-base)", border: "1px solid var(--border)", borderRadius: "6px", color: "white", marginBottom: 12 }}
                  placeholder="e.g. Security Team Alpha"
                  value={orgName}
                  onChange={e => setOrgName(e.target.value)}
                />
                <button className="btn btn-primary" onClick={handleCreateOrg} disabled={creating || !orgName.trim()}>
                  {creating ? "Creating..." : "+ Create Organisation"}
                </button>
              </>
            )}
          </div>
        </div>
      ) : (
        <>
          {/* Org info */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <span className="card-title">Organisation</span>
                <span style={{ 
                  fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
                  color: "var(--low)", background: "var(--low-dim)",
                  border: "1px solid rgba(34, 197, 94, 0.2)", padding: "2px 10px", borderRadius: 20, marginLeft: 12
                }}>
                  ACTIVE
                </span>
              </div>
              <button onClick={handleLeaveOrg} style={{
                background: "transparent", border: "1px solid var(--border)", color: "var(--text-muted)",
                padding: "6px 12px", borderRadius: "6px", fontSize: "12px", cursor: "pointer", transition: "all 0.2s"
              }}
              onMouseEnter={e => { e.currentTarget.style.color = "var(--accent-red)"; e.currentTarget.style.borderColor = "var(--accent-red)"; }}
              onMouseLeave={e => { e.currentTarget.style.color = "var(--text-muted)"; e.currentTarget.style.borderColor = "var(--border)"; }}>
                Leave
              </button>
            </div>
            <div style={{ display: "flex", gap: 32, flexWrap: "wrap" }}>
              {[
                { label: "ORG NAME",  value: org.orgName },
                { label: "ORG ID",    value: org.orgId },
                { label: "DOCUMENTS", value: `${org.documentCount || docs.length} indexed` },
                { label: "NAMESPACE", value: org.pineconeNamespace || org.orgId },
              ].map(item => (
                <div key={item.label}>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", letterSpacing: "0.1em", marginBottom: 4 }}>
                    {item.label}
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 600, color: "var(--accent-cyan)" }}>
                    {item.value}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Upload section */}
          <div className="card" style={{ borderTop: "2px solid var(--accent-cyan)" }}>
            <div className="card-header">
              <span className="card-title">Upload Compliance Documents</span>
            </div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginBottom: 24 }}>
              Upload PDFs — internal security policies, SOC2 reports, custom runbooks, audit findings. 
              The AI Assistant will use these alongside global rules to answer your questions.
            </p>

            <label style={{
              display: "flex", flexDirection: "column", alignItems: "center", gap: 12,
              padding: "40px", border: "2px dashed var(--border)", borderRadius: "var(--radius-lg)",
              cursor: uploading ? "not-allowed" : "pointer", transition: "border-color 0.15s",
              background: "var(--bg-base)"
            }}
              onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = "var(--accent-cyan)"; }}
              onDragLeave={e => { e.currentTarget.style.borderColor = "var(--border)"; }}
              onDrop={e => {
                e.preventDefault();
                e.currentTarget.style.borderColor = "var(--border)";
                const file = e.dataTransfer.files[0];
                if (file && !uploading) handleFileUpload({ target: { files: [file] } });
              }}
            >
              <div style={{ fontSize: 32, opacity: 0.4 }}>📄</div>
              <div style={{ fontSize: 14, color: "var(--text-primary)", fontWeight: 600 }}>
                {uploading ? <><span className="spinner" style={{marginRight: 8}}/> Indexing to Pinecone...</> : "Drop PDF here or click to browse"}
              </div>
              <div style={{ fontSize: 11, color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                PDF only · Max 10MB per file
              </div>
              <input type="file" accept=".pdf" style={{ display: "none" }} onChange={handleFileUpload} disabled={uploading} />
            </label>

            {/* Uploaded docs list */}
            {docs.length > 0 && (
              <div style={{ marginTop: 24, display: "flex", flexDirection: "column", gap: 8 }}>
                {docs.map((doc, i) => (
                  <div key={i} style={{
                    display: "flex", alignItems: "center", gap: 16, padding: "12px 16px",
                    background: "var(--bg-elevated)", border: "1px solid var(--border)",
                    borderRadius: "var(--radius-md)",
                  }}>
                    <div style={{ fontSize: 18, opacity: 0.6 }}>◧</div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-primary)" }}>
                        {doc.name}
                      </div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--text-muted)", marginTop: 4 }}>
                        Indexed · {new Date(doc.uploadedAt).toLocaleString()}
                      </div>
                    </div>
                    <span style={{ 
                      fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 700,
                      color: "var(--low)", background: "var(--low-dim)",
                      padding: "4px 8px", borderRadius: 4 
                    }}>
                      ✓ SECURE
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}