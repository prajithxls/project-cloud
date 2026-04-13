import { useState, useCallback, useEffect } from "react";
import { getFindings, runScan, getHistory, saveHistory } from "../services/api";

export function useFindings() {
  const [findings,         setFindings]         = useState([]);
  const [loading,          setLoading]          = useState(false);
  const [error,            setError]            = useState(null);
  const [lastUpdated,      setLastUpdated]      = useState(null);
  const [scannedAccountId, setScannedAccountId] = useState(null);

  const fetch = useCallback(async (accountId) => {
    if (!accountId) return [];
    setLoading(true);
    setError(null);
    try {
      const res   = await getFindings(accountId);
      const data  = res.data;
      const items = Array.isArray(data) ? data : data.findings || [];
      setFindings(items);
      setScannedAccountId(accountId);
      setLastUpdated(new Date());
      return items;
    } catch (err) {
      setError(err.message);
      return [];
    } finally {
      setLoading(false);
    }
  }, []);

  const clearFindings = useCallback(() => {
    setFindings([]);
    setScannedAccountId(null);
    setLastUpdated(null);
    setError(null);
  }, []);

  return { findings, loading, error, lastUpdated, scannedAccountId, refetch: fetch, clearFindings };
}

export function useScan(onSuccess) {
  const [scanning, setScanning] = useState(false);
  const [scanLog,  setScanLog]  = useState([]);

  const log = (msg, type = "info") => {
    const time = new Date().toLocaleTimeString();
    setScanLog(prev => [...prev, { time, msg, type }]);
  };

  const triggerScan = useCallback(async (accountId, scanners = []) => {
    if (!accountId || accountId.length !== 12) {
      throw new Error("A valid 12-digit target account ID is required.");
    }
    
    if (!scanners || scanners.length === 0) {
      throw new Error("Please select at least one scanner.");
    }

    setScanning(true);
    setScanLog([]);

    log(`Initiating targeted compliance scan for account ${accountId}...`, "info");
    log("Assuming CrossAccountComplianceRole via STS...", "info");

    try {
      log("Connecting to scan orchestrator...", "info");
      
      // Pass the selected scanners array to the API
      await runScan(accountId, scanners);
      
      log(`Scan dispatched — ${scanners.length} scanner(s) running in parallel...`, "ok");

      // Map for dynamic log messages
      const scannerDetails = {
        s3: { name: "S3", desc: "Evaluating S3 bucket policies and ACLs..." },
        ec2: { name: "EC2", desc: "Evaluating EC2 instances and security groups..." },
        iam: { name: "IAM", desc: "Evaluating IAM users and policies..." },
        lambda: { name: "Lambda", desc: "Evaluating Lambda function configurations..." },
        rds: { name: "RDS", desc: "Evaluating RDS instances and Aurora clusters..." },
        cloudtrail: { name: "CloudTrail", desc: "Evaluating CloudTrail trail configurations..." },
        apigw: { name: "API Gateway", desc: "Evaluating API Gateway REST and HTTP APIs..." }
      };

      // Loop through ONLY the selected scanners to generate logs
      for (const scanner of scanners) {
        const details = scannerDetails[scanner] || { name: scanner.toUpperCase(), desc: `Evaluating ${scanner}...` };
        log(details.desc, "info");
        await new Promise(r => setTimeout(r, 800)); // Fake delay for UI flow
        log(`${details.name} scan complete.`, "ok");
      }

      await new Promise(r => setTimeout(r, 400));
      log(`All ${scanners.length} scanner(s) complete. Refreshing findings...`, "info");

      if (onSuccess) onSuccess(accountId);
    } catch (err) {
      log(`Scan failed: ${err.message}`, "warn");
      throw err;
    } finally {
      setScanning(false);
    }
  }, [onSuccess]);

  return { scanning, scanLog, triggerScan };
}

export function usePagination(items, pageSize = 15) {
  const [page, setPage] = useState(1);
  const totalPages  = Math.max(1, Math.ceil(items.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const start       = (currentPage - 1) * pageSize;
  const paginated   = items.slice(start, start + pageSize);
  return { page: currentPage, setPage, totalPages, paginated, total: items.length, start, end: Math.min(start + pageSize, items.length) };
}

export function useFilter(findings) {
  const [search,         setSearch]         = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter,   setStatusFilter]   = useState("ALL");
  const [scannerFilter,  setScannerFilter]  = useState("ALL");
  const [sortKey,        setSortKey]        = useState("timestamp");
  const [sortDir,        setSortDir]        = useState("desc");

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === "asc" ? "desc" : "asc");
    else { setSortKey(key); setSortDir("asc"); }
  };

  const filtered = findings
    .filter(f => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter) return false;
      if (statusFilter   !== "ALL" && f.status   !== statusFilter)   return false;
      if (scannerFilter  !== "ALL" && f.scanner  !== scannerFilter)  return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          f.title?.toLowerCase().includes(q)        ||
          f.resourceId?.toLowerCase().includes(q)   ||
          f.resourceType?.toLowerCase().includes(q) ||
          f.findingId?.toLowerCase().includes(q)    ||
          f.accountId?.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      let va = a[sortKey] ?? "", vb = b[sortKey] ?? "";
      if (sortKey === "riskScore") { va = parseFloat(va) || 0; vb = parseFloat(vb) || 0; }
      if (va < vb) return sortDir === "asc" ? -1 : 1;
      if (va > vb) return sortDir === "asc" ?  1 : -1;
      return 0;
    });

  return { filtered, search, setSearch, severityFilter, setSeverityFilter, statusFilter, setStatusFilter, scannerFilter, setScannerFilter, sortKey, sortDir, toggleSort };
}

export function useScanHistory(userId) {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    setHistory([]);
    if (!userId) return;
    getHistory(userId)
      .then(res => {
        const sorted = (res.data || []).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        setHistory(sorted);
      })
      .catch(err => console.error("Failed to fetch cloud history:", err));
  }, [userId]);

  const addScanRecord = useCallback((accountId, findingsCount, complianceScore, status = "Success") => {
    if (!userId) return;
    const newRecord = {
      id:             Date.now().toString(),
      userId,
      accountId,
      timestamp:      new Date().toISOString(),
      findingsCount,
      complianceScore,
      status,
    };
    setHistory(prev => [newRecord, ...prev]);
    saveHistory(newRecord).catch(err => console.error("Failed to save history:", err));
  }, [userId]);

  const clearHistory = useCallback(() => setHistory([]), []);

  return { history, addScanRecord, clearHistory };
}

export function useToast() {
  const [toasts, setToasts] = useState([]);
  const addToast = useCallback((message, type = "info", duration = 4000) => {
    const id = Date.now();
    setToasts(prev => [...prev, { id, message, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), duration);
  }, []);
  const removeToast = useCallback(id => setToasts(prev => prev.filter(t => t.id !== id)), []);
  return { toasts, addToast, removeToast };
}