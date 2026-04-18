import axios from "axios";

const API_BASE =
  import.meta.env.VITE_API_BASE ||
  "https://4xhy1jajvb.execute-api.ap-south-1.amazonaws.com/dev";

export const CSV_BUCKET_URL =
  import.meta.env.VITE_CSV_BUCKET ||
  "https://csv-output-buckett.s3.amazonaws.com/";

const api = axios.create({
  baseURL: API_BASE,
  timeout: 60000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const message =
      err.response?.data?.message || err.message || "An unexpected error occurred";
    return Promise.reject(new Error(message));
  }
);

export const runScan = (accountId, scanners = [], orgId) => {
  let url = `/scan?accountId=${accountId}`;
  if (scanners && scanners.length > 0) {
    url += `&scanners=${scanners.join(",")}`;
  }
  if (orgId) {
    url += `&orgId=${orgId}`;
  }
  return api.get(url);
};
export const getFindings     = (accountId) => api.get(`/findings?accountId=${accountId}`);
export const refreshFindings = (accountId) => api.get(`/refresh?accountId=${accountId}`);

export const listReports = async () => {
  try {
    const response = await axios.get(CSV_BUCKET_URL, { timeout: 10000 });
    const parser   = new DOMParser();
    const xml      = parser.parseFromString(response.data, "text/xml");
    const keys     = Array.from(xml.querySelectorAll("Key")).map((k) => k.textContent);
    return keys.filter((k) => k.endsWith(".csv")).sort().reverse();
  } catch {
    return [];
  }
};

export const getReportDownloadUrl = (filename) => `${CSV_BUCKET_URL}${filename}`;
export const getHistory           = (userId)   => api.get(`/history?userId=${userId}`);
export const saveHistory          = (data)     => api.post("/history", data);

// ── Security Assistant ────────────────────────────────────────────────────────
// POST /assistant  { message, findings, conversationHistory, accountId }
export const sendChatMessage = (payload) => api.post("/assistant", payload);

export default api;