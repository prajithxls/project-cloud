# CloudGuard — Cloud Compliance & Audit Management Dashboard

A professional React frontend for the Cloud Security Compliance and Audit Management System.

---

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Configure the API endpoint

```bash
cp .env.example .env
```

Then open `.env` and set your actual API Gateway URL:

```env
VITE_API_BASE=https://YOUR_API_ID.execute-api.ap-south-1.amazonaws.com/dev
VITE_CSV_BUCKET=https://csv-output-buckett.s3.amazonaws.com/
```

### 3. Run the development server

```bash
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser.

### 4. Build for production

```bash
npm run build
npm run preview
```

---

## Project Structure

```
src/
├── components/
│   ├── charts/
│   │   ├── ComplianceScore.jsx   # SVG compliance ring chart
│   │   ├── ScannerBarChart.jsx   # Findings by scanner bar chart
│   │   └── SeverityDonut.jsx     # Severity distribution donut chart
│   ├── layout/
│   │   ├── Sidebar.jsx           # Left navigation sidebar
│   │   └── Topbar.jsx            # Top navigation bar
│   └── ui/
│       ├── FindingsTable.jsx     # Sortable, paginated findings table
│       └── Toast.jsx             # Notification toasts
├── hooks/
│   └── useCompliance.js          # Custom hooks: useFindings, useScan, useFilter, usePagination, useToast
├── pages/
│   ├── Dashboard.jsx             # Overview with stats, charts, recent findings
│   ├── FindingsPage.jsx          # Full findings table with search/filter
│   ├── ReportsPage.jsx           # CSV report download
│   └── ScanPage.jsx              # Trigger compliance scans
├── services/
│   └── api.js                    # Axios API service (all backend calls)
├── styles/
│   └── global.css                # Full design system CSS
├── utils/
│   └── helpers.js                # Stats, formatting, chart color utilities
├── App.jsx                       # Root component with routing + global state
└── main.jsx                      # Entry point
```

---

## Features

- **Dashboard** — Stat cards, severity donut chart, scanner bar chart, compliance score ring, recent critical findings, compliance framework breakdown
- **Findings Table** — Searchable, filterable (severity, status, scanner), sortable by any column, paginated (15 per page)
- **Scan Trigger** — Full compliance scan with live log output, individual scanner info cards
- **Reports** — Download latest CSV from S3, generate new report, export current findings client-side

---

## Backend API Endpoints Used

| Method | Path | Description |
|--------|------|-------------|
| GET | `/scan` | Trigger full compliance scan |
| GET | `/scan/s3` | Trigger S3 scanner only |
| GET | `/scan/ec2` | Trigger EC2 scanner only |
| GET | `/scan/iam` | Trigger IAM scanner only |
| GET | `/findings` | Fetch all findings from DynamoDB |
| GET | `/refresh` | Refresh findings + generate CSV |

---

## Technology Stack

- **React 18** — Component framework
- **Vite 5** — Build tool
- **React Router 6** — Client-side routing
- **Axios** — HTTP client
- **Chart.js + react-chartjs-2** — Dashboard charts
- **Custom CSS** — No UI library dependency (Syne + Space Mono fonts)

---

## Connecting to Production

1. Deploy your Serverless backend: `serverless deploy`
2. Copy the API Gateway URL from the output
3. Update `VITE_API_BASE` in your `.env` file
4. Ensure CORS is enabled on all endpoints (already configured in serverless.yml)

---

## CORS Note

If you see CORS errors in the browser console, verify that:
- Your API Gateway endpoints allow `Access-Control-Allow-Origin: *`
- The S3 bucket has a CORS policy allowing GET from your domain
