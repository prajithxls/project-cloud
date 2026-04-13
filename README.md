# Project Cloud Compliance (CloudGuard)

A cloud compliance scanning system consisting of:
- **AWS Serverless backend** (`infra/compliance-scanners`): Python Lambdas behind API Gateway that scan AWS resources and store findings in DynamoDB (and can export CSVs to S3).
- **React dashboard** (`compliance-dashboard`): UI to trigger scans, view findings, and download reports.

---

## Repository structure

- `infra/compliance-scanners/`
  - `serverless.yml` — Serverless Framework service (API Gateway + Lambdas + DynamoDB table)
  - `lambdas/*/app.py` — scanner lambdas and findings/report lambda
- `compliance-dashboard/`
  - Vite + React dashboard frontend
- `frontend/` / `backend/`
  - Additional Node projects (if used in your environment)

---

## What the system does

### 1) Run scans (per AWS account)
The dashboard calls:

- `GET /scan?accountId=<12-digit-account-id>`

The backend fans out to 4 scanners (in parallel) and writes findings into DynamoDB table `Findings`:

- S3 scanner
- EC2 scanner
- IAM scanner
- Lambda scanner

### 2) View findings
The dashboard fetches findings (scoped to an accountId):

- `GET /findings?accountId=<12-digit-account-id>`

### 3) Generate CSV reports
The backend can generate a fresh CSV for an account and upload to S3:

- `GET /refresh?accountId=<12-digit-account-id>`

The dashboard can list/download CSVs from the configured bucket URL.

---

## Backend: `infra/compliance-scanners`

### Deploy prerequisites
- AWS credentials configured for deployment
- Serverless Framework installed (`serverless` / `sls`)
- Python 3.9 runtime (AWS Lambda runtime is set to python3.9)

### Deploy
```bash
cd infra/compliance-scanners
serverless deploy