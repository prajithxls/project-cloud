# Secret Rotation and Storage Guide

This repository had exposed keys in Git history. Treat those keys as compromised.

## Immediate rotation checklist

1. Rotate `GOOGLE_API_KEY`.
2. Rotate `PINECONE_API_KEY`.
3. Update new keys only in secure secret stores (never in source files).
4. Verify old keys are disabled and cannot be used.

## Where secrets must live

- Vercel project environment variables for frontend/runtime config.
- AWS Secrets Manager or SSM Parameter Store for backend Lambda secrets.
- Local developer `.env` files (ignored by Git) for local testing only.

## GitHub protections to enable

1. Enable Secret scanning.
2. Enable Push protection for secret scanning.
3. Restrict who can force-push protected branches after incident cleanup.

## Verification command

Run this before every push:

```bash
git log --all -S "AIza" --oneline
git log --all -S "pcsk_" --oneline
```

Both commands should return no results for known leaked values.
