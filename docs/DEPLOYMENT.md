# Deployment Guide

TraceGuard is optimized for deployment on Vercel or as a self-hosted Docker container.

## 1. Vercel (Recommended)

Because TraceGuard uses chunked scanning (one API call per service), it operates within Vercel's free tier execution limits (10s limit, broken into ~20 separate calls).

1. **Fork the repository** on GitHub.
2. **Import Project** in Vercel.
3. Set the required **Environment Variables** (see below).
4. **Sanity CORS:** Ensure your production Vercel URL is added to the Sanity project's CORS configuration with credentials enabled.

## 2. Self-Hosted (Docker)

### `Dockerfile`
```dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runner
WORKDIR /app
COPY --from=builder /app/next.config.js ./
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3000
CMD ["node", "server.js"]
```

### `docker-compose.yml`
```yaml
version: '3.8'
services:
  traceguard:
    build: .
    ports:
      - "3000:3000"
    environment:
      - SANITY_PROJECT_ID=${SANITY_PROJECT_ID}
      - SANITY_API_TOKEN=${SANITY_API_TOKEN}
      - CREDENTIAL_ENCRYPTION_KEY=${CREDENTIAL_ENCRYPTION_KEY}
      - GOOGLE_GENERATIVE_AI_API_KEY=${GOOGLE_GENERATIVE_AI_API_KEY}
```

## 3. Environment Variables Reference

| Variable | Description |
|---|---|
| `SANITY_PROJECT_ID` | **Required**. Your Sanity project ID. |
| `SANITY_API_TOKEN` | **Required**. Token with write access. |
| `SANITY_DATASET` | Default: `production`. |
| `NEXT_PUBLIC_SANITY_PROJECT_ID` | **Required**. (client-side) |
| `NEXT_PUBLIC_SANITY_DATASET` | **Required**. (client-side) |
| `SANITY_API_VERSION` | Default: `2024-01-01`. |
| `GOOGLE_GENERATIVE_AI_API_KEY` | **Required** for AI pipeline. |
| `AI_PROVIDER` | Default: `google`. |
| `AI_MODEL` | Default: `gemini-3.6-flash`. |
| `CREDENTIAL_ENCRYPTION_KEY` | **Required**. (64-char hex, 32 bytes) |
| `AWS_ACCESS_KEY_ID` | Optional (env-mode accounts). |
| `AWS_SECRET_ACCESS_KEY` | Optional (env-mode accounts). |
| `AWS_REGION` | Default: `us-east-1`. |
| `GCP_SERVICE_ACCOUNT_JSON` | Optional (env-mode accounts). |
| `NEXT_PUBLIC_APP_URL` | Your deployment URL. |

## 4. Sanity Setup Guide
1. Go to [Sanity.io](https://www.sanity.io) and create a project.
2. Go to **API > Tokens** and generate an Editor token.
3. Go to **API > CORS Origins** and add `http://localhost:3000` and your production URL. Check "Allow credentials".

## 5. Generating the Encryption Key
To securely encrypt cloud credentials, you need a 32-byte hex key:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```
Place this in `CREDENTIAL_ENCRYPTION_KEY`.

## 6. Production Checklist
1. [ ] Generate strong `CREDENTIAL_ENCRYPTION_KEY`.
2. [ ] Restrict Sanity API Token scopes.
3. [ ] Set `NEXT_PUBLIC_APP_URL` correctly.
4. [ ] Configure CORS in Sanity.
5. [ ] Ensure no local API keys are committed.
6. [ ] Set up billing alerts for cloud providers.
7. [ ] Validate Gemini API quotas.
8. [ ] Verify Vercel / Docker logs are functioning.
9. [ ] Run a test scan in an isolated environment.
10. [ ] Enforce HTTPS only.
