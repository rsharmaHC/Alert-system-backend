# Railway Deployment Guide

## Overview

This project uses a **monorepo deployment strategy** on Railway with three separate services:
1. **API Service** - Web server (FastAPI/Uvicorn)
2. **Worker Service** - Celery worker for background tasks
3. **Beat Service** - Celery beat for scheduled tasks

## Service Configuration

### Configuration Files

| File | Purpose |
|------|---------|
| `railway.toml` | Default config (no healthcheck - safe for all) |
| `railway.api.toml` | API service config (with `/health` check) |
| `railway.worker.toml` | Worker service config (no healthcheck) |
| `railway.beat.toml` | Beat service config (no healthcheck) |

## Setup Instructions

### 1. Create Three Services in Railway

For each service (API, Worker, Beat):

1. Go to Railway dashboard
2. Click **New Project**
3. Select **Deploy from GitHub repo**
4. Connect your repository

### 2. Configure Each Service

#### API Service
```
Settings → Configuration
- SERVICE_TYPE: api
- Healthcheck Path: /health (or use railway.api.toml)
```

#### Worker Service
```
Settings → Configuration
- SERVICE_TYPE: worker
- Healthcheck Path: (leave empty)
```

#### Beat Service
```
Settings → Configuration
- SERVICE_TYPE: beat
- Healthcheck Path: (leave empty)
```

### 3. Set Environment Variables

All three services need these environment variables:

```bash
# Database
DATABASE_URL=postgresql://...

# Redis (for Celery)
REDIS_URL=redis://...

# Application
ENVIRONMENT=production
SECRET_KEY=your-secret-key
SERVICE_TYPE=api|worker|beat

# Twilio (for SMS/Voice)
TWILIO_ACCOUNT_SID=...
TWILIO_AUTH_TOKEN=...
TWILIO_FROM_NUMBER=...

# Email (SES)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=...
SES_FROM_EMAIL=...

# Optional: Webhooks
SLACK_WEBHOOK_URL=...
TEAMS_WEBHOOK_URL=...
```

### 4. Deploy Order

1. **Deploy API first** - Runs migrations on startup
2. **Deploy Worker** - Starts processing tasks
3. **Deploy Beat** - Starts scheduling tasks

## How It Works

### Startup Flow

```
┌─────────────────────────────────────────────────────────┐
│  Container Starts                                       │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  start.sh detects SERVICE_TYPE                          │
│  - api → runs uvicorn                                   │
│  - worker → runs celery worker                          │
│  - beat → runs celery beat                              │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Before starting service:                               │
│  1. validate_db_schema.py --fix (auto-fix columns)      │
│  2. alembic upgrade head (run migrations)               │
└─────────────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│  Service starts                                         │
└─────────────────────────────────────────────────────────┘
```

### Healthcheck Behavior

| Service | Healthcheck | Why |
|---------|-------------|-----|
| API | ✅ `/health` | Has HTTP endpoint |
| Worker | ❌ None | No HTTP endpoint |
| Beat | ❌ None | No HTTP endpoint |

**Important:** Workers and Beat services do NOT have HTTP endpoints. Railway monitors them via process health instead.

## Troubleshooting

### Worker/Beat Failing Healthchecks

**Problem:** `Attempt #1 failed with service unavailable`

**Solution:** 
1. Go to Railway dashboard
2. Select the Worker/Beat service
3. Settings → Configuration
4. Clear the **Healthcheck Path** field (make it empty)
5. Save and redeploy

### API Not Starting

**Check logs for:**
- Database connection errors
- Missing environment variables
- Migration failures

**Fix:**
```bash
# Check Railway logs
railway logs --service api

# Or view in dashboard: Deployments → View Logs
```

### Migrations Not Running

**Problem:** Schema errors in production

**Solution:**
1. Check that `start.sh` is being used as CMD in Dockerfile
2. Verify migrations exist: `alembic history`
3. Manually trigger: `alembic upgrade head`

### Service Crashes

**Check:**
1. Railway dashboard → Deployments → View Logs
2. Look for OOM (Out of Memory) errors
3. Check restart policy settings

**Fix:**
- Increase memory limit in Railway settings
- Set `restartPolicyType = "ON_FAILURE"`
- Set `restartPolicyMaxRetries = 5`

## Using Config Files

### Option 1: Use railway.toml directly

In Railway Dashboard:
```
Settings → Advanced → Config File
 railway.toml
```

### Option 2: Set via Environment

Instead of config files, set these in Railway:

**For API:**
```
HEALTHCHECK_PATH=/health
SERVICE_TYPE=api
```

**For Worker:**
```
HEALTHCHECK_PATH=
SERVICE_TYPE=worker
```

**For Beat:**
```
HEALTHCHECK_PATH=
SERVICE_TYPE=beat
```

## Deployment Commands

### Local Testing

```bash
# Test API locally
SERVICE_TYPE=api ./start.sh

# Test Worker locally
SERVICE_TYPE=worker ./start.sh

# Test Beat locally
SERVICE_TYPE=beat ./start.sh
```

### Deploy to Railway

```bash
# Push to trigger deploy
git push origin main

# Or use Railway CLI
railway up
```

## Monitoring

### View Logs

```bash
# API logs
railway logs --service api

# Worker logs
railway logs --service worker

# Beat logs
railway logs --service beat
```

### Check Service Health

```bash
# API health endpoint
curl https://your-api.railway.app/health

# Worker/Beat - check Railway dashboard for process status
```

## Best Practices

1. **Always set SERVICE_TYPE** - Ensures correct service starts
2. **Use separate services** - API, Worker, Beat should be separate Railway services
3. **Disable healthchecks for workers** - They don't have HTTP endpoints
4. **Monitor all three services** - Check logs regularly
5. **Set resource limits** - Prevent OOM errors
6. **Use environment variables** - Don't hardcode secrets

## Quick Reference

| Service | SERVICE_TYPE | Healthcheck Path | Command |
|---------|--------------|------------------|---------|
| API | `api` | `/health` | `uvicorn app.main:app` |
| Worker | `worker` | (empty) | `celery -A app.celery_app worker` |
| Beat | `beat` | (empty) | `celery -A app.celery_app beat` |
