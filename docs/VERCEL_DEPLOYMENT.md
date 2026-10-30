# CyberDuel AI — Vercel Deployment Guide

This guide outlines how to prepare and deploy CyberDuel AI on [Vercel](https://vercel.com).

---

## Architecture Overview

CyberDuel AI consists of:
1. **Command Center Dashboard** (`apps/dashboard`): Modern React + Vite SPA.
2. **Core API Application** (`apps/api`): FastAPI ASGI service.
3. **Research Laboratory & Policy Engine** (`packages/*`, `services/*`): Threat detection, AI agents, and cryptographic release management.

---

## Deployment Strategy

You can deploy on Vercel using either of the following two deployment models:

### Model A: Standalone Dashboard on Vercel (Recommended)
Deploy the Command Center Dashboard on Vercel's global edge network and connect it to a persistent FastAPI backend (on Railway, Render, or any VPS).

- **Best for:** Hackathon demos, high availability, sub-second global dashboard load times, and persistent background workers.
- **Frontend:** Vercel edge CDN.
- **Backend:** Railway / VPS (handles long-running Red/Blue AI experiments, PostgreSQL, and cryptographic signing).

#### Step-by-Step Instructions:
1. Log in to [Vercel](https://vercel.com) and click **"Add New..."** -> **"Project"**.
2. Select your repository: `abhaysharma000/CYBERDUEL-AI`.
3. In the **Configure Project** screen:
   - **Framework Preset**: `Vite` (automatically detected).
   - **Root Directory**: Click *Edit* and select `apps/dashboard`.
   - **Build Command**: `npm run build` (default).
   - **Output Directory**: `dist` (default).
4. Under **Environment Variables**, add:
   ```env
   VITE_API_URL=https://<your-backend-domain>.up.railway.app
   ```
   *(Or your hosted backend URL. If not set, it defaults to `/api/v1` on the same domain).*
5. Click **"Deploy"**.
6. SPA routing is already configured via `apps/dashboard/vercel.json`, so page refreshes (`/threats`, `/policies`, `/experiments`) will work seamlessly without 404 errors.

---

### Model B: Fullstack Monorepo on Vercel (Dashboard + Serverless FastAPI)
Deploy both the frontend and the FastAPI backend directly on Vercel as Serverless Functions using the root `vercel.json` and `api/index.py` bridge.

- **Best for:** Lightweight serverless deployments where external background daemons are not required.

#### Step-by-Step Instructions:
1. In Vercel, import `abhaysharma000/CYBERDUEL-AI`.
2. Leave **Root Directory** as `./` (the repository root).
3. Under **Environment Variables**, configure:
   ```env
   ENVIRONMENT=production
   SECRET_KEY=generate_a_secure_32_character_secret_key_here
   DATABASE_URL=postgresql+asyncpg://user:pass@ep-xyz.neon.tech/cyberduel
   QWEN_API_KEY=your_qwen_or_deepinfra_api_key
   QWEN_API_BASE=https://api.deepinfra.com/v1/openai
   QWEN_MODEL_NAME=Qwen/Qwen2.5-Coder-7B-Instruct
   AI_PROVIDER_TYPE=qwen
   CORS_ORIGINS=https://<your-vercel-domain>.vercel.app
   ```
   *(Note: Because Vercel serverless filesystems are ephemeral and read-only outside `/tmp`, a hosted PostgreSQL database like Neon, Supabase, or Railway Postgres is required for persistent production records).*
4. Click **"Deploy"**.

---

## Verifying Deployment

Once deployed, verify the endpoints:
- **Dashboard UI**: `https://<your-app>.vercel.app/`
- **System Health Check**: `https://<your-app>.vercel.app/api/v1/health`
- **Interactive API Documentation**: `https://<your-app>.vercel.app/docs`
- **Audit Logs & Telemetry**: Check the dashboard Overview and Audit screens.

---

## Edge Client Connectivity

Once your Vercel deployment URL is live (e.g. `https://cyberduel-command.vercel.app`):
1. **Browser Extension**: Set `VITE_BACKEND_URL` in `apps/browser-extension/.env` to your API URL before packing the extension.
2. **Android Mobile App**: Set the backend URL in the mobile app settings or `ApiConfig.kt` to point to your live deployment.
