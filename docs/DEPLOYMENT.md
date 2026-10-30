# CyberDuel AI — Deployment Architecture & Production Guide

## 1. Deployment Topology

CyberDuel AI is designed to deploy across containerized PaaS environments (e.g. Railway, GCP Cloud Run, AWS ECS) or Kubernetes.

```
                     [Cloudflare / Ingress Edge]
                                  |
                           (TLS Termination)
                                  |
                                  v
                    [CyberDuel API Service (FastAPI)]
                                  |
                +-----------------+-----------------+
                |                                   |
                v                                   v
      [Managed PostgreSQL 16]              [Managed Redis 7]
                |
                v
  [Isolated Worker Cluster (Firecracker / VPC Isolated)]
```

---

## 2. Production Security Checklist

- [ ] `ENVIRONMENT` set to `production`.
- [ ] `DEBUG` set to `false`.
- [ ] `SECRET_KEY` rotated to a high-entropy string ($\ge 32$ characters) stored in a secure secret manager.
- [ ] `CORS_ORIGINS` strictly limited to authorized production frontend origins.
- [ ] PostgreSQL connections enforce TLS (`sslmode=require`).
- [ ] Database migrations executed as a pre-deploy release hook (`alembic upgrade head`).
- [ ] Laboratory workers deployed on private VPC subnets with egress internet blocked.
- [ ] Production release signing keys isolated in KMS/HSM.
- [ ] Centralized structured JSON logging streaming to Datadog/CloudWatch.

---

## 3. Deploying to Railway

The repository includes root `railway.json` and service-specific configurations for multi-service deployment.
See the comprehensive [Railway Deployment Guide](file:///c:/Users/abhay/OneDrive/Desktop/CYBERDUEL%20AI/docs/RAILWAY_DEPLOYMENT.md) for full instructions, topology diagrams, and environment variable matrices.

### Railway Quick Checklist:
1. Connect Git repository in Railway.
2. Add **PostgreSQL 16** and **Redis 7** managed plugins.
3. Attach persistent volume `/app/storage/releases` to `cyberduel-api`.
4. Configure required environment variables (`SECRET_KEY`, `ENVIRONMENT=production`, `DEBUG=false`).
5. Execute preflight validation before cutover:
   ```bash
   python scripts/railway_preflight.py
   ```
6. Deploy `cyberduel-api`, `cyberduel-worker`, and `cyberduel-dashboard`. Health checks automatically verify `/health/live` before routing traffic.


