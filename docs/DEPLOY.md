# Deploying makina to GCP Cloud Run

The public deployment of `makina.sh` runs as a **single Cloud Run
service** holding both the Rust API and the Python ML inside one
container. The frontend is hosted separately on **Cloudflare Pages**
(free) and points at the Cloud Run URL via `api.makina.sh`.

```
Cloudflare DNS ─┬─→ makina.sh        Pages (SvelteKit static build)
                └─→ api.makina.sh    Cloud Run (Rust + Python ML)
```

This document walks through the one-time GCP setup and the
GitHub Actions secrets/vars the pipeline expects. Once configured,
every push to `main` rebuilds and redeploys automatically.

---

## 1. GCP project + APIs

```bash
gcloud projects create makina-prod                      # or pick an ID you own
gcloud config set project makina-prod
gcloud services enable \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    iamcredentials.googleapis.com \
    sts.googleapis.com
```

`asia-northeast1` (Tokyo) is the assumed region throughout — change it
to suit. Set a billing account on the project before deploying; Cloud
Run is free under the monthly free tier but the project must be linked.

## 2. Artifact Registry

```bash
gcloud artifacts repositories create makina \
    --repository-format=docker \
    --location=asia-northeast1
```

## 3. Service account for deploys

The pipeline assumes the SA is named `makina-deployer`. It needs:

```bash
gcloud iam service-accounts create makina-deployer

PROJECT=makina-prod
SA="makina-deployer@${PROJECT}.iam.gserviceaccount.com"

for role in \
    roles/run.admin \
    roles/artifactregistry.writer \
    roles/iam.serviceAccountUser
do
    gcloud projects add-iam-policy-binding "${PROJECT}" \
        --member="serviceAccount:${SA}" --role="${role}"
done
```

## 4. Workload Identity Federation (no keys!)

GitHub Actions exchanges its OIDC token for a short-lived GCP
credential. No JSON keys leave the repo.

```bash
PROJECT_NUMBER=$(gcloud projects describe makina-prod --format='value(projectNumber)')
GH_REPO="s-zaizen/makina"

# 1. Pool
gcloud iam workload-identity-pools create github-pool \
    --location=global \
    --display-name="GitHub Actions pool"

# 2. Provider — restricted to this single repo
gcloud iam workload-identity-pools providers create-oidc github-provider \
    --location=global \
    --workload-identity-pool=github-pool \
    --display-name="GitHub OIDC" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.ref=assertion.ref" \
    --attribute-condition="assertion.repository == '${GH_REPO}'"

# 3. Bind the SA to the provider — only pushes to main may impersonate
gcloud iam service-accounts add-iam-policy-binding \
    "makina-deployer@makina-prod.iam.gserviceaccount.com" \
    --role=roles/iam.workloadIdentityUser \
    --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-pool/attribute.repository/${GH_REPO}"
```

## 5. GitHub repository configuration

In **Settings → Secrets and variables → Actions → Variables** add:

| Variable           | Value                                                                 |
|--------------------|-----------------------------------------------------------------------|
| `GCP_PROJECT`      | `makina-prod`                                                         |
| `GCP_REGION`       | `asia-northeast1`                                                     |
| `AR_REPO`          | `makina`                                                              |
| `CR_SERVICE`       | `makina-api`                                                          |
| `GCP_DEPLOY_SA`    | `makina-deployer@makina-prod.iam.gserviceaccount.com`                 |
| `WIF_PROVIDER`     | `projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-pool/providers/github-provider` |

No secrets are needed — auth is keyless.

## 6. First deploy

```bash
git push origin main
```

The workflow runs tests, builds the `cloudrun` stage of the Dockerfile,
pushes to Artifact Registry, and deploys. Subsequent pushes are
incremental thanks to Docker layer caching.

The Rust API listens on Cloud Run's injected `$PORT`; the Python ML
sidecar listens on loopback `127.0.0.1:8081` only. `MAKINA_PUBLIC_MODE`
is hardcoded `true` in the deploy step — every learning-loop write is
404'd and `/train` returns 405.

## 7. Custom domain — `api.makina.sh`

```bash
gcloud run domain-mappings create \
    --service makina-api \
    --domain api.makina.sh \
    --region asia-northeast1
```

GCP returns a CNAME target (e.g. `ghs.googlehosted.com`); add that
record on Cloudflare with **proxy status = DNS only** so the TLS
termination happens at Cloud Run and Google's certificate is served.

## 8. Frontend on Cloudflare Pages

In Pages **Connect to Git → s-zaizen/makina → branch `main`** with:

| Setting                | Value                                          |
|------------------------|------------------------------------------------|
| Build command          | `cd frontend && npm ci && npm run build`        |
| Build output directory | `frontend/build`                               |
| Environment variables  | `PUBLIC_API_URL=https://api.makina.sh`         |
|                        | `PUBLIC_MAKINA_PUBLIC_MODE=true`               |

Set `makina.sh` as the custom domain. Cloudflare's edge serves the
static SvelteKit build globally; first paint is sub-100ms.

## Cost expectations

| Component                    | Monthly      |
|------------------------------|--------------|
| Cloud Run, 1 vCPU / 2 GiB / `min-instances=1` | ~$15 |
| Artifact Registry storage    | < $1         |
| Egress (low traffic)         | $0–2         |
| Cloudflare Pages + DNS       | $0           |
| **Total**                    | **~$15–20**  |

`min-instances=0` halves the cost but introduces a 30-60 s cold start
on every fresh visit (CodeBERT load), which is brutal for a public demo.
Keep `min=1` until traffic justifies a scale-to-zero strategy.

## Rollback

```bash
gcloud run services update-traffic makina-api \
    --region asia-northeast1 \
    --to-revisions=<previous-revision>=100
```

Revision history is visible in `gcloud run revisions list --service makina-api`.
