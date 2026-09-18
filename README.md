# Drox Command Tower ⚡

**Centralized Sovereign Licensing, Entitlements & Customer Kill-Switch Hub**  
*The central control deck for TradePost and all DroxAI ecosystem applications.*

---

## 🌟 Overview

**Drox Command Tower** is a local-first, production-grade licensing and customer entitlements server built on FastAPI and SQLite (WAL mode). It provides sovereign cryptographic validation, centralized API proxying, automated payment lifecycle synchronization, and instant one-click customer/key kill switches.

### Core Capabilities

1. **Dual-Mode Credential Issuance**:
   * **Desktop Licenses (TradePost Ed25519)**: Asymmetrically signed URL-safe tokens verified offline or online by Aegis / TradePost terminals using the sovereign root public key.
   * **Cloud/Live API Keys**: Cryptographically hashed using PBKDF2-HMAC-SHA256 (100,000 iterations), with raw tokens displayed only once.
2. **Central Verification & Entitlement Enforcement (`/api/v1/entitlements/verify`)**:
   * Boot-time and polling verification endpoint for TradePost and external apps.
   * **Fail-closed security**: Instantly returns `REVOKED` (HTTP 402/403) if a customer's kill switch has been tripped, if their account is `SUSPENDED`, or if their payment is `PAST_DUE` beyond the grace period.
3. **One-Click Sovereign Kill Switch**:
   * Instant administrative toggle (`POST /api/v1/admin/customers/{id}/toggle-kill`) that flips the customer to `SUSPENDED` and immediately deactivates all active keys and desktop licenses.
   * Instant restoration toggle (`POST /api/v1/admin/customers/{id}/restore`) that re-enables access across all credentials.
   * Granular per-key kill switches (`POST /api/v1/admin/credentials/{key_id}/toggle-kill`).
4. **API Gateway & Reverse Proxy (`/api/v1/proxy/{project_slug}/*`)**:
   * Validates incoming caller credentials, increments usage metrics, and rejects non-entitled or killed callers with HTTP 402/403.
5. **Stripe Webhook Ingestion (`/api/v1/webhooks/stripe`)**:
   * `invoice.payment_succeeded`: Automatically marks customer `ACTIVE`, extends subscription period, and reactivates credentials.
   * `invoice.payment_failed`: Flags account `PAST_DUE`.
   * `customer.subscription.deleted`: Instantly cascades the kill switch (`is_active = 0`).
6. **Cyber-Dark Command Center HUD (`www/index.html`)**:
   * High-contrast, neon-carbon operator cockpit with live telemetry (MRR, Active Customers, Tripped Kill Switches).
   * Real-time scrolling audit radar feed of verification pings and blocked attempts.

---

## 🏗️ Architecture & Database Schema

The hub runs in high-concurrency **SQLite WAL Mode** (`droxaitower.db`) with foreign-key integrity:

* `customers`: `customer_id`, `email`, `company_name`, `billing_status` (`ACTIVE`, `PAST_DUE`, `SUSPENDED`, `CANCELLED`, `LIFETIME`), `payment_method`, `stripe_customer_id`, `created_at`, `notes`.
* `projects`: `project_slug` (e.g., `tradepost`, `securosoc`, `ai-proxy`), `name`, `description`, `is_active`.
* `subscriptions`: `subscription_id`, `customer_id`, `project_slug`, `plan_tier` (`STANDARD`, `PRO`, `ENTERPRISE`, `LIFETIME`), `billing_interval`, `amount_usd`, `current_period_start`, `current_period_end`, `grace_period_days`, `is_auto_kill_enabled`.
* `credentials`: `key_id`, `customer_id`, `project_slug`, `credential_type` (`API_KEY`, `DESKTOP_LICENSE`), `raw_token_preview`, `key_hash`, `is_active` (**THE KILL SWITCH**), `revoked_reason`, `last_seen_at`, `created_at`.
* `audit_log`: `id`, `key_id`, `customer_id`, `project_slug`, `action` (`API_CALL`, `VERIFY_PING`, `KILL_SWITCH`, `PAYMENT_SYNC`, `CREDENTIAL_ISSUED`), `ip_address`, `status_code`, `latency_ms`, `timestamp`.

---

## 🚀 Quick Start

### 1. Requirements
* Python 3.12 or higher
* `uv` package manager

### 2. Install Dependencies
```bash
uv sync
```

### 3. Launch Command Tower Interactively
```bash
uv run python server.py
```
* **Cockpit Operator HUD**: `http://127.0.0.1:8088/`
* **Swagger API Docs**: `http://127.0.0.1:8088/docs`

### 4. Run as a 24/7 Background Windows Service (NSSM)
The Windows service scripts expect NSSM to be installed locally under `nssm-2.24/`. That directory is intentionally excluded from Git.

```powershell
# Install & start service (automatically self-elevates to Administrator)
.\service_install.ps1

# Inspect status and live API health
.\service_control.ps1 -Action status

# Tail service logs
.\service_control.ps1 -Action logs

# Uninstall service
.\service_uninstall.ps1
```

### 5. Run Test Suite & Linters
```bash
# Execute unit and integration tests
uv run pytest -v

# Run code style & formatting checks
uv run ruff check .
uv run ruff format --check .
```

---

## 📡 API Reference

| Endpoint | Method | Auth | Description |
| :--- | :---: | :---: | :--- |
| `/` | GET | None | Cyber-Dark Operator Cockpit HUD |
| `/api/v1/entitlements/verify` | GET | Public / Key | Verifies API key or TradePost Ed25519 token (returns ACTIVE / REVOKED) |
| `/api/v1/proxy/{project_slug}/{path}` | ANY | API Key | Gateway reverse proxy with 402/403 kill switch enforcement |
| `/api/v1/admin/stats` | GET | Master Key | Operational telemetry (MRR, Active Customers, Tripped Kill Switches) |
| `/api/v1/admin/customers` | GET, POST | Master Key | List and create customer accounts and subscriptions |
| `/api/v1/admin/customers/{id}/toggle-kill` | POST | Master Key | **One-click kill switch** (immediately cuts off all credentials) |
| `/api/v1/admin/customers/{id}/restore` | POST | Master Key | **One-click restore** (reactivates customer and credentials) |
| `/api/v1/admin/credentials/issue` | POST | Master Key | Issue live Cloud API key or TradePost Ed25519 desktop license |
| `/api/v1/admin/credentials/{id}/toggle-kill` | POST | Master Key | Toggle kill switch on a single credential |
| `/api/v1/admin/audit-logs` | GET | Master Key | Live scrolling radar audit logs |
| `/api/v1/webhooks/stripe` | POST | Webhook | Automated payment sync and subscription deletion kill switch |

---

## 🔒 TradePost Ed25519 License Verification

TradePost desktop instances verify tokens generated by Drox Command Tower using the vendor Ed25519 public key stored in `keys/vendor_public.key`.

Tokens are formatted as `payload_b64.signature_b64`. TradePost unpacks the canonical JSON payload and validates the Ed25519 signature either completely offline or via `/api/v1/entitlements/verify`.
