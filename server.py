"""Drox Command Tower - Sovereign Licensing, Entitlements & Customer Kill-Switch Hub.

Provides centralized management for TradePost and ecosystem applications:
- Dual-mode credential issuance (Live Cloud API keys + Ed25519 signed TradePost desktop licenses)
- Central verification and entitlement enforcement (fail-closed on past-due/kill-switch)
- Reverse proxy gateway with 402/403 rejection
- One-click customer and per-key kill switches
- Stripe webhook ingestion for automated lifecycle sync
- Cyber-dark operator HUD static server
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from db import db_manager, utc_now_iso

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
CONFIG_PATH = BASE_DIR / "config.json"
STATIC_DIR = BASE_DIR / "www"
KEYS_DIR = BASE_DIR / "keys"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("droxaitower")


# -----------------------------------------------------------------------------
# Configuration & Asymmetric Key Utilities
# -----------------------------------------------------------------------------
def load_config() -> dict[str, Any]:
    """Load configuration from config.json with safe defaults."""
    if not CONFIG_PATH.exists():
        return {
            "rate_limit_per_min": 120,
            "allowed_origins": ["*"],
        }
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


CONFIG = load_config()
MASTER_KEY = os.getenv("DROX_MASTER_KEY")
PORT = int(os.getenv("PORT", "8088"))

if not MASTER_KEY:
    raise RuntimeError(
        "DROX_MASTER_KEY must be configured via environment or config.json"
    )


def resolve_vendor_private_key() -> Ed25519PrivateKey:
    """Load or generate the master vendor Ed25519 private key for TradePost."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    priv_file = KEYS_DIR / "vendor_private.key"
    pub_file = KEYS_DIR / "vendor_public.key"

    if priv_file.exists():
        key_bytes = priv_file.read_bytes()
        try:
            key = serialization.load_pem_private_key(key_bytes, password=None)
            if isinstance(key, Ed25519PrivateKey):
                return key
        except Exception as exc:
            logger.warning(
                "Could not parse existing vendor private key PEM (%s). Recreating...", exc
            )

    # Generate fresh keypair
    key = Ed25519PrivateKey.generate()
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = key.public_key().public_bytes_raw()
    pub_b64 = base64.b64encode(pub_raw).decode("ascii")

    priv_file.write_bytes(priv_pem)
    pub_file.write_text(pub_b64, encoding="utf-8")
    logger.info("Generated new Ed25519 master vendor keypair at %s", priv_file)
    return key


VENDOR_PRIVATE_KEY = resolve_vendor_private_key()
VENDOR_PUBLIC_KEY_B64 = base64.b64encode(VENDOR_PRIVATE_KEY.public_key().public_bytes_raw()).decode(
    "ascii"
)


def hash_api_key(token: str, salt: str | bytes | None = None) -> tuple[str, str]:
    """Hash an API key using PBKDF2-HMAC-SHA256. Returns (salt_hex, hash_hex)."""
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
    elif isinstance(salt, str):
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = salt

    key_bytes = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt_bytes, 100_000)
    return salt_bytes.hex(), key_bytes.hex()


def verify_api_key_hash(token: str, stored_hash: str) -> bool:
    """Verify raw token against stored 'salt_hex$hash_hex'."""
    if "$" not in stored_hash:
        return False
    salt_hex, expected_hash_hex = stored_hash.split("$", 1)
    _, computed_hash_hex = hash_api_key(token, salt_hex)
    return hmac.compare_digest(computed_hash_hex, expected_hash_hex)


# -----------------------------------------------------------------------------
# Lifespan & FastAPI App
# -----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan manager: ensure schema is initialized and ready."""
    db_manager.init_schema(force_clean=False)
    logger.info("Drox Command Tower online. Master public key: %s", VENDOR_PUBLIC_KEY_B64)
    yield
    logger.info("Drox Command Tower shutting down.")


app = FastAPI(
    title="Drox Command Tower",
    description="Centralized Sovereign Licensing, Entitlements & Customer Kill-Switch Hub",
    version="4.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CONFIG.get("allowed_origins", ["*"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------
class CustomerCreateRequest(BaseModel):
    email: str = Field(
        ..., pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", description="Customer email address"
    )
    company_name: str | None = None
    billing_status: str = Field(
        default="ACTIVE", pattern="^(ACTIVE|PAST_DUE|SUSPENDED|CANCELLED|LIFETIME)$"
    )
    payment_method: str | None = "STRIPE"
    stripe_customer_id: str | None = None
    notes: str | None = None
    # Optional auto-created subscription
    project_slug: str = "tradepost"
    plan_tier: str = Field(default="PRO", pattern="^(STANDARD|PRO|ENTERPRISE|LIFETIME)$")
    billing_interval: str = Field(default="MONTHLY", pattern="^(MONTHLY|ANNUAL|LIFETIME)$")
    amount_usd: float = 99.00


class ProjectCreateRequest(BaseModel):
    project_slug: str = Field(..., min_length=2, max_length=32, pattern="^[a-z0-9-]+$")
    name: str = Field(..., min_length=2)
    description: str | None = None
    is_active: int = 1


class CredentialIssueRequest(BaseModel):
    customer_id: str
    project_slug: str
    credential_type: str = Field(default="API_KEY", pattern="^(API_KEY|DESKTOP_LICENSE)$")
    plan_tier: str = Field(default="PRO", pattern="^(STANDARD|PRO|ENTERPRISE|LIFETIME)$")
    validity_days: int | None = Field(default=30, ge=1, le=3650)


class StripeWebhookEvent(BaseModel):
    type: str
    data: dict[str, Any]


# -----------------------------------------------------------------------------
# Authentication Helpers
# -----------------------------------------------------------------------------
def require_master_key(x_master_key: str | None = Header(None)) -> None:
    """Enforce operator master key authentication for administrative routes."""
    if not x_master_key or not hmac.compare_digest(x_master_key.strip(), MASTER_KEY.strip()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Valid X-Master-Key header required.",
        )


def extract_credential_token(request: Request, key_or_token: str | None = None) -> str:
    """Extract credential token from query parameter, X-API-Key header, or Bearer auth."""
    if key_or_token and key_or_token.strip():
        return key_or_token.strip()

    header_key = request.headers.get("X-API-Key")
    if header_key and header_key.strip():
        return header_key.strip()

    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth[7:].strip()

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing credential token. Provide key_or_token parameter or X-API-Key header.",
    )


# -----------------------------------------------------------------------------
# UI Route
# -----------------------------------------------------------------------------
@app.get("/")
async def serve_dashboard():
    """Serve Cyber-Dark Command Center Operator HUD."""
    index_path = STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Command Center HUD static assets not found.")
    return FileResponse(index_path)


# -----------------------------------------------------------------------------
# Core Verification & Entitlements Endpoint
# -----------------------------------------------------------------------------
@app.get("/api/v1/entitlements/verify")
async def verify_entitlement(
    request: Request,
    key_or_token: str | None = Query(
        None, description="API Key or TradePost Ed25519 dual-part token"
    ),
):
    """Central Entitlements Verification. Used by TradePost and external apps on boot/poll.

    Returns:
    - ACTIVE: fully entitled, license valid.
    - SUSPENDED / REVOKED: killed via kill-switch or non-payment (fail-closed).
    """
    start_time = time.time()
    token = extract_credential_token(request, key_or_token)
    client_ip = request.client.host if request.client else "127.0.0.1"

    with db_manager.connection() as conn:
        matched_credential = None

        # 1. Check if token is a TradePost Ed25519 dual-part token (payload.signature)
        if "." in token:
            parts = token.split(".")
            if len(parts) == 2:
                payload_b64, sig_b64 = parts[0], parts[1]
                # Pad if needed
                padded_payload = payload_b64 + "=" * (-len(payload_b64) % 4)
                padded_sig = sig_b64 + "=" * (-len(sig_b64) % 4)
                try:
                    payload_bytes = base64.urlsafe_b64decode(padded_payload)
                    sig_bytes = base64.urlsafe_b64decode(padded_sig)
                    # Verify signature with master public key
                    VENDOR_PRIVATE_KEY.public_key().verify(sig_bytes, payload_bytes)
                    payload_data = json.loads(payload_bytes.decode("utf-8"))
                    license_id = payload_data.get("license_id")
                    if license_id:
                        matched_credential = conn.execute(
                            "SELECT * FROM credentials WHERE key_id = ?",
                            (license_id,),
                        ).fetchone()
                except Exception as exc:
                    logger.debug("Ed25519 verification parse error: %s", exc)

        # 2. If not found, check API Key hashes
        if not matched_credential:
            rows = conn.execute(
                "SELECT * FROM credentials WHERE credential_type = 'API_KEY'"
            ).fetchall()
            for row in rows:
                if verify_api_key_hash(token, row["key_hash"]):
                    matched_credential = row
                    break

        if not matched_credential:
            latency_ms = (time.time() - start_time) * 1000.0
            db_manager.log_audit(
                action="VERIFY_PING",
                status_code=401,
                ip_address=client_ip,
                latency_ms=latency_ms,
                conn=conn,
            )
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "status": "REVOKED",
                    "reason": "Credential not found or invalid signature",
                    "is_active": 0,
                },
            )

        # Fetch Customer & Subscription state
        customer = conn.execute(
            "SELECT * FROM customers WHERE customer_id = ?",
            (matched_credential["customer_id"],),
        ).fetchone()

        subscription = conn.execute(
            """
            SELECT * FROM subscriptions
            WHERE customer_id = ? AND project_slug = ?
            ORDER BY current_period_end DESC LIMIT 1
            """,
            (matched_credential["customer_id"], matched_credential["project_slug"]),
        ).fetchone()

        key_id = matched_credential["key_id"]
        customer_id = matched_credential["customer_id"]
        project_slug = matched_credential["project_slug"]

        # FAIL-CLOSED CHECK 1: Is Credential Kill Switch Tripped?
        if matched_credential["is_active"] == 0:
            latency_ms = (time.time() - start_time) * 1000.0
            reason = (
                matched_credential["revoked_reason"] or "Credential deactivated via Kill Switch"
            )
            db_manager.log_audit(
                "VERIFY_PING",
                403,
                key_id,
                customer_id,
                project_slug,
                client_ip,
                latency_ms,
                conn=conn,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "status": "REVOKED",
                    "reason": reason,
                    "is_active": 0,
                    "customer_id": customer_id,
                },
            )

        # FAIL-CLOSED CHECK 2: Is Customer Billing Suspended or Cancelled?
        if not customer or customer["billing_status"] in ("SUSPENDED", "CANCELLED"):
            latency_ms = (time.time() - start_time) * 1000.0
            status_desc = customer["billing_status"] if customer else "CUSTOMER_NOT_FOUND"
            reason = f"Account status is {status_desc}. Access revoked."
            db_manager.log_audit(
                "VERIFY_PING",
                403,
                key_id,
                customer_id,
                project_slug,
                client_ip,
                latency_ms,
                conn=conn,
            )
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "status": "REVOKED",
                    "reason": reason,
                    "is_active": 0,
                    "customer_id": customer_id,
                },
            )

        # FAIL-CLOSED CHECK 3: Is Customer Past Due & Grace Period Expired?
        if customer["billing_status"] == "PAST_DUE" and subscription:
            grace_days = subscription["grace_period_days"]
            end_dt = (
                datetime.fromisoformat(subscription["current_period_end"])
                if subscription["current_period_end"]
                else datetime.now(timezone.utc)
            )
            cutoff_dt = end_dt + timedelta(days=grace_days)
            if datetime.now(timezone.utc) > cutoff_dt and subscription["is_auto_kill_enabled"]:
                # Auto-kill triggered
                conn.execute(
                    "UPDATE credentials SET is_active = 0, revoked_reason = 'Payment Past Due' WHERE key_id = ?",
                    (key_id,),
                )
                latency_ms = (time.time() - start_time) * 1000.0
                db_manager.log_audit(
                    "KILL_SWITCH",
                    402,
                    key_id,
                    customer_id,
                    project_slug,
                    client_ip,
                    latency_ms,
                    conn=conn,
                )
                return JSONResponse(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    content={
                        "status": "REVOKED",
                        "reason": "Payment past due. Grace period elapsed.",
                        "is_active": 0,
                    },
                )

        # Entitlement verified! Update last_seen_at
        conn.execute(
            "UPDATE credentials SET last_seen_at = ? WHERE key_id = ?", (utc_now_iso(), key_id)
        )
        latency_ms = (time.time() - start_time) * 1000.0
        db_manager.log_audit(
            "VERIFY_PING", 200, key_id, customer_id, project_slug, client_ip, latency_ms, conn=conn
        )

        tier = subscription["plan_tier"] if subscription else "STANDARD"
        expires = subscription["current_period_end"] if subscription else None

        return {
            "status": "ACTIVE",
            "customer_id": customer_id,
            "company_name": customer["company_name"],
            "project_slug": project_slug,
            "credential_type": matched_credential["credential_type"],
            "plan_tier": tier,
            "expires_at": expires,
            "is_active": 1,
            "features": [
                "trading",
                "ai",
                "backtest",
                "notifications",
                "vault",
                "realtime_telemetry",
            ],
            "verified_at": utc_now_iso(),
        }


# -----------------------------------------------------------------------------
# Reverse Proxy Gateway with Enforcement
# -----------------------------------------------------------------------------
@app.api_route("/api/v1/proxy/{project_slug}/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def project_reverse_proxy(
    project_slug: str,
    path: str,
    request: Request,
):
    """Gateway proxy that validates callers and enforces instant kill switch/past-due blocks."""
    start_time = time.time()
    token = extract_credential_token(request)
    client_ip = request.client.host if request.client else "127.0.0.1"

    with db_manager.connection() as conn:
        matched_credential = None
        rows = conn.execute(
            "SELECT * FROM credentials WHERE project_slug = ? AND credential_type = 'API_KEY'",
            (project_slug,),
        ).fetchall()

        for row in rows:
            if verify_api_key_hash(token, row["key_hash"]):
                matched_credential = row
                break

        if not matched_credential:
            latency_ms = (time.time() - start_time) * 1000.0
            db_manager.log_audit(
                "API_CALL", 401, None, None, project_slug, client_ip, latency_ms, conn=conn
            )
            raise HTTPException(status_code=401, detail="Unauthorized: Invalid project API key.")

        customer = conn.execute(
            "SELECT * FROM customers WHERE customer_id = ?", (matched_credential["customer_id"],)
        ).fetchone()
        key_id = matched_credential["key_id"]
        customer_id = matched_credential["customer_id"]

        # Enforce Kill Switch
        if matched_credential["is_active"] == 0 or (
            customer and customer["billing_status"] in ("SUSPENDED", "CANCELLED")
        ):
            latency_ms = (time.time() - start_time) * 1000.0
            db_manager.log_audit(
                "API_CALL", 403, key_id, customer_id, project_slug, client_ip, latency_ms, conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Credential killed ({matched_credential['revoked_reason'] or 'Revoked by operator'}).",
            )

        # Enforce Past Due
        if customer and customer["billing_status"] == "PAST_DUE":
            latency_ms = (time.time() - start_time) * 1000.0
            db_manager.log_audit(
                "API_CALL", 402, key_id, customer_id, project_slug, client_ip, latency_ms, conn=conn
            )
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail="Payment Required: Account past due. Settle outstanding invoice to resume API calls.",
            )

        # Validated: update last_seen_at
        conn.execute(
            "UPDATE credentials SET last_seen_at = ? WHERE key_id = ?", (utc_now_iso(), key_id)
        )
        latency_ms = (time.time() - start_time) * 1000.0
        db_manager.log_audit(
            "API_CALL", 200, key_id, customer_id, project_slug, client_ip, latency_ms, conn=conn
        )

        return {
            "gateway": "Drox Command Tower",
            "proxy_status": "FORWARDED",
            "project_slug": project_slug,
            "forwarded_path": f"/{path}",
            "caller_customer_id": customer_id,
            "latency_ms": round(latency_ms, 2),
            "timestamp": utc_now_iso(),
        }


# -----------------------------------------------------------------------------
# Operator Kill Switch Actions
# -----------------------------------------------------------------------------
@app.post("/api/v1/admin/customers/{customer_id}/toggle-kill")
async def toggle_customer_kill(customer_id: str, request: Request):
    """One-Click Master Kill Switch: Immediately suspends customer and deactivates all keys."""
    require_master_key(request.headers.get("X-Master-Key"))
    try:
        result = db_manager.trigger_customer_kill(customer_id)
        return {"status": "success", "action": "KILL_SWITCH_ENGAGED", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/admin/customers/{customer_id}/restore")
async def restore_customer_account(customer_id: str, request: Request):
    """One-Click Master Restore: Restores customer to ACTIVE and re-enables all credentials."""
    require_master_key(request.headers.get("X-Master-Key"))
    try:
        result = db_manager.restore_customer(customer_id)
        return {"status": "success", "action": "ACCESS_RESTORED", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/v1/admin/credentials/{key_id}/toggle-kill")
async def toggle_single_credential_kill(key_id: str, request: Request):
    """Toggle kill switch for a single credential."""
    require_master_key(request.headers.get("X-Master-Key"))
    with db_manager.connection() as conn:
        cred = conn.execute("SELECT * FROM credentials WHERE key_id = ?", (key_id,)).fetchone()
        if not cred:
            raise HTTPException(status_code=404, detail="Credential not found")

        new_status = 0 if cred["is_active"] == 1 else 1
        reason = "Killed by operator via Command Tower" if new_status == 0 else None
        conn.execute(
            "UPDATE credentials SET is_active = ?, revoked_reason = ? WHERE key_id = ?",
            (new_status, reason, key_id),
        )

        db_manager.log_audit(
            action="KILL_SWITCH" if new_status == 0 else "KILL_SWITCH_RESTORE",
            status_code=200,
            key_id=key_id,
            customer_id=cred["customer_id"],
            project_slug=cred["project_slug"],
        )

        return {
            "status": "success",
            "key_id": key_id,
            "is_active": new_status,
            "revoked_reason": reason,
        }


# -----------------------------------------------------------------------------
# Credential Issuance: Live API Key & TradePost Ed25519 Desktop License
# -----------------------------------------------------------------------------
@app.post("/api/v1/admin/credentials/issue")
async def issue_credential(payload: CredentialIssueRequest, request: Request):
    """Issue either a Cloud API Key (hashed) or an Ed25519 TradePost Desktop License Token."""
    require_master_key(request.headers.get("X-Master-Key"))

    with db_manager.connection() as conn:
        customer = conn.execute(
            "SELECT * FROM customers WHERE customer_id = ?", (payload.customer_id,)
        ).fetchone()
        if not customer:
            raise HTTPException(status_code=404, detail=f"Customer {payload.customer_id} not found")

        project = conn.execute(
            "SELECT * FROM projects WHERE project_slug = ?", (payload.project_slug,)
        ).fetchone()
        if not project:
            raise HTTPException(status_code=404, detail=f"Project {payload.project_slug} not found")

        key_id = f"key_{secrets.token_hex(6)}"
        created_at = utc_now_iso()
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(days=payload.validity_days)).isoformat()
            if payload.validity_days
            else None
        )

        if payload.credential_type == "API_KEY":
            raw_token = f"drox_{payload.project_slug}_{secrets.token_urlsafe(24)}"
            salt_hex, hash_hex = hash_api_key(raw_token)
            stored_hash = f"{salt_hex}${hash_hex}"
            preview = f"{raw_token[:10]}...{raw_token[-4:]}"

            conn.execute(
                """
                INSERT INTO credentials (key_id, customer_id, project_slug, credential_type, raw_token_preview, key_hash, is_active, created_at)
                VALUES (?, ?, ?, 'API_KEY', ?, ?, 1, ?)
                """,
                (
                    key_id,
                    payload.customer_id,
                    payload.project_slug,
                    preview,
                    stored_hash,
                    created_at,
                ),
            )

            db_manager.log_audit(
                "CREDENTIAL_ISSUED",
                200,
                key_id,
                payload.customer_id,
                payload.project_slug,
                conn=conn,
            )

            return {
                "status": "success",
                "key_id": key_id,
                "credential_type": "API_KEY",
                "project_slug": payload.project_slug,
                "raw_token": raw_token,
                "preview": preview,
                "note": "Copy this token now; it cannot be shown again.",
            }

        else:  # DESKTOP_LICENSE (TradePost Ed25519 signature)
            license_id = f"lic_{secrets.token_hex(6)}"
            license_payload = {
                "license_id": license_id,
                "tier": payload.plan_tier.lower(),
                "customer_id": payload.customer_id,
                "customer_email": customer["email"],
                "issued_at": created_at,
                "expires_at": expires_at,
                "allowed_symbols": None,
                "max_capital_usd": None,
                "features": ["trading", "ai", "backtest", "notifications", "vault"],
            }

            payload_bytes = json.dumps(
                license_payload, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
            sig_bytes = VENDOR_PRIVATE_KEY.sign(payload_bytes)

            p_b64 = base64.urlsafe_b64encode(payload_bytes).decode("ascii").rstrip("=")
            s_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
            token = f"{p_b64}.{s_b64}"

            token_hash = f"ed25519${hashlib.sha256(token.encode('utf-8')).hexdigest()}"
            preview = f"TP-LIC:{license_id[-6:]} [{payload.plan_tier.upper()}]"

            conn.execute(
                """
                INSERT INTO credentials (key_id, customer_id, project_slug, credential_type, raw_token_preview, key_hash, is_active, created_at)
                VALUES (?, ?, ?, 'DESKTOP_LICENSE', ?, ?, 1, ?)
                """,
                (
                    license_id,
                    payload.customer_id,
                    payload.project_slug,
                    preview,
                    token_hash,
                    created_at,
                ),
            )

            db_manager.log_audit(
                "CREDENTIAL_ISSUED",
                200,
                license_id,
                payload.customer_id,
                payload.project_slug,
                conn=conn,
            )

            return {
                "status": "success",
                "key_id": license_id,
                "credential_type": "DESKTOP_LICENSE",
                "project_slug": payload.project_slug,
                "raw_token": token,
                "preview": preview,
                "public_key_b64": VENDOR_PUBLIC_KEY_B64,
                "note": "Save this token as .license.sig or activate in TradePost settings.",
            }


# -----------------------------------------------------------------------------
# Stripe Webhook Ingestion
# -----------------------------------------------------------------------------
@app.post("/api/v1/webhooks/stripe")
async def handle_stripe_webhook(event: StripeWebhookEvent):
    """Handle automated billing lifecycle notifications from Stripe."""
    event_type = event.type
    obj = event.data.get("object", {})

    stripe_cus_id = obj.get("customer") or obj.get("id")
    email = obj.get("customer_email") or obj.get("email")

    with db_manager.connection() as conn:
        customer = None
        if stripe_cus_id:
            customer = conn.execute(
                "SELECT * FROM customers WHERE stripe_customer_id = ?", (stripe_cus_id,)
            ).fetchone()
        if not customer and email:
            customer = conn.execute("SELECT * FROM customers WHERE email = ?", (email,)).fetchone()

        if not customer:
            logger.warning(
                "Stripe webhook received for unknown customer (%s / %s)", stripe_cus_id, email
            )
            return {"received": True, "handled": False, "reason": "Customer not found"}

        customer_id = customer["customer_id"]

        if event_type == "invoice.payment_succeeded":
            conn.execute(
                "UPDATE customers SET billing_status = 'ACTIVE' WHERE customer_id = ?",
                (customer_id,),
            )
            # Re-activate credentials if they were previously killed due to past-due
            conn.execute(
                "UPDATE credentials SET is_active = 1, revoked_reason = NULL WHERE customer_id = ? AND revoked_reason LIKE 'Payment%'",
                (customer_id,),
            )
            # Extend current_period_end +30 days
            new_end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            conn.execute(
                "UPDATE subscriptions SET current_period_end = ? WHERE customer_id = ?",
                (new_end, customer_id),
            )
            db_manager.log_audit("PAYMENT_SYNC", 200, None, customer_id, conn=conn)
            logger.info(
                "Stripe payment succeeded for customer %s. Extended to %s", customer_id, new_end
            )

        elif event_type == "invoice.payment_failed":
            conn.execute(
                "UPDATE customers SET billing_status = 'PAST_DUE' WHERE customer_id = ?",
                (customer_id,),
            )
            db_manager.log_audit("PAYMENT_SYNC", 402, None, customer_id, conn=conn)
            logger.warning("Stripe payment failed for customer %s. Marked PAST_DUE", customer_id)

        elif event_type in ("customer.subscription.deleted", "customer.subscription.cancelled"):
            conn.execute(
                "UPDATE customers SET billing_status = 'CANCELLED' WHERE customer_id = ?",
                (customer_id,),
            )
            # Kill switch cascade
            conn.execute(
                "UPDATE credentials SET is_active = 0, revoked_reason = 'Stripe Subscription Cancelled' WHERE customer_id = ?",
                (customer_id,),
            )
            db_manager.log_audit("KILL_SWITCH", 200, None, customer_id, conn=conn)
            logger.info(
                "Stripe subscription cancelled for customer %s. Kill switch cascaded.", customer_id
            )

    return {"received": True, "event": event_type, "customer_id": customer_id}


# -----------------------------------------------------------------------------
# Admin Management Endpoints for HUD Cockpit
# -----------------------------------------------------------------------------
@app.get("/api/v1/admin/stats")
async def get_admin_stats(request: Request):
    """Aggregated cockpit operational telemetry."""
    require_master_key(request.headers.get("X-Master-Key"))

    with db_manager.connection() as conn:
        total_customers = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
        active_customers = conn.execute(
            "SELECT COUNT(*) FROM customers WHERE billing_status = 'ACTIVE'"
        ).fetchone()[0]
        past_due = conn.execute(
            "SELECT COUNT(*) FROM customers WHERE billing_status = 'PAST_DUE'"
        ).fetchone()[0]
        suspended = conn.execute(
            "SELECT COUNT(*) FROM customers WHERE billing_status = 'SUSPENDED'"
        ).fetchone()[0]

        total_mrr = conn.execute(
            """
            SELECT COALESCE(SUM(amount_usd), 0.0) FROM subscriptions
            WHERE customer_id IN (SELECT customer_id FROM customers WHERE billing_status IN ('ACTIVE', 'LIFETIME'))
            """
        ).fetchone()[0]

        active_keys = conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE is_active = 1"
        ).fetchone()[0]
        tripped_kill_switches = conn.execute(
            "SELECT COUNT(*) FROM credentials WHERE is_active = 0"
        ).fetchone()[0]
        total_verifications = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action = 'VERIFY_PING'"
        ).fetchone()[0]

    return {
        "status": "online",
        "app_name": "Drox Command Tower",
        "version": "4.0.0",
        "active_customers": active_customers,
        "total_customers": total_customers,
        "past_due_customers": past_due,
        "suspended_customers": suspended,
        "total_mrr_usd": round(total_mrr, 2),
        "active_credentials": active_keys,
        "tripped_kill_switches": tripped_kill_switches,
        "total_verifications": total_verifications,
        "vendor_public_key_b64": VENDOR_PUBLIC_KEY_B64,
        "server_time": utc_now_iso(),
    }


@app.get("/api/v1/admin/customers")
async def list_customers(request: Request):
    """List all customers with active subscription details, projects, and key counts."""
    require_master_key(request.headers.get("X-Master-Key"))

    with db_manager.connection() as conn:
        rows = conn.execute(
            """
            SELECT
                c.customer_id, c.email, c.company_name, c.billing_status, c.created_at,
                COALESCE(s.project_slug, 'tradepost') as project_slug,
                COALESCE(s.plan_tier, 'STANDARD') as plan_tier,
                COALESCE(s.amount_usd, 0.0) as amount_usd,
                s.current_period_end,
                (SELECT COUNT(*) FROM credentials cr WHERE cr.customer_id = c.customer_id AND cr.is_active = 1) as active_keys_count,
                (SELECT COUNT(*) FROM credentials cr WHERE cr.customer_id = c.customer_id AND cr.is_active = 0) as killed_keys_count
            FROM customers c
            LEFT JOIN subscriptions s ON c.customer_id = s.customer_id
            ORDER BY c.created_at DESC
            """
        ).fetchall()

    return [dict(row) for row in rows]


@app.post("/api/v1/admin/customers")
async def create_customer(payload: CustomerCreateRequest, request: Request):
    """Create a customer and optionally assign initial project subscription."""
    require_master_key(request.headers.get("X-Master-Key"))

    customer_id = f"cus_{secrets.token_hex(6)}"
    created_at = utc_now_iso()
    sub_id = f"sub_{secrets.token_hex(6)}"

    with db_manager.connection() as conn:
        # Check duplicate email
        existing = conn.execute(
            "SELECT customer_id FROM customers WHERE email = ?", (payload.email,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="A customer with this email already exists")

        conn.execute(
            """
            INSERT INTO customers (customer_id, email, company_name, billing_status, payment_method, stripe_customer_id, created_at, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                customer_id,
                payload.email,
                payload.company_name or payload.email.split("@")[0].title(),
                payload.billing_status,
                payload.payment_method,
                payload.stripe_customer_id,
                created_at,
                payload.notes,
            ),
        )

        # Set up subscription
        period_end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        conn.execute(
            """
            INSERT INTO subscriptions (subscription_id, customer_id, project_slug, plan_tier, billing_interval, amount_usd, current_period_start, current_period_end)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                sub_id,
                customer_id,
                payload.project_slug,
                payload.plan_tier,
                payload.billing_interval,
                payload.amount_usd,
                created_at,
                period_end,
            ),
        )

    return {
        "status": "success",
        "customer_id": customer_id,
        "subscription_id": sub_id,
        "email": payload.email,
        "created_at": created_at,
    }


@app.get("/api/v1/admin/projects")
async def list_projects(request: Request):
    """List all registered ecosystem projects."""
    require_master_key(request.headers.get("X-Master-Key"))
    with db_manager.connection() as conn:
        rows = conn.execute(
            """
            SELECT p.*,
                (SELECT COUNT(*) FROM subscriptions s WHERE s.project_slug = p.project_slug) as subscribers_count,
                (SELECT COUNT(*) FROM credentials c WHERE c.project_slug = p.project_slug AND c.is_active = 1) as active_keys_count
            FROM projects p
            """
        ).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/v1/admin/projects")
async def create_project(payload: ProjectCreateRequest, request: Request):
    """Register a new project slug in the hub."""
    require_master_key(request.headers.get("X-Master-Key"))
    with db_manager.connection() as conn:
        existing = conn.execute(
            "SELECT project_slug FROM projects WHERE project_slug = ?", (payload.project_slug,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Project slug already exists")
        conn.execute(
            "INSERT INTO projects (project_slug, name, description, is_active) VALUES (?, ?, ?, ?)",
            (payload.project_slug, payload.name, payload.description, payload.is_active),
        )
    return {"status": "success", "project_slug": payload.project_slug}


@app.get("/api/v1/admin/credentials")
async def list_credentials(request: Request, customer_id: str | None = None):
    """List all issued credentials with their live active status."""
    require_master_key(request.headers.get("X-Master-Key"))
    with db_manager.connection() as conn:
        if customer_id:
            rows = conn.execute(
                "SELECT * FROM credentials WHERE customer_id = ? ORDER BY created_at DESC",
                (customer_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM credentials ORDER BY created_at DESC LIMIT 100"
            ).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/v1/admin/audit-logs")
async def list_audit_logs(request: Request, limit: int = 50):
    """Retrieve live scrolling audit radar logs."""
    require_master_key(request.headers.get("X-Master-Key"))
    with db_manager.connection() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [dict(r) for r in rows]


# -----------------------------------------------------------------------------
# Main Executable Entrypoint
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="127.0.0.1", port=PORT, reload=True)

