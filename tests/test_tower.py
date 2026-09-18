"""Comprehensive test suite for Drox Command Tower.

Verifies:
- Customer registration and subscription tracking
- Dual-mode credential issuance (Live API Keys + Ed25519 TradePost desktop licenses)
- Central entitlement verification and fail-closed security
- One-click customer and per-key kill switches
- Restoration flow
- Reverse proxy gateway authorization and 402/403 rejections
- Automated Stripe webhook lifecycle synchronization
"""

from __future__ import annotations

import base64
import json

import pytest
from httpx import ASGITransport, AsyncClient

from db import db_manager
from server import MASTER_KEY, VENDOR_PRIVATE_KEY, app


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure clean test database state for each test run."""
    db_manager.init_schema(force_clean=True)


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Provide administrative master key headers."""
    return {"X-Master-Key": MASTER_KEY}


@pytest.mark.asyncio
async def test_admin_stats_and_auth(auth_headers: dict[str, str]):
    """Verify admin stats endpoint with valid master key and rejection on unauthorized calls."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Unauthorized check
        unauth_resp = await client.get("/api/v1/admin/stats")
        assert unauth_resp.status_code == 401

        # Authorized check
        resp = await client.get("/api/v1/admin/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "online"
        assert data["app_name"] == "Drox Command Tower"
        assert "vendor_public_key_b64" in data


@pytest.mark.asyncio
async def test_customer_creation_and_listing(auth_headers: dict[str, str]):
    """Test registering customers with associated subscriptions."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "email": "alpha_trader@aegis.io",
            "company_name": "Alpha Algorithmic LLC",
            "project_slug": "tradepost",
            "plan_tier": "PRO",
            "billing_interval": "MONTHLY",
            "amount_usd": 149.00,
        }
        res = await client.post("/api/v1/admin/customers", json=payload, headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert "customer_id" in data
        assert data["email"] == "alpha_trader@aegis.io"

        # Verify listing
        list_res = await client.get("/api/v1/admin/customers", headers=auth_headers)
        assert list_res.status_code == 200
        customers = list_res.json()
        assert len(customers) == 1
        assert customers[0]["company_name"] == "Alpha Algorithmic LLC"
        assert customers[0]["billing_status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_api_key_issuance_verification_and_proxy(auth_headers: dict[str, str]):
    """Test generating live cloud API keys, verifying entitlement, and proxying."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create customer
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "trader1@test.com",
                "company_name": "Trader One",
                "project_slug": "tradepost",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        # 2. Issue API Key
        issue_res = await client.post(
            "/api/v1/admin/credentials/issue",
            json={
                "customer_id": customer_id,
                "project_slug": "tradepost",
                "credential_type": "API_KEY",
                "plan_tier": "PRO",
                "validity_days": 30,
            },
            headers=auth_headers,
        )
        assert issue_res.status_code == 200
        key_data = issue_res.json()
        raw_token = key_data["raw_token"]
        assert raw_token.startswith("drox_tradepost_")

        # 3. Verify entitlement via query param
        verify_res = await client.get(f"/api/v1/entitlements/verify?key_or_token={raw_token}")
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["status"] == "ACTIVE"
        assert verify_data["customer_id"] == customer_id
        assert verify_data["is_active"] == 1

        # 4. Verify entitlement via X-API-Key header
        header_verify_res = await client.get(
            "/api/v1/entitlements/verify", headers={"X-API-Key": raw_token}
        )
        assert header_verify_res.status_code == 200
        assert header_verify_res.json()["status"] == "ACTIVE"

        # 5. Access Reverse Proxy Gateway
        proxy_res = await client.post(
            "/api/v1/proxy/tradepost/orders/execute",
            headers={"X-API-Key": raw_token},
            json={"symbol": "BTC/USD", "amount": 1.5},
        )
        assert proxy_res.status_code == 200
        proxy_data = proxy_res.json()
        assert proxy_data["proxy_status"] == "FORWARDED"
        assert proxy_data["caller_customer_id"] == customer_id


@pytest.mark.asyncio
async def test_tradepost_ed25519_desktop_license(auth_headers: dict[str, str]):
    """Test generating an Ed25519 signed license token compatible with TradePost and verifying it."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Create customer
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "desk_trader@propfirm.com",
                "company_name": "Prop Desk Alpha",
                "project_slug": "tradepost",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        # 2. Issue DESKTOP_LICENSE
        issue_res = await client.post(
            "/api/v1/admin/credentials/issue",
            json={
                "customer_id": customer_id,
                "project_slug": "tradepost",
                "credential_type": "DESKTOP_LICENSE",
                "plan_tier": "LIFETIME",
                "validity_days": 365,
            },
            headers=auth_headers,
        )
        assert issue_res.status_code == 200
        lic_data = issue_res.json()
        token = lic_data["raw_token"]
        assert "." in token
        p_b64, s_b64 = token.split(".")

        # 3. Cryptographically verify Ed25519 token signature locally
        padded_p = p_b64 + "=" * (-len(p_b64) % 4)
        padded_s = s_b64 + "=" * (-len(s_b64) % 4)
        payload_bytes = base64.urlsafe_b64decode(padded_p)
        sig_bytes = base64.urlsafe_b64decode(padded_s)
        VENDOR_PRIVATE_KEY.public_key().verify(sig_bytes, payload_bytes)
        parsed = json.loads(payload_bytes.decode("utf-8"))
        assert parsed["customer_email"] == "desk_trader@propfirm.com"
        assert parsed["tier"] == "lifetime"

        # 4. Verify token through Tower Entitlements API
        verify_res = await client.get(f"/api/v1/entitlements/verify?key_or_token={token}")
        assert verify_res.status_code == 200
        v_data = verify_res.json()
        assert v_data["status"] == "ACTIVE"
        assert v_data["customer_id"] == customer_id
        assert v_data["credential_type"] == "DESKTOP_LICENSE"


@pytest.mark.asyncio
async def test_kill_switch_activation_and_restoration(auth_headers: dict[str, str]):
    """Test one-click kill switch cascade immediately cutting off access, followed by restoration."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create customer & API key
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "rogue@fund.com",
                "company_name": "Rogue Capital",
                "project_slug": "tradepost",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        key_res = await client.post(
            "/api/v1/admin/credentials/issue",
            json={
                "customer_id": customer_id,
                "project_slug": "tradepost",
                "credential_type": "API_KEY",
            },
            headers=auth_headers,
        )
        raw_token = key_res.json()["raw_token"]

        # Initial verification works
        v1 = await client.get(f"/api/v1/entitlements/verify?key_or_token={raw_token}")
        assert v1.status_code == 200
        assert v1.json()["status"] == "ACTIVE"

        # --- TRIGGER KILL SWITCH ---
        kill_res = await client.post(
            f"/api/v1/admin/customers/{customer_id}/toggle-kill",
            headers=auth_headers,
        )
        assert kill_res.status_code == 200
        assert kill_res.json()["data"]["billing_status"] == "SUSPENDED"

        # Entitlement verification must now immediately FAIL-CLOSED with 403 REVOKED
        v2 = await client.get(f"/api/v1/entitlements/verify?key_or_token={raw_token}")
        assert v2.status_code == 403
        assert v2.json()["status"] == "REVOKED"
        assert v2.json()["is_active"] == 0

        # Reverse proxy must also reject with 403 Forbidden
        proxy_res = await client.get(
            "/api/v1/proxy/tradepost/risk/portfolio", headers={"X-API-Key": raw_token}
        )
        assert proxy_res.status_code == 403

        # --- RESTORE CUSTOMER ACCESS ---
        restore_res = await client.post(
            f"/api/v1/admin/customers/{customer_id}/restore",
            headers=auth_headers,
        )
        assert restore_res.status_code == 200
        assert restore_res.json()["data"]["billing_status"] == "ACTIVE"

        # Entitlement check must now succeed again
        v3 = await client.get(f"/api/v1/entitlements/verify?key_or_token={raw_token}")
        assert v3.status_code == 200
        assert v3.json()["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_stripe_webhook_lifecycle(auth_headers: dict[str, str]):
    """Test Stripe webhook handling for payment success, failure, and subscription cancellation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create customer
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "saas_user@acme.com",
                "company_name": "SaaS Acme",
                "project_slug": "securosoc",
                "stripe_customer_id": "cus_stripe_12345",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        # 1. invoice.payment_failed -> marks PAST_DUE
        event_failed = {
            "type": "invoice.payment_failed",
            "data": {"object": {"customer": "cus_stripe_12345"}},
        }
        res_fail = await client.post("/api/v1/webhooks/stripe", json=event_failed)
        assert res_fail.status_code == 200

        with db_manager.connection() as conn:
            c = conn.execute(
                "SELECT billing_status FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
            assert c["billing_status"] == "PAST_DUE"

        # 2. invoice.payment_succeeded -> restores ACTIVE
        event_success = {
            "type": "invoice.payment_succeeded",
            "data": {"object": {"customer": "cus_stripe_12345"}},
        }
        res_succ = await client.post("/api/v1/webhooks/stripe", json=event_success)
        assert res_succ.status_code == 200

        with db_manager.connection() as conn:
            c = conn.execute(
                "SELECT billing_status FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
            assert c["billing_status"] == "ACTIVE"

        # 3. customer.subscription.deleted -> triggers kill switch and CANCELLED
        event_del = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"customer": "cus_stripe_12345"}},
        }
        res_del = await client.post("/api/v1/webhooks/stripe", json=event_del)
        assert res_del.status_code == 200

        with db_manager.connection() as conn:
            c = conn.execute(
                "SELECT billing_status FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
            assert c["billing_status"] == "CANCELLED"


@pytest.mark.asyncio
async def test_single_credential_kill_and_tampered_token(auth_headers: dict[str, str]):
    """Test individual credential kill toggle and tampered Ed25519 signature rejection."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create customer & issue key
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "operator@test.com",
                "company_name": "OpCorp",
                "project_slug": "ai-proxy",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        key_res = await client.post(
            "/api/v1/admin/credentials/issue",
            json={
                "customer_id": customer_id,
                "project_slug": "ai-proxy",
                "credential_type": "API_KEY",
            },
            headers=auth_headers,
        )
        key_id = key_res.json()["key_id"]
        raw_token = key_res.json()["raw_token"]

        # Toggle single credential off
        toggle_res = await client.post(
            f"/api/v1/admin/credentials/{key_id}/toggle-kill",
            headers=auth_headers,
        )
        assert toggle_res.status_code == 200
        assert toggle_res.json()["is_active"] == 0

        # Verification must now return 403 REVOKED
        v = await client.get(f"/api/v1/entitlements/verify?key_or_token={raw_token}")
        assert v.status_code == 403
        assert v.json()["status"] == "REVOKED"

        # Tampered Ed25519 token check: invalid payload or signature returns 401
        tampered_token = "eyJ0aWVyIjoicHJvIn0.invalid_signature_bits"
        tampered_res = await client.get(
            f"/api/v1/entitlements/verify?key_or_token={tampered_token}"
        )
        assert tampered_res.status_code == 401
        assert tampered_res.json()["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_proxy_past_due_and_invalid_token(auth_headers: dict[str, str]):
    """Verify reverse proxy returns 402 for past due customers and 401 for invalid tokens."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Invalid token returns 401
        bad_proxy = await client.get(
            "/api/v1/proxy/tradepost/feed", headers={"X-API-Key": "drox_invalid_key"}
        )
        assert bad_proxy.status_code == 401

        # 2. Create customer and issue key
        cust_res = await client.post(
            "/api/v1/admin/customers",
            json={
                "email": "late_payer@test.com",
                "company_name": "Late Payer LLC",
                "project_slug": "tradepost",
            },
            headers=auth_headers,
        )
        customer_id = cust_res.json()["customer_id"]

        key_res = await client.post(
            "/api/v1/admin/credentials/issue",
            json={
                "customer_id": customer_id,
                "project_slug": "tradepost",
                "credential_type": "API_KEY",
            },
            headers=auth_headers,
        )
        raw_token = key_res.json()["raw_token"]

        # Mark customer PAST_DUE
        with db_manager.connection() as conn:
            conn.execute(
                "UPDATE customers SET billing_status = 'PAST_DUE' WHERE customer_id = ?",
                (customer_id,),
            )

        # Proxy must reject with 402 Payment Required
        past_due_proxy = await client.get(
            "/api/v1/proxy/tradepost/feed", headers={"X-API-Key": raw_token}
        )
        assert past_due_proxy.status_code == 402
        assert "Payment Required" in past_due_proxy.json()["detail"]
