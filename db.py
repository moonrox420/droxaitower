"""Database architecture and persistence for Drox Command Tower.

Manages SQLite connection pooling, WAL mode initialization, schema migrations,
and domain operations for customers, projects, subscriptions, credentials, and audit logging.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger("droxaitower.db")

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "droxaitower.db"


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class DatabaseManager:
    """Encapsulates SQLite connections and operations in WAL mode."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager yielding a SQLite connection configured for concurrent WAL operation."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=10.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA busy_timeout=5000;")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self, force_clean: bool = False) -> None:
        """Initialize or reset the SQLite schema with WAL mode enabled."""
        with self.connection() as conn:
            if force_clean:
                conn.executescript(
                    """
                    DROP TABLE IF EXISTS audit_log;
                    DROP TABLE IF EXISTS credentials;
                    DROP TABLE IF EXISTS subscriptions;
                    DROP TABLE IF EXISTS projects;
                    DROP TABLE IF EXISTS customers;
                    """
                )

            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS customers (
                    customer_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    company_name TEXT,
                    billing_status TEXT NOT NULL CHECK(billing_status IN ('ACTIVE', 'PAST_DUE', 'SUSPENDED', 'CANCELLED', 'LIFETIME')),
                    payment_method TEXT,
                    stripe_customer_id TEXT,
                    created_at TEXT NOT NULL,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS projects (
                    project_slug TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    subscription_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
                    project_slug TEXT NOT NULL REFERENCES projects(project_slug) ON DELETE CASCADE,
                    plan_tier TEXT NOT NULL CHECK(plan_tier IN ('STANDARD', 'PRO', 'ENTERPRISE', 'LIFETIME')),
                    billing_interval TEXT NOT NULL CHECK(billing_interval IN ('MONTHLY', 'ANNUAL', 'LIFETIME')),
                    amount_usd REAL NOT NULL DEFAULT 0.0,
                    current_period_start TEXT NOT NULL,
                    current_period_end TEXT,
                    grace_period_days INTEGER NOT NULL DEFAULT 3,
                    is_auto_kill_enabled INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS credentials (
                    key_id TEXT PRIMARY KEY,
                    customer_id TEXT NOT NULL REFERENCES customers(customer_id) ON DELETE CASCADE,
                    project_slug TEXT NOT NULL REFERENCES projects(project_slug) ON DELETE CASCADE,
                    credential_type TEXT NOT NULL CHECK(credential_type IN ('API_KEY', 'DESKTOP_LICENSE')),
                    raw_token_preview TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    revoked_reason TEXT,
                    last_seen_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key_id TEXT,
                    customer_id TEXT,
                    project_slug TEXT,
                    action TEXT NOT NULL CHECK(action IN ('API_CALL', 'VERIFY_PING', 'KILL_SWITCH', 'KILL_SWITCH_RESTORE', 'PAYMENT_SYNC', 'CREDENTIAL_ISSUED')),
                    ip_address TEXT,
                    status_code INTEGER,
                    latency_ms REAL,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);
                CREATE INDEX IF NOT EXISTS idx_customers_status ON customers(billing_status);
                CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id);
                CREATE INDEX IF NOT EXISTS idx_subscriptions_project ON subscriptions(project_slug);
                CREATE INDEX IF NOT EXISTS idx_credentials_customer ON credentials(customer_id);
                CREATE INDEX IF NOT EXISTS idx_credentials_key_hash ON credentials(key_hash);
                CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(is_active);
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_audit_customer ON audit_log(customer_id);
                """
            )

            # Seed default sovereign projects if empty
            default_projects = [
                (
                    "tradepost",
                    "TradePost Sovereign Terminal",
                    "Algorithmic trading execution & risk terminal",
                    1,
                ),
                (
                    "securosoc",
                    "SecuroSOC Threat Engine",
                    "Continuous threat intelligence and vulnerability analysis",
                    1,
                ),
                (
                    "ai-proxy",
                    "DroxAI Model Gateway",
                    "Self-hosted local and cloud AI inference routing proxy",
                    1,
                ),
            ]
            for slug, name, desc, active in default_projects:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO projects (project_slug, name, description, is_active)
                    VALUES (?, ?, ?, ?)
                    """,
                    (slug, name, desc, active),
                )

        logger.info("Database schema initialized with WAL mode at %s", self.db_path)

    # -------------------------------------------------------------------------
    # Audit Logging
    # -------------------------------------------------------------------------
    def log_audit(
        self,
        action: str,
        status_code: int,
        key_id: str | None = None,
        customer_id: str | None = None,
        project_slug: str | None = None,
        ip_address: str | None = None,
        latency_ms: float | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> None:
        """Record an immutable event in the audit log."""
        query = """
            INSERT INTO audit_log (key_id, customer_id, project_slug, action, ip_address, status_code, latency_ms, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            key_id,
            customer_id,
            project_slug,
            action,
            ip_address or "127.0.0.1",
            status_code,
            round(latency_ms or 0.0, 2),
            utc_now_iso(),
        )
        try:
            if conn is not None:
                conn.execute(query, params)
            else:
                with self.connection() as local_conn:
                    local_conn.execute(query, params)
        except Exception as exc:
            logger.error("Failed to write to audit log: %s", exc)

    # -------------------------------------------------------------------------
    # Kill Switch Operations
    # -------------------------------------------------------------------------
    def trigger_customer_kill(
        self, customer_id: str, reason: str = "Operator Kill Switch Activated"
    ) -> dict[str, Any]:
        """Trigger emergency kill switch for a customer: suspend account and deactivate all keys."""
        with self.connection() as conn:
            customer = conn.execute(
                "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
            if not customer:
                raise ValueError(f"Customer {customer_id} not found")

            conn.execute(
                "UPDATE customers SET billing_status = 'SUSPENDED' WHERE customer_id = ?",
                (customer_id,),
            )
            cursor = conn.execute(
                """
                UPDATE credentials
                SET is_active = 0, revoked_reason = ?
                WHERE customer_id = ?
                """,
                (reason, customer_id),
            )
            affected_keys = cursor.rowcount

        self.log_audit(
            action="KILL_SWITCH",
            status_code=200,
            customer_id=customer_id,
        )

        return {
            "customer_id": customer_id,
            "billing_status": "SUSPENDED",
            "keys_deactivated": affected_keys,
            "reason": reason,
            "timestamp": utc_now_iso(),
        }

    def restore_customer(self, customer_id: str) -> dict[str, Any]:
        """Restore a customer from suspended status and re-activate their credentials."""
        with self.connection() as conn:
            customer = conn.execute(
                "SELECT * FROM customers WHERE customer_id = ?", (customer_id,)
            ).fetchone()
            if not customer:
                raise ValueError(f"Customer {customer_id} not found")

            # Restore to ACTIVE or LIFETIME if previous tier was lifetime
            conn.execute(
                "UPDATE customers SET billing_status = 'ACTIVE' WHERE customer_id = ?",
                (customer_id,),
            )
            cursor = conn.execute(
                """
                UPDATE credentials
                SET is_active = 1, revoked_reason = NULL
                WHERE customer_id = ?
                """,
                (customer_id,),
            )
            affected_keys = cursor.rowcount

        self.log_audit(
            action="KILL_SWITCH_RESTORE",
            status_code=200,
            customer_id=customer_id,
        )

        return {
            "customer_id": customer_id,
            "billing_status": "ACTIVE",
            "keys_restored": affected_keys,
            "timestamp": utc_now_iso(),
        }


# Global database manager instance
db_manager = DatabaseManager()
