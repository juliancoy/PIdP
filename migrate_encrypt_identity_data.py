from __future__ import annotations

import argparse
import asyncio
import json
import logging
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from config import settings
from encrypted_json import encrypt_json, pii_encryption_enabled, validate_pii_encryption_config

LOG = logging.getLogger(__name__)
_TABLES = ("users", "website_users")
_MARKER = "__arkavo_encrypted_json__"


def _is_encrypted(value: Any) -> bool:
    return isinstance(value, dict) and value.get(_MARKER) is True


async def _migrate_table(conn, table_name: str, dry_run: bool) -> tuple[int, int]:
    result = await conn.execute(text(f"SELECT id, identity_data FROM {table_name}"))
    rows = result.mappings().all()
    updated = 0
    skipped = 0
    for row in rows:
        identity_data = row["identity_data"] or {}
        if _is_encrypted(identity_data):
            skipped += 1
            continue
        encrypted = encrypt_json(identity_data)
        if not _is_encrypted(encrypted):
            raise RuntimeError("encrypt_json did not produce an encrypted payload; check PII_ENCRYPTION_KEYS")
        updated += 1
        if dry_run:
            continue
        await conn.execute(
            text(f"UPDATE {table_name} SET identity_data = CAST(:identity_data AS JSONB) WHERE id = :id"),
            {"identity_data": json.dumps(encrypted, separators=(",", ":")), "id": row["id"]},
        )
    return updated, skipped


async def migrate_identity_data(dry_run: bool = False) -> dict[str, dict[str, int]]:
    validate_pii_encryption_config()
    if not pii_encryption_enabled():
        raise RuntimeError("PII_ENCRYPTION_KEYS is required to migrate identity_data")

    engine = create_async_engine(settings.database_url, echo=False, future=True)
    try:
        async with engine.begin() as conn:
            summary: dict[str, dict[str, int]] = {}
            for table_name in _TABLES:
                updated, skipped = await _migrate_table(conn, table_name, dry_run=dry_run)
                summary[table_name] = {"encrypted": updated, "already_encrypted": skipped}
            if dry_run:
                await conn.rollback()
            return summary
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Encrypt plaintext PIdP identity_data JSONB rows.")
    parser.add_argument("--dry-run", action="store_true", help="Report rows that would be encrypted without writing changes.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    summary = asyncio.run(migrate_identity_data(dry_run=args.dry_run))
    for table_name, counts in summary.items():
        LOG.info(
            "%s encrypted=%s already_encrypted=%s dry_run=%s",
            table_name,
            counts["encrypted"],
            counts["already_encrypted"],
            args.dry_run,
        )


if __name__ == "__main__":
    main()
