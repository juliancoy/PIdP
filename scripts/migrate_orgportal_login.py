"""Rename the shared OrgPortal login application without replacing accounts."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db import engine
from sqlalchemy import text


async def main():
    try:
        async with engine.begin() as connection:
            await connection.execute(text("""
                UPDATE websites SET slug = 'orgportal', name = 'OrgPortal',
                    description = 'One OrgPortal account for all groups.'
                WHERE slug = 'code-collective'
            """))
    finally:
        await engine.dispose()


if __name__ == '__main__':
    asyncio.run(main())
