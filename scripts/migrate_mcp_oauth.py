"""Create the PostgreSQL OAuth tables without changing existing identity tables."""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db import engine
from models import Base
import mcp_authorization  # Registers the shared OAuth schema with Base.


async def main():
    tables = [table for table in Base.metadata.sorted_tables if table.name.startswith('mcp_oauth_')]
    async with engine.begin() as connection:
        await connection.run_sync(lambda conn: Base.metadata.create_all(conn, tables=tables, checkfirst=True))
    await engine.dispose()
    print('MCP OAuth tables are ready.')


if __name__ == '__main__':
    asyncio.run(main())
