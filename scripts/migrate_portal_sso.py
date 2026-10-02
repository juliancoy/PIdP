"""Create browser SSO handoff storage without altering identity tables."""
import asyncio
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from db import engine
from models import PortalSsoRequest, PortalSsoLimit
async def main():
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: PortalSsoRequest.__table__.create(c, checkfirst=True))
        await conn.run_sync(lambda c: PortalSsoLimit.__table__.create(c, checkfirst=True))
    await engine.dispose()
if __name__ == '__main__':
    asyncio.run(main())
