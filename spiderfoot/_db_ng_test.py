from __future__ import annotations

import pytest
import sqlalchemy.orm
from sqlalchemy import func
from sqlalchemy import select

from ._db_ng import SpiderFootDb
from ._db_schema import TblEventType


@pytest.fixture
def db() -> SpiderFootDb:
    return SpiderFootDb({
        "__database": "sqlite:///:memory:",
    })


def test_create(db: SpiderFootDb):
    db.create()
    
    # with sqlalchemy.orm.Session(db._engine) as session, session.begin():
    #     result = session.execute(
    #         select(func.count()).select_from(TblEventType),
    #     )
    
    # assert result.scalar_one() == 172
    
    with sqlalchemy.orm.Session(db._engine) as session, session.begin():
        for tbl_event_type in session.execute(
            select(TblEventType),
        ).scalars():
            print(f"{tbl_event_type = }")


if __name__ == "__main__":
    _db = SpiderFootDb({"__database": "sqlite:///:memory:"}, init=True)
    
    with sqlalchemy.orm.Session(_db._engine) as ctx, ctx.begin():
        for tbl_event_type in ctx.execute(select(TblEventType)).scalars():
            print(f"{tbl_event_type = }")
