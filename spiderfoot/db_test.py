from __future__ import annotations

from contextlib import suppress

import pytest

from .db import SpiderFootDb


@pytest.fixture
def db() -> SpiderFootDb:
    return SpiderFootDb({"__database": f"sqlite+pysqlite://{'/:memory:'}"}, init=True)


class TestSpiderFootDb:
    
    @pytest.mark.skip("TODO")
    class Test__Init__:
        
        @pytest.mark.skip("TODO")
        def test_opts(self): ...
        
        @pytest.mark.skip("TODO")
        def test_init(self): ...
        
        @pytest.mark.skip("TODO")
        def test_init_defaults_to_False(self): ...
    
    @pytest.mark.skip("TODO")
    class TestCreate: ...
    
    @pytest.mark.skip("TODO")
    class TestClose: ...
    
    class TestSearch:
        
        @pytest.mark.skip("TODO")
        def test_criteria(self): ...
        
        def test_criteria_invalid_key(self, db: SpiderFootDb):
            invalid_key = "name"
            criteria = {invalid_key: ""}
            with suppress(ValueError):
                with pytest.warns(
                    Warning,
                    match=f"Found invalid search criteria",
                ):
                    db.search(criteria)
        
        def test_criteria_len_0_raises_ValueError(self, db: SpiderFootDb):
            criteria ={}
            with pytest.raises(
                ValueError,
                match="No valid search criteria provided",
            ):
                db.search(criteria)
        
        def test_criteria_len_1_raises_ValueError(self, db: SpiderFootDb):
            criteria ={"scan_id": ""}
            with pytest.raises(
                ValueError,
                match="Only one search criteria provided",
            ):
                db.search(criteria)
        
        @pytest.mark.skip("TODO")
        def test_criteria_scan_id(self): ...
        
        @pytest.mark.skip("TODO")
        def test_criteria_type(self): ...
        
        @pytest.mark.skip("TODO")
        def test_criteria_value(self): ...
        
        @pytest.mark.skip("TODO")
        def test_criteria_regex(self): ...
        
        @pytest.mark.skip("TODO")
        def test_filterFp(self): ...
        
        @pytest.mark.skip("TODO")
        def test_filterFp_defaults_to_False(self): ...
        
        # TODO Patch sqlalchemy to raise an exception
        @pytest.mark.skip("TODO")
        def test_raises_IOError_on_sqlalchemy_exc_DBAPIError(self): ...
