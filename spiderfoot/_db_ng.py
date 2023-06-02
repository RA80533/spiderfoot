from __future__ import annotations

import itertools
import typing
from time import time

import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.ext.asyncio
import sqlalchemy.orm

from .db import _eventDetails
from ._db_schema import TblConfig, TblScanCorrelationResult
from ._db_schema import TblEventType
from ._db_schema import TblScanInstance
from ._db_schema import TblScanLog
from ._db_schema import TblScanResult
from ._db_schema import orm_registry


class _Opts(typing.TypedDict):
    
    __database: str
    """Path to the database file."""


class SpiderFootDb:
    
    _engine: sqlalchemy.ext.asyncio.AsyncEngine
    _session_factory: sqlalchemy.ext.asyncio.async_sessionmaker[sqlalchemy.ext.asyncio.AsyncSession]
    
    def __init__(self, opts: _Opts, init: bool = False) -> None:
        self._engine = sqlalchemy.ext.asyncio.create_async_engine(
            opts["__database"],
        )
        self._session_factory = sqlalchemy.ext.asyncio.async_sessionmaker(
            self._engine,
            expire_on_commit=False,
        )
        
        if init:
            self.create()
    
    def create(self) -> None:
        tbl_event_type_iter = itertools.starmap(TblEventType, _eventDetails)
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                with ctx.begin_nested():
                    orm_registry.metadata.create_all(ctx.connection())
                
                ctx.add_all(tbl_event_type_iter)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when setting up database") from e
    
    def close(self) -> None:
        self._engine.sync_engine.dispose()
    
    class _Criteria(typing.TypedDict, total=False):
        scan_id: str
        type: str
        value: str
        regex: str
    
    class _CriteriaScanid(typing.TypedDict):
        scan_id: str
    
    class _CriteriaType(typing.TypedDict):
        type: str
    
    class _CriteriaValue(typing.TypedDict):
        value: str
    
    class _CriteriaRegex(typing.TypedDict):
        regex: str
    
    class _CriteriaScanidType(
        _Criteria,
        _CriteriaScanid,
        _CriteriaType,
    ):
        pass
    
    class _CriteriaScanidValue(
        _Criteria,
        _CriteriaScanid,
        _CriteriaValue,
    ):
        pass
    
    class _CriteriaScanidRegex(
        _Criteria,
        _CriteriaScanid,
        _CriteriaRegex,
    ):
        pass
    
    class _CriteriaTypeValue(
        _Criteria,
        _CriteriaType,
        _CriteriaValue,
    ):
        pass
    
    class _CriteriaTypeRegex(
        _Criteria,
        _CriteriaType,
        _CriteriaRegex,
    ):
        pass
    
    class _CriteriaValueRegex(
        _Criteria,
        _CriteriaValue,
        _CriteriaRegex,
    ):
        pass
    
    Criteria = typing.Union[
        _CriteriaScanidType,
        _CriteriaScanidValue,
        _CriteriaScanidRegex,
        _CriteriaTypeValue,
        _CriteriaTypeRegex,
        _CriteriaValueRegex,
    ]
    
    def search(
        self,
        criteria: Criteria,
        filterFp: bool = False,
    ) -> typing.Sequence[...]:
        tbl_c = sqlalchemy.orm.aliased(TblScanResult)
        tbl_s = sqlalchemy.orm.aliased(TblScanResult)
        
        stmt = (
            sqlalchemy
                .select(
                    sqlalchemy.func.round(  # type: ignore[reportUnknownMemberType]
                        tbl_c.generated,
                    ).alias(
                        tbl_c.generated,
                    ),
                    tbl_c.data,
                    tbl_s.data.label("source_data"),
                    tbl_c.module,
                    tbl_c.type,
                    tbl_c.confidence,
                    tbl_c.visibility,
                    tbl_c.risk,
                    tbl_c.hash,
                    tbl_c.source_event_hash,
                    TblEventType.event_descr,
                    TblEventType.event_type,
                    tbl_c.scan_instance_id,
                    tbl_c.false_positive.label("fp"),
                    tbl_s.false_positive.label("parent_fp"),
                )
                .join_from(
                    tbl_c,
                    tbl_s,
                    # tbl_c.scan_instance_id == tbl_s.scan_instance_id,
                )
                .join_from(
                    tbl_c,
                    TblEventType,
                    tbl_c.type == TblEventType.event,
                )
                .where(tbl_c.source_event_hash == tbl_s.hash)
                .order_by(tbl_c.data)
        )
        
        if filterFp:
            stmt = stmt.where(tbl_c.false_positive != 1)
        
        if "scan_id" in criteria:
            _scan_id = criteria["scan_id"]
            stmt = stmt.where(tbl_c.scan_instance_id == _scan_id)
        
        if "type" in criteria:
            _type = criteria["type"]
            stmt = stmt.where(tbl_c.type == _type)
        
        if "value" in criteria:
            _value = criteria["value"]
            stmt = stmt.where(
                sqlalchemy.or_(
                    tbl_c.data.like(_value),
                    tbl_s.data.like(_value),
                ),
            )
        
        if "regex" in criteria:
            _regex = criteria["regex"]
            stmt = stmt.where(
                sqlalchemy.or_(
                    tbl_c.data.like(_regex),
                    tbl_s.data.like(_regex),
                ),
            )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when fetching search results") from e
    
    def eventTypes(self) -> typing.Sequence[TblEventType]:
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.scalars(sqlalchemy.select(TblEventType)).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when retrieving event types") from e
    
    # def scanLogEvents(self, batch: list[...]) -> bool:
    #     raise NotImplementedError
    
    # def scanLogEvent(
    #     self,
    #     instanceId: str,
    #     classification: str,
    #     message: str,
    #     component: str | None = None,
    # ) -> None:
    #     raise NotImplementedError
    
    def scanInstanceCreate(
        self,
        instanceId: str,
        scanName: str,
        scanTarget: str,
    ) -> None:
        tbl_scan_instance = TblScanInstance(
            guid=instanceId,
            name=scanName,
            seed_target=scanTarget,
            created=int(time() * 1_000),
            status="CREATED",
        )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.add(tbl_scan_instance)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to create scan instance in database") from e
    
    @typing.overload
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str,
        ended: str | None = None,
        status: str | None = None,
    ) -> None:
        ...
    
    @typing.overload
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None,
        ended: str,
        status: str | None = None,
    ) -> None:
        ...
    
    @typing.overload
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None = None,
        *,
        ended: str,
        status: str | None = None,
    ) -> None:
        ...
    
    @typing.overload
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None,
        ended: str | None,
        status: str,
    ) -> None:
        ...
    
    @typing.overload
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None = None,
        ended: str | None = None,
        *,
        status: str,
    ) -> None:
        ...
    
    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None = None,
        ended: str | None = None,
        status: str | None = None,
    ) -> None:
        partial_tbl_scan_instance = {
            TblScanInstance.started: started,
            TblScanInstance.ended: ended,
            TblScanInstance.status: status,
        }
        partial_tbl_scan_instance = {
            k: int(v)
            for k, v in partial_tbl_scan_instance.items()
            if v is not None
        }
        
        stmt = (
            sqlalchemy
                .update(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
                .values(partial_tbl_scan_instance)
        )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError:
            raise IOError("Unable to set information for the scan instance.") from None
    
    def scanInstanceGet(self, instanceId: str) -> TblScanInstance:
        stmt = (
            sqlalchemy
                .select(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
        )
        
        # stmt = (
        #     sqlalchemy
        #         .select(
        #             TblScanInstance.name,
        #             TblScanInstance.seed_target,
        #             sqlalchemy.func.round(  # type: ignore[reportUnknownMemberType]
        #                 TblScanInstance.created / 1_000,
        #             ).alias(
        #                 TblScanInstance.created,
        #             ),
        #             sqlalchemy.func.round(  # type: ignore[reportUnknownMemberType]
        #                 TblScanInstance.started / 1_000,
        #             ).alias(
        #                 TblScanInstance.started,
        #             ),
        #             sqlalchemy.func.round(  # type: ignore[reportUnknownMemberType]
        #                 TblScanInstance.ended / 1_000,
        #             ).alias(
        #                 TblScanInstance.ended,
        #             ),
        #             TblScanInstance.status,
        #         )
        #         .where(TblScanInstance.guid == instanceId)
        # )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.execute(stmt).scalar_one()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when retrieving scan instance") from e
    
    ...
    
    def scanResultEventUnique(
        self,
        instanceId: str,
        eventType: str = "ALL",
        filterFp: bool = False,
    ) -> typing.Sequence[...]:
        stmt = (
            sqlalchemy
                .select(
                    sqlalchemy.distinct(TblScanResult.data),
                    TblScanResult.type,
                    sqlalchemy.func.count(),
                )
                .select_from(TblScanResult)
                .where(TblScanResult.scan_instance_id == instanceId)
                .group_by(
                    TblScanResult.type,
                    TblScanResult.data,
                )
                .order_by(sqlalchemy.func.count())
        )
        
        if eventType != "ALL":
            stmt = stmt.where(TblScanResult.type == eventType)
        
        if filterFp:
            stmt = stmt.where(TblScanResult.false_positive != 1)
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when fetching unique result events") from e
    
    def scanLogs(
        self,
        instanceId: str,
        limit: int | None = None,
        fromRowId: int = 0,
        reverse: bool = False,
    ) -> typing.Sequence[TblScanLog]:
        stmt = (
            sqlalchemy
                .select(TblScanLog)
                .where(TblScanLog.scan_instance_id == instanceId)
        )
        
        if fromRowId:
            raise NotImplementedError
        
        if reverse:
            stmt = stmt.order_by(TblScanLog.generated.asc())
        else:
            stmt = stmt.order_by(TblScanLog.generated)
        
        if limit is not None:
            stmt = stmt.limit(limit)
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when fetching scan logs") from e
    
    def scanErrors(
        self,
        instanceId: str,
        limit: int = 0,
    ) -> typing.Sequence[...]:
        stmt = (
            sqlalchemy
                .select(
                    TblScanLog.generated,
                    TblScanLog.component,
                    TblScanLog.message,
                )
                .where(
                    TblScanLog.scan_instance_id == instanceId,
                    TblScanLog.type == "ERROR",
                )
                .order_by(TblScanLog.generated)
        )
        
        if limit:
            stmt = stmt.limit(limit)
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when fetching scan errors") from e
    
    ...
    
    def scanInstanceDelete(self, instanceId: str) -> bool:
        stmt = (
            sqlalchemy
                .delete(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
        )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when deleting scan") from e
        
        return True
    
    def scanResultsUpdateFP(
        self,
        instanceId: str,
        resultHashes: list[str],
        fpFlag: int,
    ) -> bool:
        partial_tbl_scan_result = {
            TblScanResult.false_positive: fpFlag,
        }
        
        stmt = (
            sqlalchemy
                .update(TblScanResult)
                .values(partial_tbl_scan_result)
                .where(
                    TblScanResult.scan_instance_id == instanceId,
                    TblScanResult.hash.in_(resultHashes),
                )
        )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when updating false-positive") from e
        
        return True
    
    ...
    
    def configClear(self) -> None:
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.execute(sqlalchemy.delete(TblConfig))
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to clear configuration from the database") from e
    
    ...
    
    def scanInstanceList(self) -> ...:
        stmt = ...
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ...
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when fetching scan list") from e
    
    ...
    
    def correlationResultCreate(
        self,
        instanceId: str,
        ruleId: str,
        ruleName: str,
        ruleDescr: str,
        ruleRisk: str,
        ruleYaml: str,
        correlationTitle: str,
        eventHashes: list[...],
    ) -> str:
        tbl_scan_correlation_result = TblScanCorrelationResult(
            scan_instance_id=instanceId,
            title=correlationTitle,
            rule_risk=ruleRisk,
            rule_id=ruleId,
            rule_name=ruleName,
            rule_descr=ruleDescr,
            rule_logic=ruleYaml,
        )
        
        try:
            with self._session_factory().sync_session as ctx, ctx.begin():
                ctx.add(tbl_scan_correlation_result)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to create correlation result in database") from e
        
        return tbl_scan_correlation_result.id
