from __future__ import annotations

import typing
import uuid
from time import time

import sqlalchemy
import sqlalchemy.orm
from sqlalchemy.orm import mapped_column


orm_registry = sqlalchemy.orm.registry()


@orm_registry.mapped_as_dataclass
class TblConfig:
    __tablename__ = "tbl_config"
    
    scope: sqlalchemy.orm.Mapped[str] = mapped_column(primary_key=True)
    opt: sqlalchemy.orm.Mapped[str] = mapped_column(primary_key=True)
    val: sqlalchemy.orm.Mapped[str]
    
    @classmethod
    def from_tbl_iter(
        cls,
        tbl_iter: typing.Sequence[TblConfig],
    ) -> dict[str, str]:
        raw_config = dict[str, str]()
        for tbl_config in tbl_iter:
            key = (
                f"{tbl_config.scope}:{tbl_config.opt}"
                if tbl_config.scope != "GLOBAL"
                else tbl_config.opt
            )
            raw_config[key] = tbl_config.val
        return raw_config
    
    @classmethod
    def from_raw(cls, raw: dict[str, str]) -> typing.Sequence[TblConfig]:
        tbl_config_iter = list[TblConfig]()
        for key, val in raw.items():
            if ":" in key:
                scope, opt = key.split(":")
            else:
                scope, opt = "GLOBAL", key
            tbl_config = TblConfig(scope, opt, val)
            tbl_config_iter.append(tbl_config)
        return tbl_config_iter


# TODO Change "tbl_event_types" to "tbl_event_type"
# TODO Fix `event_raw` default
@orm_registry.mapped_as_dataclass
class TblEventType:
    __tablename__ = "tbl_event_types"
    
    event: sqlalchemy.orm.Mapped[str] = mapped_column(primary_key=True)
    event_descr: sqlalchemy.orm.Mapped[str]
    event_raw: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    event_type: sqlalchemy.orm.Mapped[str]


_tbl_scan_config_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanConfig:
    __tablename__ = "tbl_scan_config"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_config_rowid
        _tbl_scan_config_rowid += 1
        return _tbl_scan_config_rowid
    
    rowid: sqlalchemy.orm.Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    component: sqlalchemy.orm.Mapped[str]
    opt: sqlalchemy.orm.Mapped[str]
    val: sqlalchemy.orm.Mapped[str]
    
    
    @classmethod
    def from_tbl_iter(
        cls,
        tbl_iter: typing.Sequence[TblScanConfig],
    ) -> dict[str, str]:
        raw_scan_config = dict[str, str]()
        for tbl_scan_config in tbl_iter:
            key = (
                f"{tbl_scan_config.component}:{tbl_scan_config.opt}"
                if tbl_scan_config.component != "GLOBAL"
                else tbl_scan_config.opt
            )
            raw_scan_config[key] = tbl_scan_config.val
        return raw_scan_config
    
    @classmethod
    def from_raw(
        cls,
        raw: dict[str, str],
        *,
        scan_instance_id: str,
    ) -> typing.Sequence[TblScanConfig]:
        tbl_scan_config_iter = list[TblScanConfig]()
        for key, val in raw.items():
            if ":" in key:
                component, opt = key.split(":")
            else:
                component, opt = "GLOBAL", key
            tbl_scan_config = TblScanConfig(
                scan_instance_id,
                component,
                opt,
                val,
            )
            tbl_scan_config_iter.append(tbl_scan_config)
        return tbl_scan_config_iter


# TODO Change "tbl_scan_correlation_results" to "tbl_scan_correlation_result"
@orm_registry.mapped_as_dataclass
class TblScanCorrelationResult:
    __tablename__ = "tbl_scan_correlation_results"
    
    id: sqlalchemy.orm.Mapped[str] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    title: sqlalchemy.orm.Mapped[str]
    rule_risk: sqlalchemy.orm.Mapped[str]
    rule_id: sqlalchemy.orm.Mapped[str]
    rule_name: sqlalchemy.orm.Mapped[str]
    rule_descr: sqlalchemy.orm.Mapped[str]
    rule_logic: sqlalchemy.orm.Mapped[str]


_tbl_scan_correlation_results_events_rowid = 0

# TODO Change "tbl_scan_correlation_results_events" to "tbl_scan_correlation_result_event"
@orm_registry.mapped_as_dataclass
class TblScanCorrelationResultEvent:
    __tablename__ = "tbl_scan_correlation_results_events"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_correlation_results_events_rowid
        _tbl_scan_correlation_results_events_rowid += 1
        return _tbl_scan_correlation_results_events_rowid
    
    rowid: sqlalchemy.orm.Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    correlation_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_correlation_results.id"),
    )
    event_hash: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_results.hash"),
    )


# TODO Change "tbl_scan_instances" to "tbl_scan_instance"
@orm_registry.mapped_as_dataclass
class TblScanInstance:
    __tablename__ = "tbl_scan_instances"
    
    guid: sqlalchemy.orm.Mapped[str] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    name: sqlalchemy.orm.Mapped[str]
    seed_target: sqlalchemy.orm.Mapped[str]
    created: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default_factory=lambda: int(time() * 1_000),
        kw_only=True,
    )
    started: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default=None,
        kw_only=True,
    )
    ended: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default=None,
        kw_only=True,
    )
    status: sqlalchemy.orm.Mapped[str] = mapped_column(
        default="CREATED",
    )


_tbl_scan_log_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanLog:
    __tablename__ = "tbl_scan_log"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_log_rowid
        _tbl_scan_log_rowid += 1
        return _tbl_scan_log_rowid
    
    rowid: sqlalchemy.orm.Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    generated: sqlalchemy.orm.Mapped[int]
    component: sqlalchemy.orm.Mapped[str | None]
    type: sqlalchemy.orm.Mapped[str]
    message: sqlalchemy.orm.Mapped[str | None]


_tbl_scan_results_rowid = 0

# TODO Change "tbl_scan_results" to "tbl_scan_result"
# TODO Fix `confidence` default
# TODO Fix `visibility` default
# TODO Fix `risk` default
# TODO Fix `false_positive` default
# TODO Fix `source_event_hash` default
@orm_registry.mapped_as_dataclass
class TblScanResult:
    __tablename__ = "tbl_scan_results"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_results_rowid
        _tbl_scan_results_rowid += 1
        return _tbl_scan_results_rowid
    
    rowid: sqlalchemy.orm.Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    hash: sqlalchemy.orm.Mapped[str]
    type: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_event_types.event"),
    )
    generated: sqlalchemy.orm.Mapped[int]
    confidence: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("100"),  # DEFAULT 100
    )
    visibility: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("100"),  # DEFAULT 100
    )
    risk: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    module: sqlalchemy.orm.Mapped[str]
    data: sqlalchemy.orm.Mapped[str | None]
    false_positive: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    source_event_hash: sqlalchemy.orm.Mapped[str | None] = mapped_column(
        server_default=sqlalchemy.text("'ROOT'"),  # DEFAULT 'ROOT'
    )
