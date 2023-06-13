from __future__ import annotations

import typing
import uuid

import sqlalchemy
import sqlalchemy.orm
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


orm_registry: sqlalchemy.orm.registry = sqlalchemy.orm.registry()


@orm_registry.mapped_as_dataclass
class TblConfig:
    __tablename__ = "tbl_config"
    
    scope: Mapped[str] = mapped_column(primary_key=True)
    opt: Mapped[str] = mapped_column(primary_key=True)
    val: Mapped[str]
    
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


@orm_registry.mapped_as_dataclass
class TblEventType:
    __tablename__ = "tbl_event_types"
    
    event: Mapped[str] = mapped_column(primary_key=True)
    event_descr: Mapped[str]
    event_raw: Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    event_type: Mapped[str]


_tbl_scan_config_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanConfig:
    __tablename__ = "tbl_scan_config"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_config_rowid
        _tbl_scan_config_rowid += 1
        return _tbl_scan_config_rowid
    
    rowid: Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    component: Mapped[str]
    opt: Mapped[str]
    val: Mapped[str]
    
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


@orm_registry.mapped_as_dataclass
class TblScanCorrelationResult:
    __tablename__ = "tbl_scan_correlation_results"
    
    id: Mapped[str] = mapped_column(
        default_factory=lambda: str(uuid.uuid4()),
        kw_only=True,
        primary_key=True,
    )
    scan_instance_id: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    title: Mapped[str]
    rule_risk: Mapped[str]
    rule_id: Mapped[str]
    rule_name: Mapped[str]
    rule_descr: Mapped[str]
    rule_logic: Mapped[str]


_tbl_scan_correlation_results_events_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanCorrelationResultEvent:
    __tablename__ = "tbl_scan_correlation_results_events"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_correlation_results_events_rowid
        _tbl_scan_correlation_results_events_rowid += 1
        return _tbl_scan_correlation_results_events_rowid
    
    rowid: Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    correlation_id: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_correlation_results.id"),
    )
    event_hash: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_results.hash"),
    )


@orm_registry.mapped_as_dataclass
class TblScanInstance:
    __tablename__ = "tbl_scan_instances"
    
    guid: Mapped[str] = mapped_column(
        default_factory=lambda: str(uuid.uuid4()),
        kw_only=True,
        primary_key=True,
    )
    name: Mapped[str]
    seed_target: Mapped[str]
    created: Mapped[int | None] = mapped_column(
        default=0,
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    started: Mapped[int | None] = mapped_column(
        default=0,
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    ended: Mapped[int | None] = mapped_column(
        default=0,
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    status: Mapped[str]


_tbl_scan_log_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanLog:
    __tablename__ = "tbl_scan_log"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_log_rowid
        _tbl_scan_log_rowid += 1
        return _tbl_scan_log_rowid
    
    rowid: Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    generated: Mapped[int]
    component: Mapped[str | None]
    type: Mapped[str]
    message: Mapped[str | None]


_tbl_scan_results_rowid = 0

@orm_registry.mapped_as_dataclass
class TblScanResult:
    __tablename__ = "tbl_scan_results"
    
    @staticmethod
    def autoincrement() -> int:
        global _tbl_scan_results_rowid
        _tbl_scan_results_rowid += 1
        return _tbl_scan_results_rowid
    
    rowid: Mapped[int] = mapped_column(
        default_factory=autoincrement,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    hash: Mapped[str]
    type: Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_event_types.event"),
    )
    generated: Mapped[int]
    confidence: Mapped[int] = mapped_column(
        default=100,
        kw_only=True,
        server_default=sqlalchemy.text("100"),  # DEFAULT 100
    )
    visibility: Mapped[int] = mapped_column(
        default=100,
        kw_only=True,
        server_default=sqlalchemy.text("100"),  # DEFAULT 100
    )
    risk: Mapped[int] = mapped_column(
        default=0,
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    module: Mapped[str]
    data: Mapped[str | None]
    false_positive: Mapped[int] = mapped_column(
        default=0,
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    source_event_hash: Mapped[str | None] = mapped_column(
        default="ROOT",
        kw_only=True,
        server_default=sqlalchemy.text("'ROOT'"),  # DEFAULT 'ROOT'
    )
