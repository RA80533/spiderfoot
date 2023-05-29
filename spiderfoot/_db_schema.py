from __future__ import annotations

import typing
import uuid

import warnings

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


@orm_registry.mapped_as_dataclass
class TblEventType:
    __tablename__ = "tbl_event_type"
    
    event: sqlalchemy.orm.Mapped[str] = mapped_column(primary_key=True)
    event_descr: sqlalchemy.orm.Mapped[str]
    event_raw: sqlalchemy.orm.Mapped[int] = mapped_column(
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    event_type: sqlalchemy.orm.Mapped[str]


@orm_registry.mapped_as_dataclass
class TblScanConfig:
    __tablename__ = "tbl_scan_config"
    
    _pk: sqlalchemy.orm.Mapped[uuid.UUID] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instance.guid"),
    )
    component: sqlalchemy.orm.Mapped[str]
    opt: sqlalchemy.orm.Mapped[str]
    val: sqlalchemy.orm.Mapped[str]


@orm_registry.mapped_as_dataclass
class TblScanCorrelationResult:
    __tablename__ = "tbl_scan_correlation_result"
    
    # TODO Change `str` to `uuid.UUID`
    id: sqlalchemy.orm.Mapped[str] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instance.guid"),
    )
    title: sqlalchemy.orm.Mapped[str]
    rule_risk: sqlalchemy.orm.Mapped[str]
    rule_id: sqlalchemy.orm.Mapped[str]
    rule_name: sqlalchemy.orm.Mapped[str]
    rule_descr: sqlalchemy.orm.Mapped[str]
    rule_logic: sqlalchemy.orm.Mapped[str]


@orm_registry.mapped_as_dataclass
class TblScanCorrelationResultEvent:
    __tablename__ = "tbl_scan_correlation_result_event"
    
    _pk: sqlalchemy.orm.Mapped[uuid.UUID] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    
    correlation_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_correlation_result.id"),
    )
    event_hash: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_result.hash"),
    )


@orm_registry.mapped_as_dataclass
class TblScanInstance:
    __tablename__ = "tbl_scan_instance"
    
    # TODO Change `str` to `uuid.UUID`
    guid: sqlalchemy.orm.Mapped[str] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    name: sqlalchemy.orm.Mapped[str]
    seed_target: sqlalchemy.orm.Mapped[str]
    created: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default=0,  # TODO Figure out how to not require this
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    started: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default=0,  # TODO Figure out how to not require this
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    ended: sqlalchemy.orm.Mapped[int | None] = mapped_column(
        default=0,  # TODO Figure out how to not require this
        kw_only=True,
        server_default=sqlalchemy.text("0"),  # DEFAULT 0
    )
    status: sqlalchemy.orm.Mapped[str]


@orm_registry.mapped_as_dataclass
class TblScanLog:
    __tablename__ = "tbl_scan_log"
    
    _pk: sqlalchemy.orm.Mapped[uuid.UUID] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instance.guid"),
    )
    generated: sqlalchemy.orm.Mapped[int]
    component: sqlalchemy.orm.Mapped[str | None]
    type: sqlalchemy.orm.Mapped[str]
    message: sqlalchemy.orm.Mapped[str | None]


@orm_registry.mapped_as_dataclass
class TblScanResult:
    __tablename__ = "tbl_scan_result"
    
    _pk: sqlalchemy.orm.Mapped[uuid.UUID] = mapped_column(
        default_factory=uuid.uuid4,
        kw_only=True,
        primary_key=True,
    )
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instance.guid"),
    )
    hash: sqlalchemy.orm.Mapped[str]
    type: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_event_type.event"),
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
