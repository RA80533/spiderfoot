from __future__ import annotations

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


@orm_registry.mapped_as_dataclass
class TblScanConfig:
    __tablename__ = "tbl_scan_config"
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    component: sqlalchemy.orm.Mapped[str]
    opt: sqlalchemy.orm.Mapped[str]
    val: sqlalchemy.orm.Mapped[str]


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


# TODO Change "tbl_scan_correlation_results_events" to "tbl_scan_correlation_result_event"
@orm_registry.mapped_as_dataclass
class TblScanCorrelationResultEvent:
    __tablename__ = "tbl_scan_correlation_results_events"
    
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


@orm_registry.mapped_as_dataclass
class TblScanLog:
    __tablename__ = "tbl_scan_log"
    
    scan_instance_id: sqlalchemy.orm.Mapped[str] = mapped_column(
        sqlalchemy.ForeignKey("tbl_scan_instances.guid"),
    )
    generated: sqlalchemy.orm.Mapped[int]
    component: sqlalchemy.orm.Mapped[str | None]
    type: sqlalchemy.orm.Mapped[str]
    message: sqlalchemy.orm.Mapped[str | None]


# TODO Change "tbl_scan_results" to "tbl_scan_result"
# TODO Fix `confidence` default
# TODO Fix `visibility` default
# TODO Fix `risk` default
# TODO Fix `false_positive` default
# TODO Fix `source_event_hash` default
@orm_registry.mapped_as_dataclass
class TblScanResult:
    __tablename__ = "tbl_scan_results"
    
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
