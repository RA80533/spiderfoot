from __future__ import annotations

import dataclasses
import typing


@dataclasses.dataclass(frozen=True)
class Rule:
    id: str
    version: int
    meta: _RuleSummary
    collections: _Collections
    aggregation: _Aggregation | None
    analysis: _Analysis | None


@dataclasses.dataclass(frozen=True)
class _RuleSummary:
    name: str
    description: str
    risk: ...


@dataclasses.dataclass(frozen=True)
class _CollectionsItem:
    collect: list[Matchrule]


_Collections = list[_CollectionsItem]


@dataclasses.dataclass(frozen=True)
class _Aggregation:
    field: str


@dataclasses.dataclass(frozen=True)
class _AnalysisItem_FirstCollectionOnly:
    method: typing.Literal["first_collection_only"]
    field: str


@dataclasses.dataclass(frozen=True)
class _AnalysisItem_MatchAllToFirstCollection:
    method: typing.Literal["match_all_to_first_collection"]
    field: str
    match_method: str


@dataclasses.dataclass(frozen=True)
class _AnalysisItem_Outlier:
    method: typing.Literal["outlier"]
    maximum_percent: float
    noisy_percent: float = 10.0


@dataclasses.dataclass(frozen=True)
class _AnalysisItem_Threshold:
    method: typing.Literal["threshold"]
    field: str
    count_unique_only: bool = False
    minimum: int = 0
    maximum: int = 999999999


_AnalysisItem = typing.Union[
    _AnalysisItem_FirstCollectionOnly,
    _AnalysisItem_MatchAllToFirstCollection,
    _AnalysisItem_Outlier,
    _AnalysisItem_Threshold,
]


_Analysis = list[_AnalysisItem]


@dataclasses.dataclass(frozen=True)
class Matchrule:
    method: ...
    field: ...
    value: list[str] | str
