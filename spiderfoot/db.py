# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfdb
# Purpose:      Common functions for working with the database back-end.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

from __future__ import annotations

import dataclasses
import itertools
import sqlite3
import typing
import warnings
from time import time

import dacite
import sqlalchemy
import sqlalchemy.exc
import sqlalchemy.orm
from sqlalchemy.orm import sessionmaker

from .db_schema import TblConfig
from .db_schema import TblEventType
from .db_schema import TblScanConfig
from .db_schema import TblScanCorrelationResult
from .db_schema import TblScanCorrelationResultEvent
from .db_schema import TblScanInstance
from .db_schema import TblScanLog
from .db_schema import TblScanResult
from .db_schema import orm_registry
from .event import SpiderFootEvent


# 3 in spiderfoot/db.py
# Queries for creating the SpiderFoot database
_createSchemaQueries = [
    "PRAGMA journal_mode=WAL",
    "CREATE INDEX idx_scan_results_id ON tbl_scan_results (scan_instance_id)",
    "CREATE INDEX idx_scan_results_type ON tbl_scan_results (scan_instance_id, type)",
    "CREATE INDEX idx_scan_results_hash ON tbl_scan_results (scan_instance_id, hash)",
    "CREATE INDEX idx_scan_results_module ON tbl_scan_results(scan_instance_id, module)",
    "CREATE INDEX idx_scan_results_srchash ON tbl_scan_results (scan_instance_id, source_event_hash)",
    "CREATE INDEX idx_scan_logs ON tbl_scan_log (scan_instance_id)",
    "CREATE INDEX idx_scan_correlation ON tbl_scan_correlation_results (scan_instance_id, id)",
    "CREATE INDEX idx_scan_correlation_events ON tbl_scan_correlation_results_events (correlation_id)"
]


_EventType = typing.Literal["DATA", "DESCRIPTOR", "ENTITY", "INTERNAL", "SUBENTITY"]


# 1 in spiderfoot/db.py
_eventDetails: list[tuple[str, str, typing.Literal[0, 1], _EventType]] = [
    ('ROOT', 'Internal SpiderFoot Root event', 1, 'INTERNAL'),
    ('ACCOUNT_EXTERNAL_OWNED', 'Account on External Site', 0, 'ENTITY'),
    ('ACCOUNT_EXTERNAL_OWNED_COMPROMISED', 'Hacked Account on External Site', 0, 'DESCRIPTOR'),
    ('ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED', 'Hacked User Account on External Site', 0, 'DESCRIPTOR'),
    ('AFFILIATE_EMAILADDR', 'Affiliate - Email Address', 0, 'ENTITY'),
    ('AFFILIATE_INTERNET_NAME', 'Affiliate - Internet Name', 0, 'ENTITY'),
    ('AFFILIATE_INTERNET_NAME_HIJACKABLE', 'Affiliate - Internet Name Hijackable', 0, 'ENTITY'),
    ('AFFILIATE_INTERNET_NAME_UNRESOLVED', 'Affiliate - Internet Name - Unresolved', 0, 'ENTITY'),
    ('AFFILIATE_IPADDR', 'Affiliate - IP Address', 0, 'ENTITY'),
    ('AFFILIATE_IPV6_ADDRESS', 'Affiliate - IPv6 Address', 0, 'ENTITY'),
    ('AFFILIATE_WEB_CONTENT', 'Affiliate - Web Content', 1, 'DATA'),
    ('AFFILIATE_DOMAIN_NAME', 'Affiliate - Domain Name', 0, 'ENTITY'),
    ('AFFILIATE_DOMAIN_UNREGISTERED', 'Affiliate - Domain Name Unregistered', 0, 'ENTITY'),
    ('AFFILIATE_COMPANY_NAME', 'Affiliate - Company Name', 0, 'ENTITY'),
    ('AFFILIATE_DOMAIN_WHOIS', 'Affiliate - Domain Whois', 1, 'DATA'),
    ('AFFILIATE_DESCRIPTION_CATEGORY', 'Affiliate Description - Category', 0, 'DESCRIPTOR'),
    ('AFFILIATE_DESCRIPTION_ABSTRACT', 'Affiliate Description - Abstract', 0, 'DESCRIPTOR'),
    ('APPSTORE_ENTRY', 'App Store Entry', 0, 'ENTITY'),
    ('CLOUD_STORAGE_BUCKET', 'Cloud Storage Bucket', 0, 'ENTITY'),
    ('CLOUD_STORAGE_BUCKET_OPEN', 'Cloud Storage Bucket Open', 0, 'DESCRIPTOR'),
    ('COMPANY_NAME', 'Company Name', 0, 'ENTITY'),
    ('CREDIT_CARD_NUMBER', 'Credit Card Number', 0, 'ENTITY'),
    ('BASE64_DATA', 'Base64-encoded Data', 1, 'DATA'),
    ('BITCOIN_ADDRESS', 'Bitcoin Address', 0, 'ENTITY'),
    ('BITCOIN_BALANCE', 'Bitcoin Balance', 0, 'DESCRIPTOR'),
    ('BGP_AS_OWNER', 'BGP AS Ownership', 0, 'ENTITY'),
    ('BGP_AS_MEMBER', 'BGP AS Membership', 0, 'ENTITY'),
    ('BLACKLISTED_COHOST', 'Blacklisted Co-Hosted Site', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_INTERNET_NAME', 'Blacklisted Internet Name', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_AFFILIATE_INTERNET_NAME', 'Blacklisted Affiliate Internet Name', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_IPADDR', 'Blacklisted IP Address', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_AFFILIATE_IPADDR', 'Blacklisted Affiliate IP Address', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_SUBNET', 'Blacklisted IP on Same Subnet', 0, 'DESCRIPTOR'),
    ('BLACKLISTED_NETBLOCK', 'Blacklisted IP on Owned Netblock', 0, 'DESCRIPTOR'),
    ('COUNTRY_NAME', 'Country Name', 0, 'ENTITY'),
    ('CO_HOSTED_SITE', 'Co-Hosted Site', 0, 'ENTITY'),
    ('CO_HOSTED_SITE_DOMAIN', 'Co-Hosted Site - Domain Name', 0, 'ENTITY'),
    ('CO_HOSTED_SITE_DOMAIN_WHOIS', 'Co-Hosted Site - Domain Whois', 1, 'DATA'),
    ('DARKNET_MENTION_URL', 'Darknet Mention URL', 0, 'DESCRIPTOR'),
    ('DARKNET_MENTION_CONTENT', 'Darknet Mention Web Content', 1, 'DATA'),
    ('DATE_HUMAN_DOB', 'Date of Birth', 0, 'ENTITY'),
    ('DEFACED_INTERNET_NAME', 'Defaced', 0, 'DESCRIPTOR'),
    ('DEFACED_IPADDR', 'Defaced IP Address', 0, 'DESCRIPTOR'),
    ('DEFACED_AFFILIATE_INTERNET_NAME', 'Defaced Affiliate', 0, 'DESCRIPTOR'),
    ('DEFACED_COHOST', 'Defaced Co-Hosted Site', 0, 'DESCRIPTOR'),
    ('DEFACED_AFFILIATE_IPADDR', 'Defaced Affiliate IP Address', 0, 'DESCRIPTOR'),
    ('DESCRIPTION_CATEGORY', 'Description - Category', 0, 'DESCRIPTOR'),
    ('DESCRIPTION_ABSTRACT', 'Description - Abstract', 0, 'DESCRIPTOR'),
    ('DEVICE_TYPE', 'Device Type', 0, 'DESCRIPTOR'),
    ('DNS_TEXT', 'DNS TXT Record', 0, 'DATA'),
    ('DNS_SRV', 'DNS SRV Record', 0, 'DATA'),
    ('DNS_SPF', 'DNS SPF Record', 0, 'DATA'),
    ('DOMAIN_NAME', 'Domain Name', 0, 'ENTITY'),
    ('DOMAIN_NAME_PARENT', 'Domain Name (Parent)', 0, 'ENTITY'),
    ('DOMAIN_REGISTRAR', 'Domain Registrar', 0, 'ENTITY'),
    ('DOMAIN_WHOIS', 'Domain Whois', 1, 'DATA'),
    ('EMAILADDR', 'Email Address', 0, 'ENTITY'),
    ('EMAILADDR_COMPROMISED', 'Hacked Email Address', 0, 'DESCRIPTOR'),
    ('EMAILADDR_DELIVERABLE', 'Deliverable Email Address', 0, 'DESCRIPTOR'),
    ('EMAILADDR_DISPOSABLE', 'Disposable Email Address', 0, 'DESCRIPTOR'),
    ('EMAILADDR_GENERIC', 'Email Address - Generic', 0, 'ENTITY'),
    ('EMAILADDR_UNDELIVERABLE', 'Undeliverable Email Address', 0, 'DESCRIPTOR'),
    ('ERROR_MESSAGE', 'Error Message', 0, 'DATA'),
    ('ETHEREUM_ADDRESS', 'Ethereum Address', 0, 'ENTITY'),
    ('ETHEREUM_BALANCE', 'Ethereum Balance', 0, 'DESCRIPTOR'),
    ('GEOINFO', 'Physical Location', 0, 'DESCRIPTOR'),
    ('HASH', 'Hash', 0, 'DATA'),
    ('HASH_COMPROMISED', 'Compromised Password Hash', 0, 'DATA'),
    ('HTTP_CODE', 'HTTP Status Code', 0, 'DATA'),
    ('HUMAN_NAME', 'Human Name', 0, 'ENTITY'),
    ('IBAN_NUMBER', 'IBAN Number', 0, 'ENTITY'),
    ('INTERESTING_FILE', 'Interesting File', 0, 'DESCRIPTOR'),
    ('INTERESTING_FILE_HISTORIC', 'Historic Interesting File', 0, 'DESCRIPTOR'),
    ('JUNK_FILE', 'Junk File', 0, 'DESCRIPTOR'),
    ('INTERNAL_IP_ADDRESS', 'IP Address - Internal Network', 0, 'ENTITY'),
    ('INTERNET_NAME', 'Internet Name', 0, 'ENTITY'),
    ('INTERNET_NAME_UNRESOLVED', 'Internet Name - Unresolved', 0, 'ENTITY'),
    ('IP_ADDRESS', 'IP Address', 0, 'ENTITY'),
    ('IPV6_ADDRESS', 'IPv6 Address', 0, 'ENTITY'),
    ('LEI', 'Legal Entity Identifier', 0, 'ENTITY'),
    ('JOB_TITLE', 'Job Title', 0, 'DESCRIPTOR'),
    ('LINKED_URL_INTERNAL', 'Linked URL - Internal', 0, 'SUBENTITY'),
    ('LINKED_URL_EXTERNAL', 'Linked URL - External', 0, 'SUBENTITY'),
    ('MALICIOUS_ASN', 'Malicious AS', 0, 'DESCRIPTOR'),
    ('MALICIOUS_BITCOIN_ADDRESS', 'Malicious Bitcoin Address', 0, 'DESCRIPTOR'),
    ('MALICIOUS_IPADDR', 'Malicious IP Address', 0, 'DESCRIPTOR'),
    ('MALICIOUS_COHOST', 'Malicious Co-Hosted Site', 0, 'DESCRIPTOR'),
    ('MALICIOUS_EMAILADDR', 'Malicious E-mail Address', 0, 'DESCRIPTOR'),
    ('MALICIOUS_INTERNET_NAME', 'Malicious Internet Name', 0, 'DESCRIPTOR'),
    ('MALICIOUS_AFFILIATE_INTERNET_NAME', 'Malicious Affiliate', 0, 'DESCRIPTOR'),
    ('MALICIOUS_AFFILIATE_IPADDR', 'Malicious Affiliate IP Address', 0, 'DESCRIPTOR'),
    ('MALICIOUS_NETBLOCK', 'Malicious IP on Owned Netblock', 0, 'DESCRIPTOR'),
    ('MALICIOUS_PHONE_NUMBER', 'Malicious Phone Number', 0, 'DESCRIPTOR'),
    ('MALICIOUS_SUBNET', 'Malicious IP on Same Subnet', 0, 'DESCRIPTOR'),
    ('NETBLOCK_OWNER', 'Netblock Ownership', 0, 'ENTITY'),
    ('NETBLOCKV6_OWNER', 'Netblock IPv6 Ownership', 0, 'ENTITY'),
    ('NETBLOCK_MEMBER', 'Netblock Membership', 0, 'ENTITY'),
    ('NETBLOCKV6_MEMBER', 'Netblock IPv6 Membership', 0, 'ENTITY'),
    ('NETBLOCK_WHOIS', 'Netblock Whois', 1, 'DATA'),
    ('OPERATING_SYSTEM', 'Operating System', 0, 'DESCRIPTOR'),
    ('LEAKSITE_URL', 'Leak Site URL', 0, 'ENTITY'),
    ('LEAKSITE_CONTENT', 'Leak Site Content', 1, 'DATA'),
    ('PASSWORD_COMPROMISED', 'Compromised Password', 0, 'DATA'),
    ('PHONE_NUMBER', 'Phone Number', 0, 'ENTITY'),
    ('PHONE_NUMBER_COMPROMISED', 'Phone Number Compromised', 0, 'DESCRIPTOR'),
    ('PHONE_NUMBER_TYPE', 'Phone Number Type', 0, 'DESCRIPTOR'),
    ('PHYSICAL_ADDRESS', 'Physical Address', 0, 'ENTITY'),
    ('PHYSICAL_COORDINATES', 'Physical Coordinates', 0, 'ENTITY'),
    ('PGP_KEY', 'PGP Public Key', 0, 'DATA'),
    ('PROXY_HOST', 'Proxy Host', 0, 'DESCRIPTOR'),
    ('PROVIDER_DNS', 'Name Server (DNS ''NS'' Records)', 0, 'ENTITY'),
    ('PROVIDER_JAVASCRIPT', 'Externally Hosted Javascript', 0, 'ENTITY'),
    ('PROVIDER_MAIL', 'Email Gateway (DNS ''MX'' Records)', 0, 'ENTITY'),
    ('PROVIDER_HOSTING', 'Hosting Provider', 0, 'ENTITY'),
    ('PROVIDER_TELCO', 'Telecommunications Provider', 0, 'ENTITY'),
    ('PUBLIC_CODE_REPO', 'Public Code Repository', 0, 'ENTITY'),
    ('RAW_RIR_DATA', 'Raw Data from RIRs/APIs', 1, 'DATA'),
    ('RAW_DNS_RECORDS', 'Raw DNS Records', 1, 'DATA'),
    ('RAW_FILE_META_DATA', 'Raw File Meta Data', 1, 'DATA'),
    ('SEARCH_ENGINE_WEB_CONTENT', 'Search Engine Web Content', 1, 'DATA'),
    ('SOCIAL_MEDIA', 'Social Media Presence', 0, 'ENTITY'),
    ('SIMILAR_ACCOUNT_EXTERNAL', 'Similar Account on External Site', 0, 'ENTITY'),
    ('SIMILARDOMAIN', 'Similar Domain', 0, 'ENTITY'),
    ('SIMILARDOMAIN_WHOIS', 'Similar Domain - Whois', 1, 'DATA'),
    ('SOFTWARE_USED', 'Software Used', 0, 'SUBENTITY'),
    ('SSL_CERTIFICATE_RAW', 'SSL Certificate - Raw Data', 1, 'DATA'),
    ('SSL_CERTIFICATE_ISSUED', 'SSL Certificate - Issued to', 0, 'ENTITY'),
    ('SSL_CERTIFICATE_ISSUER', 'SSL Certificate - Issued by', 0, 'ENTITY'),
    ('SSL_CERTIFICATE_MISMATCH', 'SSL Certificate Host Mismatch', 0, 'DESCRIPTOR'),
    ('SSL_CERTIFICATE_EXPIRED', 'SSL Certificate Expired', 0, 'DESCRIPTOR'),
    ('SSL_CERTIFICATE_EXPIRING', 'SSL Certificate Expiring', 0, 'DESCRIPTOR'),
    ('TARGET_WEB_CONTENT', 'Web Content', 1, 'DATA'),
    ('TARGET_WEB_CONTENT_TYPE', 'Web Content Type', 0, 'DESCRIPTOR'),
    ('TARGET_WEB_COOKIE', 'Cookies', 0, 'DATA'),
    ('TCP_PORT_OPEN', 'Open TCP Port', 0, 'SUBENTITY'),
    ('TCP_PORT_OPEN_BANNER', 'Open TCP Port Banner', 0, 'DATA'),
    ('TOR_EXIT_NODE', 'TOR Exit Node', 0, 'DESCRIPTOR'),
    ('UDP_PORT_OPEN', 'Open UDP Port', 0, 'SUBENTITY'),
    ('UDP_PORT_OPEN_INFO', 'Open UDP Port Information', 0, 'DATA'),
    ('URL_ADBLOCKED_EXTERNAL', 'URL (AdBlocked External)', 0, 'DESCRIPTOR'),
    ('URL_ADBLOCKED_INTERNAL', 'URL (AdBlocked Internal)', 0, 'DESCRIPTOR'),
    ('URL_FORM', 'URL (Form)', 0, 'DESCRIPTOR'),
    ('URL_FLASH', 'URL (Uses Flash)', 0, 'DESCRIPTOR'),
    ('URL_JAVASCRIPT', 'URL (Uses Javascript)', 0, 'DESCRIPTOR'),
    ('URL_WEB_FRAMEWORK', 'URL (Uses a Web Framework)', 0, 'DESCRIPTOR'),
    ('URL_JAVA_APPLET', 'URL (Uses Java Applet)', 0, 'DESCRIPTOR'),
    ('URL_STATIC', 'URL (Purely Static)', 0, 'DESCRIPTOR'),
    ('URL_PASSWORD', 'URL (Accepts Passwords)', 0, 'DESCRIPTOR'),
    ('URL_UPLOAD', 'URL (Accepts Uploads)', 0, 'DESCRIPTOR'),
    ('URL_FORM_HISTORIC', 'Historic URL (Form)', 0, 'DESCRIPTOR'),
    ('URL_FLASH_HISTORIC', 'Historic URL (Uses Flash)', 0, 'DESCRIPTOR'),
    ('URL_JAVASCRIPT_HISTORIC', 'Historic URL (Uses Javascript)', 0, 'DESCRIPTOR'),
    ('URL_WEB_FRAMEWORK_HISTORIC', 'Historic URL (Uses a Web Framework)', 0, 'DESCRIPTOR'),
    ('URL_JAVA_APPLET_HISTORIC', 'Historic URL (Uses Java Applet)', 0, 'DESCRIPTOR'),
    ('URL_STATIC_HISTORIC', 'Historic URL (Purely Static)', 0, 'DESCRIPTOR'),
    ('URL_PASSWORD_HISTORIC', 'Historic URL (Accepts Passwords)', 0, 'DESCRIPTOR'),
    ('URL_UPLOAD_HISTORIC', 'Historic URL (Accepts Uploads)', 0, 'DESCRIPTOR'),
    ('USERNAME', 'Username', 0, 'ENTITY'),
    ('VPN_HOST', 'VPN Host', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_DISCLOSURE', 'Vulnerability - Third Party Disclosure', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_CVE_CRITICAL', 'Vulnerability - CVE Critical', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_CVE_HIGH', 'Vulnerability - CVE High', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_CVE_MEDIUM', 'Vulnerability - CVE Medium', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_CVE_LOW', 'Vulnerability - CVE Low', 0, 'DESCRIPTOR'),
    ('VULNERABILITY_GENERAL', 'Vulnerability - General', 0, 'DESCRIPTOR'),
    ('WEB_ANALYTICS_ID', 'Web Analytics', 0, 'ENTITY'),
    ('WEBSERVER_BANNER', 'Web Server', 0, 'DATA'),
    ('WEBSERVER_HTTPHEADERS', 'HTTP Headers', 1, 'DATA'),
    ('WEBSERVER_STRANGEHEADER', 'Non-Standard HTTP Header', 0, 'DATA'),
    ('WEBSERVER_TECHNOLOGY', 'Web Technology', 0, 'DESCRIPTOR'),
    ('WIFI_ACCESS_POINT', 'WiFi Access Point Nearby', 0, 'ENTITY'),
    ('WIKIPEDIA_PAGE_EDIT', 'Wikipedia Page Edit', 0, 'DESCRIPTOR'),
]


# 46 in test/unit/spiderfoot/test_spiderfootdb.py
# 36 in sfwebui.py
#  9 in spiderfoot/db.py
#  7 in test/unit/spiderfoot/test_spiderfootplugin.py
#  5 in test/unit/spiderfoot/test_spiderfootcorrelator.py
#  4 in sf.py
#  3 in sfscan.py
#  3 in spiderfoot/plugin.py
#  3 in test/unit/test_modules.py
#  2 in spiderfoot/correlation.py
#  2 in spiderfoot/logger.py
#  1 in spiderfoot/__init__.py
class SpiderFootDb:
    _sync_engine: sqlalchemy.Engine
    _sync_session_factory: sessionmaker[sqlalchemy.orm.Session]

    def __init__(
        self,
        opts: dict[typing.Literal["__database"], str],
        *,
        init: bool = False,
    ) -> None:
        self._sync_engine = sqlalchemy.create_engine(
            f"sqlite+pysqlite://{'/:memory:'}",
            echo=True,
        )
        self._sync_session_factory = sessionmaker(
            self._sync_engine,
            expire_on_commit=False,
        )
        if init:
            self.create()

    def create(self) -> None:
        tbl_event_type_iter = itertools.starmap(TblEventType, _eventDetails)
        try:
            with self._sync_engine.begin() as ctx:
                orm_registry.metadata.create_all(ctx)
            with self._sync_session_factory.begin() as ctx:
                ctx.add_all(tbl_event_type_iter)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when setting up database",
            ) from e

    def close(self) -> None:
        self._sync_engine.dispose()

    # 4 in test/unit/spiderfoot/test_spiderfootdb.py
    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    def search(self, criteria: dict[str, str], filterFp: bool = False) -> list:
        """Search database.

        Args:
            criteria (dict): search criteria such as:
                - scan_id (search within a scan, if omitted search all)
                - type (search a specific type, if omitted search all)
                - value (search values for a specific string, if omitted search all)
                - regex (search values for a regular expression)
                ** at least two criteria must be set **
            filterFp (bool): filter out false positives

        Returns:
            list: search results

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
            IOError: database I/O failed
        """
        valid_criteria = ['scan_id', 'type', 'value', 'regex']

        for key in list(criteria.keys()):
            if key not in valid_criteria:
                warnings.warn(f"Found invalid search criteria: {key}")
                criteria.pop(key, None)
                continue

        if len(criteria) == 0:
            raise ValueError(f"No valid search criteria provided; expected: {', '.join(valid_criteria)}") from None

        if len(criteria) == 1:
            raise ValueError("Only one search criteria provided; expected at least two")

        qvars = dict[str, str]()
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, c.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
            WHERE s.scan_instance_id = c.scan_instance_id AND \
            t.event = c.type AND c.source_event_hash = s.hash "

        if filterFp:
            qry += " AND c.false_positive <> 1 "

        if "scan_id" in criteria:
            qry += "AND c.scan_instance_id = :scan_id "
            qvars["scan_id"] = criteria["scan_id"]

        if "type" in criteria:
            qry += " AND c.type = :type "
            qvars["type"] = criteria["type"]

        if "value" in criteria:
            qry += " AND (c.data LIKE :value OR s.data LIKE :value) "
            qvars["value"] = criteria["value"]

        if "regex" in criteria:
            qry += " AND (c.data REGEXP :regex OR s.data REGEXP :regex) "
            qvars["regex"] = criteria["regex"]

        qry += " ORDER BY c.data"

        with self._lock:
            stmt = sqlalchemy.text(qry)

            try:
                with self._sync_session_factory.begin() as ctx:
                    return list(ctx.scalars(stmt, qvars).all())
            except sqlalchemy.exc.DBAPIError as e:
                raise IOError("SQL error encountered when fetching search results") from e

    def eventTypes(self) -> typing.Sequence[TblEventType]:
        stmt = sqlalchemy.select(TblEventType)
        try:
            with self._sync_session_factory.begin() as ctx:
                tbl_event_type_iter = ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when retrieving event types",
            ) from e
        return tbl_event_type_iter

    def scanLogEvents(
        self,
        batch: list[tuple[str, str, str, str | None, float]],
    ) -> None:
        tbl_scan_log_iter = list[TblScanLog]()
        for instanceId, classification, message, component, logTime in batch:
            tbl_scan_log = TblScanLog(
                scan_instance_id=instanceId,
                generated=int(logTime * 1_000),
                component=component,
                type=classification,
                message=message,
            )
            tbl_scan_log_iter.append(tbl_scan_log)
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.add_all(tbl_scan_log_iter)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to log scan event in database") from e

    def scanLogEvent(
        self,
        instanceId: str,
        classification: str,
        message: str,
        component: str | None = None,
    ) -> None:
        tbl_scan_log = TblScanLog(
            scan_instance_id=instanceId,
            generated=int(time() * 1_000),
            component=component,
            type=classification,
            message=message,
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.add(tbl_scan_log)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to log scan event in database") from e

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
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.add(tbl_scan_instance)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("Unable to create scan instance in database") from e

    def scanInstanceSet(
        self,
        instanceId: str,
        started: str | None = None,
        ended: str | None = None,
        status: str | None = None,
    ) -> None:
        stmt = (
            sqlalchemy
                .update(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
        )
        if started is not None:
            stmt = stmt.values({TblScanInstance.started: started})
        if ended is not None:
            stmt = stmt.values({TblScanInstance.ended: ended})
        if status is not None:
            stmt = stmt.values({TblScanInstance.status: status})
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "Unable to set information for the scan instance",
            ) from e

    def scanInstanceGet(self, instanceId: str) -> TblScanInstance:
        stmt = (
            sqlalchemy
                .select(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                return ctx.execute(stmt).scalar_one()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when retrieving scan instance",
            ) from e

    # XXX Revisit
    def scanResultSummary(
        self,
        instanceId: str,
        by: typing.Literal["type", "module", "entity"] = "type",
    ):
        stmt = None
        if by == "type":
            stmt = self._compose_scanResultSummary_by_type_stmt(instanceId)
        if by == "module":
            stmt = self._compose_scanResultSummary_by_module_stmt(instanceId)
        if by == "entity":
            stmt = self._compose_scanResultSummary_by_entity_stmt(instanceId)
        assert stmt is not None
        try:
            with self._sync_session_factory.begin() as ctx:
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when fetching result summary",
            ) from e

    def _compose_scanResultSummary_by_type_stmt(self, instanceId: str):
        stmt = (
            sqlalchemy
                .select(
                    TblScanResult.type,
                    TblEventType.event_descr,
                    sqlalchemy.func.max(
                        sqlalchemy.func.round(TblScanResult.generated),
                    ).label("last_in"),
                    sqlalchemy.func.count().label("total"),
                    sqlalchemy.func.count(
                        TblScanResult.data.distinct(),
                    ).label("utotal"),
                )
                .where(TblScanResult.scan_instance_id == instanceId)
                .join(
                    TblEventType,
                    TblEventType.event == TblScanResult.type,
                )
                .group_by(TblScanResult.type)
                .order_by(TblEventType.event_descr)
        )
        return stmt

    def _compose_scanResultSummary_by_module_stmt(self, instanceId: str):
        stmt = (
            sqlalchemy
                .select(
                    TblScanResult.module,
                    "",
                    sqlalchemy.func.max(
                        sqlalchemy.func.round(TblScanResult.generated),
                    ).label("last_in"),
                    sqlalchemy.func.count().label("total"),
                    sqlalchemy.func.count(
                        TblScanResult.data.distinct(),
                    ).label("utotal"),
                )
                .where(TblScanResult.scan_instance_id == instanceId)
                .join(
                    TblEventType,
                    TblEventType.event == TblScanResult.type,
                )
                .group_by(TblScanResult.module)
                .order_by(TblScanResult.module.desc)
        )
        return stmt

    def _compose_scanResultSummary_by_entity_stmt(self, instanceId: str):
        stmt = (
            sqlalchemy
                .select(
                    TblScanResult.data,
                    TblEventType.event_descr,
                    sqlalchemy.func.max(
                        sqlalchemy.func.round(TblScanResult.generated),
                    ).label("last_in"),
                    sqlalchemy.func.count().label("total"),
                    sqlalchemy.func.count(
                        TblScanResult.data.distinct(),
                    ).label("utotal"),
                )
                .where(TblScanResult.scan_instance_id == instanceId)
                .join(
                    TblEventType,
                    TblEventType.event == TblScanResult.type,
                )
                .group_by(
                    TblScanResult.data,
                    TblEventType.event_descr,
                )
                .order_by(sqlalchemy.column("total").desc)
                .limit(50)
        )
        return stmt

    # XXX Revisit
    def scanCorrelationSummary(
        self,
        instanceId: str,
        by: typing.Literal["rule", "risk"] = "rule",
    ):
        stmt = None
        if by == "rule":
            stmt = \
                self._compose_scanCorrelationSummary_by_rule_stmt(instanceId)
        if by == "risk":
            stmt = \
                self._compose_scanCorrelationSummary_by_risk_stmt(instanceId)
        assert stmt is not None
        try:
            with self._sync_session_factory.begin() as ctx:
                return ctx.scalars(stmt).all()
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when fetching correlation summary",
            ) from e

    def _compose_scanCorrelationSummary_by_rule_stmt(self, instanceId: str):
        stmt = (
            sqlalchemy
                .select(
                    TblScanCorrelationResult.rule_id,
                    TblScanCorrelationResult.rule_name,
                    TblScanCorrelationResult.rule_risk,
                    TblScanCorrelationResult.rule_descr,
                    sqlalchemy.func.count().label("total"),
                )
                .where(TblScanCorrelationResult.scan_instance_id == instanceId)
                .group_by(TblScanCorrelationResult.rule_id)
                .order_by(TblScanCorrelationResult.rule_id)
        )
        return stmt

    def _compose_scanCorrelationSummary_by_risk_stmt(self, instanceId: str):
        stmt = (
            sqlalchemy
                .select(
                    TblScanCorrelationResult.rule_risk,
                    sqlalchemy.func.count().label("total"),
                )
                .where(TblScanCorrelationResult.scan_instance_id == instanceId)
                .group_by(TblScanCorrelationResult.rule_risk)
                .order_by(TblScanCorrelationResult.rule_id)
        )
        return stmt

    # 2 in sfwebui.py
    # 1 in spiderfoot/db.py
    def scanCorrelationList(self, instanceId: str) -> list:
        """Obtain a list of the correlations from a scan

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan correlation list

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT c.id, c.title, c.rule_id, c.rule_risk, c.rule_name, \
            c.rule_descr, c.rule_logic, count(e.event_hash) AS event_count FROM \
            tbl_scan_correlation_results c, tbl_scan_correlation_results_events e \
            WHERE scan_instance_id = ? AND c.id = e.correlation_id \
            GROUP BY c.id ORDER BY c.title, c.rule_risk"

        qvars = [instanceId]

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching correlation list") from e

    # 6 in spiderfoot/db.py
    @dataclasses.dataclass(frozen=True, kw_only=True)
    class ScanResultEvent(typing.NamedTuple):
        generated: int
        c_data: str | None
        source_data: str | None
        c_module: str
        c_type: str
        c_confidence: int
        c_visibility: int
        c_risk: int
        c_hash: str
        c_source_event_hash: str
        t_event_descr: str
        t_event_type: str
        s_scan_instance_id: str
        fp: int
        parent_fp: int

        @classmethod
        def from_row(cls, row: tuple) -> typing.Self:
            return dacite.from_dict(
                data_class=cls,
                data=dict(zip(cls.__dataclass_fields__.keys(), row)),
            )

    # 7 in sfwebui.py
    # 2 in spiderfoot/correlation.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanResultEvent(
        self,
        instanceId: str,
        eventType: str = 'ALL',
        srcModule: str | None = None,
        data: list[str] | None = None,
        sourceId: list[str] | None = None,
        correlationId: str | None = None,
        filterFp: bool = False
    ) -> list[SpiderFootDb.ScanResultEvent]:
        """Obtain the data for a scan and event type.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            srcModule (str): filter by the generating module
            data (list): filter by the data
            sourceId (list): filter by the ID of the source event
            correlationId (str): filter by the ID of a correlation result
            filterFp (bool): filter false positives

        Returns:
            list: scan results

        Raises:
            TypeError: arg type was invalid
            IOError: database I/O failed
        """

        if not isinstance(eventType, str) and not isinstance(eventType, list):
            raise TypeError(f"eventType is {type(eventType)}; expected str() or list()") from None

        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t "

        if correlationId is not None:
            qry += ", tbl_scan_correlation_results_events ce "

        qry += "WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND t.event = c.type"

        qvars = [instanceId]

        if correlationId is not None:
            qry += " AND ce.event_hash = c.hash AND ce.correlation_id = ?"
            qvars.append(correlationId)

        if eventType != "ALL":
            if isinstance(eventType, list):
                qry += " AND c.type in (" + ','.join(['?'] * len(eventType)) + ")"
                qvars.extend(eventType)
            else:
                qry += " AND c.type = ?"
                qvars.append(eventType)

        if filterFp:
            qry += " AND c.false_positive <> 1"

        if srcModule is not None:
            if isinstance(srcModule, list):
                qry += " AND c.module in (" + ','.join(['?'] * len(srcModule)) + ")"
                qvars.extend(srcModule)
            else:
                qry += " AND c.module = ?"
                qvars.append(srcModule)

        if data is not None:
            if isinstance(data, list):
                qry += " AND c.data in (" + ','.join(['?'] * len(data)) + ")"
                qvars.extend(data)
            else:
                qry += " AND c.data = ?"
                qvars.append(data)

        if sourceId is not None:
            if isinstance(sourceId, list):
                qry += " AND c.source_event_hash in (" + ','.join(['?'] * len(sourceId)) + ")"
                qvars.extend(sourceId)
            else:
                qry += " AND c.source_event_hash = ?"
                qvars.append(sourceId)

        qry += " ORDER BY c.data"

        rows = []
        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                rows = self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching result events") from e
        
        results: list[SpiderFootDb.ScanResultEvent] = []
        for row in rows:
            assert isinstance(row, tuple)
            results.append(self.ScanResultEvent.from_row(row))

        return results

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanResultEventUnique(self, instanceId: str, eventType: str = 'ALL', filterFp: bool = False) -> list:
        """Obtain a unique list of elements.

        Args:
            instanceId (str): scan instance ID
            eventType (str): filter by event type
            filterFp (bool): filter false positives

        Returns:
            list: unique scan results

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT DISTINCT data, type, COUNT(*) FROM tbl_scan_results \
            WHERE scan_instance_id = ?"
        qvars = [instanceId]

        if eventType != "ALL":
            qry += " AND type = ?"
            qvars.append(eventType)

        if filterFp:
            qry += " AND false_positive <> 1"

        qry += " GROUP BY type, data ORDER BY COUNT(*)"

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching unique result events") from e

    # 2 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanLogs(self, instanceId: str, limit: int = None, fromRowId: int = 0, reverse: bool = False) -> list:
        """Get scan logs.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results
            fromRowId (int): retrieve logs starting from row ID
            reverse (bool): search result order

        Returns:
            list: scan logs

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT generated AS generated, component, \
            type, message, rowid FROM tbl_scan_log WHERE scan_instance_id = ?"
        if fromRowId:
            qry += " and rowid > ?"

        qry += " ORDER BY generated "
        if reverse:
            qry += "ASC"
        else:
            qry += "DESC"
        qvars = [instanceId]

        if fromRowId:
            qvars.append(str(fromRowId))

        if limit is not None:
            qry += " LIMIT ?"
            qvars.append(str(limit))

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching scan logs") from e

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanErrors(self, instanceId: str, limit: int = 0) -> list:
        """Get scan errors.

        Args:
            instanceId (str): scan instance ID
            limit (int): limit number of results

        Returns:
            list: scan errors

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT generated AS generated, component, \
            message FROM tbl_scan_log WHERE scan_instance_id = ? \
            AND type = 'ERROR' ORDER BY generated DESC"
        qvars = [instanceId]

        if limit:
            qry += " LIMIT ?"
            qvars.append(str(limit))

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching scan errors") from e

    def scanInstanceDelete(self, instanceId: str) -> None:
        stmt = (
            sqlalchemy
                .delete(TblScanInstance)
                .where(TblScanInstance.guid == instanceId)
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError("SQL error encountered when deleting scan") from e

    def scanResultsUpdateFP(
        self,
        instanceId: str,
        resultHashes: list[str],
        fpFlag: int,
    ) -> None:
        stmt = (
            sqlalchemy
                .update(TblScanResult)
                .values({TblScanResult.false_positive: fpFlag})
                .where(
                    TblScanResult.scan_instance_id == instanceId,
                    TblScanResult.hash.in_(resultHashes),
                )
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when updating false-positive",
            ) from e

    def configSet(self, optMap: dict[str, str]) -> None:
        tbl_config_iter = TblConfig.from_raw(optMap)
        stmt = (
            sqlalchemy
                .update(TblConfig)
                .values(tbl_config_iter)
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when storing config, aborting",
            ) from e

    def configGet(self) -> dict[str, str]:
        stmt = sqlalchemy.select(TblConfig)
        try:
            with self._sync_session_factory.begin() as ctx:
                tbl_config_iter_raw = ctx.scalars(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when fetching configuration",
            ) from e
        tbl_config_iter = tbl_config_iter_raw.all()
        return TblConfig.from_tbl_iter(tbl_config_iter)

    def configClear(self) -> None:
        stmt = sqlalchemy.delete(TblConfig)
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "Unable to clear configuration from the database",
            ) from e

    def scanConfigSet(self, instanceId: str, optMap: dict[str, str]) -> None:
        tbl_scan_config_iter = TblScanConfig.from_raw(
            optMap,
            scan_instance_id=instanceId,
        )
        stmt = (
            sqlalchemy
                .update(TblScanConfig)
                .where(TblScanConfig.scan_instance_id == instanceId)
                .values(tbl_scan_config_iter)
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.execute(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when storing config, aborting",
            ) from e

    def scanConfigGet(self, instanceId: str) -> dict[str, str]:
        stmt = (
            sqlalchemy
                .select(TblScanConfig)
                .where(TblScanConfig.scan_instance_id == instanceId)
                .order_by(
                    TblScanConfig.component,
                    TblScanConfig.opt,
                )
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                tbl_scan_config_iter_raw = ctx.scalars(stmt)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "SQL error encountered when fetching configuration",
            ) from e
        tbl_scan_config_iter = tbl_scan_config_iter_raw.all()
        return TblScanConfig.from_tbl_iter(tbl_scan_config_iter)

    def scanEventStore(
        self,
        instanceId: str,
        sfEvent: SpiderFootEvent,
        truncateSize: int = 0,
    ) -> None:
        tbl_scan_result = TblScanResult(
            scan_instance_id=instanceId,
            hash=sfEvent.hash,
            type=sfEvent.eventType,
            generated=int(sfEvent.generated * 1_000),
            confidence=sfEvent.confidence,
            visibility=sfEvent.visibility,
            risk=sfEvent.risk,
            module=sfEvent.module,
            data=sfEvent.data,
            false_positive=0,
            source_event_hash=sfEvent.sourceEventHash,
        )
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.add(tbl_scan_result)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                f"SQL error encountered when storing event data",
            ) from e

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanInstanceList(self) -> list:
        """List all previously run scans.

        Returns:
            list: previously run scans

        Raises:
            IOError: database I/O failed
        """

        # SQLite doesn't support OUTER JOINs, so we need a work-around that
        # does a UNION of scans with results and scans without results to
        # get a complete listing.
        qry = "SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, COUNT(r.type) \
            FROM tbl_scan_instances i, tbl_scan_results r WHERE i.guid = r.scan_instance_id \
            AND r.type <> 'ROOT' GROUP BY i.guid \
            UNION ALL \
            SELECT i.guid, i.name, i.seed_target, ROUND(i.created/1000), \
            ROUND(i.started)/1000 as started, ROUND(i.ended)/1000, i.status, '0' \
            FROM tbl_scan_instances i  WHERE i.guid NOT IN ( \
            SELECT distinct scan_instance_id FROM tbl_scan_results WHERE type <> 'ROOT') \
            ORDER BY started DESC"

        with self._lock:
            try:
                self._cursor.execute(qry)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when fetching scan list") from e

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanResultHistory(self, instanceId: str) -> list:
        """History of data from the scan.

        Args:
            instanceId (str): scan instance ID

        Returns:
            list: scan data history

        Raises:
            IOError: database I/O failed
        """

        qry = "SELECT STRFTIME('%H:%M %w', generated, 'unixepoch') AS hourmin, \
                type, COUNT(*) FROM tbl_scan_results \
                WHERE scan_instance_id = ? GROUP BY hourmin, type"
        qvars = [instanceId]

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError(f"SQL error encountered when fetching history for scan {instanceId}") from e

    # 6 in spiderfoot/db.py
    @dataclasses.dataclass(frozen=True, kw_only=True)
    class ScanElementSourcesDirect(typing.NamedTuple):
        generated: int
        c_data: str | None
        source_data: str | None
        c_module: str
        c_type: str
        c_confidence: int
        c_visibility: int
        c_risk: int
        c_hash: str
        c_source_event_hash: str
        t_event_descr: str
        t_event_type: str
        s_scan_instance_id: str
        fp: int
        parent_fp: int
        s_type: str
        s_module: str
        source_entity_type: str

        @classmethod
        def from_row(cls, row: tuple) -> typing.Self:
            return dacite.from_dict(
                data_class=cls,
                data=dict(zip(cls.__dataclass_fields__.keys(), row)),
            )

    # 3 in spiderfoot/correlation.py
    # 2 in spiderfoot/db.py
    # 1 in sfwebui.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanElementSourcesDirect(self, instanceId: str, elementIdList: list[str]) -> list[SpiderFootDb.ScanElementSourcesDirect]:
        """Get the source IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            IOError: database I/O failed
        """

        hashIds: list[str] = []
        for hashId in elementIdList:
            if not hashId:
                continue
            if not hashId.isalnum():
                continue
            hashIds.append(hashId)

        # the output of this needs to be aligned with scanResultEvent,
        # as other functions call both expecting the same output.
        qry = "SELECT ROUND(c.generated) AS generated, c.data, \
            s.data as 'source_data', \
            c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
            c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
            c.false_positive as 'fp', s.false_positive as 'parent_fp', \
            s.type, s.module, st.event_type as 'source_entity_type' \
            FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t, \
            tbl_event_types st \
            WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
            s.scan_instance_id = c.scan_instance_id AND st.event = s.type AND \
            t.event = c.type AND c.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        rows = []
        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                rows = self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when getting source element IDs") from e

        results: list[SpiderFootDb.ScanElementSourcesDirect] = []
        for row in rows:
            assert isinstance(row, tuple)
            results.append(self.ScanElementSourcesDirect.from_row(row))

        return results

    def scanElementChildrenDirect(self, instanceId: str, elementIdList: list[str]) -> list:
        """Get the child IDs, types and data for a set of IDs.

        Args:
            instanceId (str): scan instance ID
            elementIdList (list): TBD

        Returns:
            list: TBD

        Raises:
            IOError: database I/O failed
        """
        """
        SELECT
            ROUND("c"."generated") AS "generated",
            "c"."data",
            "s"."data" AS "source_data",
            "c"."module",
            "c"."type",
            "c"."confidence",
            "c"."visibility",
            "c"."risk",
            "c"."hash",
            "c"."source_event_hash",
            "t"."event_descr",
            "t"."event_type",
            "s"."scan_instance_id",
            "c"."false_positive" AS "fp",
            "s"."false_positive" AS "parent_fp"
        FROM
            tbl_scan_result "c",
            tbl_scan_result "s",
            tbl_event_type "t"
        WHERE
            "c"."scan_instance_id" = ?
            AND "c"."source_event_hash" = "s"."hash"
            AND "s"."scan_instance_id" = "c"."scan_instance_id"
            AND "t"."event" = "c"."type"
            AND "s"."hash" IN (?)
        """
        
        
        
        # SELECT ROUND(c.generated) AS generated, c.data, \
        # #     s.data as 'source_data', \
        # #     c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
        # #     c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
        # #     c.false_positive as 'fp', s.false_positive as 'parent_fp' \


        # # the output of this needs to be aligned with scanResultEvent,
        # # as other functions call both expecting the same output.
        # qry = "SELECT ROUND(c.generated) AS generated, c.data, \
        #     s.data as 'source_data', \
        #     c.module, c.type, c.confidence, c.visibility, c.risk, c.hash, \
        #     c.source_event_hash, t.event_descr, t.event_type, s.scan_instance_id, \
        #     c.false_positive as 'fp', s.false_positive as 'parent_fp' \
        #     FROM tbl_scan_results c, tbl_scan_results s, tbl_event_types t \
        #     WHERE c.scan_instance_id = ? AND c.source_event_hash = s.hash AND \
        #     s.scan_instance_id = c.scan_instance_id AND \
        #     t.event = c.type AND s.hash in ('%s')" % "','".join(hashIds)
        qvars = [instanceId]

        with self._lock:
            try:
                self._cursor.execute(qry, qvars)
                return self._cursor.fetchall()
            except sqlite3.Error as e:
                raise IOError("SQL error encountered when getting child element IDs") from e

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanElementSourcesAll(self, instanceId: str, childData: list) -> list:
        """Get the full set of upstream IDs which are parents to the supplied set of IDs.

        Args:
            instanceId (str): scan instance ID
            childData (list): TBD

        Returns:
            list: TBD

        Raises:
            ValueError: arg value was invalid
        """

        if not childData:
            raise ValueError("childData is empty")

        # Get the first round of source IDs for the leafs
        keepGoing = True
        nextIds = list()
        datamap = dict()
        pc = dict()

        for row in childData:
            # these must be unique values!
            parentId = row[9]
            childId = row[8]
            datamap[childId] = row

            if parentId in pc:
                if childId not in pc[parentId]:
                    pc[parentId].append(childId)
            else:
                pc[parentId] = [childId]

            # parents of the leaf set
            if parentId not in nextIds:
                nextIds.append(parentId)

        while keepGoing:
            parentSet = self.scanElementSourcesDirect(instanceId, nextIds)
            nextIds = list()
            keepGoing = False

            for row in parentSet:
                parentId = row[9]
                childId = row[8]
                datamap[childId] = row

                if parentId in pc:
                    if childId not in pc[parentId]:
                        pc[parentId].append(childId)
                else:
                    pc[parentId] = [childId]
                if parentId not in nextIds:
                    nextIds.append(parentId)

                # Prevent us from looping at root
                if parentId != "ROOT":
                    keepGoing = True

        datamap[parentId] = row
        return [datamap, pc]

    # 1 in sfwebui.py
    # 1 in spiderfoot/db.py
    # 1 in test/unit/spiderfoot/test_spiderfootdb.py
    def scanElementChildrenAll(self, instanceId: str, parentIds: list[str]) -> list[str]:
        """Get the full set of downstream IDs which are children of the supplied set of IDs.

        Args:
            instanceId (str): scan instance ID
            parentIds (list[str]): TBD

        Returns:
            list[str]: TBD

        Note: This function is not the same as the scanElementParent* functions.
              This function returns only ids.
        """
        children_ids = list[str]()

        direct_children = self.scanElementChildrenDirect(instanceId, parentIds)

        # datamap = list()
        # keepGoing = True
        # nextIds = list()

        # nextSet = self.scanElementChildrenDirect(instanceId, parentIds)
        # for row in nextSet:
        #     datamap.append(row[8])

        # for row in nextSet:
        #     if row[8] not in nextIds:
        #         nextIds.append(row[8])

        # while keepGoing:
        #     nextSet = self.scanElementChildrenDirect(instanceId, nextIds)
        #     if nextSet is None or len(nextSet) == 0:
        #         keepGoing = False
        #         break

        #     for row in nextSet:
        #         datamap.append(row[8])
        #         nextIds = list()
        #         nextIds.append(row[8])

        # return datamap

    def correlationResultCreate(
        self,
        instanceId: str,
        ruleId: str,
        ruleName: str,
        ruleDescr: str,
        ruleRisk: str,
        ruleYaml: str,
        correlationTitle: str,
        eventHashes: list[str],
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
        tbl_scan_correlation_result_event_iter = [
            TblScanCorrelationResultEvent(
                correlation_id=tbl_scan_correlation_result.id,
                event_hash=eventHash,
            )
            for eventHash in eventHashes
        ]
        try:
            with self._sync_session_factory.begin() as ctx:
                ctx.add(tbl_scan_correlation_result)
                ctx.add_all(tbl_scan_correlation_result_event_iter)
        except sqlalchemy.exc.DBAPIError as e:
            raise IOError(
                "Unable to create correlation result in database",
            ) from e
        return tbl_scan_correlation_result.id


# def _from_iter_TblConfig(tbl_config_iter: typing.Sequence[TblConfig]) -> dict[str, str]:
#     config = dict[str, str]()
#     for tbl_config in tbl_config_iter:
#         key = (
#             f"{tbl_config.scope}:{tbl_config.opt}"
#             if tbl_config.scope != "GLOBAL"
#             else tbl_config.opt
#         )
#         config[key] = tbl_config.val
#     return config


def _to_iter_TblConfig(config: dict[str, str]) -> list[TblConfig]:
    tbl_config_iter = list[TblConfig]()
    for key, val in config.items():
        if ":" in key:
            scope, opt = key.split(":")
        else:
            scope, opt = "GLOBAL", key
        tbl_config = TblConfig(scope, opt, val)
        tbl_config_iter.append(tbl_config)
    return tbl_config_iter
