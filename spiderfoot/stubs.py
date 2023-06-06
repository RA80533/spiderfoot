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
    "CREATE TABLE tbl_event_types ( \
        event       VARCHAR NOT NULL PRIMARY KEY, \
        event_descr VARCHAR NOT NULL, \
        event_raw   INT NOT NULL DEFAULT 0, \
        event_type  VARCHAR NOT NULL \
    )",
    "CREATE TABLE tbl_config ( \
        scope   VARCHAR NOT NULL, \
        opt     VARCHAR NOT NULL, \
        val     VARCHAR NOT NULL, \
        PRIMARY KEY (scope, opt) \
    )",
    "CREATE TABLE tbl_scan_instance ( \
        guid        VARCHAR NOT NULL PRIMARY KEY, \
        name        VARCHAR NOT NULL, \
        seed_target VARCHAR NOT NULL, \
        created     INT DEFAULT 0, \
        started     INT DEFAULT 0, \
        ended       INT DEFAULT 0, \
        status      VARCHAR NOT NULL \
    )",
    "CREATE TABLE tbl_scan_log ( \
        scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
        generated           INT NOT NULL, \
        component           VARCHAR, \
        type                VARCHAR NOT NULL, \
        message             VARCHAR \
    )",
    "CREATE TABLE tbl_scan_config ( \
        scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
        component           VARCHAR NOT NULL, \
        opt                 VARCHAR NOT NULL, \
        val                 VARCHAR NOT NULL \
    )",
    "CREATE TABLE tbl_scan_results ( \
        scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instance(guid), \
        hash                VARCHAR NOT NULL, \
        type                VARCHAR NOT NULL REFERENCES tbl_event_types(event), \
        generated           INT NOT NULL, \
        confidence          INT NOT NULL DEFAULT 100, \
        visibility          INT NOT NULL DEFAULT 100, \
        risk                INT NOT NULL DEFAULT 0, \
        module              VARCHAR NOT NULL, \
        data                VARCHAR, \
        false_positive      INT NOT NULL DEFAULT 0, \
        source_event_hash  VARCHAR DEFAULT 'ROOT' \
    )",
    "CREATE TABLE tbl_scan_correlation_results ( \
        id                  VARCHAR NOT NULL PRIMARY KEY, \
        scan_instance_id    VARCHAR NOT NULL REFERENCES tbl_scan_instances(guid), \
        title               VARCHAR NOT NULL, \
        rule_risk           VARCHAR NOT NULL, \
        rule_id             VARCHAR NOT NULL, \
        rule_name           VARCHAR NOT NULL, \
        rule_descr          VARCHAR NOT NULL, \
        rule_logic          VARCHAR NOT NULL \
    )",
    "CREATE TABLE tbl_scan_correlation_results_events ( \
        correlation_id      VARCHAR NOT NULL REFERENCES tbl_scan_correlation_results(id), \
        event_hash          VARCHAR NOT NULL REFERENCES tbl_scan_results(hash) \
    )",
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

    def __init__(self, opts: dict[str, str], init: bool = False) -> None:
        ...

    def create(self) -> None:
        ...

    def close(self) -> None:
        ...

    def search(self, criteria: dict[str, str], filterFp: bool = False) -> list[tuple[int, str | None, str | None, str, str, int, int, int, str, str | None, str, str, str, int, int]]:
        ...

    def eventTypes(self) -> list[tuple[str, str, int, str]]:
        ...

    def scanLogEvents(self, batch: list[tuple[str, str, str, str | None, float]]) -> bool:
        ...

    def scanLogEvent(self, instanceId: str, classification: str, message: str, component: str | None = None) -> None:
        ...

    def scanInstanceCreate(self, instanceId: str, scanName: str, scanTarget: str) -> None:
        ...

    def scanInstanceSet(self, instanceId: str, started: str | None = None, ended: str | None = None, status: str | None = None) -> None:
        ...

    def scanInstanceGet(self, instanceId: str) -> tuple[str, str, int | None, int | None, int | None, str]:
        ...

    def scanResultSummary(self, instanceId: str, by: str = "type") -> list[tuple[str, str, int, int, int]] | list[tuple[str | None, str, int, int, int]]:
        ...

    def scanCorrelationSummary(self, instanceId: str, by: str = "rule") -> list[tuple[str, int]] | list[tuple[str, str, str, str, int]]:
        ...

    def scanCorrelationList(self, instanceId: str) -> list[tuple[str, str, str, str, str, str, str, int]]:
        ...

    def scanResultEvent(
        self,
        instanceId: str,
        eventType: str | list[str] = 'ALL',
        srcModule: str | list[str] | None = None,
        data: str | list[str] | None = None,
        sourceId: str | list[str] | None = None,
        correlationId: str | None = None,
        filterFp: bool = False
    ) -> list[tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int]]:
        ...

    def scanResultEventUnique(self, instanceId: str, eventType: str = 'ALL', filterFp: bool = False) -> list[tuple[str | None, str, int]]:
        ...

    def scanLogs(self, instanceId: str, limit: int | None = None, fromRowId: int = 0, reverse: bool = False) -> list[tuple[int, str | None, str, str | None, int]]:
        ...

    def scanErrors(self, instanceId: str, limit: int = 0) -> list[tuple[int, str | None, str | None]]:
        ...

    def scanInstanceDelete(self, instanceId: str) -> bool:
        ...

    def scanResultsUpdateFP(self, instanceId: str, resultHashes: list[str], fpFlag: int) -> bool:
        ...
    
    def configSet(self, optMap: dict[str, str] = {}) -> bool:
        ...

    def configGet(self) -> dict[str, str]:
        ...

    def configClear(self) -> None:
        ...

    def scanConfigSet(self, scan_id: str, optMap: dict[str, str] = dict()) -> None:
        ...

    def scanConfigGet(self, instanceId: str) -> dict[str, str]:
        ...

    def scanEventStore(self, instanceId: str, sfEvent: SpiderFootEvent, truncateSize: int = 0) -> None:
        ...

    def scanInstanceList(self) -> list[tuple[str, str, str, int | None, int | None, int | None, str, int]]:
        ...

    def scanResultHistory(self, instanceId: str) -> list[tuple[str | None, str, int]]:
        ...

    def scanElementSourcesDirect(self, instanceId: str, elementIdList: list[str]) -> list[tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int, str, str, str]]:
        ...

    def scanElementChildrenDirect(self, instanceId: str, elementIdList: list[str]) -> list[tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int]]:
        ...

    def scanElementSourcesAll(self, instanceId: str, childData: list[tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int]]) -> list[typing.Union[dict[str, typing.Union[tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int], tuple[int, str | None, str | None, str, str, int, int, int, str, str, str, str, str, int, int, str, str, str]]], dict[str, list[str]]]]:
        ...

    def scanElementChildrenAll(self, instanceId: str, parentIds: list[str]) -> list[str]:
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
        eventHashes: list[str],
    ) -> str:
        ...
