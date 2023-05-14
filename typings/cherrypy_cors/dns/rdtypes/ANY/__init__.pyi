"""
This type stub file was generated by pyright.
"""

import struct
import binascii
import dns.immutable
import dns.rdata
import dns.rdatatype
import dns.zonetypes

@dns.immutable.immutable
class ZONEMD(dns.rdata.Rdata):
    """ZONEMD record"""
    __slots__ = ...
    def __init__(self, rdclass, rdtype, serial, scheme, hash_algorithm, digest) -> None:
        ...
    
    def to_text(self, origin=..., relativize=..., **kw): # -> str:
        ...
    
    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=..., relativize=..., relativize_to=...): # -> Self@ZONEMD:
        ...
    
    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=...): # -> Self@ZONEMD:
        ...
    

