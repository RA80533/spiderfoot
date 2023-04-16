"""
This type stub file was generated by pyright.
"""

import socket
import ssl
import struct
import time
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.quic.events
import trio
import dns.inet
from dns._asyncbackend import NullContext
from dns.quic._common import AsyncQuicConnection, AsyncQuicManager, BaseQuicStream, QUIC_MAX_DATAGRAM

class TrioQuicStream(BaseQuicStream):
    def __init__(self, connection, stream_id) -> None:
        ...
    
    async def wait_for(self, amount): # -> None:
        ...
    
    async def receive(self, timeout=...): # -> bytes:
        ...
    
    async def send(self, datagram, is_end=...): # -> None:
        ...
    
    async def close(self): # -> None:
        ...
    
    async def __aenter__(self): # -> Self@TrioQuicStream:
        ...
    
    async def __aexit__(self, exc_type, exc_val, exc_tb): # -> Literal[False]:
        ...
    


class TrioQuicConnection(AsyncQuicConnection):
    def __init__(self, connection, address, port, source, source_port, manager=...) -> None:
        ...
    
    async def write(self, stream, data, is_end=...): # -> None:
        ...
    
    async def run(self): # -> None:
        ...
    
    async def make_stream(self): # -> TrioQuicStream:
        ...
    
    async def close(self): # -> None:
        ...
    


class TrioQuicManager(AsyncQuicManager):
    def __init__(self, nursery, conf=..., verify_mode=...) -> None:
        ...
    
    def connect(self, address, port=..., source=..., source_port=...):
        ...
    
    async def __aenter__(self): # -> Self@TrioQuicManager:
        ...
    
    async def __aexit__(self, exc_type, exc_val, exc_tb): # -> Literal[False]:
        ...
    


