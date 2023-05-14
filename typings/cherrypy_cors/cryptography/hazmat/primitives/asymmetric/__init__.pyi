"""
This type stub file was generated by pyright.
"""

import abc
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.primitives import _serialization

class X25519PublicKey(metaclass=abc.ABCMeta):
    @classmethod
    def from_public_bytes(cls, data: bytes) -> X25519PublicKey:
        ...
    
    @abc.abstractmethod
    def public_bytes(self, encoding: _serialization.Encoding, format: _serialization.PublicFormat) -> bytes:
        """
        The serialized bytes of the public key.
        """
        ...
    


class X25519PrivateKey(metaclass=abc.ABCMeta):
    @classmethod
    def generate(cls) -> X25519PrivateKey:
        ...
    
    @classmethod
    def from_private_bytes(cls, data: bytes) -> X25519PrivateKey:
        ...
    
    @abc.abstractmethod
    def public_key(self) -> X25519PublicKey:
        """
        The serialized bytes of the public key.
        """
        ...
    
    @abc.abstractmethod
    def private_bytes(self, encoding: _serialization.Encoding, format: _serialization.PrivateFormat, encryption_algorithm: _serialization.KeySerializationEncryption) -> bytes:
        """
        The serialized bytes of the private key.
        """
        ...
    
    @abc.abstractmethod
    def exchange(self, peer_public_key: X25519PublicKey) -> bytes:
        """
        Performs a key exchange operation using the provided peer's public key.
        """
        ...
    

