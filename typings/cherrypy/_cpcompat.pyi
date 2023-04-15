"""
This type stub file was generated by pyright.
"""

"""Compatibility code for using CherryPy with various versions of Python.

To retain compatibility with older Python versions, this module provides a
useful abstraction over the differences between Python versions, sometimes by
preferring a newer idiom, sometimes an older one, and sometimes a custom one.

In particular, Python 2 uses str and '' for byte strings, while Python 3
uses str and '' for unicode strings. We will call each of these the 'native
string' type for each version. Because of this major difference, this module
provides
two functions: 'ntob', which translates native strings (of type 'str') into
byte strings regardless of Python version, and 'ntou', which translates native
strings to unicode strings.

Try not to use the compatibility functions 'ntob', 'ntou', 'tonative'.
They were created with Python 2.3-2.5 compatibility in mind.
Instead, use unicode literals (from __future__) and bytes literals
and their .encode/.decode methods as needed.
"""
def ntob(n, encoding=...):
    """Return the given native string as a byte string in the given
    encoding.
    """
    ...

def ntou(n, encoding=...):
    """Return the given native string as a unicode string with the given
    encoding.
    """
    ...

def tonative(n, encoding=...): # -> str:
    """Return the given string as a native string in the given encoding."""
    ...

def assert_native(n): # -> None:
    ...

HTTPSConnection = ...
text_or_bytes = ...