"""
This type stub file was generated by pyright.
"""

import sys
from importlib.resources import as_file, files

"""
certifi.py
~~~~~~~~~~

This module returns the installation location of cacert.pem or its contents.
"""
if sys.version_info >= (3, 11):
    _CACERT_CTX = ...
    _CACERT_PATH = ...
    def where() -> str:
        ...
    
    def contents() -> str:
        ...
    
else:
    ...
