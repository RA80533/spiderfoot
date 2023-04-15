"""
This type stub file was generated by pyright.
"""

import cheroot.wsgi
import cheroot.server

"""
WSGI server interface (see PEP 333).

This adds some CP-specific bits to the framework-agnostic cheroot package.
"""
class CPWSGIHTTPRequest(cheroot.server.HTTPRequest):
    """Wrapper for cheroot.server.HTTPRequest.

    This is a layer, which preserves URI parsing mode like it which was
    before Cheroot v5.8.0.
    """
    def __init__(self, server, conn) -> None:
        """Initialize HTTP request container instance.

        Args:
            server (cheroot.server.HTTPServer):
                web server object receiving this request
            conn (cheroot.server.HTTPConnection):
                HTTP connection object for this request
        """
        ...
    


class CPWSGIServer(cheroot.wsgi.Server):
    """Wrapper for cheroot.wsgi.Server.

    cheroot has been designed to not reference CherryPy in any way,
    so that it can be used in other frameworks and applications. Therefore,
    we wrap it here, so we can set our own mount points from cherrypy.tree
    and apply some attributes from config -> cherrypy.server -> wsgi.Server.
    """
    fmt = ...
    version = ...
    def __init__(self, server_adapter=...) -> None:
        """Initialize CPWSGIServer instance.

        Args:
            server_adapter (cherrypy._cpserver.Server): ...
        """
        ...
    
    def error_log(self, msg=..., level=..., traceback=...): # -> None:
        """Write given message to the error log."""
        ...
    

