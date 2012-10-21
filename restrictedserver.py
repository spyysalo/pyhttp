#!/usr/bin/env python

'''
SimpleHTTPServer variant supporting access restrictions configured
using a robots.txt-like syntax. Licence: MIT.

Author: Sampo Pyysalo
'''

# TODO:
# - Avoid hardcoded configuration
# - Separate permissions for directory listings
# - CLI

import sys
import os

from urlparse import urlparse
from posixpath import normpath
from urllib import unquote

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler
from SocketServer import ForkingMixIn

_SERVER_ADDR = ''
_SERVER_PORT = 8001

_PERMISSIONS = """
Disallow: *.py
Disallow: *.cgi
Disallow: *.py~  # no emacs backups
Disallow: *.cgi~
Disallow: /src/
Allow: /
"""

class ParseError(Exception):
    def __init__(self, linenum, line, message=None):
        self.linenum = linenum
        self.line = line
        self.message = ' (%s)' % message if message is not None else ''
    
    def __str__(self):
        return 'line %d%s: %s' % (self.linenum, self.message, self.line)


class PathPattern(object):
    def __init__(self, path):
        self.path = path
        self.plen = len(path)

    def match(self, s):
        # Require prefix match and separator/end.
        return s[:self.plen] == self.path and (self.path[-1] == '/' or
                                               s[self.plen:] == '' or 
                                               s[self.plen] == '/')

class ExtensionPattern(object):
    def __init__(self, ext):
        self.ext = ext

    def match(self, s):
        return os.path.splitext(s)[1] == self.ext


class PathPermissions(object):
    """Implements path permission checking with a robots.txt-like syntax."""

    def __init__(self, default_allow=False):
        self._entries = []
        self.default_allow = default_allow

    def allow(self, path):
        # First match wins
        for pattern, allow in self._entries:
            if pattern.match(path):
                return allow
        return self.default_allow
    
    def parse(self, lines):
        # Syntax: "DIRECTIVE : PATTERN" where
        # DIRECTIVE is either "Disallow:" or "Allow:" and
        # PATTERN either has the form "*.EXT" or "/PATH".
        # Strings starting with "#" and empty lines are ignored.

        for ln, l in enumerate(lines):            
            i = l.find('#')
            if i != -1:
                l = l[:i]
            l = l.strip()

            if not l:
                continue

            i = l.find(':')
            if i == -1:
                raise ParseError(ln, lines[ln], 'missing colon')

            directive = l[:i].strip().lower()
            pattern = l[i+1:].strip()

            if directive == 'allow':
                allow = True
            elif directive == 'disallow':
                allow = False
            else:
                raise ParseError(ln, lines[ln], 'unrecognized directive')
            
            if pattern.startswith('/'):
                patt = PathPattern(pattern)
            elif pattern.startswith('*.'):
                patt = ExtensionPattern(pattern[1:])
            else:
                raise ParseError(ln, lines[ln], 'unrecognized pattern')

            self._entries.append((patt, allow))

        return self

class RestrictedHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Restricts requests based on permission configuration, responds with
    403 for disallowed paths and delegates to SimpleHTTPRequestHandler for
    others."""

    permissions = PathPermissions().parse(_PERMISSIONS.split('\n'))

    def allow_path(self):
        """Test whether to allow a request for self.path."""

        # Cleanup in part following SimpleHTTPServer.translate_path()
        path = self.path
        path = path.split('?', 1)[0]
        path = path.split('#', 1)[0]
        path = unquote(path)
        path = normpath(path)
        parts = path.split('/')
        parts = filter(None, parts)
        if '..' in parts:
            return False
        path = '/'+'/'.join(parts)

        return self.permissions.allow(path)

    def do_GET(self):
        """Serve a GET request."""
        if not self.allow_path():
            self.send_error(403)
        else:
            SimpleHTTPRequestHandler.do_GET(self)

    def do_HEAD(self):
        """Serve a HEAD request."""
        if not self.allow_path():
            self.send_error(403)
        else:
            SimpleHTTPRequestHandler.do_HEAD(self)

    def list_directory(self, path):
        """Override SimpleHTTPRequestHandler.list_directory()"""
        # TODO: permissions for directory listings
        self.send_error(403)
        
class RestrictedHTTPServer(HTTPServer):
    def __init__(self, server_address):
        HTTPServer.__init__(self, server_address, RestrictedHTTPRequestHandler)

def main(argv):
    server = RestrictedHTTPServer((_SERVER_ADDR, _SERVER_PORT))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
