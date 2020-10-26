#!/usr/bin/python
"""uWeb3 response classes."""

# Standard modules
try:
  import httplib
except ImportError:
  import http.client as httplib

import json

from collections import defaultdict
from .libs.safestring import JSONsafestring

class Response(object):
  """Defines a full HTTP response.

  The full response consists of a required content part, and then optional
  http response code, cookies, additional headers, and a content-type.
  """
  # Default content-type for Page objects
  CONTENT_TYPE = 'text/html'

  def __init__(self, content='', content_type=CONTENT_TYPE,
               httpcode=200, headers=None, **kwds):
    """Initializes a Page object.

    Arguments:
      @ content: str
        The content to return to the client. This can be either plain text, html
        or the contents of a file (images for example).
      % content_type: str ~~ CONTENT_TYPE ('text/html' by default)
        The content type of the response. This should NOT be set in headers.
      % httpcode: int ~~ 200
        The HTTP response code to attach to the response.
      % headers: dict ~~ None
        A dictionary with header names and their associated values.
    """
    self.charset = kwds.get('charset', 'utf8')
    self.content = None
    self.text = content
    self.httpcode = httpcode
    self.headers = headers or {}
    if (content_type.startswith('text/') or
        content_type.startswith('application/json')) and ';' not in content_type:
      content_type = '{!s}; charset={!s}'.format(content_type, self.charset)
    self.content_type = content_type

  # Get and set content-type header
  @property
  def content_type(self):
    return self.headers['Content-Type']

  @content_type.setter
  def content_type(self, content_type):
    current = self.headers.get('Content-Type', '')
    if ';' in current:
      content_type = '{!s}; {!s}'.format(content_type, current.split(';', 1)[-1])
    self.headers['Content-Type'] = content_type

  def clean_content_type(self):
    if ';' not in self.headers['Content-Type']:
      return self.headers['Content-Type']
    return self.headers['Content-Type'].split(';')[0]

  # Get and set body text
  @property
  def text(self):
    return self.content

  @text.setter
  def text(self, content):
    self.content = content

  # Retrieve a header list
  @property
  def headerlist(self):
    tuple_list = []
    for key, val in self.headers.items():
      if key == 'Set-Cookie':
        for cookie in val:
          tuple_list.append((key, cookie.encode('ascii', 'ignore').decode('ascii')))
        continue
      if not isinstance(val, str):
        val = str(val)
      tuple_list.append((key, val.encode('ascii', 'ignore').decode('ascii')))
    return tuple_list

  @property
  def status(self):
    if not self.httpcode:
      return '%d %s' % (500, httplib.responses[500])
    return '%d %s' % (self.httpcode, httplib.responses[self.httpcode])

  def __repr__(self):
    return '<%s instance at %#x>' % (self.__class__.__name__, id(self))

  def __str__(self):
    return self.content


class Redirect(Response):
  """A response tailored to do redirects."""
  REDIRECT_PAGE = ('<!DOCTYPE html><html><head><title>Page moved</title></head>'
                   '<body>Page moved, please follow <a href="%s">this link</a>'
                   '</body></html>')
  def __init__(self, location, httpcode=307):
    super(Redirect, self).__init__(
        content=self.REDIRECT_PAGE % location,
        content_type='text/html',
        httpcode=httpcode,
        headers={'Location': location})
