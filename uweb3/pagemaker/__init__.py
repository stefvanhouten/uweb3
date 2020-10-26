#!/usr/bin/python3
"""uWeb3 PageMaker class and its various Mixins."""

import datetime
import logging
import mimetypes
import os
import pyclbr
import sys
import threading
import time
import hashlib
import glob
from base64 import b64encode
from pymysql import Error as pymysqlerr


import uweb3
from ..connections import ConnectionManager
from .. import response, templateparser

RFC_1123_DATE = '%a, %d %b %Y %T GMT'

class ReloadModules(Exception):
  """Signals the handler that it should reload the pageclass"""


class CacheStorage(object):
  """A (semi) persistent storage for the PageMaker."""
  def __init__(self):
    super(CacheStorage, self).__init__()
    self._dict = {}
    self._lock = threading.RLock()

  def __contains__(self, key):
    return key in self._dict

  def Del(self, key):
    """Removes the given key from the persistent storage.

    N.B. if the key was not in the persistent storage, no error is raised.
    """
    with self._lock:
      try:
        del self._dict[key]
      except KeyError:
        pass  # If a key is not in the storage, consider this a success

  def Get(self, key, *default):
    """Returns the current value for `key`, or the `default` if it doesn't."""
    with self._lock:
      if len(default) > 1:
        raise ValueError('Only one default value accepted')
      try:
        return self._dict[key]
      except KeyError:
        if default:
          return default[0]
        raise

  def Set(self, key, value):
    """Sets the `key` in the dictionary storage to `value`."""
    self._dict[key] = value

  def SetDefault(self, key, default=None):
    """Returns the value for `key` or sets it to `default` if it doesn't exist.

    Arguments:
      @ key: obj
        The key to retrieve from the dictionary storage.
      @ default: obj ~~ None
        The default new value for the given key if it doesn't exist yet.
    """
    with self._lock:
      return self._dict.setdefault(key, default)


class MimeTypeDict(dict):
  """Dictionary that defines special behavior for mimetypes.

  Mimetypes (of typical form "type/subtype") are stored as (type, subtype) keys.
  This allows grouping of types to happen, and fallbacks to occur.

  The following is a typical complete MIMEType example:
    >>> mime_type_dict['text/html'] = 'HTML content'

  One could also define a default for the whole type, as follows:
    >>> mime_type_dict['text/*'] = 'Default'Exception
    >>> mime_type_dict['text/nonexistant']
    'Default'
  """
  def __init__(self, data=(), **kwds):
    super(MimeTypeDict, self).__init__()
    if data:
      self.update(data)
    if kwds:
      self.update(**kwds)

  @staticmethod
  def MimeSplit(mime):
    """Split up a MIMEtype in a type and subtype, return as tuple.

    When the subtype if undefined or '*', only the type is returned, as 1-tuple.
    """
    mime_type, _sep, mime_subtype = mime.lower().partition('/')
    if not mime_subtype or mime_subtype == '*':
      return mime_type,  # 1-tuple
    return mime_type, mime_subtype

  def __setitem__(self, mime, value):
    super(MimeTypeDict, self).__setitem__(self.MimeSplit(mime), value)

  def __getitem__(self, mime):
    parsed_mime = self.MimeSplit(mime)
    try:
      return super(MimeTypeDict, self).__getitem__(parsed_mime)
    except KeyError:
      try:
        return super(MimeTypeDict, self).__getitem__(parsed_mime[:1])
      except KeyError:
        raise KeyError('KeyError: %r' % mime)

  def get(self, mime, default=None):
    try:
      return self[mime]
    except KeyError:
      return default

  def update(self, data=None, **kwargs):
    """Update the dictionary with new values from another dictionary.

    Also takes values from an iterable object of pairwise data.
    """
    if data:
      try:
        for key, value in data.items():
          self[key] = value
      except AttributeError:
        # Argument data is not a proper dict, treat it as an iterable of tuples.
        for key, value in data:
          self[key] = value
    if kwargs:
      self.update(kwargs)


class XSRFToken(object):
  def __init__(self, seed, remote_addr):
    self.seed = seed
    self.remote_addr = remote_addr
    self.unix_today = time.mktime(datetime.datetime.now().date().timetuple())

  def generate_token(self):
    """Generate an XSRF token

    XSRF token is generated based on the unix timestamp from today,
    a randomly generated seed and the IP addres from the request
    """
    hashed = (str(self.unix_today) + self.seed + self.remote_addr).encode('utf-8')
    h = hashlib.new('ripemd160')
    h.update(hashed)
    return h.hexdigest()


class Base(object):
  # Constant for persistent storage accross requests. This will be accessible
  # by all threads of the same application (in the same Python process).
  PERSISTENT = CacheStorage()
  # Base paths for templates and public data. These are used in the PageMaker
  # classmethods that set up paths specific for that pagemaker.
  TEMPLATE_DIR = 'templates'

  def __init__(self):
    self.persistent = self.PERSISTENT
    # clean up any request tags in the template parser
    if '__parser' in self.persistent:
      self.persistent.Get('__parser').ClearRequestTags()

  def _PostInit(self):
    pass

  @property
  def parser(self):
    """Provides a templateparser.Parser instance.

    If the config file specificied a [templates] section and a `path` is
    assigned in there, this path will be used.
    Otherwise, the `TEMPLATE_DIR` will be used to load templates from.
    """
    if '__parser' not in self.persistent:
      self.persistent.Set('__parser', templateparser.Parser(
          self.options.get('templates', {}).get('path', self.TEMPLATE_DIR)))
    return self.persistent.Get('__parser')


class WebsocketPageMaker(Base):
  """Pagemaker for the websocket routes.
  This is different from the BasePageMaker as we choose to not have a database connection
  in our WebSocketPageMaker.

  This class lacks pretty much all functionality that the BasePageMaker has.
  """

  #TODO: Add request to pagemaker?
  def Connect(self, sid, env):
    """This is the connect event,
    sets the req variable that contains the request headers.
    """
    print(f"User connected with SocketID {sid}: ")
    self.req = env


class XSRFMixin(object):
  """Provides XSRF protection by enabling setting xsrf token cookies, checking
  them and setting a flag based on their value

  A seperate decorator can then be used to clear the POST/GET/PUT variables if
  needed in specific pagemaker functions depending on that page's security
  context.
  """
  XSRFCOOKIE = 'xsrf'
  XSRF_seed = str(os.urandom(32))

  def validatexsrf(self):
    """Sets the invalid_xsrf_token flag to true or false"""
    self.invalid_xsrf_token = False
    if self.req.method != 'GET': # GET calls will be ignored, but will set a cookie
      self.invalid_xsrf_token = True
      try:
        user_supplied_xsrf_token = getattr(self, self.req.method.lower()).getfirst(self.XSRFCOOKIE)
        self.invalid_xsrf_token = (self.cookies.get(self.XSRFCOOKIE) != user_supplied_xsrf_token)
      except Exception:
        # any error in looking up the cookie of the supplied post vars will result in a invalid xsrf token flag
        pass
    # If no cookie is present, set it.
    self._Set_XSRF_cookie()

  def _Set_XSRF_cookie(self):
    """This creates a new XSRF token for this client, which is IP bound, and
    stores it in a cookie.
    """
    xsrf_cookie = self.cookies.get(self.XSRFCOOKIE, False)
    if not xsrf_cookie:
      xsrf_cookie = XSRFToken(self.XSRF_seed, self.req.env['REAL_REMOTE_ADDR']).generate_token()
      self.req.AddCookie(self.XSRFCOOKIE, xsrf_cookie, path="/", httponly=True)
    return xsrf_cookie

  def XSRFInvalidToken(self):
    """Returns an error message regarding an incorrect XSRF token."""
    errorpage = templateparser.FileTemplate(os.path.join(
        os.path.dirname(__file__), 'http_403.html'))
    error = """Your browser did not send us the correct token, any token at all, or a timed out token.
    Because of this we cannot allow you to perform this action at this time. Please refresh the previous page and try again."""

    return uweb3.Response(content=errorpage.Parse(error=error),
        httpcode=403, headers=self.req.response.headers)

  def _Get_XSRF(self):
    """Easy access to the XSRF token"""
    try:
      return self.cookies[self.XSRFCOOKIE]
    except KeyError:
      return self._Set_XSRF_cookie()


class LoginMixin(object):
  """This mixin provides a few methods that help with handling logins, sessions
  and related database/cookie interaction"""

  def _ReadSession(self):
    return NotImplemented

  @property
  def user(self):
    """Returns the current user"""
    if not hasattr(self, '_user') or not self._user:
      try:
        self._user = self._ReadSession()
      except ValueError:
        self._user = False
    return self._user


class BasePageMaker(Base):
  """Provides the base pagemaker methods for all the html generators."""
  _registery = []

  # Default Static() handler cache durations, per MIMEtype, in days
  PUBLIC_DIR = 'static'
  CACHE_DURATION = MimeTypeDict({'text': 7, 'image': 30, 'application': 7,
      'text/css': 7})

  def __init__(self,
              req,
              config=None,
              executing_path=None):
    """sets up the template parser and database connections.

    Arguments:
      @ req: request.Request
        The originating request, including environment, GET, POST and cookies.
      % config: dict ~~ None
        Configuration for the pagemaker, with database connection information
        and other settings. This will be available through `self.options`.
      % executing_path: str/path
        This is the path to the uWeb3 routing file.
    """
    super(BasePageMaker, self).__init__()
    self.__SetupPaths(executing_path)
    self.req = req
    self.cookies = req.vars['cookie']
    self.get = req.vars['get']
    self.post = req.vars['post'] if 'post' in req.vars else {}
    self.put = req.vars['put'] if 'put' in req.vars else {}
    self.delete = req.vars['delete'] if 'delete' in req.vars else {}
    self.config = config or None
    self.options = config.options if config else {}
    self.debug = DebuggerMixin in self.__class__.__mro__
    try:
      self.connection = self.persistent.Get('connection')
    except KeyError:
      self.persistent.Set('connection', ConnectionManager(self.config, self.options, self.debug))
      self.connection = self.persistent.Get('connection')

  @classmethod
  def LoadModules(cls, routes='routes/*.py'):
    """Loops over all .py files apart from some exceptions in target directory
    Looks for classes that contain pagemaker

    Arguments:
      % default_routes: str
        Location to your route files. Defaults to routes/*.py
        Supports glob style syntax, non recursive.
    """
    bases = []
    for file in glob.glob(routes):
      module = os.path.relpath(os.path.join(os.getcwd(), file[:-3])).replace('/', '.')
      classlist = pyclbr.readmodule_ex(module)
      for name, data in classlist.items():
        if hasattr(data, 'super'):
          if 'PageMaker' in data.super[0]:
            module = __import__(f, fromlist=[name])
            bases.append(getattr(module, name))
    return bases

  def _PostInit(self):
    """Method that gets called for derived classes of BasePageMaker."""

  def _ConnectionRollback(self):
    """Roll back all connections, this method can be overwritten by the user"""
    self.connection.Rollback()

  @classmethod
  def __SetupPaths(cls, executing_path):
    """This sets up the correct paths for the PageMaker subclasses.

    From the passed in `cls`, it retrieves the filename. Of that path, the
    directory is used as the working directory. Then, the module constant
    TEMPLATE_DIR is used to define class constants from.
    """
    # Unfortunately, mod_python does not always support retrieving the caller
    # filename using sys.modules. In those cases we need to query the stack.
    # pylint: disable=W0212
    try:
      local_file = os.path.abspath(sys.modules[cls.__module__].__file__)
    except KeyError:
      # This happens for old-style mod_python solutions: The pages file is
      # imported through the mechanics of mod_pythoif '__mysql' not in self.persistent: (not package imports) and
      # isn't known in sys modules. We use the CPython implementation details
      # to get the correct executing file.
      frame = sys._getframe()
      initial = frame.f_code.co_filename
      # pylint: enable=W0212
      while initial == frame.f_code.co_filename:
        if not frame.f_back:
          break  # This happens during exception handling of DebuggingPageMaker
        frame = frame.f_back
      local_file = frame.f_code.co_filename
    cls.LOCAL_DIR = cls_dir = executing_path
    cls.PUBLIC_DIR = os.path.join(cls_dir, cls.PUBLIC_DIR)
    cls.TEMPLATE_DIR = os.path.join(cls_dir, cls.TEMPLATE_DIR)

  def Static(self, rel_path):
    """Provides a handler for static content.

    The requested `path` is truncated against a root (removing any uplevels),
    and then added to the working dir + PUBLIC_DIR. If the request file exists,
    then the requested file is retrieved, its mimetype guessed, and returned
    to the client performing the request.

    Should the requested file not exist, a 404 page is returned instead.

    Arguments:
      @ rel_path: str
        The filename relative to the working directory of the webserver.

    Returns:
      Page: contains the content and mimetype of the requested file, or a 404
            page if the file was not available on the local path.
    """
    rel_path = os.path.abspath(os.path.join(os.path.sep, rel_path))[1:]
    abs_path = os.path.join(self.PUBLIC_DIR, rel_path)
    try:
      content_type, _encoding = mimetypes.guess_type(abs_path)
      if not content_type:
        content_type = 'text/plain'
      binary = False
      if not content_type.startswith('text/'):
        binary = True
      with open(abs_path, 'rb' if binary else 'r') as staticfile:
        mtime = os.path.getmtime(abs_path)
        length = os.path.getsize(abs_path)
        cache_days = self.CACHE_DURATION.get(content_type, 0)
        expires = datetime.datetime.utcnow() + datetime.timedelta(cache_days)
        return response.Response(content=staticfile.read(),
                        content_type=content_type,
                        headers={'Expires': expires.strftime(RFC_1123_DATE),
                                 'cache-control': 'max-age=%d' %
                                    (cache_days*24*60*60),
                                 'last-modified': time.ctime(mtime),
                                 'content-length': length})
    except IOError:
      return self._StaticNotFound(rel_path)

  def _StaticNotFound(self, _path):
    message = 'This is not the path you\'re looking for. No such file %r' % (
      self.req.env['PATH_INFO'])
    return response.Response(message, content_type='text/plain', httpcode=404)

  def _NotFound(self, _path):
    message = 'This is not the path you\'re looking for. No such path %r' % (
      self.req.env['PATH_INFO'])
    return response.Response(message, content_type='text/html', httpcode=404)

  def InternalServerError(self, exc_type, exc_value, traceback):
    """Returns a plain text notification about an internal server error."""
    error = 'INTERNAL SERVER ERROR (HTTP 500) DURING PROCESSING OF %r' % (
                self.req.path)
    self.req.registry.logger.error(
        error, exc_info=(exc_type, exc_value, traceback))
    return response.Response(
        content=error, content_type='text/plain', httpcode=500)

  @staticmethod
  def Reload():
    """Raises `ReloadModules`, telling the Handler() to reload its pageclass."""
    raise ReloadModules('Reloading ... ')

  def _PostRequest(self):
    """Method that gets called after each request"""
    self.connection.PostRequest()


class DebuggerMixin(object):
  """Replaces the default handler for Internal Server Errors.

  This one prints a host of debugging and request information, though it still
  lacks interactive functions.
  """
  CACHE_DURATION = MimeTypeDict({})
  ERROR_TEMPLATE = 'http_500.html'

  def _ParseStackFrames(self, stack):
    """Generates list items for traceback information.

    Each traceback item contains the file- and function name, the line numer
    and the source that belongs with it. For each stack frame, the local
    variables are also added to it, allowing proper analysis to happen.

    This most likely doesn't need overriding / redefining in a subclass.

    Arguments:
      @ stack: traceback.stack
        The stack frames to return analysis on.

    Yields:
      str: Template-parsed HTML with frame information.
    """
    frames = []
    while stack:
      frame = stack.tb_frame
      frames.append({'file': os.path.abspath(frame.f_code.co_filename),
                     'scope': frame.f_code.co_name,
                     'locals': frame.f_locals,
                     'source': self._SourceLines(
                         frame.f_code.co_filename, frame.f_lineno)})
      stack = stack.tb_next
    return reversed(frames)

  @staticmethod
  def _SourceLines(filename, line_num, context=3):
    """Yields the offending source line, and `context` lines of context.

    Arguments:
      @ filename: str
        The filename (path) of which we should print lines of source.
      @ line_num: int
        The line number for the offending line.
      % context: int ~~ 3
        Number of lines context, before and after the offending line.

    Yields:
      str: Templated list-item for a source code line.
    """
    import linecache
    for line_num in range(line_num - context, line_num + context + 1):
      yield line_num, linecache.getline(filename, line_num)

  def InternalServerError(self, exc_type, exc_value, traceback):
    """Returns a HTTP 500 response with detailed failure analysis."""
    self.req.registry.logger.error(
        'INTERNAL SERVER ERROR (HTTP 500) DURING PROCESSING OF %r',
        self.req.path, exc_info=(exc_type, exc_value, traceback))
    exception_data = {
        'cookies': self.cookies,
        'environ': self.req.env,
        'query_args': self.get,
        'post_data': self.post,
        'error_for_error': False,
        'exc': {'type': exc_type, 'value': exc_value,
                'traceback': self._ParseStackFrames(traceback)}}

    error_template = templateparser.FileTemplate(os.path.join(
      os.path.dirname(__file__), self.ERROR_TEMPLATE))
    try:
      return response.Response(
          error_template.Parse(**exception_data), httpcode=500)
    except Exception:
      exc_type, exc_value, traceback = sys.exc_info()
      self.req.registry.logger.critical(
          'INTERNAL SERVER ERROR (HTTP 500) DURING PROCESSING OF ERROR PAGE',
          exc_info=(exc_type, exc_value, traceback))
      exception_data['error_for_error'] = True
      exception_data['orig_exc'] = exception_data['exc']
      exception_data['exc'] = {'type': exc_type, 'value': exc_value,
                               'traceback': self._ParseStackFrames(traceback)}
      return response.Response(
          error_template.Parse(**exception_data), httpcode=500)


class CSPMixin(object):
  """Provides CSP header output.

  https://content-security-policy.com/
  """
  _csp = {
        "default-src": ("'none'",),
        "object-src": ("'none'",),
        "script-src":  ("'none'",),
        "style-src":  ("'none'",),
        "form-action":  ("'none'",),
        "connect-src":  ("'none'",),
        "img-src":  ("'none'",),
        "font-src":  ("'none'",),
        "frame-ancestors":  ("'none'",),
        "base-uri": ("'none'",)
  }

  def _SetCsp(self, resourcetype="default-src", urls=("'self'", ), append=True):
    """Add a new CSP url to the csp headers for the given resourcetype.

    resourcetype is any of the CSP resource types as defined in:
      https://content-security-policy.com/#directive
      defaults to: default-src

    urls should be one or more of:
      https://content-security-policy.com/#source_list
      default to 'self'
      string or tuple/list is allowed

    By default this appends to the already present list of sources for the given
    resourcetype

    """
    if isinstance(urls, str):
      urls = [urls, ]
    else:
      urls = list(urls) if type(urls) == tuple else urls
    if resourcetype not in self._csp:
      self._csp[resourcetype] = []
    if self._csp[resourcetype] == "'none'" or not append:
      self._csp[resourcetype] = urls
      return
    self._csp[resourcetype].extend(urls)

  def _CSPFromConfig(self, config):
    """sets the CSP headers from a Dictionary
    Dict keys should be resourcetypes, values should be lists of urls

    resourcetype is any of the CSP resource types as defined in:
      https://content-security-policy.com/#directive

    urls are in the form:
      https://content-security-policy.com/#source_list
    """
    self._csp = config

  def _CSPheaders(self):
    """Adds the constructed CSP header to the request"""
    csp = '; '.join(["%s %s" % (key, ' '.join(value)) for key, value in self._csp.items()])
    self.req.AddHeader('Content-Security-Policy', csp)

# ##############################################################################
# Classes for public use (wildcard import)
#
class PageMaker(XSRFMixin, BasePageMaker):
  """The basic PageMaker class, providing XSRF support."""


class DebuggingPageMaker(DebuggerMixin, PageMaker):
  """The same basic PageMaker, with added debugging on HTTP 500."""
