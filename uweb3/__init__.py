#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""µWeb3 Framework"""

__version__ = '3.0'

# Standard modules
import configparser
import logging
import os
import re
import sys
from wsgiref.simple_server import make_server
import datetime

# Package modules
from . import pagemaker, request

# Package classes
from .response import Response, Redirect
from .pagemaker import PageMaker, decorators, WebsocketPageMaker, DebuggingPageMaker, LoginMixin
from .model import SettingsManager
from .libs.safestring import HTMLsafestring, JSONsafestring, JsonEncoder, Basesafestring

class Error(Exception):
  """Superclass used for inheritance and external exception handling."""

class ImmediateResponse(Exception):
  """Used to trigger an immediate response, foregoing the regular returns."""

class HTTPException(Error):
  """SuperClass for HTTP exceptions."""

class HTTPRequestException(HTTPException):
  """Exception for http request errors."""

class NoRouteError(Error):
  """The server does not know how to route this request"""

class Registry(object):
  """Something to hook stuff to"""


class Router(object):
  def __init__(self, page_class):
    self.pagemakers = page_class.LoadModules()
    self.pagemakers.append(page_class)

  def router(self, routes):
    """Returns the first request handler that matches the request URL.

    The `routes` argument is an iterable of 2-tuples, each of which contain a
    pattern (regex) and the name of the handler to use for matching requests.

    Before returning the closure, all regexp are compiled, and handler methods
    are retrieved from the provided `page_class`.

    Arguments:
      @ routes: iterable of 2-tuples.
        Each tuple is a pair of `pattern` and `handler`, both are strings.

    Returns:
      request_router: Configured closure that processes urls.
    """
    req_routes = []
    # Variable used to store websocket pagemakers,
    # these pagemakers are only created at startup but can have multiple routes.
    # To prevent creating the same instance for each route we store them in a dict
    websocket_pagemaker = {}
    for pattern, *details in routes:
      page_maker = None
      for pm in self.pagemakers:
        # Check if the page_maker has the method/handler we are looking for
        if hasattr(pm, details[0]):
          page_maker = pm
          break
      if callable(pattern):
        # Check if the page_maker is already in the dict, if not instantiate
        # if so just use that one. This prevents creating multiple instances for one route.
        if not websocket_pagemaker.get(page_maker.__name__):
          websocket_pagemaker[page_maker.__name__] = page_maker()
        pattern(getattr(websocket_pagemaker[page_maker.__name__], details[0]))
        continue
      if not page_maker:
        raise NoRouteError(f"µWeb3 could not find a route handler called '{details[0]}' in any of the PageMakers, your application will not start.")
      req_routes.append((re.compile(pattern + '$', re.UNICODE),
                        details[0], #handler,
                        details[1].upper() if len(details) > 1 else 'ALL', #request types
                        details[2].lower() if len(details) > 2 else '*', #host
                        page_maker #pagemaker class
                        ))

    def request_router(url, method, host):
      """Returns the appropriate handler and arguments for the given `url`.

      The`url` is matched against the compiled patterns in the `req_routes`
      provided by the outer scope. Upon finding a pattern that matches, the
      match groups from the regex and the unbound handler method are returned.

      N.B. The rules are such that the first matching route will be used. There
      is no further concept of specificity. Routes should be written with this in
      mind.

      Arguments:
        @ url: str
          The URL requested by the client.
        @ method: str
          The http method requested by the client.
        @ host: str
          The http host header value requested by the client.

      Raises:
        NoRouteError: None of the patterns match the requested `url`.

      Returns:
        2-tuple: handler method (unbound), and tuple of pattern matches.
      """

      for pattern, handler, routemethod, hostpattern, page_maker in req_routes:
        if routemethod != 'ALL':
          # clearly not the route we where looking for
          if isinstance(routemethod, tuple):
            if method not in routemethod:
              continue
          if method != routemethod:
            continue

        hostmatch = None
        if hostpattern != '*':
          # see if we can match this host and extact any info from it.
          hostmatch = re.compile(f"^{host}$").match(hostpattern)
          if not hostmatch:
            # clearly not the host we where looking for
            continue
          hostmatch = hostmatch.groups()
        match = pattern.match(url)
        if match:
          # strip out optional groups, as they return '', which would override
          # the handlers default argument values later on in the page_maker
          groups = (group for group in match.groups() if group)
          return handler, groups, hostmatch, page_maker
      raise NoRouteError(url +' cannot be handled')
    return request_router


class uWeb(object):
  """Returns a configured closure for handling page requests.

  This closure is configured with a precomputed set of routes and handlers using
  the Router function. After this, incoming requests are processed and delegated
  to the correct PageMaker handler.

  The url in the received `req` object is taken and matches against the
  `router`` (refer to Router() for more documentation on this).


  Takes:
    @ page_class: PageMaker
      Class that holds request handling methods as defined in the `routes`
    @ router: request router
      The result of the Router() function.
    @ config: dict
      Configuration for the PageMaker. Typically contains entries for database
      connections, default search paths etc.

  Returns:
    RequestHandler: Configured closure that is ready to process requests.
  """
  def __init__(self, page_class, routes, executing_path=None):
    self.executing_path = executing_path if executing_path else os.path.dirname(__file__)
    self.config = SettingsManager(filename='config', executing_path=self.executing_path)
    self.logger = self.setup_logger()
    self.inital_pagemaker = page_class
    self.registry = Registry()
    self.registry.logger = logging.getLogger('root')
    self.router = Router(page_class).router(routes)
    self.setup_routing()
    self.encoders = {
        'text/html': lambda x: HTMLsafestring(x, unsafe=True),
        'text/plain': str,
        'application/json': lambda x: JSONsafestring(x, unsafe=True)}

  def __call__(self, env, start_response):
    """WSGI request handler.
    Accepts the WSGI `environment` dictionary and a function to start the
    response and returns a response iterator.
    """
    req = request.Request(env, self.registry)
    req.env['REAL_REMOTE_ADDR'] = request.return_real_remote_addr(req.env)
    response = None
    method = '_NotFound'
    args = None
    rollback = False
    try:
      method, args, hostargs, page_maker = self.router(req.path,
                                            req.env['REQUEST_METHOD'],
                                            req.env['host'])
    except NoRouteError:
      # When we catch this error this means there is no method for the route in the currently selected pagemaker.
      # If this happens we default to the initial pagemaker because we don't know what the target pagemaker should be.
      # Then we set an internalservererror and move on
      page_maker = self.inital_pagemaker
    try:
      # instantiate the pagemaker for this request
      pagemaker_instance = page_maker(req,
                            config=self.config,
                            executing_path=self.executing_path)
      # specifically call _PreRequest as promised in documentation
      if hasattr(pagemaker_instance, '_PreRequest'):
        pagemaker_instance = pagemaker_instance._PreRequest()

      response = self.get_response(pagemaker_instance, method, args)
    except Exception:
      # something broke in our pagemaker_instance, lets fall back to the most basic pagemaker for error output
      if hasattr(pagemaker_instance, '_ConnectionRollback'):
        try:
          pagemaker_instance._ConnectionRollback()
        except:
          pass
      pagemaker_instance = PageMaker(req,
                            config=self.config,
                            executing_path=self.executing_path)
      response = pagemaker_instance.InternalServerError(*sys.exc_info())

    if method != 'Static':
      if not isinstance(response, Response):
        # print('Upgrade response to Response class: %s' % type(response))
        req.response.text = response
        response = req.response

      if not isinstance(response.text, Basesafestring):
        # make sure we always output Safe HTML if our content type is something we should encode
        encoder = self.encoders.get(response.clean_content_type(), None)
        if encoder:
          response.text = encoder(response.text)

      if hasattr(pagemaker_instance, '_PostRequest'):
        pagemaker_instance._PostRequest()

    # CSP might be unneeded for some static content,
    # https://github.com/w3c/webappsec/issues/520
    if hasattr(pagemaker_instance, '_CSPheaders'):
      pagemaker_instance._CSPheaders()

    # provide users with a _PostRequest method to overide too
    if method != 'Static' and hasattr(pagemaker_instance, 'PostRequest'):
      response = pagemaker_instance.PostRequest(response)

    # we should at least send out something to make sure we are wsgi compliant.
    if not response.text:
      response.text = ''

    self._logging(req, response)
    start_response(response.status, response.headerlist)
    try:
      yield response.text.encode(response.charset)
    except AttributeError:
      yield response.text

  def setup_logger(self):
    logger = logging.getLogger('uweb3_logger')
    logger.setLevel(logging.INFO)
    fh = logging.FileHandler(os.path.join(self.executing_path, 'access_logging.log'))
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)
    return logger

  def _logging(self, req, response):
    """Logs incoming requests to a logfile.
    This is enabled by default, even if its missing in the config file.
    """
    if self.config.options.get('development', None):
      if self.config.options['development'].get('access_logging', True) == 'False':
        return

    host = req.env['HTTP_HOST'].split(':')[0]
    date = datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    method = req.method
    path = req.path
    status = response.httpcode
    protocol = req.env.get('SERVER_PROTOCOL')
    self.logger.info(f"""{host} - - [{date}] \"{method} {path} {status} {protocol}\"""")

  def get_response(self, page_maker, method, args):
    try:
      if method != 'Static':
        # We're specifically calling _PostInit here as promised in documentation.
        # pylint: disable=W0212
        page_maker._PostInit()
      elif hasattr(page_maker, '_StaticPostInit'):
        # We're specifically calling _StaticPostInit here as promised in documentation, seperate from the regular PostInit to keep things fast for static pages
        page_maker._StaticPostInit()

      # pylint: enable=W0212
      return getattr(page_maker, method)(*args)
    except pagemaker.ReloadModules as message:
      reload_message = reload(sys.modules[self.inital_pagemaker.__module__])
      return Response(content='%s\n%s' % (message, reload_message))
    except ImmediateResponse as err:
      return err[0]
    except Exception:
      if self.config.options.get('development', False):
        if self.config.options['development'].get('error_logging', True) == 'True':
          logger = logging.getLogger('uweb3_exception_logger')
          fh = logging.FileHandler(os.path.join(self.executing_path, 'uweb3_uncaught_exceptions.log'))
          logger.addHandler(fh)
          logger.exception("UNCAUGHT EXCEPTION:")
      return page_maker.InternalServerError(*sys.exc_info())

  def serve(self, hot_reloading=True):
    """Sets up and starts WSGI development server for the current app."""
    host = 'localhost'
    port = 8001
    hotreload = False
    dev = False
    if self.config.options.get('development', False):
      host = self.config.options['development'].get('host', host)
      port = self.config.options['development'].get('port', port)
      hotreload = self.config.options['development'].get('reload', False) == 'True'
      dev = self.config.options['development'].get('dev', False)
    server = make_server(host, int(port), self)
    print(f'Running µWeb3 server on http://{server.server_address[0]}:{server.server_address[1]}')
    print(f'Root dir is: {self.executing_path}')
    try:
      if hotreload:
        print(f'Hot reload is enabled for changes in: {self.executing_path}')
        HotReload(self.executing_path, uweb_dev=dev)
      server.serve_forever()
    except:
      server.shutdown()

  def setup_routing(self):
    if isinstance(self.inital_pagemaker, list):
      routes = []
      for route in self.inital_pagemaker[1:]:
        routes.append(route)
      self.inital_pagemaker[0].AddRoutes(tuple(routes))
      self.inital_pagemaker = self.inital_pagemaker[0]

    default_route = "routes"
    automatic_detection = True
    if self.config.options.get('routing'):
      default_route = self.config.options['routing'].get('default_routing', default_route)
      automatic_detection = self.config.options['routing'].get('disable_automatic_route_detection', 'False') != 'True'

    if automatic_detection:
      self.inital_pagemaker.LoadModules(routes=default_route)


class HotReload(object):
    """This class handles the thread which scans for file changes in the
    execution path and restarts the server if needed"""
    IGNOREDEXTENSIONS = (".pyc", '.ini', '.md', '.html', '.log')

    def __init__(self, path, interval=1, uweb_dev=False):
      """Takes a path, an optional interval in seconds and an optional flag
      signalling a development environment"""
      import threading
      import time

      self.running = threading.Event()
      self.interval = interval
      self.path = os.path.dirname(path)
      if uweb_dev in ('True', True):
        from pathlib import Path
        self.path = str(Path(self.path).parents[1])
      self.thread = threading.Thread(target=self.run, args=())
      self.thread.daemon = True
      self.thread.start()

    def run(self):
      """ Method runs forever and watches all files in the project folder.

      Does not trigger a reload when the following files change:
      - .pyc
      - .ini
      - .md
      - .html
      - .log

      Changes in the HTML are noticed by the TemplateParser,
      which then reloads the HTML file into the object and displays the updated version.
      """
      self.WATCHED_FILES = self.getListOfFiles()[1]
      WATCHED_FILES_MTIMES = [(f, os.path.getmtime(f)) for f in self.WATCHED_FILES]

      while True:
        if len(self.WATCHED_FILES) != self.getListOfFiles()[0]:
          print('{color}New file added or deleted\x1b[0m \nRestarting µWeb3'.format(color='\x1b[7;30;41m'))
          self.restart()
        for f, mtime in WATCHED_FILES_MTIMES:
          if os.path.getmtime(f) != mtime:
            print('{color}Detected changes in {file}\x1b[0m \nRestarting µWeb3'.format(color='\x1b[7;30;41m', file=f))
            self.restart()
        time.sleep(self.interval)

    def getListOfFiles(self):
      """Returns all files inside the working directory of uweb3.
      Also returns a count so that we can restart on file add/remove.
      """
      watched_files = []
      for r, d, f in os.walk(self.path):
        for file in f:
          ext = os.path.splitext(file)[1]
          if ext not in IGNOREDEXTENSIONS:
            watched_files.append(os.path.join(r, file))
      return (len(watched_files), watched_files)

    def restart(self):
      """Restart uweb3 with all provided system arguments."""
      self.running.clear()
      os.execl(sys.executable, sys.executable, * sys.argv)
