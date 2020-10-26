#!/usr/bin/python
"""This file contains all the connectionManager classes that interact with
databases, restfull apis, secure cookies, config files etc."""
__author__ = 'Jan Klopper (janunderdark.nl)'
__version__ = 0.1

import os
import sys
from base64 import b64encode

class ConnectionError(Exception):
  """Error class thrown when the underlying connectors thrown an error on
  connecting."""

class ConnectionManager(object):
  """This is the connection manager object that is handled by all Model Objects.
  It finds out which connection was requested by looking at the call stack, and
  figuring out what database type the model class calling it belongs to.

  Connected databases are stored and reused.
  On delete, the databases are closed and any lingering transactions are
  committed. to complete the database writes.
  """

  DEFAULTCONNECTIONMANAGER = None

  def __init__(self, config, options, debug):
    self.__connectors = {} # classes
    self.__connections = {} # instances
    self.config = config
    self.options = options
    self.debug = debug
    self.LoadDefaultConnectors()

  def LoadDefaultConnectors(self):
    self.RegisterConnector(SignedCookie)
    self.RegisterConnector(Mysql, True)
    self.RegisterConnector(Sqlite)
    self.RegisterConnector(Mongo)
    self.RegisterConnector(SqlAlchemy)

  def RegisterConnector(self, classname, default=False):
    """Make the ConnectonManager aware of a new type of connector."""
    if default:
      self.DEFAULTCONNECTIONMANAGER = classname.Name()
    self.__connectors[classname.Name()] = classname

  def RelevantConnection(self, level=2):
    """Returns the relevant database connection dependant on the caller model
    class.

    If the caller model cannot be determined, the 'relational' database
    connection is returned as a fallback method.

    Level indicates how many stack layers we should go up. Defaults to two.
    """
    # Figure out caller type or instance
    # pylint: disable=W0212
    #TODO use inspect module instead, and iterate over frames
    caller_locals = sys._getframe(level).f_locals
    # pylint: enable=W0212
    if 'self' in caller_locals:
      caller_cls = type(caller_locals['self'])
    else:
      caller_cls = caller_locals.get('cls', type)

    # Decide the type of connection to return for this caller
    con_type = (caller_cls._CONNECTOR if hasattr(caller_cls, '_CONNECTOR') else
                self.DEFAULTCONNECTIONMANAGER)
    if (con_type in self.__connections and
        hasattr(self.__connections[con_type], 'connection')):
      return self.__connections[con_type].connection
    else:
      request = sys._getframe(3).f_locals['self'].req
      try:
        # instantiate a connection
        self.__connections[con_type] = self.__connectors[con_type](
            self.config, self.options, request, self.debug)
        return self.__connections[con_type].connection
      except KeyError:
        raise TypeError('No connector for: %r, available: %r' % (con_type, self.__connectors))

  def __enter__(self):
    """Proxies the transaction to the underlying relevant connection."""
    return self.RelevantConnection().__enter__()

  def __exit__(self, *args):
    """Proxies the transaction to the underlying relevant connection."""
    return self.RelevantConnection().__exit__(*args)

  def __getattr__(self, attribute):
    return getattr(self.RelevantConnection(), attribute)

  def RollbackAll(self):
    """Performas a rollback on all connectors with pending commits"""
    if self.debug:
      print('Rolling back uncommited transaction on all connectors.')
    for classname in self.__connections:
      try:
        self.__connections[classname].Rollback()
      except NotImplementedError:
        pass

  def PostRequest(self):
    """This cleans up any non persistent connections."""
    cleanups = []
    for classname in self.__connections:
      if (hasattr(self.__connections[classname], 'PERSISTENT') and
          not self.__connections[classname].PERSISTENT):
        cleanups.append(classname)
    for classname in cleanups:
      try:
        self.__connections[classname].Disconnect()
      except (NotImplementedError, TypeError, ConnectionError):
        pass
      del(self.__connections[classname])

  def __iter__(self):
    """Pass tru to the Relevant connection as an Iterable, so variable unpacking
    can be used by the consuming class. This is used in the SecureCookie Model
    class."""
    return iter(self.RelevantConnection())

  def __del__(self):
    """Cleans up all references, and closes all connectors"""
    print('Deleting model connections.')
    for classname in self.__connectors:
      if not hasattr(self.__connectors[classname], 'connection'):
        continue
      try:
        self.__connections[classname].Disconnect()
      except (NotImplementedError, TypeError, ConnectionError):
        pass


class Connector(object):
  """Base Connector class, subclass from this to create your own connectors.
  Usually the name of your class is used to lookup its config in the
  configuration file, or the database or local filename.

  Connectors based on this class are Usually Singletons. One global connection
  is kept alive, and multiple model classes use it to connect to their
  respective tables, cookies, or files.
  """
  _NAME = None

  @classmethod
  def Name(cls):
    """Returns the 'connector' name, which is usally used to lookup its config
     in the config file.

    If this is not explicitly defined by the class constant `_TABLE`, the return
    value will be the class name with the first letter lowercased.
    """
    if cls._NAME:
      return cls._NAME
    name = cls.__name__
    return name[0].lower() + name[1:]

  def Disconnect(self):
    """Standard interface to disconnect from data source"""
    raise NotImplementedError

  def Rollback(self):
    """Standard interface to rollback any pending commits"""
    raise NotImplementedError


class SignedCookie(Connector):
  """Adds a signed cookie connection to the connection manager object.

  The name of the class is used as the Cookiename"""

  PERSISTENT = False

  def __init__(self, config, options, request, debug=False):
    """Sets up the local connection to the signed cookie store, and generates a
    new secret key if no key can be found in the config"""
    # Generating random seeds on uWeb3 startup or fetch from config
    self.debug = debug
    try:
      self.options = options[self.Name()]
      self.secure_cookie_secret = self.options['secret']
    except KeyError:
      secret = self.GenerateNewKey()
      config.Create(self.Name(), 'secret', secret)
      if self.debug:
        print('SignedCookie: Wrote new secret random to config.')
      self.secure_cookie_secret = secret
    self.connection = (request, request.vars['cookie'], self.secure_cookie_secret)

  @staticmethod
  def GenerateNewKey(length=128):
    return b64encode(os.urandom(length)).decode('utf-8')


class Mysql(Connector):
  """Adds MySQL support to connection manager object."""

  def __init__(self, config, options, request, debug=False):
    """Returns a MySQL database connection."""
    self.debug = debug
    self.options = {'host': 'localhost',
                   'user': None,
                   'password': None,
                   'database': ''}
    try:
      from .libs.sqltalk import mysql
      try:
        self.options = options[self.Name()]
      except KeyError:
        pass
      self.connection = mysql.Connect(
        host=self.options.get('host', 'localhost'),
        user=self.options.get('user'),
        passwd=self.options.get('password'),
        db=self.options.get('database'),
        charset=self.options.get('charset', 'utf8'),
        debug=self.debug)
    except Exception as e:
      raise ConnectionError('Connection to "%s" of type "%s" resulted in: %r' % (self.Name(), type(self), e))

  def Rollback(self):
    with self.connection as cursor:
      return cursor.Execute("ROLLBACK")

  def Disconnect(self):
    """Closes the MySQL connection."""
    if self.debug:
      print('%s closed connection to: %r' % (self.Name(), self.options.get('database')))
    self.connection.close()
    del(self.connection)


class Mongo(Connector):
  """Adds MongoDB support to connection manager object."""

  def __init__(self,  config, options, request, debug=False):
    """Returns a MongoDB database connection."""
    self.debug = debug
    import pymongo
    self.options = options.get(self.Name(), {})
    try:
      self.connection = pymongo.connection.Connection(
         host=self.options.get('host', 'localhost'),
         port=self.options.get('port', 27017))
      if 'database' in self.options:
        self.connection = self.connection[self.options['database']]
    except Exception as e:
      raise ConnectionError('Connection to "%s" of type "%s" resulted in: %r' % (self.Name(), type(self), e))

  def Disconnect(self):
    """Closes the Mongo connection."""
    if self.debug:
      print('%s closed connection to: %r' % (self.Name(), self.options.get('database', 'Unspecified')))
    self.connection.close()
    del(self.connection)


class SqlAlchemy(Connector):
  """Adds MysqlAlchemy connection to ConnectionManager."""

  def __init__(self,  config, options, request, debug=False):
    """Returns a Mysql database connection wrapped in a SQLAlchemy session."""
    from sqlalchemy.orm import sessionmaker
    self.debug = debug
    self.options = {'host': 'localhost',
                   'user': None,
                   'password': None,
                   'database': ''}
    try:
      self.options = options[self.Name()]
    except KeyError:
      pass
    Session = sessionmaker()
    Session.configure(bind=self.engine, expire_on_commit=False)
    try:
      self.connection = Session()
    except Exception as e:
      raise ConnectionError('Connection to "%s" of type "%s" resulted in: %r' % (self.Name(), type(self), e))

  def engine(self):
    from sqlalchemy import create_engine
    return create_engine('mysql://{username}:{password}@{host}/{database}'.format(
      username=self.options.get('user'),
      password=self.options.get('password'),
      host=self.options.get('host', 'localhost'),
      database=self.options.get('database')),
      pool_size=5,
      max_overflow=0,
      encoding=self.options.get('charset', 'utf8'),)


class Sqlite(Connector):
  """Adds SQLite support to connection manager object."""

  def __init__(self,  config, options, request, debug=False):
    """Returns a SQLite database connection.
    The name of the class is used as the local filename.
    """
    from .libs.sqltalk import sqlite
    self.debug = debug
    self.options = options[self.Name()]
    try:
      self.connection = sqlite.Connect(self.options.get('database'))
    except Exception as e:
      raise ConnectionError('Connection to "%s" of type "%s" resulted in: %r' % (self.Name(), type(self), e))

  def Rollback(self):
    """Rolls back any uncommited transactions."""
    return self.connection.rollback()

  def Disconnect(self):
    """Closes the SQLite connection."""
    if self.debug:
      print('%s closed connection to: %r' % (self.Name(), self.options.get('database')))
    self.connection.close()
    del(self.connection)
