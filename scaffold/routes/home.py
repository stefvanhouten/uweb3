#!/usr/bin/python3
"""Request handlers for the uWeb3 project scaffold"""

import uweb3
import json
from uweb3 import PageMaker
from uweb3.pagemaker.new_decorators import loggedin
from uweb3.pagemaker.new_login import UserCookie
from uweb3.pagemaker.new_decorators import checkxsrf


class Test(PageMaker):
  """Holds all the request handlers for the application"""
  @loggedin
  @checkxsrf
  def Home(self):
    """Returns the index template"""
    return self.parser.Parse('home.html', xsrf=self.xsrf, variable='test')

  @loggedin
  @checkxsrf
  def Create(self):
    if self.req.method == "POST":
      scookie = UserCookie(self.secure_cookie_connection)    
      scookie.Create("test", {"data": "somedata", "nested dict": {"data": "value"}})
    return self.req.Redirect('/home')

  @loggedin
  @checkxsrf
  def Update(self):
    if self.req.method == "POST":
      scookie = UserCookie(self.secure_cookie_connection)
      scookie.Update("test", "replaced all data in the test cookie")
    return self.req.Redirect('/home')

  @loggedin
  @checkxsrf
  def Delete(self):
    if self.req.method == "POST":
      scookie = UserCookie(self.secure_cookie_connection)
      scookie.Delete("test")
    return self.req.Redirect('/home')

  @loggedin
  def Logout(self):
    self.req.DeleteCookie('xsrf')
    scookie = UserCookie(self.secure_cookie_connection)
    scookie.Delete('login')
    return self.req.Redirect('/login')