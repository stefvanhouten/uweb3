#!/usr/bin/python
"""Test suite for the database abstraction module (model)."""

# Too many public methods
# pylint: disable=R0904

# Standard modules
import unittest

# Custom modules
# import newweb
# Importing newWeb makes the SQLTalk library available as a side-effect
import uweb3
from uweb3.ext_lib.underdark.libs.sqltalk import mysql
# Unittest target
from uweb3 import alchemy_model as model
import pymysql
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData
from sqlalchemy.ext.declarative import declarative_base
from contextlib import contextmanager
from pymysql.err import InternalError

# ##############################################################################
# Record classes for testing
#
Base = declarative_base()

class BasicTestRecord(uweb3.alchemy_model.Record, Base):
  """Test record for offline tests."""
  __tablename__ = 'basicTestRecord'
  ID = Column(Integer, primary_key=True)
  name = Column(String(32), nullable=False)
  x = Column(String(32))


class Author(uweb3.alchemy_model.Record, Base):
  __tablename__ = 'author'
  ID = Column(Integer, primary_key=True)
  name = Column(String(32), nullable=False)
  
  
class Book(uweb3.alchemy_model.Record, Base):
  """Book class for testing purposes."""
  __tablename__ = 'book'
  ID = Column(Integer, primary_key=True)
  author = Column(Integer, nullable=False)
  title = Column(String(32), nullable=False)
  
  
class BaseRecordTests(unittest.TestCase):
  """Offline tests of methods and behavior of the BaseRecord class."""
  def setUp(self):
    """Sets up the tests for the offline Record test."""
    self.record_class = BasicTestRecord

  def testTableName(self):
    """[BaseRecord] TableName returns the expected value and obeys _TABLE"""
    self.assertEqual(self.record_class.TableName(), 'basicTestRecord')

  def testPrimaryKey(self):
    """[BaseRecord] Primary key value on `key` property, default field 'ID'"""
    record = self.record_class(None, {'ID': 12, 'name': 'J.R.R. Tolkien'})
    self.assertEqual(record.key, 12)

  def testEquality(self):
    """[BaseRecord] Records of the same content are equal to eachother"""
    record_one = self.record_class(None, {'ID': 2, 'name': 'Rowling'})
    record_two = self.record_class(None, {'ID': 2, 'name': 'Rowling'})
    record_three = self.record_class(None, {'ID': 3, 'name': 'Rowling'})
    record_four = self.record_class(None, {'ID': 2, 'name': 'Rowling', 'x': 2})
    self.assertFalse(record_one is record_two)
    self.assertEqual(record_one, record_two)
    self.assertNotEqual(record_one, record_three)
    self.assertNotEqual(record_one, record_four)

class RecordTests(unittest.TestCase):
  """Online tests of methods and behavior of the Record class."""
  def setUp(self):
    """Sets up the tests for the Record class."""
    self.meta = MetaData()
    author = Table(
      'author', self.meta,
      Column('ID', Integer, primary_key=True),
      Column('name', String(32), nullable=False),
    )
    book = Table(
      'book', self.meta, 
      Column('ID', Integer,primary_key=True),
      Column('author', Integer, nullable=False),
      Column('title', String(32), nullable=False)
    )
    self.engine = DatabaseConnection()
    self.session = Create_session(self.engine)
    self.meta.create_all(self.engine)

  def tearDown(self):
    """Destroy tables after testing."""
    for tbl in reversed(self.meta.sorted_tables):
      tbl.drop(self.engine)

  def testLoadPrimary(self):
    """[Record] Records can be loaded by primary key using FromPrimary()"""
    inserted = Author.Create(self.session, {'name': 'A. Chrstie'})
    author = Author.FromPrimary(self.session, inserted.key)
    self.assertEqual(type(author), Author)
    self.assertEqual(len(author), 2)
    self.assertEqual(author.key, author.ID)
    self.assertEqual(author.name, 'A. Chrstie')
    
  def testCreateRecord(self):
    """Database records can be created using Create()"""
    new_author = Author.Create(self.session, {'name': 'W. Shakespeare'})
    author = Author.FromPrimary(self.session, new_author.key)
    self.assertEqual(author._record['name'], 'W. Shakespeare')
    self.assertEqual(author.name, 'W. Shakespeare')

  def testCreateRecordWithBadField(self):
      """Database record creation fails if there are unknown fields present"""
      self.assertRaises(AttributeError, Author.Create, self.session,
                        {'name': 'L. Tolstoy', 'email': 'leo@tolstoy.ru'})
      
  def testUpdateRecord(self):
    """The record can be given new values and these are properly stored"""
    author = Author.Create(self.session, {'name': 'B. King'})
    author.name = 'S. King'
    author.Save()
    same_author = Author.FromPrimary(self.session, author.key)
    self.assertEqual(author.name, 'S. King')
    self.assertEqual(author, same_author)
    
  def testUpdatingDeletedRecord(self):
    """Should raise an error because the record no longer exists"""
    author = Author.Create(self.session, {'name': 'B. King'})
    Author.DeletePrimary(self.session, author.ID)
    author.name = 'S. King'
    self.assertRaises(model.NotExistError, author.Save)
    
  def testUpdatePrimaryKey(self):
    """Saving with an updated primary key properly saved the record"""
    author = Author.Create(self.session, {'name': 'C. Dickens'})
    self.assertEqual(author.key, 1)
    author.ID = 101
    author.Save()
    self.assertRaises(model.NotExistError, Author.FromPrimary,
                      self.session, 1)
    same_author = Author.FromPrimary(self.session, 101)
    self.assertEqual(same_author, author)
    
  def testLoadRelated(self):
    """Fieldnames that match tablenames trigger automatic loading"""
    Author.Create(self.session, {'name': 'D. Koontz'})
    book = Book(self.session, {'author': 1})
    # self.assertEqual(type(book['author']), Author)
    # self.assertEqual(book['author']['name'], 'D. Koontz')
    # self.assertEqual(book['author'].key, 1)
      


def DatabaseConnection():
  """Returns an SQLTalk database connection to 'newweb_model_test'."""
  return create_engine('mysql://{user}:{passwd}@{host}/{db}'.format(
    host='localhost',
    user='stef',
    passwd='24192419',
    db='uweb_test'
  ))
  
def Create_session(engine):
  from sqlalchemy.orm import sessionmaker
  Session = sessionmaker(autocommit=False)
  Session.configure(bind=engine)
  return Session

if __name__ == '__main__':
  unittest.main(testRunner=unittest.TextTestRunner(verbosity=2))
