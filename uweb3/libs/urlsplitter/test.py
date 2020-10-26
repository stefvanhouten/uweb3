import unittest
from __init__ import split_url

class testUrlSplitter(unittest.TestCase):
  
  def testValidUrl(self):
    """See if we correctly clean up header injection attemps"""
    self.assertEqual(split_url('https://test.test.com'), {
                                                         'type': 'https://', 
                                                         'domain': 'test.test', 
                                                         'suffix': 'com', 
                                                         'target': ''
                                                          })
    
    self.assertEqual(split_url('https://test.test.com/someurl'), {
                                                                 'type': 'https://', 
                                                                 'domain': 'test.test', 
                                                                 'suffix': 'com', 
                                                                 'target': '/someurl'
                                                                  })
    
    self.assertEqual(split_url('https://www.google.co.uk'), {
                                                            'type': 'https://www', 
                                                            'domain': 'google', 
                                                            'suffix': 'co.uk', 
                                                            'target': ''
                                                            })
    
    self.assertEqual( split_url('https://www.test.com.nl.de'), {
                                                               'type': 'https://www', 
                                                               'domain': 'test.com.nl', 
                                                               'suffix': 'de', 
                                                               'target': ''
                                                               })

    
  def testInvalidUrl(self):
    message = 'Url not valid'
    with self.assertRaises(Exception) as context:
      split_url('www.google.com')
    self.assertTrue(message in str(context.exception))
    
    with self.assertRaises(Exception) as context:
      split_url(' ')
    self.assertTrue(message in str(context.exception))
    

if __name__ == '__main__':
    unittest.main()