#!/usr/bin/python3
"""This module is used to split an url into a dict and simultaneously validates
if the url is valid or not.

Every url provided should start with http:// or https:// otherwise it is seen as invalid.
"""

__author__ = 'Stef van Houten (stefvanhouten@gmail.com)'
__version__ = 0.1

import re

from tld import get_tld

def split_url(url):
  # If fail_silently is True return None if url suffix is invalid
  if not isinstance(url, str):
    raise Exception("Url should be a string")
  
  suffix = get_tld(url, fail_silently=True)
  
  if not suffix:
    # TODO: What should the function return on a invalid url suffix?
    raise Exception("Url not valid")

  # Get the leftovers after the suffix
  route = url[url.find(suffix) + len(suffix):]
  
  # Use regex to filter out the https:// or www. 
  regex = re.compile(r"https?://(www\.)?")
  domain = regex.sub('', url).strip().strip('/')[:-(len(route) + len(suffix))]
     
  url_type = url[:url.find(domain)]
  
  # Remove trailing dot if there is any
  if domain[-1] == ".":
    domain = domain[:-1]
    
  if url_type[-1] == ".":
    url_type = url_type[:-1]
    
  return { 
         'type': url_type, 
         'domain': domain,
         'suffix': suffix, 
         'route': target,
         }
