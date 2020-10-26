"""uWeb3 installer."""

import os
import re
from setuptools import setup, find_packages

REQUIREMENTS = [
  'decorator',
  'PyMySQL',
  'python-magic',
  'pytz',
  'simplejson',
  'bcrypt'
]

#  'sqlalchemy',
#  'werkzeug',

def description():
  with open(os.path.join(os.path.dirname(__file__), 'README.md')) as r_file:
    return r_file.read()


def version():
  main_lib = os.path.join(os.path.dirname(__file__), 'uweb3', '__init__.py')
  with open(main_lib) as v_file:
    return re.match(".*__version__ = '(.*?)'", v_file.read(), re.S).group(1)


setup(
    name='uWeb3 test',
    version=version(),
    description='uWeb, python3, uswgi compatible micro web platform',
    long_description_file = 'README.md',
    long_description_content_type = 'text/markdown',
    license='ISC',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Operating System :: POSIX :: Linux',
    ],
    author='Jan Klopper',
    author_email='jan@underdark.nl',
    url='https://github.com/underdark.nl/uWeb3',
    keywords='minimal web framework',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=REQUIREMENTS)
