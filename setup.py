import sys

from setuptools import setup

# Require users to uninstall versions that used the appscale namespace.
try:
  import appscale.appscale_tools
  print('Please run "pip uninstall appscale-tools" first.\n'
        "Your installed version conflicts with this version's namespace.")
  sys.exit()
except ImportError:
  pass


long_description = """AppScale Agents 
---------------

A set of agents for interacting with various clouds 

What is AppScale?
-----------------

AppScale is an open-source cloud computing platform that automatically deploys
and scales unmodified Google App Engine applications over public and private
cloud systems and on-premise clusters. AppScale is modeled on the App Engine
APIs and has support for Python, Go, PHP and Java applications.

AppScale is developed and maintained by AppScale Systems, Inc., based in
Santa Barbara, California, and Google.

http://www.appscale.com
"""

setup(
  name='appscale-agents',
  version='3.8.1',
  description='A set of agents for interacting with various clouds',
  long_description=long_description,
  author='AppScale Systems, Inc.',
  url='https://github.com/appscale/appscale-agents',
  license='Apache License 2.0',
  keywords='appscale google-app-engine python java go php',
  platforms='Posix; MacOS X',
  install_requires=[
    'adal>=0.4.7',
    'azure==2.0.0',
    'azure-mgmt-marketplaceordering',
    'cryptography',
    'argparse',
    'boto',
    'google-api-python-client==1.5.4',
    'httplib2',
    'keyring>=12.0.2,<19.0.0',
    'keyrings.alt>=3.1,<3.2',
    'msrestazure==0.4.34',
    'oauth2client==4.0.0',
    'PyYAML',
    'requests[security]>=2.20.0',
    'retrying==1.3.3',
    'setuptools>=11.3,<34',
    'SOAPpy',
    'tabulate==0.7.7',
    'termcolor',
    'wstools==0.4.3'
  ],
  extras_require={'testing': ['mock']},
  classifiers=[
    'Development Status :: 5 - Production/Stable',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Topic :: Utilities'
  ],
  namespace_packages=['appscale'],
  packages=['appscale.agents'],
  entry_points={
    'console_scripts': [
    ]
  },
  package_data={}
)
