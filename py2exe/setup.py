#
# usage: > python setup.py py2exe
#

from distutils.core import setup
import py2exe

setup(	console = ['w4c.py'], 
	options = {'py2exe': {'bundle_files': 1, 'compressed': True}}, 
	zipfile = None)
