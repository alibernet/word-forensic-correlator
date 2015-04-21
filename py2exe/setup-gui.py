#
# usage: > python setup-gui.py py2exe
#
# see: http://sourceforge.net/p/py2exe/bugs/108/
#

from distutils.core import setup
import py2exe

setup(	windows = ['w4c-gui.py'],
	options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
	zipfile = None)
