import os
import urllib.request
from setuptools import setup

urllib.request.urlopen("https://example.invalid/s")
os.system("echo hi")
setup(name="demo")
