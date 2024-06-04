import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from distutils.core import setup

setup(
    name='angr-utils',
    version='0.5.0',
    author='Attila Axt',
    author_email='axt@load.hu',
    license='BSD',
    platforms=['Linux'],
    packages=['angrutils'],
    install_requires=[
        'pydot',
        'networkx',
        'angr',
        'claripy',
        'bingraphvis >= 0.2.0'
    ],
    description='Various utilities for angr binary analysis framework',
    long_description='Various utilities for angr binary analysis framework',
    url='https://github.com/axt/angr-utils',
)
