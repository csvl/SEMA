import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
__author__ = 'mike'

import volatility.utils as utils

class Bytes(bytes):
    """String class to allow us to encode binary data"""
    def __new__(cls, data):
        if data == None:
            return str.__new__(cls, "-")
        return str.__new__(cls, data.encode("hex"))

class Address(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""
    def __new__(cls, number):
        return int.__new__(cls, number)


class Address64(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return int.__new__(cls, number)


class Hex(long):
    """Integer class to allow renderers to differentiate between addresses and numbers"""

    def __new__(cls, number):
        return int.__new__(cls, number)


class Renderer(object):
    def render(self, outfd, grid):
        """Renders the content, ideally to outfd, but this is not strictly necessary"""
