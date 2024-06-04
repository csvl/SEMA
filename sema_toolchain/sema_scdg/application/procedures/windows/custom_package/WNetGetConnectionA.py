import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .WNetGetConnectionW import WNetGetConnectionW


class WNetGetConnectionA(WNetGetConnectionW):
    def get_netRessource(self, size, buf_src):
        localName = self.state.mem[buf_src].string.concrete
        return (("net_" + localName.decode("utf-8"))[: size - 1] + "\0").encode("utf-8")
