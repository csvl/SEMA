import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import angr


class PluginEvasion(angr.SimStatePlugin):
    def __init__(self):
        super(PluginEvasion, self).__init__()
        self.libraries = []
        self.syscalls = []
        self.decoded = []
        self.compare = []

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginEvasion()
        p.libraries = self.libraries
        p.syscalls = self.syscalls
        p.decoded = self.decoded
        p.compare = self.compare
        return p
