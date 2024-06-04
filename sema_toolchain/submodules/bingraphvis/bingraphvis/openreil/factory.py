import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from ..base import *
from . import *

class OpenreilVisFactory(object):
    def __init__(self):
        pass

    def default_cfg_pipeline(self, asminst=False, reilinst=False):
        vis = Vis()
        vis.set_source(OpenreilCFGSource())
        vis.add_content(OpenreilCFGHead())
        if asminst:
            vis.add_content(OpenreilAsm())
        if reilinst:
            vis.add_content(OpenreilREIL())

        vis.add_edge_annotator(OpenreilColorEdgesAsm())

        return vis
