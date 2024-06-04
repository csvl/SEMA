import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from .base import *

class ColorNodes(NodeAnnotator):
    def __init__(self, nodes=None, fillcolor=None, color=None, filter=None):
        super(ColorNodes, self).__init__()
        self.nodes = nodes
        self.fillcolor = fillcolor
        self.color = color
        self.filter = filter


    def annotate_node(self, node):
        if (self.nodes and node.obj in self.nodes) or (self.filter and self.filter(node)):
            node.style = 'filled'
            if self.fillcolor:
                node.fillcolor = self.fillcolor
            if self.color:
                node.color = self.color
