
from ..base import *
import pyopenreil

class OpenreilCFGSource(Source):
    def __init__(self):
        super(OpenreilCFGSource, self).__init__()
        self.lookup = {}
        self.seq = 0

    def parse(self, obj, graph):
        if not isinstance(obj, pyopenreil.REIL.CFGraph):
            raise VisError("Unknown input type '%s'" % type(obj))

        for k,n in obj.nodes.items():
            if n not in self.lookup:
                wn = Node(self.seq, n)
                self.seq += 1
                self.lookup[n] = wn
                graph.add_node(wn)
            else:
                raise VisError("Duplicate node %s" % str(n))

        for e in obj.edges:
            if not e.node_from in self.lookup or not e.node_to in self.lookup:
                raise VisError("Missing nodes %s %s" % str(src), str(dst))
            wsrc = self.lookup[e.node_from]
            wdst = self.lookup[e.node_to]
            graph.add_edge(Edge(wsrc, wdst, {'name': e.name}))
