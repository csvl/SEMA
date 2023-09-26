
from ..base import Source, VisError, Node, Edge
from .clusterer import AngrStructuredClusterer
import angr
import networkx
import itertools

class AngrCFGSource(Source):
    def __init__(self):
        super(AngrCFGSource, self).__init__()
        self.lookup = {}
        self.seq = 0

    def parse(self, obj, graph):
        if not isinstance(obj, networkx.classes.digraph.DiGraph):
            raise VisError("Unknown input type '%s'" % type(obj))

        for n in obj.nodes():
            if n not in self.lookup:
                wn = Node(self.seq, n)
                self.seq += 1
                self.lookup[n] = wn
                graph.add_node(wn)
            else:
                raise VisError("Duplicate node %s" % str(n))

        for src, dst, data in obj.edges(data=True):
            if not src in self.lookup or not dst in self.lookup:
                raise VisError("Missing nodes %s %s" % str(src), str(dst))
            wsrc = self.lookup[src]
            wdst = self.lookup[dst]
            graph.add_edge(Edge(wsrc, wdst, data))

class AngrKbCGSource(Source):
    def __init__(self):
        super(AngrKbCGSource, self).__init__()
        self.lookup = {}
        self.seq = 0

    def parse(self, obj, graph):
        if not isinstance(obj, angr.knowledge_base.KnowledgeBase):
            raise VisError("Unknown input type '%s'" % type(obj))

        for n in obj.callgraph.nodes():
            if n not in self.lookup:
                if n in obj.functions:
                    nn = obj.functions[n]
                else:
                    #add warning
                    continue
                wn = Node(self.seq, nn)
                self.seq += 1
                self.lookup[n] = wn
                graph.add_node(wn)
            else:
                raise VisError("Duplicate node %s" % str(n))

        for src, dst, data in obj.callgraph.edges(data=True):
            if not src in self.lookup or not dst in self.lookup:
                #raise VisError("Missing nodes %s %s" % str(src), str(dst))
                continue
            wsrc = self.lookup[src]
            wdst = self.lookup[dst]
            graph.add_edge(Edge(wsrc, wdst, data))

#Same as above, merge them in refact -> DiGraphSource
class AngrCommonSource(Source):
    def __init__(self):
        super(AngrCommonSource, self).__init__()
        self.lookup = {}
        self.seq = 0

    def parse(self, obj, graph):
        if not isinstance(obj, networkx.classes.digraph.DiGraph):
            raise VisError("Unknown input type '%s'" % type(obj))

        for n in obj.nodes():
            if n not in self.lookup:
                wn = Node(self.seq, n)
                self.seq += 1
                self.lookup[n] = wn
                graph.add_node(wn)
            else:
                raise VisError("Duplicate node %s" % str(n))

        for src, dst, data in obj.edges(data=True):
            if not src in self.lookup or not dst in self.lookup:
                raise VisError("Missing nodes %s %s" % str(src), str(dst))
            wsrc = self.lookup[src]
            wdst = self.lookup[dst]
            graph.add_edge(Edge(wsrc, wdst, data))

class AngrStructuredSource(Source):
    def __init__(self):
        super(AngrStructuredSource, self).__init__()
        self.lookup = {}
        self.seq = itertools.count()
        self.nwo = None

    def parse(self, obj, graph):

        self.build(obj, graph, None)

    def node(self, n, graph):
        if n not in self.lookup:
             wn = Node(next(self.seq), n)
             self.lookup[n] = wn
             graph.add_node(wn)
        return wn
    
    def build(self, obj, graph, parent_cluster):
        if type(obj).__name__ == 'SequenceNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=repr(obj))    
            for n in obj.nodes:
                self.build(n, graph, cluster)
        elif type(obj).__name__ == 'CodeNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=["CODE NODE 0x%x" % obj.addr] + AngrStructuredClusterer._render_condition("Reaching Condition",obj.reaching_condition))
            self.build(obj.node, graph, cluster)
        elif type(obj).__name__ == 'LoopNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=["LOOP NODE 0x%x" % obj.addr] + AngrStructuredClusterer._render_condition("Condition",obj.condition))
            self.build(obj.sequence_node, graph, cluster)
        elif type(obj).__name__ == 'ConditionNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=["CONDITION NODE 0x%x" % obj.addr] + AngrStructuredClusterer._render_condition("Condition",obj.condition) + AngrStructuredClusterer._render_condition("Reaching Condition", obj.reaching_condition))
            if obj.true_node:
                self.build(obj.true_node, graph, cluster)
            if obj.false_node:
                self.build(obj.false_node, graph, cluster)
        elif type(obj).__name__ == 'BreakNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=["BREAK NODE"])
            self.build(obj.target, graph, cluster)
        elif type(obj).__name__ == 'ConditionalBreakNode':
            cluster = graph.create_cluster(str(next(self.seq)), parent=parent_cluster, label=["CONDITIONAL BREAK NODE"] + AngrStructuredClusterer._render_condition("Condition",obj.condition))
            self.build(obj.target, graph, cluster)
        elif type(obj).__name__ == 'MultiNode':
            for n in obj.nodes:
                nw = self.node(n, graph)
                parent_cluster.add_node(nw)
                if not self.nwo is None:
                    graph.add_edge(Edge(self.nwo, nw, style="invis"))
                self.nwo = nw
        elif type(obj).__name__ == 'Block':
            nw = self.node(obj, graph)
            parent_cluster.add_node(nw)
            if not self.nwo is None:
                graph.add_edge(Edge(self.nwo, nw, style="invis"))
            self.nwo = nw
        else:
            import ipdb; ipdb.set_trace()
