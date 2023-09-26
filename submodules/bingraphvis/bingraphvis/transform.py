from .base import *

#TODO
# refactor sources: handle lookup, type-specific properties 
# change AngrXXX transformers to generic ones

class AddTransitionEdges(Transformer):
    def __init__(self, transitions):
        self.transitions = transitions
        self.seq = 0

    def transform(self, graph):
        lookup = {}
        for n in graph.nodes:
            lookup[n.obj] = n
        
        
        for c, d in enumerate(self.transitions):
            s = d[0]
            d = d[1]
            ss = None
            dd = None
            if s in lookup:
                ss = lookup[s]

            if not d in lookup:
                #TODO move to source, also move lookup to source
                dd = Node("tr_" + str(self.seq), d)
                self.seq += 1
                lookup[d] = dd
                graph.add_node(dd)
            else:
                dd = lookup[d]
    
            graph.add_edge(Edge(ss, dd, color="purple", label=str(c)))

class AngrAddEdges(Transformer):
    def __init__(self, graph, reverse=False, color=None, label=None, style=None, width=None, weight=None):
        self.graph = graph
        self.reverse = reverse
        self.color = color
        self.label = label
        self.style = style
        self.width = width
        self.weight = weight

    def transform(self, graph):
        lookup = {}
        for n in graph.nodes:
            lookup[n.obj] = n
        
        for s,t in self.graph.edges():
            #TODO option to add missing nodes (?)
            try: 
                if self.reverse:
                    ss,tt = lookup[t],lookup[s]
                else:
                    ss,tt = lookup[s],lookup[t]
                
                graph.add_edge(Edge(ss, tt, color=self.color, label=self.label, style=self.style, width=self.width, weight=self.weight))
            except:
                #FIXME WARN
                pass

class AngrFilterNodes(Transformer):
    def __init__(self, node_filter):
        self.node_filter = node_filter
        pass
        
    def transform(self, graph):
        graph.filter_nodes(self.node_filter)
