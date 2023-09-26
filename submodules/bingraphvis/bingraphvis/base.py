

from collections import OrderedDict
import itertools

class VisError(Exception):
    pass


class Node(object):
    def __init__(self, seq, obj, cluster=None):
        self.obj = obj
        self.seq = seq
        self.cluster = cluster
        self.content = OrderedDict()
        self.style = None
        self.fillcolor = None
        self.color = None
        self.width = None
        self.url = None
        self.tooltip = None

    def set_cluster(cluster):
        if self.cluster != None:
            self.cluster.remove_node(self)
        cluster.add_node(self)
        node.cluster = cluster
        
    def __eq__(self, other):
        return self.obj.__eq__(other.obj) and self.seq == other.seq

    def __hash__(self):
        return self.obj.__hash__()
    
class Edge(object):
    def __init__(self, src, dst, meta = {}, color=None, label=None, style=None, width=None, weight=None):
        self.src = src
        self.dst = dst
        self.meta = meta
        
        self.color = color
        self.label = label
        self.style = style
        self.width = width
        self.weight = weight
        
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __hash__(self):
        return hash(self.src, self.dst)

class Source(object):
    def __init__(self):
        pass
        
    def set_vis(self, vis):
        self.vis = vis

    def parse(self, obj):
        raise NotImplementedError('parse() is not implemented.')


class NodeAnnotator(object):
    def __init__(self):
        self.graph = None
        
    def set_graph(self, graph):
        self.graph = graph
        
    def annotate_node(self, node):
        raise NotImplementedError('annotate_node() is not implemented.')

                
class EdgeAnnotator(object):
    def __init__(self):
        self.graph = None
        
    def set_graph(self, graph):
        self.graph = graph
    
    def annotate_edge(self, edge):
        raise NotImplementedError('annotate_edge() is not implemented.')

class Transformer(object):
    def __init__(self):
        pass
        
    def transform(self, graph):
        raise NotImplementedError('transform() is not implemented.')


class Clusterer(object):
    def __init__(self):
        pass
        
    def cluster(self, graph):
        raise NotImplementedError('cluster() is not implemented.')


class Content(object):
    def __init__(self, name, columns):
        self.name = name
        self.columns = columns
        self.annotators = []
        
    def get_columns(self):
        return self.columns

    def add_column_after(self, column):
        if column not in self.columns:
            self.columns.append(column)

    def add_column_before(self, column):
        if column not in self.columns:
            self.columns.insert(0, column)
        
    def add_annotator(self, obj):
        obj.register(self)
        self.annotators.append(obj)
    
    def render(self, n):
        self.gen_render(n)
        for an in self.annotators:
            if self.name in n.content:
                an.annotate_content(n, n.content[self.name])


class ContentAnnotator(object):
    def __init__(self, cname):
        self.cname = cname

    def get_cname(self):
        return self.cname

    def annotate_content(self, content):
        raise NotImplementedError('annotate_content() is not implemented.')


class Cluster(object):
    def __init__(self, key, parent=None, nodes=None, label=None, visible=True):
        self.key = key
        self.parent = parent
        self.nodes = nodes if nodes else set()
        self.visible = visible
        self.label = label
        self.style = None;
        self.fillcolor = None;
        
    def add_node(self, node):
        self.nodes.add(node)
        node.cluster = self

    def remove_node(self, node):
        self.nodes.remove(node)
        node.cluster = None


class Graph(object):
    def __init__(self, nodes=None, edges=None):
        self.nodes = nodes if nodes else set()
        self.edges = edges if edges else []
        self.seqctr = itertools.count()
        self.seqmap = {}
        self.clusters = {}

    def create_cluster(self, key, parent=None, nodes=None, label=None, visible=True):
        cluster = Cluster(key, parent, nodes, label, visible)
        self.clusters[key] = cluster
        self.seqmap[key] = next(self.seqctr)
        return cluster

    def get_cluster(self, key):
        if key in self.clusters:
            return self.clusters[key]
        else:
            return None
    
    def get_clusters(self, parent=None):
        return list(filter(lambda c:c.parent==parent, self.clusters.values()))
        
    def add_node(self, node):
        self.nodes.add(node)
        if node.cluster:
            node.cluster.add_node(node)
        
    def add_edge(self, edge):
        self.edges.append(edge)
        
    def remove_node(self, node):
        self.nodes.remove(node)
        self.edges = list(filter(lambda edge: edge.src != node and edge.dst != node, self.edges))
        
    def remove_edge(self, edge):
        self.edges.remove(edge)

    #TODO FIXME thats bad
    def filter_nodes(self, node_filter):
        new_graph = self.filtered_view(node_filter)
        self.nodes = new_graph.nodes
        self.edges = new_graph.edges

    def filtered_view(self, node_filter):
        nodes = list(filter(lambda _: node_filter(_), self.nodes))
        edges = list(filter(lambda edge: node_filter(edge.src) and node_filter(edge.dst), self.edges))
        return Graph(nodes, edges)
    

class VisPipeLine(object):
        
    def __init__(self):
        self.content = OrderedDict()
        self.node_annotators = []
        self.edge_annotators = []
        self.transformers = []
        self.clusterers = []
        self.graph = Graph()
        
    def set_source(self, source):
        if not isinstance(source, Source):
            raise VisError("Incompatible source type '%s'" % type(obj))
        self.source = source
        
    def add_content(self, obj):
        if not isinstance(obj, Content):
            raise VisError("Incompatible content type '%s'" % type(obj))
        self.content[obj.name] = obj
    
    def add_node_annotator(self, obj):
        if not isinstance(obj, NodeAnnotator):
            raise VisError("Incompatible node annotator type '%s'" % type(obj))
        self.node_annotators.append(obj)
        return self

    def add_edge_annotator(self, obj):
        if not isinstance(obj, EdgeAnnotator):
            raise VisError("Incompatible edge annotator type '%s'" % type(obj))
        self.edge_annotators.append(obj)
        return self

    def add_clusterer(self, obj):
        if not isinstance(obj, Clusterer):
            raise VisError("Incompatible clusterer type '%s'" % type(obj))
        self.clusterers.append(obj)
        return self

    
    def add_content_annotator(self, obj):
        if not isinstance(obj, ContentAnnotator):
            raise VisError("Incompatible content annotator type '%s'" % type(obj))
        cname = obj.get_cname()
        if cname not in self.content:
            raise VisError("Content '%s' not found, required by annotator '%s'" % (cname, type(obj)))
        self.content[cname].add_annotator(obj)
        return self

        
    def add_transformer(self, obj):
        if not isinstance(obj, Transformer):
            raise VisError("Incompatible transformer type '%s'" % type(obj))
        self.transformers.append(obj)
        return self

    def set_input(self, obj):
        self.source.parse(obj, self.graph)

    def preprocess(self, obj, filter=None):
        self.set_input(obj)
        for t in self.transformers:
            t.transform(self.graph)

    def process(self, filter=None):
        if filter is None:
            graph = self.graph
        else:
            graph = self.graph.filtered_view(filter)

        for ea in self.edge_annotators:
            ea.set_graph(graph)
            
        for na in self.node_annotators:
            na.set_graph(graph)
            
        for n in graph.nodes:
            for c in self.content.values():
                c.render(n)
            for na in self.node_annotators:
                na.annotate_node(n)

        for e in graph.edges:
            for ea in self.edge_annotators:
                ea.annotate_edge(e)
        for c in self.clusterers:
            c.cluster(graph)
        
        return graph
        
        
class Vis(object):
    def __init__(self):
        self.pipeline = VisPipeLine()
    
    def preprocess(self, obj):
        self.pipeline.preprocess(obj)
        
    def process(self, obj=None, filter=None):
        if obj:
            self.preprocess(obj)
        graph = self.pipeline.process(filter=filter)        
        return self.output.generate(graph)

    def set_source(self, source):
        self.pipeline.set_source(source)
        return self
        
    def add_content(self, obj):
        self.pipeline.add_content(obj)
        return self

    def add_node_annotator(self, obj):
        self.pipeline.add_node_annotator(obj)
        return self

    def add_edge_annotator(self, obj):
        self.pipeline.add_edge_annotator(obj)
        return self

    def add_content_annotator(self, obj):
        self.pipeline.add_content_annotator(obj)
        return self

    def add_clusterer(self, obj):
        self.pipeline.add_clusterer(obj)
        return self
        
    def add_transformer(self, obj):
        self.pipeline.add_transformer(obj)
        return self

    def set_output(self, output):
        if not isinstance(output, Output):
            raise VisError("Incompatible output type '%s'" % type(obj))
        self.output = output

class Output(object):
    def __init__(self):
        pass

    def set_vis(self, vis):
        self.vis = vis

    def generate():
        raise NotImplementedError('parse() is not implemented.')
