from .base import *
from .util import get_palette
class ColorDepthClusterer(Clusterer):

    def __init__(self, palette='grays'):
        super(ColorDepthClusterer, self).__init__()
        if isinstance(palette, list):
            self.palette = palette
        else:
            self.palette = get_palette(palette)

    def cluster(self, graph):
        for c in graph.get_clusters():
            self.color_clusters(graph, c)
            
    def color_clusters(self, graph, c, level=0):
        c.style = "filled";
        c.fillcolor = self.palette[level % len(self.palette)];
        for cc in graph.get_clusters(c):
            self.color_clusters(graph, cc, level=level+1)
