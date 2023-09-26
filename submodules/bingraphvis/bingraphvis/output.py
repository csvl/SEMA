import pydot

from subprocess import Popen, PIPE, STDOUT

from .base import Output

escape_map = {
    "!" : "&#33;",
    "#" : "&#35;",
    ":" : "&#58;",
    "{" : "&#123;",
    "}" : "&#125;",
    "<" : "&#60;",
    ">" : "&#62;",
    "\t": "&nbsp;",
    "&" : "&amp;",
    "|" : "&#124;",
}

def escape(text):
    return "".join(escape_map.get(c,c) for c in text)

default_node_attributes = {
    'shape'    : 'Mrecord',
#    'shape': 'none',
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

default_edge_attributes = {
    'fontname' : 'monospace',
    'fontsize' : '8.0',
}

class XDot(pydot.Dot):
    def __init__(self, content):
        super(XDot, self).__init__()
        self.content = content
    def to_string(self):
        return self.content

class DotOutput(Output):

    def __init__(self, fname, format='png', show=False, pause=False):
        super(DotOutput, self).__init__()
        self.fname = fname
        self.format = format
        self.show = show
        self.pause = pause

    def render_attributes(self, default, attrs):
        a = {}
        a.update(default)
        a.update(attrs)
        r = []
        for k,v in a.items():
            r.append(k+"="+v)
        
        return "["+", ".join(r)+"]"
    
    def render_cell(self, key, data):
        if data != None and data['content'] != None and data['content'].strip() != '':
            ret = '<TD '+ ('bgcolor="'+data['bgcolor']+'" ' if 'bgcolor' in data else '') + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
            if 'color' in data:
                ret += '<FONT COLOR="'+data['color']+'">'
            if 'style' in data:
                ret += '<'+data['style']+'>'
            
            #'content': "<TABLE><TR><TD>" +  "</TD></TR><TR><TD>".join(self.cllog[key]) + "</TD></TR></TABLE>",
            if isinstance(data['content'], list):
                ret += '<TABLE BORDER="0">'
                for c in data['content']:
                    ret += '<TR><TD ' + ('ALIGN="'+data['align']+'"' if 'align' in data else '' )+'>'
                    ret += escape(c)
                    ret += '</TD></TR>'
                ret += '</TABLE>'
            else:
                ret += escape(data['content'])
            if 'style' in data:
                ret += '</'+data['style']+'>'
            if 'color' in data:
                ret += '</FONT>'
            ret += "</TD>"
            return ret
        else:
            return "<TD></TD>"
    
    def render_row(self, row, colmeta):
        ret = "<TR>"
        for k in colmeta:
            ret += self.render_cell(k, row[k] if k in row else None) 
        ret += "</TR>"
        return ret
    
    def render_content(self, c):
        ret = ''
        if len(c['data']) > 0:
            ret = '<TABLE BORDER="0" CELLPADDING="1" ALIGN="LEFT">'
            for r in c['data']:
                ret += self.render_row(r, c['columns'])
            ret += '</TABLE>'
        return ret
        
    def render_node(self, n):
        attrs = {}
        if n.style:
            attrs['style'] = n.style
        if n.fillcolor:
            attrs['fillcolor'] = '"'+n.fillcolor+'"'
        if n.color:
            attrs['color'] = n.color
        if n.width:
            attrs['penwidth'] = str(n.width)
        if n.url:
            attrs['URL'] = '"'+n.url+'"'
        if n.tooltip:
            attrs['tooltip'] = '"'+n.tooltip+'"'
            
            
        label = "|".join([self.render_content(c) for c in n.content.values()])
        if label:
            attrs['label'] = '<{ %s }>' % label
        
        #label = '<TABLE ROWS="*" BORDER="1" STYLE="ROUNDED" CELLSPACING="4" CELLPADDING="0" CELLBORDER="0"><TR><TD FIXEDSIZE="FALSE" ALIGN="LEFT">' + '</TD></TR><TR><TD FIXEDSIZE="FALSE"  ALIGN="LEFT">'.join([self.render_content(c) for c in n.content.values()]) + "</TD></TR></TABLE>"
        #if label:
        #    attrs['label'] = '<%s>' % label
        
        
        return "%s %s" % (str(n.seq), self.render_attributes(default_node_attributes, attrs))

    def render_edge(self, e):
        attrs = {}
        if e.color:
            attrs['color'] = e.color
        if e.label:
            attrs['label'] = '"'+e.label+'"'
        if e.style:
            attrs['style'] = e.style
        if e.width:
            attrs['penwidth'] = str(e.width)
        if e.weight:
            attrs['weight'] = str(e.weight)

        return "%s -> %s %s" % (str(e.src.seq), str(e.dst.seq), self.render_attributes(default_edge_attributes, attrs))
        
        
    def generate_cluster_label(self, label):
        rendered = ""
        
        if label is None:
            pass
        elif isinstance(label, list):
            rendered = ""
            rendered += "<BR ALIGN=\"left\"/>"
            for l in label:
                rendered += escape(l) 
                rendered += "<BR ALIGN=\"left\"/>"
        else:
            rendered += escape(label)
        
        return 'label=< %s >;' % rendered
        
    def generate_cluster(self, graph, cluster):
        ret = ""
        if cluster:
            ret += "subgraph " + ("cluster" if cluster.visible else "X") + "_" + str(graph.seqmap[cluster.key]) + "{\n"
            ret += self.generate_cluster_label(cluster.label)+"\n"
            if cluster.style:
                ret +='style="%s";\n' % cluster.style
            if cluster.fillcolor:
                ret +='color="%s";\n' % cluster.fillcolor
                
        nodes = list(filter(lambda n:n.cluster == cluster, graph.nodes))
        
        if len(nodes) > 0 and hasattr(nodes[0].obj, 'addr'):
            nodes = sorted(nodes, key=lambda n: n.obj.addr)
        
        for n in nodes:
            ret += self.render_node(n) + "\n"

        if cluster:
            for child_cluster in graph.get_clusters(cluster):
                ret += self.generate_cluster(graph, child_cluster)

        if cluster:
            ret += "}\n"
        return ret
        
    def generate(self, graph):
        ret  = "digraph \"\" {\n"
        ret += "rankdir=TB;\n"
        ret += "newrank=true;\n"
        # for some clusters graphviz ignores the alignment specified in BR
        # but does the alignment based on this value (possible graphviz bug)
        ret += "labeljust=l;\n"
        
        for cluster in graph.get_clusters():
            ret += self.generate_cluster(graph, cluster)
            
        ret += self.generate_cluster(graph, None)

        for e in graph.edges:
            ret += self.render_edge(e) + "\n"
            
        ret += "}\n"
                
        if self.show:
            p = Popen(['xdot', '-'], stdin=PIPE)
            p.stdin.write(ret)
            p.stdin.flush()
            p.stdin.close()
            if self.pause:
                p.wait()
        
        if self.fname:
            dotfile = XDot(ret)
            dotfile.write("{}.{}".format(self.fname, self.format), format=self.format)


class DumpOutput(Output):

    def __init__(self):
        super(DumpOutput, self).__init__()

    def generate(self, graph):
        ret = ""
        for e in graph.edges:
            ret += self.render_edge(e) + "\n"
        print(ret)

    def render_edge(self, e):
        return "%s %s %s" % (hex(e.src.obj.addr), hex(e.dst.obj.addr), e.meta['jumpkind'])
        
