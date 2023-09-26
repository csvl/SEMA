
from ..base import *
from ..style import get_style
import capstone
import pyvex

class AngrColorSimprocedures(NodeAnnotator):
    def __init__(self):
        super(AngrColorSimprocedures, self).__init__()
    
    def annotate_node(self, node):
        if node.obj.is_simprocedure:
            if node.obj.simprocedure_name in ['PathTerminator','ReturnUnconstrained','UnresolvableTarget']:
                node.style = 'filled'
                node.fillcolor = '#ffcccc'
            else:
                node.style = 'filled'
                node.fillcolor = '#dddddd'

class AngrColorExit(NodeAnnotator):
    def __init__(self):
        super(AngrColorExit, self).__init__()

    def annotate_node(self, node):
        if not node.obj.is_simprocedure:
            found = False
            for e in self.graph.edges:
                if e.src == node:                
                    found = True
                    if 'jumpkind' in e.meta and e.meta['jumpkind'] == 'Ijk_Ret':
                        node.style = 'filled'
                        node.fillcolor = '#ddffdd'
            if not found:
                node.style = 'filled'
                node.fillcolor = '#ddffdd'
            
class AngrColorEntry(NodeAnnotator):
    def __init__(self):
        super(AngrColorEntry, self).__init__()

    def annotate_node(self, node):
        if not node.obj.is_simprocedure:
            if hasattr(node.obj, 'function_address') and node.obj.addr == node.obj.function_address:
                node.style = 'filled'
                node.fillcolor = '#ffffcc'

class AngrColorEdgesVex(EdgeAnnotator):
    def __init__(self):
        super(AngrColorEdgesVex, self).__init__()


    def annotate_edge(self, edge):
        style = get_style()
        vex = None
        if 'jumpkind' in edge.meta:
            jk = edge.meta['jumpkind']
            if jk == 'Ijk_Ret':
                style.make_edge(edge, 'RET')
            elif jk == 'Ijk_FakeRet':
                style.make_edge(edge, 'FAKE_RET')
            elif jk == 'Ijk_Call':
                style.make_edge(edge, 'CALL')
                if 'vex' in edge.src.content:
                    vex = edge.src.content['vex']['vex']
                    if len (vex.next.constants) == 1 and vex.next.constants[0].value != edge.dst.obj.addr:
                        #TODO
                        edge.style='dotted'
            elif jk == 'Ijk_Boring':
                if 'vex' in edge.src.content:
                    vex = edge.src.content['vex']['vex']
                    if len(vex.constant_jump_targets) > 1:
                        if len (vex.next.constants) == 1:
                            if edge.dst.obj.addr == vex.next.constants[0].value:
                                style.make_edge(edge, 'CONDITIONAL_FALSE')
                            else:
                                style.make_edge(edge, 'CONDITIONAL_TRUE')
                        else:
                            style.make_edge(edge, 'UNKNOWN')
                    else:
                        style.make_edge(edge, 'UNCONDITIONAL')
                else:
                    style.make_edge(edge, 'UNCONDITIONAL')
            else:
                #TODO warning
                style.make_edge(edge, 'UNKNOWN')
        else:
            style.make_edge(edge, 'UNKNOWN')


class AngrPathAnnotator(EdgeAnnotator, NodeAnnotator):
    
    def __init__(self, path):
        super(AngrPathAnnotator, self).__init__()
        self.path = path
        self.trace = list(path.history.bbl_addrs)

    def set_graph(self, graph):
        super(AngrPathAnnotator, self).set_graph(graph)
        self.vaddr = self.valid_addrs()        
        ftrace = list(filter(lambda _: _ in self.vaddr, self.trace))
        self.edges_hit = set(zip(ftrace[:-1], ftrace[1:]))
        
            
    def valid_addrs(self):
        vaddr = set()
        for n in self.graph.nodes:
            vaddr.add(n.obj.addr)
        return vaddr
        
    #TODO add caching
    #TODO not sure if this is valid
    def node_hit(self, node):

        if node.callstack_key:
            ck = list(node.callstack_key)
        else:
            ck = []
        ck.append(node.addr)
        rtrace = list(reversed(self.trace))
        
        found = True
        si = 0
        for c in reversed(ck):
            if c == None:
                break
            try: 
                si = rtrace[si:].index(c)
            except:
                found = False
                break
        return found
        
    def annotate_edge(self, edge):
        key = (edge.src.obj.addr, edge.dst.obj.addr)
        if key in self.edges_hit and self.node_hit(edge.src.obj) and self.node_hit(edge.dst.obj):
            edge.width = 3
            edge.color = 'red'
    
    def annotate_node(self, node):
        if self.node_hit(node.obj):
            node.width = 3
            node.color = 'red'


class AngrBackwardSliceAnnotatorVex(ContentAnnotator):
    def __init__(self, bs):
        super(AngrBackwardSliceAnnotatorVex, self).__init__('vex')
        self.bs = bs
        self.targets = set(self.bs._targets)

    def register(self, content):
        content.add_column_before('taint')
        
    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        st =  self.bs.chosen_statements[node.obj.addr]        
        for k in range(len(content['data'])):                
            c = content['data'][k]
            if k in st:
                c['addr']['style'] = 'B'
                c['statement']['style'] = 'B'
                c['taint'] = {
                    'content':'[*]',
                    'style':'B'
                }
                if (node.obj, k) in self.targets:
                    c['addr']['color'] = 'red'
                    c['statement']['color'] = 'red'

class AngrBackwardSliceAnnotatorAsm(ContentAnnotator):
    def __init__(self, bs):
        super(AngrBackwardSliceAnnotatorAsm, self).__init__('asm')
        self.bs = bs
        self.targets = set(self.bs._targets)

    def register(self, content):
        content.add_column_before('taint')
        
    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        st =  self.bs.chosen_statements[node.obj.addr]
        staddr = set()

        #TODO
        vex = self.bs.project.factory.block(addr=node.obj.addr, size=node.obj.size).vex
        
        caddr = None
        for j, s in enumerate(vex.statements):
            if isinstance(s, pyvex.stmt.IMark):
                caddr = s.addr
            if j in st:
                staddr.add(caddr)
        
        for c in content['data']:
            if c['_addr'] in staddr:
                c['addr']['style'] = 'B'
                c['mnemonic']['style'] = 'B'
                c['operands']['style'] = 'B'
                c['taint'] = {
                    'content':'[*]',
                    'style':'B'
                }
    


class AngrColorDDGStmtEdges(EdgeAnnotator):
    def __init__(self,project=None):
        super(AngrColorDDGStmtEdges, self).__init__()
        self.project = project

    def annotate_edge(self, edge):
        if 'type' in edge.meta:
            if edge.meta['type'] == 'tmp':
                edge.color = 'blue'
                edge.label = 't'+ str(edge.meta['data'])
            elif edge.meta['type'] == 'reg':
                edge.color = 'green'
                if self.project:
                    edge.label = self.project.arch.register_names[edge.meta['data'].reg] + " " + str(edge.meta['data'].size)
                else:
                    edge.label = "reg"+str(edge.meta['data'].reg) + " " + str(edge.meta['data'].size)
            elif edge.meta['type'] == 'mem':
                edge.color = 'red'
                edge.label = str(edge.meta['data'])
            else:
                edge.label = edge.meta['type']
                edge.style = 'dotted'
            
class AngrColorDDGData(EdgeAnnotator, NodeAnnotator):
    def __init__(self,project=None, labels=False):
        super(AngrColorDDGData, self).__init__()
        self.project = project
        self.labels = labels

    def annotate_edge(self, edge):
        if 'type' in edge.meta:
            if edge.meta['type'] == 'kill':
                edge.color = 'red'
            elif edge.meta['type'] == 'mem_addr':
                edge.color = 'blue'
                edge.style = 'dotted'
            elif edge.meta['type'] == 'mem_data':
                edge.color = 'blue'
            else:
                edge.color = 'yellow'
            if self.labels:
                edge.label = edge.meta['type']

    def annotate_node(self, node):
        if node.obj.initial:
            node.fillcolor = '#ccffcc'
            node.style = 'filled'


class AngrActionAnnotatorVex(ContentAnnotator):
    def __init__(self):
        super(AngrActionAnnotatorVex, self).__init__('vex')

    def register(self, content):
        content.add_column_after('action_type')
        content.add_column_after('action_addr')
        content.add_column_after('action_data')
        
    def annotate_content(self, node, content):
        from angr.state_plugins.sim_action import SimActionData

        if node.obj.is_simprocedure or node.obj.is_syscall:
            return
        
        if len(node.obj.final_states) > 0:
            state = node.obj.final_states[0]
            for action in state.log.actions:
                if isinstance(action, SimActionData):
                    c = content['data'][action.stmt_idx]
                    c['action_type'] = {
                        'content': action.type+"/"+action.action+"("+str(action.size.ast)+")",
                        'align': 'LEFT'
                    }
                    #TODO
                    if str(action.addr) != 'None':
                        c['action_addr'] = {
                            'content': str(action.addr.ast),
                            'align': 'LEFT'
                        }
                    if str(action.data) != 'None':
                        c['action_data'] = {
                            'content': str(action.data.ast),
                            'align': 'LEFT'
                        }


#EXPERIMENTAL
class AngrCodelocLogAnnotator(ContentAnnotator):
    def __init__(self, cllog):
        super(AngrCodelocLogAnnotator, self).__init__('vex')
        self.cllog = cllog
        
    def register(self, content):
        content.add_column_after('log')
        
    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        for k in range(len(content['data'])):
            c = content['data'][k]
            key = (node.obj.addr, k)
            if key in self.cllog:
                c['log'] = {
                    'content': self.cllog[key],
                    'align':'LEFT'
                }


class AngrCommentsAsm(ContentAnnotator):
    def __init__(self, project):
        super(AngrCommentsAsm, self).__init__('asm')
        self.project = project

    def register(self, content):
        content.add_column_after('comment')

    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        comments_by_addr = {}
        if len(node.obj.final_states) > 0:
            state = node.obj.final_states[0]
            for action in state.log.actions:
                label = ''
                if action.type == 'mem' or action.type == 'reg':
                    if isinstance(action.data.ast, int) or action.data.ast.concrete:
                        d = state.solver.eval(action.data.ast)
                        if d in self.project.kb.labels:
                            label += 'data=' + self.project.kb.labels[d] + ' '
                    if isinstance(action.addr.ast, int) or action.addr.ast.concrete:
                        a = state.solver.eval(action.addr.ast)
                        if a in self.project.kb.labels:
                            label += 'addr=' + self.project.kb.labels[a] + ' '

                if action.type == 'exit':
                    if action.target.ast.concrete:
                        a = state.solver.eval(action.target.ast)
                        if a in self.project.kb.labels:
                            label += self.project.kb.labels[a] + ' '

                if label != '':
                    comments_by_addr[action.ins_addr] = label

        for k in content['data']:
            ins = k['_ins']
            if ins.address in comments_by_addr:
                if not ('comment' in k and 'content' in k['comment']):
                    k['comment'] = {
                        'content': "; " + comments_by_addr[ins.address][:100]
                    }
                else:
                    k['comment']['content'] += ", " + comments_by_addr[ins.address][:100]

                k['comment']['color'] = 'gray'
                k['comment']['align'] = 'LEFT'



class AngrCommentsDataRef(ContentAnnotator):
    def __init__(self, project):
        super(AngrCommentsDataRef, self).__init__('asm')
        self.project = project

    def register(self, content):
        content.add_column_after('comment')

    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        comments_by_addr = {}
        for dr in node.obj.accessed_data_references:
            comments_by_addr[dr.ins_addr] = str(dr)
            if dr.memory_data.sort == 'string':
                comments_by_addr[dr.ins_addr] = str(dr.memory_data.content)

        for k in content['data']:
            ins = k['_ins']
            if ins.address in comments_by_addr:
                if not ('comment' in k and 'content' in k['comment']):
                    k['comment'] = {
                        'content': "; " + comments_by_addr[ins.address][:100]
                    }
                else:
                    k['comment']['content'] += ", " + comments_by_addr[ins.address][:100]

                k['comment']['color'] = 'gray'
                k['comment']['align'] = 'LEFT'




class AngrVariables(ContentAnnotator):
    def __init__(self, project, debug=False):
        super(AngrVariables, self).__init__('asm')
        self.project = project
        self.debug = debug

    def register(self, content):
        content.add_column_before('variables')

    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return

        vm = self.project.kb.variables[node.obj.function_address]

        for k in content['data']:
            ins = k['_ins']
            vars = vm.find_variables_by_insn(ins.address, 'memory')
            if vars: 
                for var in vars:
                    if not 'variables' in k:
                        k['variables'] = {'content':''}
                    k['variables']['content'] += repr(var[0].name + (' (' + var[0].ident + ')' if self.debug else '') )
                    k['variables']['color'] = 'lightblue'
                    k['variables']['align'] = 'LEFT'



