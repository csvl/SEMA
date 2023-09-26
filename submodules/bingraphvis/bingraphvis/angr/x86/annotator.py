
from ...base import *
from ...style import get_style
import capstone
from capstone.x86 import *



class AngrColorEdgesAsmX86(EdgeAnnotator):
    def __init__(self):
        super(AngrColorEdgesAsmX86, self).__init__()

    def annotate_edge(self, edge):
        style = get_style()
        if 'jumpkind' in edge.meta:
            jk = edge.meta['jumpkind']
            if jk == 'Ijk_Ret':
                style.make_edge(edge, 'RET')
            elif jk == 'Ijk_FakeRet':
                style.make_edge(edge, 'FAKE_RET')
            elif jk == 'Ijk_Call':
                style.make_edge(edge, 'CALL')
            elif jk == 'Ijk_Boring':
                if 'asm' in edge.src.content:
                    asm = edge.src.content['asm']
                    if 'data' in asm and len(asm['data']) > 0:
                        last = edge.src.content['asm']['data'][-1]
                        if last['mnemonic']['content'].find('jmp') == 0:
                            style.make_edge(edge, 'UNCONDITIONAL')
                        elif last['mnemonic']['content'].find('j') == 0:
                            try:
                                if int(last['operands']['content'],16) == edge.dst.obj.addr:
                                    style.make_edge(edge, 'CONDITIONAL_TRUE')
                                else:
                                    style.make_edge(edge, 'CONDITIONAL_FALSE')
                            except Exception as e:
                                #TODO warning
                                style.make_edge(edge, 'UNKNOWN')
                        else:
                            style.make_edge(edge, 'NEXT')
                    else:
                        style.make_edge(edge, 'UNKNOWN')
            else:
                #TODO warning
                style.make_edge(edge, 'UNKNOWN')

class AngrX86ArrayAccessAnnotator(ContentAnnotator):
    def __init__(self):
        super(AngrX86ArrayAccessAnnotator, self).__init__('asm')

    def register(self, content):
        content.add_column_after('comment')
        
    def annotate_content(self, node, content):
        for k in content['data']:
            ins = k['_ins']
            if ins.mnemonic == 'mov':
                if len(ins.operands) > 0:
                    c = -1
                    for i in ins.operands:
                        c += 1
                        if i.type == X86_OP_MEM:
                            if i.mem.index != 0:
                                try:
                                    content = "R" if c == 1 else "W" + "," + ins.reg_name(i.mem.base) +"," + ins.reg_name(i.mem.index)+","+hex(i.mem.disp)+",+"+hex(i.mem.scale)
                                except:
                                    content = "EXCEPTION"
                                k['comment'] = {
                                    'content': content,
                                    'color':'gray',
                                    'align': 'LEFT'
                                }
                                node.fillcolor = '#ffff33'
                                node.style = 'filled'


class AngrX86CommentsAsm(ContentAnnotator):
    def __init__(self, project):
        super(AngrX86CommentsAsm, self).__init__('asm')
        self.project = project

    def register(self, content):
        content.add_column_after('comment')
        
    def demangle(self, names):
        import subprocess
        args = ['c++filt']
        args.extend(names)
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.split("\n")

        assert len(demangled) == len(names)+1
        return demangled[:-1]

    def annotate_content(self, node, content):
        if node.obj.is_simprocedure or node.obj.is_syscall:
            return
        for k in content['data']:
            ins = k['_ins']
            if ins.group(capstone.CS_GRP_CALL):
                caddr = ins.operands[0]
                try:
                    addr = int(caddr.value.imm)
                    fm = self.project.kb.functions
                    fname = None
                    if addr in fm:
                        fname = fm[addr].name
                        if fname.find('_Z') == 0:
                            try:
                                fname = self.demangle([fname])[0]
                            except Exception as e:
                                pass
                    
                    if fname:
                        if not ('comment' in k and 'content' in k['comment']):
                            k['comment'] = {
                                'content': "; "+ fname
                            }
                        else:
                            k['comment']['content'] += ", " + fname

                        k['comment']['color'] ='gray'
                        k['comment']['align'] = 'LEFT'
                except: 
                    pass
