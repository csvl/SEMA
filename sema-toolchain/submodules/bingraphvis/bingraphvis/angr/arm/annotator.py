
from ...base import *
from ...style import get_style

class AngrColorEdgesAsmArm(EdgeAnnotator):
    def __init__(self):
        super(AngrColorEdgesAsmArm, self).__init__()

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
                    last = edge.src.content['asm']['data'][-1]
                    # Get rid of width specifiers (.w or .n)
                    asm = last['mnemonic']['content'].split('.')[0]
                    if asm in ['b', 'bx']:
                        style.make_edge(edge, 'UNCONDITIONAL')
                    elif asm.startswith('b') or asm in ('cbz', 'cbnz'):
                        try:
                            if int(last['operands']['content'].split(', ')[-1].replace('#',''),16) == edge.dst.obj.addr:
                                style.make_edge(edge, 'CONDITIONAL_TRUE')
                            else:
                                style.make_edge(edge, 'CONDITIONAL_FALSE')
                        except Exception as e:
                            #TODO warning
                            style.make_edge(edge, 'UNKNOWN')
                    else:
                        style.make_edge(edge, 'NEXT')
            else:
                #TODO warning
                style.make_edge(edge, 'UNKNOWN')
