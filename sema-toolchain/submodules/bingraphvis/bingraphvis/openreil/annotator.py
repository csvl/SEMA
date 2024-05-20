
from ..base import *
from ..style import get_style
import pyopenreil

class OpenreilColorEdgesAsm(EdgeAnnotator):
    def __init__(self):
        super(OpenreilColorEdgesAsm, self).__init__()

    def annotate_edge(self, edge):
        style = get_style()
        if 'asm' in edge.src.content:
            last = edge.src.content['asm']['data'][-1]

            if last['mnemonic']['content'].find('jmp') == 0:
                style.make_edge(edge, 'UNCONDITIONAL')
            elif last['mnemonic']['content'].find('j') == 0:
                try:
                    if int(last['operands']['content'],16) + last['_addr'] == edge.dst.obj.item.ir_addr[0]:
                        style.make_edge(edge, 'CONDITIONAL_TRUE')
                    else:
                        style.make_edge(edge, 'CONDITIONAL_FALSE')
                except Exception as e:
                    #TODO warning
                    style.make_edge(edge, 'UNKNOWN')
            else:
                style.make_edge(edge, 'NEXT')
