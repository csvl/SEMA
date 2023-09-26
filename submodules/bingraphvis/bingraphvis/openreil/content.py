
from ..base import *

import pyopenreil

class OpenreilCFGHead(Content):
    def __init__(self):
        super(OpenreilCFGHead, self).__init__('head', ['addr'])

    def gen_render(self, n):
        
        n.content[self.name] = {
            'data': [{
                'addr': {
                    'content': "{:#08x}".format(n.obj.item.ir_addr[0])
                }
            }], 
            'columns': self.get_columns()
        }



class OpenreilAsm(Content):
    def __init__(self):
        super(OpenreilAsm, self).__init__('asm', ['addr', 'mnemonic', 'operands'])

    def gen_render(self, n):
        data = []
        for ins in n.obj.item:
            if not ins.has_attr(pyopenreil.IR.IATTR_ASM):
                continue
            
            mnem, args = ins.get_attr(pyopenreil.IR.IATTR_ASM)
            data.append({
                'addr': {
                    'content': "0x%08x:" % ins.ir_addr()[0],
                    'align': 'LEFT'
                },
                'mnemonic': {
                    'content': mnem,
                    'align': 'LEFT'
                },
                'operands': {
                    'content': args,
                    'align': 'LEFT'
                },
                '_ins': ins,
                '_addr': ins.ir_addr()[0]
            })
        
        n.content[self.name] = {
            'data': data, 
            'columns': self.get_columns()
        }






class OpenreilREIL(Content):
    def __init__(self):
        super(OpenreilREIL, self).__init__('reil', ['addr', 'op', 'a','b','c'])

    def gen_render(self, n):
        data = []
        for ins in n.obj.item:
            data.append({
                'addr': {
                    'content': "%.8x.%.2x:" % ins.ir_addr(),
                    'align': 'LEFT'
                },
                'op': {
                    'content': '%7s' % ins.op_name(),
                    'align': 'LEFT'
                },
                'a': {
                    'content': '%16s' % ins.a,
                    'align': 'LEFT'
                },
                'b': {
                    'content': '%16s' % ins.b,
                    'align': 'LEFT'
                },
                'c': {
                    'content': '%16s' % ins.c,
                    'align': 'LEFT'
                },
                '_ins': ins,
                '_addr': ins.ir_addr()
            })
        
        n.content[self.name] = {
            'data': data, 
            'columns': self.get_columns()
        }




