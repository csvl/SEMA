import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class send(angr.SimProcedure):
    def run(self, s, buf, length, flags):
        if length.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)           
        else:
            length = self.state.solver.eval(length)
            x = self.state.solver.eval(self.state.memory.load(buf,length))
            try:
                lw.info(self.state.memory.load(buf,length))
                z = ''.join(chr((x>>8*(length-byte-1))&0xFF) for byte in range(length))
                lw.info("send("+hex(self.state.solver.eval(s))+", "+z+", "+hex(length)+", "+hex(self.state.solver.eval(flags))+")")
            except:
                lw.info(hex(x))
            return length
