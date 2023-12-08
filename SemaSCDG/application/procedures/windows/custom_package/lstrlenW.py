import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class lstrlenW(angr.SimProcedure):
    def run(self, s):
        if s.symbolic:
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
        
        try:
            string = self.state.mem[s].wstring.concrete
            return len(string)
        except:
            lw.debug("s not resolvable")
            for i in range(0x100):
                if self.state.solver.eval(self.state.memory.load(s+(2*i),2)) == 0x0:
                    return i
            lw.debug("can't find length")
            return self.state.solver.BVS("retval_{}".format(self.display_name), 32)
        

