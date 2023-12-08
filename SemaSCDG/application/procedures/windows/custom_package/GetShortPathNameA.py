import logging
import angr
import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetShortPathNameA(angr.SimProcedure):
    def run(self, lpszLongPath, lpszShortPath, cchBuffer):
        try:
            longname = self.state.mem[lpszLongPath].string.concrete
            print(longname)
            self.state.memory.store(lpszShortPath, self.state.solver.BVV(longname))
            return len(longname)
        except:
            print(self.state.memory.load(lpszLongPath,0x20))
            self.state.memory.store(lpszShortPath, self.state.memory.load(lpszLongPath,0x20))
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
