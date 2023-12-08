import logging
import angr

import configparser

config = configparser.ConfigParser()
config.read('config.ini')
lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(config['SCDG_arg'].get('log_level'))


class GetSystemDirectoryA(angr.SimProcedure):
    def getSystemName(self, size):
        path = ("C:\Windows\System32"[: size - 1] + "\0").encode(
            "utf-8"
        )  # truncate if too long
        return path

    def run(self, lpBuffer, uSize):
        size = self.state.solver.eval(uSize)
        path = self.getSystemName(size)
        path = self.state.solver.BVV(path)
        self.state.memory.store(lpBuffer, path)  # ,endness=self.arch.memory_endness)
        # import pdb; pdb.set_trace()
        return len(path) + 2
