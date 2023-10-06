import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class FindWindowW(angr.SimProcedure):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-16-le")
        return lib
        
    def run(
        self,
        lpClassName,
        lpWindowName
    ):
        className = self.decodeString(lpClassName)
        return 0x0
