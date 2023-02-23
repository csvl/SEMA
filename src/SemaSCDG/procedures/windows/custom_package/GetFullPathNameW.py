import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class GetFullPathNameW(angr.SimProcedure):
    def run(self, lpFileName, nBufferLength, lpBuffer, lpFilePart):
        try:
            f = self.state.mem[lpFileName].wstring.concrete
            lw.info(f)
            f_bytes = f.encode("utf-16-le")
            lenfile = len(f_bytes) 
            lw.info(lenfile)
            # "C:\Windows\System32\\".encode("utf-16-le") +
            longname =  f_bytes #self.state.memory.load(lpFileName, lenfile)
            lw.info(longname)
            self.state.memory.store(lpBuffer, longname) # , size=len(longname)
            return len(longname.decode("utf-16-le"))
        except Exception as e:
            lw.info(e)
            longname = "C:\Windows\System32\\".encode("utf-16-le")
            longname =+ self.state.memory.load(lpFileName, nBufferLength)
            # lw.info(self.state.memory.load(lpBuffer,nBufferLength))
            lw.info(longname)
            self.state.memory.store(lpBuffer,longname)
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
