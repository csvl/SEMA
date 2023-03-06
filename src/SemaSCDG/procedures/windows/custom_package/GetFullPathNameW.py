import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class GetFullPathNameW(angr.SimProcedure):
    def run(self, lpFileName, nBufferLength, lpBuffer, lpFilePart):
        try:
            f = self.state.mem[lpFileName].wstring.concrete
            lw.info(f)
            filepart = f.split("\\")[-1]
            pathpath = f.replace(filepart,"")
            lw.info(filepart)
            lw.info(pathpath)
            
            filepart_bytes = filepart.encode("utf-16-le") + b"\0\0"
            lenfile = len(filepart_bytes) 
            lw.info(lenfile)
            lw.info(filepart_bytes.decode("utf-16-le"))
            self.state.memory.store(lpFilePart, filepart) # , size=len(longname)
            
            pathpath_bytes = pathpath.encode("utf-16-le") + b"\0\0"
            lenpath = len(pathpath_bytes) 
            lw.info(lenpath)
            lw.info(pathpath_bytes.decode("utf-16-le"))
            self.state.memory.store(lpBuffer, pathpath)   # , size=len(longname)
            
            return len(pathpath_bytes.decode("utf-16-le"))
        except Exception as e:
            lw.info(e)
            longname = "C:\Windows\System32\\".encode("utf-16-le")
            longname =+ self.state.memory.load(lpFileName, nBufferLength)
            # lw.info(self.state.memory.load(lpBuffer,nBufferLength))
            lw.info(longname)
            self.state.memory.store(lpBuffer,longname)
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
