import logging
import angr
import os

lw = logging.getLogger("CustomSimProcedureWindows")
lw.setLevel(os.environ["LOG_LEVEL"])


class GetFullPathNameW(angr.SimProcedure):
    def run(self, lpFileName, nBufferLength, lpBuffer, lpFilePart):
        try:
            f = self.state.mem[lpFileName].wstring.concrete
            lw.debug(f)
            if f[-1] == "\\": # is folder
                pathpath_bytes = f.encode("utf-16-le") 
                lenpath = len(pathpath_bytes) 
                lw.debug(lenpath)
                lw.debug(pathpath_bytes.decode("utf-16-le"))
                self.state.memory.store(lpBuffer, pathpath_bytes)   # , size=len(longname)
                
                self.state.memory.store(lpFilePart, 0) # , size=len(longname) 
            else:
                lenpath = len(f)
                pathpath_bytes = f.encode("utf-16-le") 
                #lenpath = len(pathpath_bytes) 
                lw.debug(lenpath)
                lw.debug(pathpath_bytes.decode("utf-16-le"))
                self.state.memory.store(lpBuffer, pathpath_bytes)   # , size=len(longname)
                
                if "C:" not in f: #only file
                    filepart_bytes = f.encode("utf-16-le")
                    f = "C:\\Windows\\System32\\" + f
                    filepart_offset = len("C:\\Windows\\System32\\".encode("utf-16-le"))
                else: # full path already
                    filepart = f.split("\\")[-1] 
                    filepart_bytes = filepart.encode("utf-16-le")
                    filepart_offset = len(pathpath_bytes) - len(filepart_bytes) - 2
                lenfile = len(filepart_bytes) 
                lw.debug(filepart_offset)
                lw.debug(filepart_bytes.decode("utf-16-le"))
                self.state.memory.store(lpFilePart, lpBuffer+filepart_offset) # , size=len(longname) 
                
            return lenpath
        except Exception as e:
            lw.warning(e)
            # longname = "C:\Windows\System32\\".encode("utf-16-le")
            # longname =+ self.state.memory.load(lpFileName, nBufferLength)
            # # lw.debug(self.state.memory.load(lpBuffer,nBufferLength))
            # lw.debug(longname)
            # self.state.memory.store(lpBuffer,longname)
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
