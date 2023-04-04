import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class GetFullPathNameW(angr.SimProcedure):
    def run(self, lpFileName, nBufferLength, lpBuffer, lpFilePart):
        try:
            f = self.state.mem[lpFileName].wstring.concrete
            lw.info(f)
            if f[-1] == "\\": # is folder
                pathpath_bytes = f.encode("utf-16-le") 
                lenpath = len(pathpath_bytes) 
                lw.info(lenpath)
                lw.info(pathpath_bytes.decode("utf-16-le"))
                self.state.memory.store(lpBuffer, pathpath_bytes)   # , size=len(longname)
                
                self.state.memory.store(lpFilePart, 0) # , size=len(longname) 
            else:
                lenpath = len(f)
                pathpath_bytes = f.encode("utf-16-le") 
                #lenpath = len(pathpath_bytes) 
                lw.info(lenpath)
                lw.info(pathpath_bytes.decode("utf-16-le"))
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
                lw.info(filepart_offset)
                lw.info(filepart_bytes.decode("utf-16-le"))
                self.state.memory.store(lpFilePart, lpBuffer+filepart_offset) # , size=len(longname) 
                
            return lenpath
        except Exception as e:
            lw.info(e)
            # longname = "C:\Windows\System32\\".encode("utf-16-le")
            # longname =+ self.state.memory.load(lpFileName, nBufferLength)
            # # lw.info(self.state.memory.load(lpBuffer,nBufferLength))
            # lw.info(longname)
            # self.state.memory.store(lpBuffer,longname)
            return self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
