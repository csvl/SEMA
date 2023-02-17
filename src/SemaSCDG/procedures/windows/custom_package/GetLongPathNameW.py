import angr


class GetLongPathNameW(angr.SimProcedure):
    def decodeWString(self, ptr):
        fileName = self.state.mem[ptr].wstring.concrete
        # if hasattr(fileName, "decode"):
        #     fileName = fileName.decode("utf-16-le")
        return fileName
    
    def decodeString(self, ptr):
        fileName = self.state.mem[ptr].string.concrete
        if hasattr(fileName, "decode"):
            fileName = fileName.decode("utf-8")
        return fileName
    
    def run(self, lpszShortPath, lpszLongPath, cchBuffer):
        #tchar = self.state.solver.BVV(cchBuffer, 16)
        size = self.state.solver.eval(cchBuffer)
        print("size: {}".format(size))
        
        lpszShortPath_str = self.decodeWString(lpszShortPath)
        print("lpszShortPath: {}".format(lpszShortPath_str))
        # lpszShortPath_converted = lpszShortPath_str.encode('utf-16-le') + b'\x00\x00'
        
        # print("lpszShortPath: {}".format(lpszShortPath_converted))
        
        self.state.memory.store(lpszLongPath, lpszShortPath_str)
        
        return cchBuffer
